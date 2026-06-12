// Package dirscan performs directory scans for ransomware activity (files with ransomware
// extensions, and ransom-note correlation) and emits indicators through an injected
// AlertEmitter. Extracted from DetectionService (Phase 6) to isolate the scanning concern
// and make it unit-testable (the usecase test binary is AV-blocked in some dev envs).
//
// This is a BEHAVIOR-PRESERVING extraction: the two walkers (progressive single-directory
// vs multi-directory-with-ransom-note-correlation) and the per-event goroutine spawn are
// kept exactly as they were in DetectionService. Bounding goroutine concurrency and
// unifying the two walkers (the audit's recommendation) are deliberately deferred to a
// follow-up that can be runtime-tested, since they change detection behavior.
package dirscan

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"procSniper/internal/domain"
)

// AlertEmitter feeds scan findings into the detection/response pipeline. Implemented by
// usecase.DetectionService (RaiseIndicator -> addRuleIndicator, Evaluate -> evaluateAndAlert).
type AlertEmitter interface {
	RaiseIndicator(processGuid, image string, pid int, indicator domain.Indicator) int
	Evaluate(processGuid, image string, pid int)
}

// Scanner owns the directory-scan concern: the in-progress dedup set and the ransomware
// extension list, emitting through the injected AlertEmitter.
type Scanner struct {
	emitter        AlertEmitter
	ransomwareExts []string

	inProgressMu sync.Mutex
	inProgress   map[string]bool // DirPath -> scanning (prevents duplicate progressive scans)
}

// NewScanner builds a Scanner wired to the detection-pipeline emitter.
func NewScanner(emitter AlertEmitter, ransomwareExts []string) *Scanner {
	return &Scanner{
		emitter:        emitter,
		ransomwareExts: ransomwareExts,
		inProgress:     make(map[string]bool),
	}
}

// ScanDirectory scans a directory for files with ransomware extensions.
// Returns the list of ransomware file names found and the total file count.
func (s *Scanner) ScanDirectory(dirPath string) ([]string, int) {
	ransomFiles := make([]string, 0)
	totalFiles := 0

	// Read directory contents
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		// Directory might not exist or access denied
		log.Printf("[DIRECTORY SCAN] ERROR: Failed to read directory %s: %v", dirPath, err)
		return ransomFiles, 0
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip subdirectories
		}

		totalFiles++
		fileName := entry.Name()
		filePath := filepath.Join(dirPath, fileName)

		//print all the list of files
		log.Printf("[DIRECTORY SCAN FILES] File: %s", filePath)

		// Check if file has ransomware extension
		if domain.IsRansomwareExtension(filePath, s.ransomwareExts) {
			log.Printf("[DIRECTORY SCAN] Found malicious file: %s", fileName)
			ransomFiles = append(ransomFiles, fileName)
		}
	}

	return ransomFiles, totalFiles
}

// processResult processes the results of a directory scan and emits a bulk-encryption
// indicator. Centralizes scan-result processing for the progressive scans.
func (s *Scanner) processResult(event *domain.MonitorEvent, dirPath string, ransomFiles []string, totalFiles int, scanType string) {
	if len(ransomFiles) == 0 {
		return
	}

	log.Printf("[DETECTION] 🚨 PATH ANALYSIS [%s]: Found %d suspicious files in %s (total files: %d)",
		scanType, len(ransomFiles), dirPath, totalFiles)

	// Show first 5 suspicious files found
	sampleSize := len(ransomFiles)
	if sampleSize > 5 {
		sampleSize = 5
	}
	for i := 0; i < sampleSize; i++ {
		log.Printf("    [%d] %s", i+1, ransomFiles[i])
	}
	if len(ransomFiles) > 5 {
		log.Printf("    ... and %d more suspicious files", len(ransomFiles)-5)
	}

	// Calculate percentage of directory encrypted
	encryptionPercentage := 0.0
	if totalFiles > 0 {
		encryptionPercentage = (float64(len(ransomFiles)) / float64(totalFiles)) * 100.0
	}

	log.Printf("[DETECTION] 🔴 PATH ENCRYPTION [%s]: %.1f%% of files modified (%d/%d files)",
		scanType, encryptionPercentage, len(ransomFiles), totalFiles)

	// Add indicator based on severity
	var severity domain.ThreatLevel
	var points int

	// Adjust scoring based on scan type (immediate = more critical)
	bonusPoints := 0
	if scanType == "IMMEDIATE" {
		bonusPoints = 5 // Immediate detection = fast encryption = more dangerous
	} else if scanType == "IN_PROGRESS" {
		bonusPoints = 3 // Active encryption detected
	}

	if encryptionPercentage >= 50.0 || len(ransomFiles) >= 10 {
		// High severity: >50% encrypted OR 10+ files
		severity = domain.ThreatCritical
		points = 40 + bonusPoints
	} else if len(ransomFiles) >= 3 {
		// Medium severity: 3-9 files
		severity = domain.ThreatHigh
		points = 30 + bonusPoints
	} else {
		// Low severity: 1-2 files
		severity = domain.ThreatMedium
		points = 20 + bonusPoints
	}

	indicator := domain.Indicator{
		Type:     domain.IndicatorBulkEncryption,
		Severity: severity,
		Points:   points,
		Description: fmt.Sprintf("Bulk file modification detected [%s]: %d suspicious files found (%.1f%% modified)",
			scanType, len(ransomFiles), encryptionPercentage),
		Timestamp: event.Timestamp,
		Evidence: map[string]string{
			"directory":             dirPath,
			"malicious_files":       fmt.Sprintf("%d", len(ransomFiles)),
			"total_files":           fmt.Sprintf("%d", totalFiles),
			"encryption_percentage": fmt.Sprintf("%.1f%%", encryptionPercentage),
			"sample_files":          strings.Join(ransomFiles[:sampleSize], ", "),
			"scan_type":             scanType,
		},
	}

	score := s.emitter.RaiseIndicator(
		event.ProcessGuid,
		event.Image,
		event.ProcessID,
		indicator,
	)

	log.Printf("[DETECTION] 🔴 BULK ENCRYPTION INDICATOR ADDED [%s]: %s (Score: %d, Points: +%d)",
		scanType, dirPath, score, points)

	// Immediately evaluate for response
	s.emitter.Evaluate(event.ProcessGuid, event.Image, event.ProcessID)
}

// ScanDeletedFileDir runs a progressive (immediate / +2s / +5s) directory scan triggered by
// a file delete on a high-I/O process, deduplicated per directory to prevent goroutine
// explosion. The scan runs in a background goroutine; this method returns immediately.
//
// Returns true if a new scan was started, false if one was already in progress for the
// directory (deduped). The caller preserves the original behavior of skipping the rest of
// its delete handling when a scan is already running.
func (s *Scanner) ScanDeletedFileDir(event *domain.MonitorEvent) bool {
	dirPath := filepath.Dir(event.TargetFile)

	// DEDUPLICATION: Check if scan already in progress for this directory
	s.inProgressMu.Lock()
	if s.inProgress[dirPath] {
		s.inProgressMu.Unlock()
		log.Printf("[PATH ANALYSIS] Scan already in progress for %s, skipping duplicate", dirPath)
		return false // Scan already running for this directory
	}
	s.inProgress[dirPath] = true
	s.inProgressMu.Unlock()

	// Run progressive directory scan in parallel to avoid blocking event processing
	go func() {
		defer func() {
			// Cleanup: Remove from in-progress map when done
			s.inProgressMu.Lock()
			delete(s.inProgress, dirPath)
			s.inProgressMu.Unlock()
		}()

		log.Printf("[PATH ANALYSIS] Starting progressive scan for %s...", dirPath)

		// SCAN 1: IMMEDIATE (catch early encryption)
		log.Printf("[PATH ANALYSIS] Scan 1/3: Immediate check...")
		scan1Files, scan1Total := s.ScanDirectory(dirPath)
		if len(scan1Files) > 3 {
			// Early detection: 3+ suspicious files immediately
			log.Printf("[DETECTION] ⚡ IMMEDIATE DETECTION: %d suspicious files in %s", len(scan1Files), dirPath)
			s.processResult(event, dirPath, scan1Files, scan1Total, "IMMEDIATE")
			return // Alert immediately, no need to wait
		}

		// SCAN 2: After 2 seconds (catch in-progress encryption)
		time.Sleep(2 * time.Second)
		log.Printf("[PATH ANALYSIS] Scan 2/3: Re-checking after 2s...")
		scan2Files, scan2Total := s.ScanDirectory(dirPath)

		// Check if encryption is progressing
		if len(scan2Files) > len(scan1Files)+5 {
			// Encryption in progress: 5+ more files in 2 seconds
			log.Printf("[DETECTION] 🔥 ENCRYPTION IN PROGRESS: %d suspicious files (+%d in 2s) in %s",
				len(scan2Files), len(scan2Files)-len(scan1Files), dirPath)
			s.processResult(event, dirPath, scan2Files, scan2Total, "IN_PROGRESS")
			return // Alert on active encryption
		}

		// SCAN 3: After 5 more seconds (catch slow ransomware, total 7s from start)
		time.Sleep(3 * time.Second)
		log.Printf("[PATH ANALYSIS] Scan 3/3: Final check after 5s total...")
		scan3Files, scan3Total := s.ScanDirectory(dirPath)

		// Final check: Standard threshold
		if len(scan3Files) > 0 {
			log.Printf("[DETECTION] 🕒 SLOW ENCRYPTION: %d suspicious files in %s (detected over 5s)",
				len(scan3Files), dirPath)
			s.processResult(event, dirPath, scan3Files, scan3Total, "FINAL")
		} else {
			log.Printf("[PATH ANALYSIS] No significant threats detected in %s after 3 scans", dirPath)
		}
	}()

	return true
}

// ScanDirectoriesForEncryptedFiles scans multiple directories for ransomware-extension
// files alongside ransom-note .txt files, triggered by a ransom-note creation pattern.
func (s *Scanner) ScanDirectoriesForEncryptedFiles(processGuid string, processImage string, processID int, directories []string, timestamp time.Time) {
	log.Printf("[DIR SCAN] 🔍 Ransom note pattern detected - scanning %d directories for encrypted files", len(directories))
	log.Printf("[DIR SCAN] Process: %s (PID: %d)", filepath.Base(processImage), processID)
	log.Printf("[DIR SCAN] Strategy: Look for ransomware extensions alongside .txt files")

	encryptedFiles := make([]string, 0)
	encryptedFilesByExt := make(map[string]int) // Count by extension
	ransomNoteFiles := make([]string, 0)
	totalFilesScanned := 0
	ransomFound := false

	// Common ransom note file name patterns (case-insensitive)
	ransomNotePatterns := []string{
		"readme", "read_me", "read-me",
		"how_to_decrypt", "how-to-decrypt", "how_to_recover",
		"decrypt", "decryption", "recovery",
		"!!!_read_me_!!!", "!!!read_me!!!",
		"your_files", "files_encrypted",
		"ransom", "locked", "encrypted",
		"help_restore", "help_decrypt",
		"restore_files", "unlock_files",
	}

	for _, dirPath := range directories {
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			log.Printf("[DIR SCAN] Failed to read directory %s: %v", dirPath, err)
			continue
		}

		log.Printf("[DIR SCAN] Scanning directory: %s (%d files)", dirPath, len(entries))

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			totalFilesScanned++
			fileName := entry.Name()
			fileNameLower := strings.ToLower(fileName)
			fullPath := filepath.Join(dirPath, fileName)
			ext := filepath.Ext(fileName)

			// Check if file has ransomware extension
			if domain.IsRansomwareExtension(fullPath, s.ransomwareExts) {
				encryptedFiles = append(encryptedFiles, fullPath)
				encryptedFilesByExt[ext]++
				log.Printf("[DIR SCAN] 🚨 ENCRYPTED FILE FOUND: %s (extension: %s)", fullPath, ext)
				ransomFound = true
				break
			}

			// Also track ransom note files for correlation analysis
			if strings.HasSuffix(fileNameLower, ".txt") {
				for _, pattern := range ransomNotePatterns {
					if strings.Contains(fileNameLower, pattern) {
						ransomNoteFiles = append(ransomNoteFiles, fullPath)
						log.Printf("[DIR SCAN] 📝 Ransom note found: %s", fullPath)
						break
					}
				}
			}
		}
	}

	// Analyze results
	log.Printf("[DIR SCAN] ═══════════════════════════════════════════════════")
	log.Printf("[DIR SCAN] Scan Results:")
	log.Printf("[DIR SCAN]   Total files scanned: %d", totalFilesScanned)
	log.Printf("[DIR SCAN]   Encrypted files found: %d", len(encryptedFiles))
	log.Printf("[DIR SCAN]   Ransom notes found: %d", len(ransomNoteFiles))
	log.Printf("[DIR SCAN]   Directories scanned: %d", len(directories))
	log.Printf("[DIR SCAN] ═══════════════════════════════════════════════════")

	// Log encrypted files by extension
	if len(encryptedFilesByExt) > 0 {
		log.Printf("[DIR SCAN] Encrypted files by extension:")
		for ext, count := range encryptedFilesByExt {
			log.Printf("[DIR SCAN]   %s: %d files", ext, count)
		}
	}

	// CRITICAL: Only add indicators if ENCRYPTED FILES found alongside ransom notes
	// Ransom notes alone are NOT sufficient - we need actual encrypted files
	//if len(encryptedFiles) >= 3 && len(ransomNoteFiles) >= 1 {
	if ransomFound {
		log.Printf("[DIR SCAN] 🚨 HIGH CONFIDENCE DETECTION: %d encrypted files + %d ransom notes found together",
			len(encryptedFiles), len(ransomNoteFiles))

		// Add ransomware extension indicator based on actual encrypted files found
		indicator := domain.Indicator{
			Type:        domain.IndicatorRansomExtension,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
			Description: fmt.Sprintf("Directory scan found %d encrypted files with ransomware extensions alongside %d ransom notes", len(encryptedFiles), len(ransomNoteFiles)),
			Timestamp:   timestamp,
			Evidence: map[string]string{
				"encrypted_files":  fmt.Sprintf("%d", len(encryptedFiles)),
				"ransom_notes":     fmt.Sprintf("%d", len(ransomNoteFiles)),
				"directories":      fmt.Sprintf("%d", len(directories)),
				"detection_method": "directory_scan_tier2",
				"correlation":      "encrypted_files_with_ransom_notes",
			},
		}

		score := s.emitter.RaiseIndicator(
			processGuid,
			processImage,
			processID,
			indicator,
		)

		log.Printf("[DIR SCAN] 🔴 ENCRYPTED FILES CONFIRMED: Added indicator based on directory scan (Score: %d)", score)

		// Immediate evaluation due to high confidence correlation
		s.emitter.Evaluate(processGuid, processImage, processID)
	} else if len(encryptedFiles) > 0 {
		log.Printf("[DIR SCAN] ⚠️  Found %d encrypted files but below threshold (need 3+) or no ransom notes", len(encryptedFiles))
		log.Printf("[DIR SCAN] Continuing to monitor process...")
	} else {
		log.Printf("[DIR SCAN] ℹ️  No encrypted files found in scanned directories")
		log.Printf("[DIR SCAN] False positive: .txt files may not be ransom notes")
	}
}
