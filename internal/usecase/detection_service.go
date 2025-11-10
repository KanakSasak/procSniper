package usecase

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"procSniper/internal/domain"
)

// DetectionService orchestrates threat detection and response
//
// STAGED RANSOMWARE DETECTION APPROACH
// =====================================
//
// This service implements a multi-stage detection pipeline designed to minimize false positives
// while maintaining high detection accuracy for ransomware behavior. The staged approach reduces
// computational overhead by only performing expensive analysis on processes exhibiting suspicious
// I/O patterns.
//
// STAGE 1: I/O Velocity Trigger (Primary Gate)
// ----------------------------------------------
// - ALL file operations are tracked for velocity calculation
// - Processes exceeding 100 files/minute are flagged for deep monitoring
// - This threshold is based on research showing ransomware encrypts at 38-280 files/sec
// - Flagged processes are added to highIOProcesses map with timestamp
// - I/O velocity indicator added to threat score (30 points, counted once per process)
//
// STAGE 2: Deep File Analysis (Only for Flagged Processes)
// ---------------------------------------------------------
//   - Only processes in highIOProcesses map undergo entropy and extension analysis
//   - This prevents expensive file reads and entropy calculations for normal applications
//   - Checks performed on flagged processes:
//     a) Ransomware Extension Detection (20 points)
//   - Matches against known ransomware extensions (.encrypted, .locked, etc.)
//     b) Shannon Entropy Analysis (25 points)
//   - Reads first 8KB of created files
//   - Calculates entropy (encrypted files typically ≥7.5-8.0 bits/byte)
//   - File type-specific thresholds prevent false positives on compressed formats
//
// BENEFITS OF STAGED DETECTION
// -----------------------------
//  1. False Positive Reduction: Normal apps creating many files (builds, installers) won't
//     trigger deep analysis unless they exhibit abnormal I/O velocity patterns
//  2. Performance: Avoids reading/analyzing every created file in the system
//  3. Resource Efficiency: CPU/IO overhead only incurred for suspicious processes
//  4. Sequential Logic: I/O velocity acts as a reliable first-stage filter before expensive
//     entropy calculations
//
// EXAMPLE DETECTION FLOW
// -----------------------
// Benign Application (Visual Studio build):
//   - Creates 500 files in 2 minutes (250 files/min)
//   - STAGE 1: High I/O velocity detected → flagged for monitoring
//   - STAGE 2: Files analyzed → normal entropy (compiled code ≈6.5), no ransom extensions
//   - Result: Low threat score, no alert
//
// Ransomware (WannaCry-like):
//   - Creates 200 encrypted files in 1 minute (200 files/min)
//   - STAGE 1: High I/O velocity detected → flagged for monitoring
//   - STAGE 2: Files analyzed → high entropy (8.0), .WNCRY extensions detected
//   - Result: Critical threat score (30 + 25 + 20 = 75), HIGH alert triggered
//
// Normal File Operations (user editing documents):
//   - Creates 5 files in 1 minute (5 files/min)
//   - STAGE 1: Low I/O velocity → NOT flagged
//   - STAGE 2: Skipped entirely (no entropy analysis performed)
//   - Result: No detection overhead, zero false positives
//
// ProcessFileCounters tracks file counts per process for threshold-based detection
type ProcessFileCounters struct {
	HighEntropyCount           int
	RansomExtensionCount       int
	CombinedEntropyAndExtCount int      // Files with BOTH high entropy AND ransomware extension
	TxtFileCount               int      // Count of .txt files created (potential ransom notes)
	TxtFileDirectories         []string // Directories where .txt files were created
	LastUpdated                time.Time
}

// ModifiedHighEntropyFile tracks files that were recently modified with high entropy
// Used to detect ransomware pattern: modify (encrypt) → delete original
type ModifiedHighEntropyFile struct {
	FilePath    string
	ProcessGuid string
	Image       string
	ProcessID   int
	Entropy     float64
	Timestamp   time.Time
}

// DetectionService orchestrates threat detection and response
type DetectionService struct {
	velocityTracker *domain.FileOperationTracker
	threatScorer    *domain.ThreatScorer
	alertChan       chan *domain.Alert

	// Multi-tier velocity tracking
	monitoredProcesses map[string]time.Time // Tier 1: Lightweight monitoring (10-29 files/min)
	monitoredMux       sync.RWMutex         // Protects monitoredProcesses map
	analyzedProcesses  map[string]time.Time // Tier 2: Deep analysis (30-99 files/min)
	analyzedMux        sync.RWMutex         // Protects analyzedProcesses map
	highIOProcesses    map[string]time.Time // Tier 3: Critical (>=100 files/min)
	highIOProcessesMux sync.RWMutex         // Protects highIOProcesses map

	// File counters for threshold-based detection
	fileCounters    map[string]*ProcessFileCounters // ProcessGuid -> counters
	fileCountersMux sync.RWMutex                    // Protects fileCounters map

	// Entropy tracking for detecting encryption
	entropyTracker *domain.EntropyTracker // Tracks entropy changes over time

	// Modified high-entropy files tracking (for modify-delete pattern detection)
	modifiedHighEntropyFiles    map[string]*ModifiedHighEntropyFile // FilePath -> details
	modifiedHighEntropyFilesMux sync.RWMutex                        // Protects modifiedHighEntropyFiles map

	// Directory scan deduplication (FLAW #7 fix: prevent goroutine explosion)
	directoryScanInProgress map[string]bool // DirPath -> scanning (prevents duplicate scans)
	directoryScanMux        sync.RWMutex    // Protects directoryScanInProgress map

	// Canary files (honeypot detection for slow-moving ransomware)
	canaryFiles    map[string]*domain.CanaryFile // FilePath -> canary metadata
	canaryFilesMux sync.RWMutex                  // Protects canaryFiles map

	// Detection thresholds from config
	entropyFileThreshold   int
	extensionFileThreshold int
	combinedThreshold      int // Files with BOTH entropy AND extension before immediate termination

	// Feature flags
	enableRansomNoteDetection bool // Enable/disable ransom note detection (default: false, focus on behavioral)

	// Detection data from config
	ransomwareExtensions []string // List of ransomware extensions to detect
}

// NewDetectionService creates a new detection service
// entropyThreshold: number of high entropy files required before adding entropy indicator
// extensionThreshold: number of ransomware extension files required before adding extension indicator
// combinedThreshold: files with BOTH high entropy AND ransomware extension for immediate termination
// enableRansomNoteDetection: enable/disable ransom note detection (default: false, focus on behavioral)
// ransomwareExtensions: list of ransomware file extensions to detect
func NewDetectionService(entropyThreshold, extensionThreshold, combinedThreshold int, enableRansomNoteDetection bool, ransomwareExtensions []string) *DetectionService {
	return &DetectionService{
		velocityTracker:           domain.NewFileOperationTracker(60 * time.Second),
		threatScorer:              domain.NewThreatScorer(),
		alertChan:                 make(chan *domain.Alert, 100),
		monitoredProcesses:        make(map[string]time.Time), // Tier 1: Lightweight monitoring
		analyzedProcesses:         make(map[string]time.Time), // Tier 2: Deep analysis
		highIOProcesses:           make(map[string]time.Time), // Tier 3: Critical
		fileCounters:              make(map[string]*ProcessFileCounters),
		entropyTracker:            domain.NewEntropyTracker(10 * time.Minute), // Track entropy for 10 minutes
		modifiedHighEntropyFiles:  make(map[string]*ModifiedHighEntropyFile),  // Track modified high-entropy files
		directoryScanInProgress:   make(map[string]bool),                      // Prevent goroutine explosion
		canaryFiles:               make(map[string]*domain.CanaryFile),        // Honeypot files for detection
		entropyFileThreshold:      entropyThreshold,
		extensionFileThreshold:    extensionThreshold,
		combinedThreshold:         combinedThreshold,
		enableRansomNoteDetection: enableRansomNoteDetection,
		ransomwareExtensions:      ransomwareExtensions,
	}
}

// ProcessFileCreate handles file creation events with staged detection
// Stage 1: Check I/O velocity as trigger
// Stage 2: Only analyze files from high I/O processes (entropy + extensions)
func (ds *DetectionService) ProcessFileCreate(ctx context.Context, event *domain.SysmonEvent) {
	// DEBUG: Print ALL file creations to verify ransomware activity
	ext := filepath.Ext(event.TargetFile)
	log.Printf("[FILE_CREATED] %s (ext: %s) by %s (PID: %d)",
		event.TargetFile, ext, filepath.Base(event.Image), event.ProcessID)

	// OPTIONAL: Check for ransom note BEFORE velocity check (configurable)
	// Ransom notes are DEFINITIVE ransomware indicators with near-zero false positives
	// This catches slow-moving ransomware that doesn't trigger velocity thresholds
	// NOTE: Disabled by default (ENABLE_RANSOM_NOTE_DETECTION=false) - focus on behavioral detection
	if ds.enableRansomNoteDetection && domain.IsRansomNote(event.TargetFile) {
		log.Printf("[DETECTION] 🚨 RANSOM NOTE DETECTED: %s by %s (PID: %d)",
			event.TargetFile, filepath.Base(event.Image), event.ProcessID)

		indicator := domain.Indicator{
			Type:        domain.IndicatorRansomNote,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorRansomNote],
			Description: fmt.Sprintf("CRITICAL: Ransom note file created: %s", filepath.Base(event.TargetFile)),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"filename": filepath.Base(event.TargetFile),
				"fullpath": event.TargetFile,
			},
		}

		score := ds.threatScorer.AddIndicator(
			event.ProcessGuid,
			event.Image,
			event.ProcessID,
			indicator,
		)

		log.Printf("[DETECTION] 🔴 RANSOM NOTE INDICATOR ADDED: %s (Score: %d)",
			filepath.Base(event.TargetFile), score)

		// Immediately evaluate for response (score 50 = instant termination)
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
	}

	// Always track file operation for velocity calculation
	op := domain.FileOperation{
		Timestamp:   event.Timestamp,
		ProcessGuid: event.ProcessGuid,
		ProcessID:   event.ProcessID,
		Operation:   "create",
		FilePath:    event.TargetFile,
		Image:       event.Image,
	}
	ds.velocityTracker.AddOperation(op)

	// STAGE 1: Multi-Tier Velocity Detection
	// Implements graduated response based on I/O velocity
	tier, velocity, tierName := ds.velocityTracker.DetectAnomalousActivity(event.ProcessGuid)

	// Handle each tier with appropriate response
	switch tier {
	case domain.VelocityTierCritical:
		// TIER 3: CRITICAL (>=100 files/min)
		// Immediate deep analysis + indicator + alert evaluation
		ds.highIOProcessesMux.Lock()
		if _, exists := ds.highIOProcesses[event.ProcessGuid]; !exists {
			ds.highIOProcesses[event.ProcessGuid] = time.Now()
			ds.highIOProcessesMux.Unlock()

			indicator := domain.Indicator{
				Type:        domain.IndicatorIOVelocity,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorIOVelocity],
				Description: fmt.Sprintf("CRITICAL I/O velocity: %.2f files/min (fast ransomware)", velocity),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"velocity": fmt.Sprintf("%.2f", velocity),
					"tier":     tierName,
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 TIER 3 CRITICAL: %.2f files/min - %s (Score: %d)", velocity, event.Image, score)
		} else {
			ds.highIOProcessesMux.Unlock()
		}

	case domain.VelocityTierAnalyze:
		// TIER 2: ANALYZE (30-99 files/min)
		// Deep analysis enabled, but lower severity indicator
		ds.analyzedMux.Lock()
		if _, exists := ds.analyzedProcesses[event.ProcessGuid]; !exists {
			ds.analyzedProcesses[event.ProcessGuid] = time.Now()
			ds.analyzedMux.Unlock()

			indicator := domain.Indicator{
				Type:        domain.IndicatorIOVelocity,
				Severity:    domain.ThreatHigh,
				Points:      domain.IndicatorScores[domain.IndicatorIOVelocity] - 5, // 25 points (30-5)
				Description: fmt.Sprintf("High I/O velocity: %.2f files/min (moderate ransomware)", velocity),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"velocity": fmt.Sprintf("%.2f", velocity),
					"tier":     tierName,
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] ⚠️  TIER 2 ANALYZE: %.2f files/min - %s (Score: %d)", velocity, event.Image, score)
		} else {
			ds.analyzedMux.Unlock()
		}

	case domain.VelocityTierMonitor:
		// TIER 1: MONITOR (10-29 files/min)
		// Lightweight tracking, no entropy analysis yet
		ds.monitoredMux.Lock()
		if _, exists := ds.monitoredProcesses[event.ProcessGuid]; !exists {
			ds.monitoredProcesses[event.ProcessGuid] = time.Now()
			ds.monitoredMux.Unlock()

			log.Printf("[MONITORING] 👁️  TIER 1 MONITOR: %.2f files/min - %s (watching for escalation)", velocity, event.Image)
			// No indicator added yet - just tracking
		} else {
			ds.monitoredMux.Unlock()
		}

	case domain.VelocityTierNone:
		// TIER 0: NONE (<10 files/min)
		// Normal activity, no action needed
		return
	}

	// STAGE 2: Determine analysis level based on tier
	// CRITICAL and ANALYZE tiers get deep file analysis
	// MONITOR tier gets lightweight tracking only
	shouldDeepAnalyze := (tier == domain.VelocityTierCritical || tier == domain.VelocityTierAnalyze)

	// IMPORTANT: Track .txt files BEFORE entropy analysis (which has early returns)
	// This ensures ransom note detection happens even if ransomware creates encrypted files first
	// Note: ext variable already declared at function start (line 168)

	// TIER 2/3 ENHANCEMENT: Track .txt file creation for ransom note detection
	// Pattern: Ransomware creates .txt files across multiple directories alongside encrypted files
	if ext == ".txt" && (tier == domain.VelocityTierAnalyze || tier == domain.VelocityTierCritical) {
		dirPath := filepath.Dir(event.TargetFile)

		ds.fileCountersMux.Lock()
		counters, exists := ds.fileCounters[event.ProcessGuid]
		if !exists {
			counters = &ProcessFileCounters{
				HighEntropyCount:           0,
				RansomExtensionCount:       0,
				CombinedEntropyAndExtCount: 0,
				TxtFileCount:               0,
				TxtFileDirectories:         make([]string, 0),
				LastUpdated:                time.Now(),
			}
			ds.fileCounters[event.ProcessGuid] = counters
		}

		counters.TxtFileCount++

		// Track unique directories where .txt files are created
		dirExists := false
		for _, existingDir := range counters.TxtFileDirectories {
			if existingDir == dirPath {
				dirExists = true
				break
			}
		}
		if !dirExists {
			counters.TxtFileDirectories = append(counters.TxtFileDirectories, dirPath)
		}

		txtCount := counters.TxtFileCount
		dirCount := len(counters.TxtFileDirectories)
		counters.LastUpdated = time.Now()
		ds.fileCountersMux.Unlock()

		log.Printf("[TIER 2] .txt file created: %s (%d total .txt files across %d directories)",
			filepath.Base(event.TargetFile), txtCount, dirCount)

		// TRIGGER: If >= 5 .txt files created across multiple directories
		// This is a STRONG INDICATOR to inspect directories for encrypted files
		if txtCount >= 5 && dirCount >= 3 {
			log.Printf("[TIER 2] 🔍 RANSOM NOTE PATTERN DETECTED: %d .txt files across %d directories",
				txtCount, dirCount)
			log.Printf("[TIER 2] Triggering directory scan to find encrypted files alongside ransom notes...")

			// Trigger directory scan to find ENCRYPTED FILES
			go ds.scanDirectoriesForEncryptedFiles(event.ProcessGuid, event.Image, event.ProcessID, counters.TxtFileDirectories, event.Timestamp)
		}
	}

	// REAL-TIME CANARY DETECTION: Check if created file is a honeypot
	// This provides immediate detection with process context (unlike periodic checks)
	if canary, isCanary := ds.isCanaryFile(event.TargetFile); isCanary {
		log.Printf("[CANARY] 🚨 REAL-TIME DETECTION: Canary file accessed: %s", event.TargetFile)
		log.Printf("[CANARY] Process: %s (PID: %d, GUID: %s)", event.Image, event.ProcessID, event.ProcessGuid)

		// Check for correlation with .txt file creation
		ds.fileCountersMux.RLock()
		counters, hasCounters := ds.fileCounters[event.ProcessGuid]
		var txtFileCount int
		var txtDirCount int
		if hasCounters {
			txtFileCount = counters.TxtFileCount
			txtDirCount = len(counters.TxtFileDirectories)
		}
		ds.fileCountersMux.RUnlock()

		// HIGH CONFIDENCE CORRELATION: Canary touched + ransom notes created
		if txtFileCount >= 3 {
			log.Printf("[CANARY] 🔥 CORRELATION DETECTED: Canary file + %d ransom notes across %d directories",
				txtFileCount, txtDirCount)
			log.Printf("[CANARY] HIGH CONFIDENCE: This is ransomware behavior!")

			// Add correlated indicator with MAXIMUM severity
			indicator := domain.Indicator{
				Type:        domain.IndicatorCanaryCompromised,
				Severity:    domain.ThreatCritical,
				Points:      100, // Maximum points - definitive ransomware
				Description: fmt.Sprintf("CORRELATED: Canary file + %d ransom notes (high confidence ransomware)", txtFileCount),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"canary_path":      event.TargetFile,
					"detection_method": "REAL_TIME_CANARY_WITH_RANSOM_NOTES",
					"txt_file_count":   fmt.Sprintf("%d", txtFileCount),
					"txt_directories":  fmt.Sprintf("%d", txtDirCount),
					"correlation":      "CANARY_AND_RANSOM_NOTES",
					"confidence":       "VERY_HIGH",
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[CANARY] 🔴 CORRELATED INDICATOR ADDED: Score: %d (immediate termination)", score)

			// Immediate evaluation - this is definitive ransomware
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return // Early return - ransomware confirmed
		}

		// Canary accessed without ransom notes (still suspicious)
		log.Printf("[CANARY] ⚠️  Canary accessed but no ransom notes detected yet")
		log.Printf("[CANARY] Adding canary indicator (waiting for correlation)")

		// Analyze canary entropy to confirm encryption
		canaryEntropy, err := domain.AnalyzeFileEntropy(event.TargetFile, canary.Extension)
		if err == nil {
			entropyDelta := canaryEntropy.Entropy - canary.OriginalEntropy

			if entropyDelta >= 2.0 || canaryEntropy.IsLikelyEncrypted {
				log.Printf("[CANARY] 🚨 Canary ENCRYPTED: entropy %.3f → %.3f (Δ +%.3f)",
					canary.OriginalEntropy, canaryEntropy.Entropy, entropyDelta)

				indicator := domain.Indicator{
					Type:        domain.IndicatorCanaryCompromised,
					Severity:    domain.ThreatCritical,
					Points:      100, // Maximum - canary encryption = definitive ransomware
					Description: "Honeypot file encrypted (canary compromise)",
					Timestamp:   event.Timestamp,
					Evidence: map[string]string{
						"canary_path":         event.TargetFile,
						"original_entropy":    fmt.Sprintf("%.3f", canary.OriginalEntropy),
						"current_entropy":     fmt.Sprintf("%.3f", canaryEntropy.Entropy),
						"entropy_delta":       fmt.Sprintf("%.3f", entropyDelta),
						"detection_method":    "REAL_TIME_CANARY",
						"false_positive_rate": "< 0.01%",
					},
				}

				score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
				log.Printf("[CANARY] 🔴 ENCRYPTED CANARY DETECTED: Score: %d (immediate termination)", score)

				// Immediate evaluation
				ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
				return // Early return - ransomware confirmed
			}
		}
	}

	if !shouldDeepAnalyze {
		// For MONITOR tier or below: skip expensive entropy analysis
		return
	}

	log.Printf("[DEEP ANALYSIS] Analyzing file from high I/O process: %s", event.TargetFile)

	// Get or create file counters for this process
	ds.fileCountersMux.Lock()
	counters, exists := ds.fileCounters[event.ProcessGuid]
	if !exists {
		counters = &ProcessFileCounters{
			HighEntropyCount:           0,
			RansomExtensionCount:       0,
			CombinedEntropyAndExtCount: 0,
			TxtFileCount:               0,
			TxtFileDirectories:         make([]string, 0),
			LastUpdated:                time.Now(),
		}
		ds.fileCounters[event.ProcessGuid] = counters
	}
	ds.fileCountersMux.Unlock()

	// Check both conditions: ransomware extension AND entropy
	hasRansomExtension := domain.IsRansomwareExtension(event.TargetFile, ds.ransomwareExtensions)
	entropy, entropyErr := domain.AnalyzeFileEntropy(event.TargetFile, ext)

	// DEBUG: Log entropy analysis result
	if entropyErr != nil {
		log.Printf("[DEEP ANALYSIS] ⚠️  Failed to analyze entropy for %s: %v", filepath.Base(event.TargetFile), entropyErr)
	} else {
		log.Printf("[DEEP ANALYSIS] Entropy: %.3f bits/byte, Extension: %s, Ransomware ext: %v, Encrypted: %v",
			entropy.Entropy, ext, hasRansomExtension, entropy.IsLikelyEncrypted)
	}

	// ENHANCEMENT 1: Check if extension is naturally high-entropy (video/image/archive)
	// If yes, verify magic bytes to prevent ransomware evasion by fake extensions
	isNaturallyHighEntropy := domain.IsNaturallyHighEntropyExtension(ext)

	var hasHighEntropy bool
	var isFakeFile bool // File extension doesn't match actual content (ransomware renamed)

	if entropyErr == nil && entropy.IsLikelyEncrypted {
		if isNaturallyHighEntropy {
			// File has naturally high-entropy extension (.jpg, .mp4, etc.)
			// Verify magic bytes to ensure it's a real video/image, not encrypted data
			isValid, signatureInfo := domain.VerifyFileSignature(event.TargetFile, ext)

			if !isValid {
				// CRITICAL: File claims to be .jpg but magic bytes don't match!
				// This is likely ransomware trying to evade detection by using whitelisted extension
				isFakeFile = true
				hasHighEntropy = true

				log.Printf("[DETECTION] 🚨 FAKE FILE DETECTED: %s claims to be %s but signature mismatch (%s)",
					event.TargetFile, ext, signatureInfo)
			} else {
				// Magic bytes match - legitimate video/image/archive file
				// Skip entropy detection (naturally high entropy expected)
				hasHighEntropy = false

				log.Printf("[DETECTION] ✓ Naturally high-entropy file verified: %s (%s, entropy: %.3f)",
					filepath.Base(event.TargetFile), signatureInfo, entropy.Entropy)
			}
		} else {
			// Normal file extension (.txt, .doc, etc.) with high entropy
			// This is suspicious - likely encrypted
			hasHighEntropy = true
		}
	} else {
		hasHighEntropy = false
	}

	// ENHANCEMENT 2: Track entropy delta for existing files
	// If file existed before with low entropy and now has high entropy → encryption detected
	var entropyDelta float64
	var isEntropyIncrease bool

	if entropyErr == nil {
		isNew, delta, record := ds.entropyTracker.TrackFileEntropy(event.TargetFile, entropy.Entropy)
		entropyDelta = delta

		if !isNew && domain.IsSignificantEntropyIncrease(delta) {
			// File existed before with lower entropy, now significantly higher
			// This is VERY suspicious - likely encryption
			isEntropyIncrease = true

			log.Printf("[DETECTION] 🔴 ENTROPY INCREASE DETECTED: %s (%.3f → %.3f, delta: +%.3f)",
				filepath.Base(event.TargetFile), record.OriginalEntropy, record.CurrentEntropy, delta)
		}
	}

	// ENHANCEMENT 3: Track modified files with high entropy for modify-delete pattern detection
	// Ransomware pattern: modify file (encrypt) → delete original → create .ENCRYPTED copy
	if hasHighEntropy && entropyErr == nil {
		ds.modifiedHighEntropyFilesMux.Lock()
		ds.modifiedHighEntropyFiles[event.TargetFile] = &ModifiedHighEntropyFile{
			FilePath:    event.TargetFile,
			ProcessGuid: event.ProcessGuid,
			Image:       event.Image,
			ProcessID:   event.ProcessID,
			Entropy:     entropy.Entropy,
			Timestamp:   time.Now(),
		}
		ds.modifiedHighEntropyFilesMux.Unlock()

		log.Printf("[TRACKING] High-entropy file modification recorded: %s (entropy: %.3f) - watching for deletion",
			filepath.Base(event.TargetFile), entropy.Entropy)
	}

	// ENHANCEMENT PATH: Handle fake file detection (highest priority - clear evasion)
	if isFakeFile {
		indicator := domain.Indicator{
			Type:        domain.IndicatorFakeFile,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorFakeFile],
			Description: fmt.Sprintf("FAKE FILE: Extension %s doesn't match file content (ransomware evasion attempt)", ext),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"file":      event.TargetFile,
				"extension": ext,
				"entropy":   fmt.Sprintf("%.3f", entropy.Entropy),
				"evasion":   "magic_bytes_mismatch",
			},
		}

		score := ds.threatScorer.AddIndicator(
			event.ProcessGuid,
			event.Image,
			event.ProcessID,
			indicator,
		)

		log.Printf("[DETECTION] 🚨 FAKE FILE INDICATOR ADDED: Ransomware evasion detected (Score: %d)", score)

		// Immediate evaluation for fake files - this is critical
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
	}

	// ENHANCEMENT PATH: Handle entropy increase detection (in-place encryption)
	if isEntropyIncrease {
		indicator := domain.Indicator{
			Type:        domain.IndicatorEntropyIncrease,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorEntropyIncrease],
			Description: fmt.Sprintf("ENTROPY INCREASE: File entropy increased by +%.3f bits/byte (in-place encryption)", entropyDelta),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"file":             event.TargetFile,
				"entropy_delta":    fmt.Sprintf("+%.3f", entropyDelta),
				"current_entropy":  fmt.Sprintf("%.3f", entropy.Entropy),
				"detection_method": "entropy_tracking",
			},
		}

		score := ds.threatScorer.AddIndicator(
			event.ProcessGuid,
			event.Image,
			event.ProcessID,
			indicator,
		)

		log.Printf("[DETECTION] 🚨 ENTROPY INCREASE INDICATOR ADDED: In-place encryption detected (Score: %d)", score)

		// Immediate evaluation for entropy increases - this is critical
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
	}

	// CRITICAL PATH: Files with BOTH high entropy AND ransomware extension
	// This is the highest confidence indicator - triggers immediate termination
	if hasRansomExtension && hasHighEntropy {
		ds.fileCountersMux.Lock()
		counters.CombinedEntropyAndExtCount++
		counters.HighEntropyCount++
		counters.RansomExtensionCount++
		counters.LastUpdated = time.Now()
		combinedCount := counters.CombinedEntropyAndExtCount
		ds.fileCountersMux.Unlock()

		log.Printf("[DETECTION] ⚠️  CRITICAL: File with HIGH ENTROPY + RANSOMWARE EXTENSION detected: %s (%.3f) - Combined Count: %d/%d",
			event.TargetFile, entropy.Entropy, combinedCount, ds.combinedThreshold)

		// IMMEDIATE TERMINATION if combined threshold reached
		if combinedCount >= ds.combinedThreshold {
			log.Printf("[DETECTION] 🚨 COMBINED THRESHOLD REACHED: %d files with HIGH ENTROPY + RANSOMWARE EXTENSION", combinedCount)

			// Add BOTH indicators immediately
			entropyIndicator := domain.Indicator{
				Type:        domain.IndicatorHighEntropy,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorHighEntropy],
				Description: fmt.Sprintf("CRITICAL: %d files with high entropy + ransomware extension (entropy: %.3f)", combinedCount, entropy.Entropy),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"entropy":        fmt.Sprintf("%.3f", entropy.Entropy),
					"threshold":      fmt.Sprintf("%.3f", entropy.Threshold),
					"file":           event.TargetFile,
					"combined_count": fmt.Sprintf("%d", combinedCount),
					"detection_mode": "COMBINED_HIGH_CONFIDENCE",
				},
			}

			extensionIndicator := domain.Indicator{
				Type:        domain.IndicatorRansomExtension,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
				Description: fmt.Sprintf("CRITICAL: %d files with ransomware extension + high entropy", combinedCount),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":           event.TargetFile,
					"extension":      ext,
					"combined_count": fmt.Sprintf("%d", combinedCount),
					"detection_mode": "COMBINED_HIGH_CONFIDENCE",
				},
			}

			ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, entropyIndicator)
			finalScore := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, extensionIndicator)

			log.Printf("[DETECTION] 🔴 IMMEDIATE TERMINATION TRIGGERED: Combined threshold reached (Score: %d)",
				finalScore)

			// Immediate evaluation and alert
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return
		}

		// Below combined threshold - continue monitoring
		log.Printf("[DETECTION] Combined high-confidence files: %d/%d (monitoring)", combinedCount, ds.combinedThreshold)
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		return
	}

	// SEPARATE PATH: Check for ransomware extension only (without high entropy)
	if hasRansomExtension {
		ds.fileCountersMux.Lock()
		counters.RansomExtensionCount++
		counters.LastUpdated = time.Now()
		currentCount := counters.RansomExtensionCount
		ds.fileCountersMux.Unlock()

		log.Printf("[DETECTION] Ransomware extension file detected: %s (Count: %d/%d)",
			event.TargetFile, currentCount, ds.extensionFileThreshold)

		// Only add indicator if threshold reached
		if currentCount >= ds.extensionFileThreshold {
			indicator := domain.Indicator{
				Type:        domain.IndicatorRansomExtension,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
				Description: fmt.Sprintf("Ransomware extension threshold reached: %d files", currentCount),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":      event.TargetFile,
					"count":     fmt.Sprintf("%d", currentCount),
					"threshold": fmt.Sprintf("%d", ds.extensionFileThreshold),
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] 🔴 RANSOMWARE EXTENSION THRESHOLD REACHED: %d files (Score: %d)",
				currentCount, score)
		}
	}

	// SEPARATE PATH: Check for high entropy only (without ransomware extension)
	if hasHighEntropy {
		ds.fileCountersMux.Lock()
		counters.HighEntropyCount++
		counters.LastUpdated = time.Now()
		currentCount := counters.HighEntropyCount
		ds.fileCountersMux.Unlock()

		log.Printf("[DETECTION] High entropy file detected: %s (%.3f > %.3f) - Count: %d/%d",
			event.TargetFile, entropy.Entropy, entropy.Threshold, currentCount, ds.entropyFileThreshold)

		// Only add indicator if threshold reached
		if currentCount >= ds.entropyFileThreshold {
			indicator := domain.Indicator{
				Type:        domain.IndicatorHighEntropy,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorHighEntropy],
				Description: fmt.Sprintf("High entropy threshold reached: %d files (avg entropy: %.3f)", currentCount, entropy.Entropy),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"entropy":   fmt.Sprintf("%.3f", entropy.Entropy),
					"threshold": fmt.Sprintf("%.3f", entropy.Threshold),
					"file":      event.TargetFile,
					"count":     fmt.Sprintf("%d", currentCount),
					"min_files": fmt.Sprintf("%d", ds.entropyFileThreshold),
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] 🔴 HIGH ENTROPY THRESHOLD REACHED: %d files (Score: %d)",
				currentCount, score)
		}
	}

	// NOTE: .txt tracking is now done BEFORE entropy analysis to avoid early returns

	// Evaluate overall threat for flagged processes
	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// ProcessFileModified handles file modification events (Event ID 2)
// This is CRITICAL for detecting in-place encryption where ransomware modifies existing files
// without creating new files or changing extensions
func (ds *DetectionService) ProcessFileModified(ctx context.Context, event *domain.SysmonEvent) {
	ext := filepath.Ext(event.TargetFile)
	log.Printf("[FILE_MODIFIED] %s (ext: %s) by %s (PID: %d)",
		event.TargetFile, ext, filepath.Base(event.Image), event.ProcessID)

	// STAGE 1: Check if process is being monitored at ANY tier
	tier := ds.velocityTracker.GetVelocityTier(event.ProcessGuid)

	// Only analyze file modifications from monitored processes (TIER 1+)
	// This includes MONITOR, ANALYZE, and CRITICAL tiers
	if tier == domain.VelocityTierNone {
		// Not being monitored - ignore
		return
	}

	log.Printf("[FILE_MODIFIED] Process %s is monitored (Tier: %s) - analyzing entropy change",
		filepath.Base(event.Image), tier.String())

	// STAGE 2: Get previous entropy from tracking (if exists)
	previousEntropy := ds.entropyTracker.GetPreviousEntropy(event.TargetFile)

	// STAGE 3: Analyze current entropy with RETRY logic (file may be locked during encryption)
	// Try up to 3 times with 50ms delay between attempts
	currentEntropy, err := domain.AnalyzeFileEntropyWithRetry(event.TargetFile, ext, 3, 50*time.Millisecond)

	if err != nil {
		// File locked or access denied even after retries
		log.Printf("[FILE_MODIFIED] ⚠️  Failed to analyze entropy after retries for %s: %v",
			filepath.Base(event.TargetFile), err)

		// If file is locked by suspicious process, this is STILL suspicious
		if tier == domain.VelocityTierAnalyze || tier == domain.VelocityTierCritical {
			log.Printf("[FILE_MODIFIED] 🚨 File locked by high-velocity process - possible in-place encryption")

			indicator := domain.Indicator{
				Type:        domain.IndicatorInPlaceEncryption,
				Severity:    domain.ThreatHigh,
				Points:      20,
				Description: fmt.Sprintf("File locked during modification by suspicious process (Tier: %s)", tier.String()),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":     filepath.Base(event.TargetFile),
					"error":    err.Error(),
					"tier":     tier.String(),
					"behavior": "file_locked_modification",
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 FILE LOCKED INDICATOR ADDED: %s (Score: %d)",
				filepath.Base(event.TargetFile), score)

			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		}
		return
	}

	// STAGE 4: Check for entropy increase (IN-PLACE ENCRYPTION DETECTION)
	log.Printf("[FILE_MODIFIED] Entropy analysis: previous=%.3f, current=%.3f, change=%.3f",
		previousEntropy, currentEntropy.Entropy, currentEntropy.Entropy-previousEntropy)

	// If we have previous entropy and it's significantly increased, this is IN-PLACE ENCRYPTION
	if previousEntropy > 0 {
		entropyDelta := currentEntropy.Entropy - previousEntropy

		// Significant entropy increase detection
		// From normal text (4.5-5.5) to encrypted (7.5-8.0) = ~2.5-3.5 increase
		if entropyDelta >= 2.0 && currentEntropy.IsLikelyEncrypted {
			// CRITICAL: File was normal, now encrypted
			// This is IN-PLACE ENCRYPTION - one of the most dangerous ransomware techniques

			log.Printf("[DETECTION] 🚨 IN-PLACE ENCRYPTION DETECTED: %s", event.TargetFile)
			log.Printf("[DETECTION] 🚨 Entropy jumped from %.3f → %.3f (Δ +%.3f)",
				previousEntropy, currentEntropy.Entropy, entropyDelta)

			// Determine severity based on tier
			severity := domain.ThreatCritical
			points := 45 // High points for in-place encryption

			if tier == domain.VelocityTierCritical {
				points = 50 // Even higher for critical tier
			}

			indicator := domain.Indicator{
				Type:        domain.IndicatorInPlaceEncryption,
				Severity:    severity,
				Points:      points,
				Description: fmt.Sprintf("IN-PLACE ENCRYPTION: entropy %.3f → %.3f (Δ +%.3f)", previousEntropy, currentEntropy.Entropy, entropyDelta),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":             event.TargetFile,
					"previous_entropy": fmt.Sprintf("%.3f", previousEntropy),
					"current_entropy":  fmt.Sprintf("%.3f", currentEntropy.Entropy),
					"entropy_delta":    fmt.Sprintf("+%.3f", entropyDelta),
					"tier":             tier.String(),
					"confidence":       "VERY_HIGH",
					"technique":        "in_place_encryption",
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 IN-PLACE ENCRYPTION INDICATOR ADDED: %s (Score: %d)",
				filepath.Base(event.TargetFile), score)

			// Immediate evaluation - this is critical
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return
		}
	}

	// STAGE 5: Track current entropy for future comparisons
	// Even if no previous entropy exists, track this for next modification
	isNew, delta, _ := ds.entropyTracker.TrackFileEntropy(event.TargetFile, currentEntropy.Entropy)

	if !isNew && domain.IsSignificantEntropyIncrease(delta) {
		// Entropy increased from tracked value (alternative detection path)
		log.Printf("[DETECTION] 🔴 ENTROPY INCREASE via tracker: %s (Δ +%.3f)",
			filepath.Base(event.TargetFile), delta)

		indicator := domain.Indicator{
			Type:        domain.IndicatorEntropyIncrease,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorEntropyIncrease],
			Description: fmt.Sprintf("File entropy increased by +%.3f (tracked encryption)", delta),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"file":          event.TargetFile,
				"entropy_delta": fmt.Sprintf("+%.3f", delta),
			},
		}

		score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[DETECTION] 🔴 ENTROPY INCREASE INDICATOR ADDED: %s (Score: %d)",
			filepath.Base(event.TargetFile), score)

		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		return
	}

	// STAGE 6: Check for high entropy on modified file (even without previous baseline)
	// This catches ransomware that modifies files we haven't seen before
	if currentEntropy.IsLikelyEncrypted && (tier == domain.VelocityTierAnalyze || tier == domain.VelocityTierCritical) {
		log.Printf("[FILE_MODIFIED] Modified file has high entropy: %.3f (threshold: %.3f)",
			currentEntropy.Entropy, currentEntropy.Threshold)

		// Get or create file counters
		ds.fileCountersMux.Lock()
		counters, exists := ds.fileCounters[event.ProcessGuid]
		if !exists {
			counters = &ProcessFileCounters{
				HighEntropyCount:           0,
				RansomExtensionCount:       0,
				CombinedEntropyAndExtCount: 0,
				LastUpdated:                time.Now(),
			}
			ds.fileCounters[event.ProcessGuid] = counters
		}
		counters.HighEntropyCount++
		currentCount := counters.HighEntropyCount
		ds.fileCountersMux.Unlock()

		log.Printf("[FILE_MODIFIED] High-entropy modification count: %d/%d",
			currentCount, ds.entropyFileThreshold)

		// Add indicator if threshold reached
		if currentCount >= ds.entropyFileThreshold {
			indicator := domain.Indicator{
				Type:        domain.IndicatorHighEntropy,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorHighEntropy],
				Description: fmt.Sprintf("High entropy modification threshold: %d files (%.3f entropy)", currentCount, currentEntropy.Entropy),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":    event.TargetFile,
					"entropy": fmt.Sprintf("%.3f", currentEntropy.Entropy),
					"count":   fmt.Sprintf("%d", currentCount),
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 HIGH ENTROPY MODIFICATION THRESHOLD REACHED: %d files (Score: %d)",
				currentCount, score)

			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		}
	}
}

// ProcessProcessCreate handles process creation events
func (ds *DetectionService) ProcessProcessCreate(ctx context.Context, event *domain.SysmonEvent) {
	cmdLine := strings.ToLower(event.CommandLine)
	imageLower := strings.ToLower(event.Image)

	// CRITICAL: Detect shadow copy deletion attempts (common ransomware technique)
	// Instant termination - this is a clear indicator of ransomware preparation
	isShadowCopyDeletion := false
	if strings.Contains(imageLower, "vssadmin.exe") && strings.Contains(cmdLine, "delete shadows") {
		isShadowCopyDeletion = true
	} else if strings.Contains(imageLower, "wmic.exe") && strings.Contains(cmdLine, "shadowcopy delete") {
		isShadowCopyDeletion = true
	} else if strings.Contains(imageLower, "bcdedit.exe") && (strings.Contains(cmdLine, "recoveryenabled no") || strings.Contains(cmdLine, "bootstatuspolicy ignoreallfailures")) {
		isShadowCopyDeletion = true
	}

	if isShadowCopyDeletion {
		log.Printf("[DETECTION] 🚨 CRITICAL: Shadow copy deletion/recovery disable detected!")
		log.Printf("[DETECTION] 🚨 Command: %s", event.CommandLine)
		log.Printf("[DETECTION] 🚨 Process: %s (PID: %d)", event.Image, event.ProcessID)

		// Add indicator with MASSIVE score to guarantee immediate termination
		indicator := domain.Indicator{
			Type:        domain.IndicatorShadowCopyDeletion,
			Severity:    domain.ThreatCritical,
			Points:      100, // Override - guarantee immediate termination
			Description: fmt.Sprintf("INSTANT KILL: Shadow copy deletion/recovery disable attempt detected - %s", event.CommandLine),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"command": event.CommandLine,
				"process": event.Image,
				"pid":     fmt.Sprintf("%d", event.ProcessID),
				"instant": "true",
			},
		}

		score := ds.threatScorer.AddIndicator(
			event.ProcessGuid,
			event.Image,
			event.ProcessID,
			indicator,
		)

		log.Printf("[DETECTION] 🔴 SHADOW COPY DELETION - IMMEDIATE TERMINATION TRIGGERED (Score: %d)", score)

		// Force immediate evaluation and alert
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		return
	}

	// Check for other suspicious command patterns
	for pattern, description := range domain.SuspiciousCommandPatterns {
		if strings.Contains(cmdLine, strings.ToLower(pattern)) {
			var indicatorType domain.IndicatorType

			if strings.Contains(description, "Shadow copy") {
				indicatorType = domain.IndicatorShadowCopyDeletion
			} else if strings.Contains(description, "Recovery") {
				indicatorType = domain.IndicatorRecoveryDisable
			} else {
				indicatorType = domain.IndicatorLSASSAccess
			}

			indicator := domain.Indicator{
				Type:        indicatorType,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[indicatorType],
				Description: description,
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"command": event.CommandLine,
					"pattern": pattern,
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] Suspicious command: %s (Score: %d)", description, score)
		}
	}

	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// ProcessLSASSAccess handles LSASS memory access events
func (ds *DetectionService) ProcessLSASSAccess(ctx context.Context, event *domain.SysmonEvent) {
	if !strings.Contains(strings.ToLower(event.TargetImage), "lsass.exe") {
		return
	}

	indicator := domain.Indicator{
		Type:        domain.IndicatorLSASSAccess,
		Severity:    domain.ThreatCritical,
		Points:      domain.IndicatorScores[domain.IndicatorLSASSAccess],
		Description: "LSASS memory access detected",
		Timestamp:   event.Timestamp,
		Evidence: map[string]string{
			"granted_access": event.GrantedAccess,
			"target":         event.TargetImage,
		},
	}

	score := ds.threatScorer.AddIndicator(
		event.ProcessGuid,
		event.Image,
		event.ProcessID,
		indicator,
	)

	log.Printf("[DETECTION] LSASS access: %s (Access: %s, Score: %d)",
		event.Image, event.GrantedAccess, score)

	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// ProcessBrowserAccess handles browser credential file access
func (ds *DetectionService) ProcessBrowserAccess(ctx context.Context, event *domain.SysmonEvent) {
	// Check if non-browser process is accessing browser files
	targetLower := strings.ToLower(event.TargetFile)
	imageLower := strings.ToLower(event.Image)

	// Skip if legitimate browser
	legitimateBrowsers := []string{"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"}
	for _, browser := range legitimateBrowsers {
		if strings.Contains(imageLower, browser) {
			return
		}
	}

	// Check if accessing browser credential paths
	for _, credPath := range domain.BrowserCredentialPaths {
		if strings.Contains(targetLower, strings.ToLower(credPath)) {
			indicator := domain.Indicator{
				Type:        domain.IndicatorCredentialTheft,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorCredentialTheft],
				Description: "Browser credential file access",
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":  event.TargetFile,
					"image": event.Image,
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] Browser credential access: %s accessing %s (Score: %d)",
				event.Image, event.TargetFile, score)

			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return
		}
	}
}

// evaluateAndAlert evaluates threat level and creates alerts
func (ds *DetectionService) evaluateAndAlert(processGuid string, image string, pid int) {
	level, score := ds.threatScorer.EvaluateThreat(processGuid)

	if level == domain.ThreatNone || level == domain.ThreatLow {
		return
	}

	threatScore := ds.threatScorer.GetThreatScore(processGuid)
	if threatScore == nil {
		return
	}

	alert := domain.NewAlert(
		threatScore.Category,
		level,
		processGuid,
		pid,
		image,
		fmt.Sprintf("%s activity detected", threatScore.Category),
		score,
	)

	// Copy indicators
	for _, indicator := range threatScore.Indicators {
		alert.AddIndicator(indicator)
	}

	// Determine if auto-response is warranted
	alert.AutoRespond = ds.threatScorer.ShouldAutoRespond(processGuid)

	// Send alert
	select {
	case ds.alertChan <- alert:
		log.Printf("[ALERT] %s - %s (PID: %d, Score: %d, Auto-Respond: %v)",
			alert.Severity, alert.Description, pid, score, alert.AutoRespond)
	default:
		log.Printf("[WARNING] Alert channel full, dropping alert")
	}
}

// GetAlertChannel returns the alert channel for monitoring
func (ds *DetectionService) GetAlertChannel() <-chan *domain.Alert {
	return ds.alertChan
}

// GetThreatScore returns the current threat score for a process
func (ds *DetectionService) GetThreatScore(processGuid string) *domain.ThreatScore {
	return ds.threatScorer.GetThreatScore(processGuid)
}

// GetAllThreats returns all active threats
func (ds *DetectionService) GetAllThreats() []*domain.ThreatScore {
	return ds.threatScorer.GetAllThreats()
}

// SetupCanaryFiles creates honeypot files in common ransomware target directories
// Canary files are decoy files with known low entropy that trigger alerts if encrypted/deleted
// This catches slow-moving ransomware that doesn't trigger velocity thresholds
func (ds *DetectionService) SetupCanaryFiles() error {
	log.Println("[CANARY] Setting up honeypot files for ransomware detection...")

	successCount := 0
	failCount := 0

	for _, location := range domain.CanaryLocations {
		// Get full path for user directory
		dirPath, err := domain.GetUserDirectory(location.Directory)
		if err != nil {
			log.Printf("[CANARY] Failed to get directory path for %s: %v", location.Directory, err)
			failCount++
			continue
		}

		// Full file path
		filePath := filepath.Join(dirPath, location.FileName)

		// Check if canary already exists
		if _, err := os.Stat(filePath); err == nil {
			log.Printf("[CANARY] Canary file already exists: %s", filePath)
			// Analyze existing canary
			entropy, err := domain.AnalyzeFileEntropy(filePath, location.Extension)
			if err != nil {
				log.Printf("[CANARY] Failed to analyze existing canary: %v", err)
				failCount++
				continue
			}

			// Track existing canary
			ds.canaryFilesMux.Lock()
			ds.canaryFiles[filePath] = &domain.CanaryFile{
				Path:            filePath,
				OriginalEntropy: entropy.Entropy,
				FileSize:        entropy.FileSize,
				Created:         time.Now(),
				LastChecked:     time.Now(),
				Extension:       location.Extension,
			}
			ds.canaryFilesMux.Unlock()

			log.Printf("[CANARY] ✓ Tracked existing canary: %s (entropy: %.3f)", filePath, entropy.Entropy)
			successCount++
			continue
		}

		// Create new canary file (8KB size)
		if err := domain.CreateCanaryFile(filePath, location.Extension, 8192); err != nil {
			log.Printf("[CANARY] Failed to create canary %s: %v", filePath, err)
			failCount++
			continue
		}

		// Analyze created canary to get baseline entropy
		entropy, err := domain.AnalyzeFileEntropy(filePath, location.Extension)
		if err != nil {
			log.Printf("[CANARY] Failed to analyze created canary: %v", err)
			failCount++
			continue
		}

		// Track canary file
		ds.canaryFilesMux.Lock()
		ds.canaryFiles[filePath] = &domain.CanaryFile{
			Path:            filePath,
			OriginalEntropy: entropy.Entropy,
			FileSize:        entropy.FileSize,
			Created:         time.Now(),
			LastChecked:     time.Now(),
			Extension:       location.Extension,
		}
		ds.canaryFilesMux.Unlock()

		log.Printf("[CANARY] ✓ Created canary: %s (entropy: %.3f, size: %d bytes)",
			filepath.Base(filePath), entropy.Entropy, entropy.FileSize)
		successCount++
	}

	// Setup system-level canaries in Program Files directories
	log.Println("[CANARY] Setting up system-level honeypots in Program Files...")
	for _, location := range domain.CanarySystemLocations {
		// Use absolute path directly (no user directory lookup needed)
		filePath := filepath.Join(location.Directory, location.FileName)

		// Check if canary already exists
		if _, err := os.Stat(filePath); err == nil {
			log.Printf("[CANARY] System canary already exists: %s", filePath)
			// Analyze existing canary
			entropy, err := domain.AnalyzeFileEntropy(filePath, location.Extension)
			if err != nil {
				log.Printf("[CANARY] Failed to analyze existing system canary: %v", err)
				failCount++
				continue
			}

			// Track existing canary
			ds.canaryFilesMux.Lock()
			ds.canaryFiles[filePath] = &domain.CanaryFile{
				Path:            filePath,
				OriginalEntropy: entropy.Entropy,
				FileSize:        entropy.FileSize,
				Created:         time.Now(),
				LastChecked:     time.Now(),
				Extension:       location.Extension,
			}
			ds.canaryFilesMux.Unlock()

			log.Printf("[CANARY] ✓ Tracked existing system canary: %s (entropy: %.3f)", filePath, entropy.Entropy)
			successCount++
			continue
		}

		// Create new system canary file (8KB size)
		if err := domain.CreateCanaryFile(filePath, location.Extension, 8192); err != nil {
			log.Printf("[CANARY] Failed to create system canary %s: %v (requires admin privileges)", filePath, err)
			failCount++
			continue
		}

		// Analyze created canary to get baseline entropy
		entropy, err := domain.AnalyzeFileEntropy(filePath, location.Extension)
		if err != nil {
			log.Printf("[CANARY] Failed to analyze created system canary: %v", err)
			failCount++
			continue
		}

		// Track canary file
		ds.canaryFilesMux.Lock()
		ds.canaryFiles[filePath] = &domain.CanaryFile{
			Path:            filePath,
			OriginalEntropy: entropy.Entropy,
			FileSize:        entropy.FileSize,
			Created:         time.Now(),
			LastChecked:     time.Now(),
			Extension:       location.Extension,
		}
		ds.canaryFilesMux.Unlock()

		log.Printf("[CANARY] ✓ Created system canary: %s (entropy: %.3f, size: %d bytes)",
			filepath.Base(filePath), entropy.Entropy, entropy.FileSize)
		successCount++
	}

	log.Printf("[CANARY] Setup complete: %d created/tracked, %d failed", successCount, failCount)

	if successCount == 0 {
		return fmt.Errorf("failed to create any canary files")
	}

	return nil
}

// isCanaryFile checks if a file path is a canary/honeypot file
// Returns true if the file is being tracked as a canary
func (ds *DetectionService) isCanaryFile(filePath string) (*domain.CanaryFile, bool) {
	ds.canaryFilesMux.RLock()
	defer ds.canaryFilesMux.RUnlock()

	canary, exists := ds.canaryFiles[filePath]
	return canary, exists
}

// CheckCanaryFiles periodically checks if canary files have been compromised
// This function should be called on a timer (e.g., every 30 seconds)
// Returns true if any canary was compromised (triggers immediate alert)
func (ds *DetectionService) CheckCanaryFiles() bool {
	ds.canaryFilesMux.RLock()
	canaryCount := len(ds.canaryFiles)
	ds.canaryFilesMux.RUnlock()

	if canaryCount == 0 {
		// No canaries to check
		return false
	}

	log.Printf("[CANARY] Checking %d honeypot files...", canaryCount)

	compromised := false

	ds.canaryFilesMux.Lock()
	defer ds.canaryFilesMux.Unlock()

	for path, canary := range ds.canaryFiles {
		canary.LastChecked = time.Now()

		// Check if canary still exists
		fileInfo, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist at original path
				// Check if ransomware renamed it with a different extension
				dirPath := filepath.Dir(path)
				baseName := filepath.Base(path)
				baseNameWithoutExt := strings.TrimSuffix(baseName, canary.Extension)

				renamed := false
				renamedPath := ""

				// Scan directory for renamed files
				entries, err := os.ReadDir(dirPath)
				if err == nil {
					for _, entry := range entries {
						if entry.IsDir() {
							continue
						}

						entryName := entry.Name()
						// Check if this is our canary with a different extension
						// Pattern: original_name.original_ext.new_ext or original_name.new_ext
						if strings.HasPrefix(entryName, baseNameWithoutExt) && entryName != baseName {
							// Found a file with same base name but different extension
							renamedPath = filepath.Join(dirPath, entryName)
							newExt := filepath.Ext(entryName)

							log.Printf("[DETECTION] 🚨 CANARY RENAMED: %s → %s", path, renamedPath)
							log.Printf("[DETECTION] 🚨 Extension changed from %s to %s", canary.Extension, newExt)
							log.Printf("[DETECTION] 🚨 This is a classic ransomware behavior!")

							// Check entropy of renamed file
							entropy, entropyErr := domain.AnalyzeFileEntropy(renamedPath, newExt)
							if entropyErr == nil {
								entropyDelta := entropy.Entropy - canary.OriginalEntropy
								log.Printf("[DETECTION] 🚨 Renamed file entropy: %.3f (original: %.3f, Δ +%.3f)",
									entropy.Entropy, canary.OriginalEntropy, entropyDelta)

								if entropyDelta >= 2.0 {
									ds.alertCanaryCompromised(path, fmt.Sprintf("RENAMED_AND_ENCRYPTED (→ %s)", filepath.Base(renamedPath)),
										entropy.Entropy, canary.OriginalEntropy)
								} else {
									ds.alertCanaryCompromised(path, fmt.Sprintf("RENAMED (→ %s)", filepath.Base(renamedPath)),
										0, canary.OriginalEntropy)
								}
							} else {
								ds.alertCanaryCompromised(path, fmt.Sprintf("RENAMED (→ %s)", filepath.Base(renamedPath)),
									0, canary.OriginalEntropy)
							}

							renamed = true
							compromised = true
							break
						}
					}
				}

				if !renamed {
					// CRITICAL: Canary file deleted → RANSOMWARE!
					log.Printf("[DETECTION] 🚨 CANARY DELETED: %s", path)
					log.Printf("[DETECTION] 🚨 This honeypot file was deleted by malicious process!")
					ds.alertCanaryCompromised(path, "DELETED", 0, canary.OriginalEntropy)
					compromised = true
				}
				continue
			}

			// File locked or access denied → Suspicious
			log.Printf("[DETECTION] ⚠️  CANARY ACCESS DENIED: %s (error: %v)", path, err)
			ds.alertCanaryCompromised(path, "ACCESS_DENIED", 0, canary.OriginalEntropy)
			compromised = true
			continue
		}

		// Check if file size changed drastically
		if fileInfo.Size() != canary.FileSize {
			log.Printf("[DETECTION] 🚨 CANARY SIZE CHANGED: %s (was: %d bytes, now: %d bytes)",
				path, canary.FileSize, fileInfo.Size())
			ds.alertCanaryCompromised(path, "SIZE_CHANGED", 0, canary.OriginalEntropy)
			compromised = true
			continue
		}

		// Analyze current entropy
		entropy, err := domain.AnalyzeFileEntropy(path, canary.Extension)
		if err != nil {
			log.Printf("[CANARY] Failed to analyze %s: %v", path, err)
			continue
		}

		// Check if entropy increased significantly (file encrypted)
		entropyDelta := entropy.Entropy - canary.OriginalEntropy
		if entropyDelta >= 2.0 {
			// CRITICAL: Canary encrypted → RANSOMWARE!
			log.Printf("[DETECTION] 🚨 CANARY ENCRYPTED: %s", path)
			log.Printf("[DETECTION] 🚨 Entropy jumped from %.3f → %.3f (Δ +%.3f)",
				canary.OriginalEntropy, entropy.Entropy, entropyDelta)
			log.Printf("[DETECTION] 🚨 This honeypot file was encrypted by ransomware!")

			ds.alertCanaryCompromised(path, "ENCRYPTED", entropy.Entropy, canary.OriginalEntropy)
			compromised = true
			continue
		}

		// Canary is intact
		// log.Printf("[CANARY] ✓ %s intact (entropy: %.3f)", filepath.Base(path), entropy.Entropy)
	}

	if !compromised {
		log.Printf("[CANARY] ✓ All %d honeypot files intact", canaryCount)
	}

	return compromised
}

// alertCanaryCompromised creates a CRITICAL alert when a canary file is compromised
// This is a definitive ransomware indicator with near-zero false positives
func (ds *DetectionService) alertCanaryCompromised(filePath string, compromiseType string, currentEntropy, originalEntropy float64) {
	log.Printf("[DETECTION] 🚨🚨🚨 CRITICAL: CANARY FILE COMPROMISED 🚨🚨🚨")
	log.Printf("[DETECTION] File: %s", filePath)
	log.Printf("[DETECTION] Type: %s", compromiseType)

	// Create CRITICAL alert
	// Note: We don't have processGuid here, so create a general system alert
	alert := &domain.Alert{
		ID:          fmt.Sprintf("CANARY_%d", time.Now().Unix()),
		Timestamp:   time.Now(),
		Severity:    domain.ThreatCritical,
		Category:    "RANSOMWARE",
		ProcessGuid: "UNKNOWN", // Canary doesn't track specific process
		ProcessID:   0,
		Image:       "UNKNOWN",
		Description: fmt.Sprintf("CANARY FILE COMPROMISED: %s (%s)", filepath.Base(filePath), compromiseType),
		Score:       100, // Maximum score
		Indicators: []domain.Indicator{
			{
				Type:        domain.IndicatorType(fmt.Sprintf("CANARY_%s", compromiseType)),
				Severity:    domain.ThreatCritical,
				Points:      100, // Maximum points - this is definitive ransomware
				Description: fmt.Sprintf("Honeypot file compromised: %s", compromiseType),
				Timestamp:   time.Now(),
				Evidence: map[string]string{
					"canary_path":         filePath,
					"compromise_type":     compromiseType,
					"original_entropy":    fmt.Sprintf("%.3f", originalEntropy),
					"current_entropy":     fmt.Sprintf("%.3f", currentEntropy),
					"entropy_delta":       fmt.Sprintf("%.3f", currentEntropy-originalEntropy),
					"detection_method":    "CANARY_HONEYPOT",
					"false_positive_rate": "< 0.01%",
				},
			},
		},
		Evidence: map[string]interface{}{
			"canary_path":      filePath,
			"compromise_type":  compromiseType,
			"detection_method": "HONEYPOT",
		},
		AutoRespond: true, // Canary compromise = definitive ransomware = auto-respond
	}

	// Send alert
	select {
	case ds.alertChan <- alert:
		log.Printf("[ALERT] Canary compromise alert sent: %s", filePath)
	default:
		log.Printf("[ALERT] Alert channel full, canary alert dropped")
	}
}

// StartCanaryMonitoring starts periodic canary file checking
// Checks every 30 seconds for compromised honeypot files
func (ds *DetectionService) StartCanaryMonitoring(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("[CANARY] Starting periodic monitoring (every 30 seconds)...")

	for {
		select {
		case <-ctx.Done():
			log.Println("[CANARY] Monitoring stopped (context cancelled)")
			return
		case <-ticker.C:
			ds.CheckCanaryFiles()
		}
	}
}

// CleanupCanaryFiles removes all canary files on shutdown
func (ds *DetectionService) CleanupCanaryFiles() {
	ds.canaryFilesMux.Lock()
	defer ds.canaryFilesMux.Unlock()

	log.Printf("[CANARY] Cleaning up %d honeypot files...", len(ds.canaryFiles))

	for path := range ds.canaryFiles {
		if err := os.Remove(path); err != nil {
			log.Printf("[CANARY] Failed to remove %s: %v", path, err)
		} else {
			log.Printf("[CANARY] Removed: %s", path)
		}
	}

	log.Println("[CANARY] Cleanup complete")
}

// GetCanaryStats returns statistics about canary files
func (ds *DetectionService) GetCanaryStats() map[string]interface{} {
	ds.canaryFilesMux.RLock()
	defer ds.canaryFilesMux.RUnlock()

	return map[string]interface{}{
		"total_canaries": len(ds.canaryFiles),
	}
}

// CleanupOldHighIOFlags removes high I/O flags for processes inactive for specified duration
// This prevents memory leaks and ensures stale flags don't affect detection
func (ds *DetectionService) CleanupOldHighIOFlags(maxAge time.Duration) int {
	ds.highIOProcessesMux.Lock()
	defer ds.highIOProcessesMux.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for guid, flaggedTime := range ds.highIOProcesses {
		if flaggedTime.Before(cutoff) {
			delete(ds.highIOProcesses, guid)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[CLEANUP] Removed %d old high I/O flags", removed)
	}

	return removed
}

// GetHighIOProcessCount returns the number of processes currently flagged for deep monitoring
func (ds *DetectionService) GetHighIOProcessCount() int {
	ds.highIOProcessesMux.RLock()
	defer ds.highIOProcessesMux.RUnlock()
	return len(ds.highIOProcesses)
}

// IsProcessFlagged checks if a process is currently flagged for deep monitoring
func (ds *DetectionService) IsProcessFlagged(processGuid string) bool {
	ds.highIOProcessesMux.RLock()
	defer ds.highIOProcessesMux.RUnlock()
	_, exists := ds.highIOProcesses[processGuid]
	return exists
}

// scanDirectoryForRansomware scans a directory for files with ransomware extensions
// Returns list of ransomware files found and total file count
func (ds *DetectionService) scanDirectoryForRansomware(dirPath string) ([]string, int) {
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
		if domain.IsRansomwareExtension(filePath, ds.ransomwareExtensions) {
			log.Printf("[DIRECTORY SCAN] Found malicious file: %s", fileName)
			ransomFiles = append(ransomFiles, fileName)
		}
	}

	return ransomFiles, totalFiles
}

// processDirectoryScanResult processes the results of a directory scan and adds indicators
// This helper function centralizes the scan result processing for progressive scans
func (ds *DetectionService) processDirectoryScanResult(event *domain.SysmonEvent, dirPath string, ransomFiles []string, totalFiles int, scanType string) {
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

	score := ds.threatScorer.AddIndicator(
		event.ProcessGuid,
		event.Image,
		event.ProcessID,
		indicator,
	)

	log.Printf("[DETECTION] 🔴 BULK ENCRYPTION INDICATOR ADDED [%s]: %s (Score: %d, Points: +%d)",
		scanType, dirPath, score, points)

	// Immediately evaluate for response
	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// ProcessFileDelete handles file deletion events
// This is critical for detecting ransomware that renames files (e.g., file.txt -> file.txt.omega)
// Windows file renames appear as: delete original + create new (but create event may not fire for renames)
func (ds *DetectionService) ProcessFileDelete(ctx context.Context, event *domain.SysmonEvent) {
	// DEBUG: Print ALL file deletions to verify ransomware activity
	ext := filepath.Ext(event.TargetFile)
	log.Printf("[FILE_DELETED] %s (ext: %s) by %s (PID: %d)",
		event.TargetFile, ext, filepath.Base(event.Image), event.ProcessID)

	// REAL-TIME CANARY DETECTION: Check if deleted file is a honeypot
	// This catches ransomware that deletes original canary files before/during encryption
	if canary, isCanary := ds.isCanaryFile(event.TargetFile); isCanary {
		log.Printf("[CANARY] 🚨 REAL-TIME DETECTION: Canary file DELETED: %s", event.TargetFile)
		log.Printf("[CANARY] Process: %s (PID: %d, GUID: %s)", event.Image, event.ProcessID, event.ProcessGuid)

		// Check for correlation with .txt file creation
		ds.fileCountersMux.RLock()
		counters, hasCounters := ds.fileCounters[event.ProcessGuid]
		var txtFileCount int
		var txtDirCount int
		if hasCounters {
			txtFileCount = counters.TxtFileCount
			txtDirCount = len(counters.TxtFileDirectories)
		}
		ds.fileCountersMux.RUnlock()

		// HIGH CONFIDENCE CORRELATION: Canary deleted + ransom notes created
		if txtFileCount >= 3 {
			log.Printf("[CANARY] 🔥 CORRELATION DETECTED: Canary file deleted + %d ransom notes across %d directories", txtFileCount, txtDirCount)

			indicator := domain.Indicator{
				Type:        domain.IndicatorCanaryCompromised,
				Severity:    domain.ThreatCritical,
				Points:      100, // MAXIMUM SCORE - immediate termination
				Description: fmt.Sprintf("CORRELATED: Canary file deleted + %d ransom notes (high confidence ransomware)", txtFileCount),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"canary_path":      event.TargetFile,
					"detection_method": "REAL_TIME_CANARY_DELETE_WITH_RANSOM_NOTES",
					"txt_file_count":   fmt.Sprintf("%d", txtFileCount),
					"txt_directories":  fmt.Sprintf("%d", txtDirCount),
					"correlation":      "CANARY_DELETE_AND_RANSOM_NOTES",
					"confidence":       "VERY_HIGH",
					"operation":        "FILE_DELETE",
				},
			}

			score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[CANARY] ⚠️  THREAT SCORE: %d (Indicator: +100 points)", score)

			// Immediate termination evaluation
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return // Early return - ransomware confirmed
		}

		// Canary deleted WITHOUT ransom note correlation - still highly suspicious
		log.Printf("[CANARY] ⚠️  Canary deleted but no ransom note correlation (txt files: %d)", txtFileCount)

		indicator := domain.Indicator{
			Type:        domain.IndicatorCanaryCompromised,
			Severity:    domain.ThreatHigh,
			Points:      50, // High severity - canary deletion alone
			Description: fmt.Sprintf("Canary file deleted: %s", filepath.Base(event.TargetFile)),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"canary_path":        event.TargetFile,
				"canary_extension":   canary.Extension,
				"original_entropy":   fmt.Sprintf("%.2f", canary.OriginalEntropy),
				"detection_method":   "REAL_TIME_CANARY_DELETE",
				"operation":          "FILE_DELETE",
				"txt_file_count":     fmt.Sprintf("%d", txtFileCount),
				"correlation_status": "NO_RANSOM_NOTES",
			},
		}

		score := ds.threatScorer.AddIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[CANARY] ⚠️  THREAT SCORE: %d (Indicator: +50 points)", score)

		// Evaluate for potential termination
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		// Continue processing - might be combined with other indicators
	}

	// CRITICAL: Check for ransomware rename IMMEDIATELY on ALL deletions
	// This catches ransomware in early stages before I/O velocity threshold is reached
	// When Conti renames document.docx → document.docx.conti:
	//   - Sysmon fires Event ID 23 (FileDelete) for "document.docx"
	//   - But NO Event ID 11 (FileCreate) for "document.docx.conti"
	// Solution: When file deleted, check if .conti/.encrypted/etc version exists
	log.Printf("[SPECIFIC FILE CHECK] Checking if %s was renamed to malicious extension...", filepath.Base(event.TargetFile))

	potentialRansomFiles := []string{
		event.TargetFile + ".conti",
		event.TargetFile + ".encrypted",
		event.TargetFile + ".locked",
		event.TargetFile + ".enc",
		event.TargetFile + ".crypt",
	}

	foundRenamed := false
	for _, ransomFile := range potentialRansomFiles {
		if _, err := os.Stat(ransomFile); err == nil {
			// Encrypted version exists! This is a ransomware rename operation
			log.Printf("[DETECTION] 🚨 MALICIOUS FILE RENAME DETECTED: %s → %s by %s (PID: %d)",
				filepath.Base(event.TargetFile), filepath.Base(ransomFile),
				filepath.Base(event.Image), event.ProcessID)

			indicator := domain.Indicator{
				Type:     domain.IndicatorRansomExtension,
				Severity: domain.ThreatCritical,
				Points:   domain.IndicatorScores[domain.IndicatorRansomExtension],
				Description: fmt.Sprintf("CRITICAL: File encrypted via rename: %s → %s",
					filepath.Base(event.TargetFile), filepath.Base(ransomFile)),
				Timestamp: event.Timestamp,
				Evidence: map[string]string{
					"original_file":  filepath.Base(event.TargetFile),
					"encrypted_file": filepath.Base(ransomFile),
					"operation":      "rename_encryption",
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] 🔴 MALICIOUS RENAME INDICATOR ADDED: %s (Score: %d)",
				filepath.Base(ransomFile), score)

			// Immediately evaluate for response
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			foundRenamed = true
			break // Only trigger once
		}
	}

	if !foundRenamed {
		log.Printf("[SPECIFIC FILE CHECK] No malicious renamed file found for %s", filepath.Base(event.TargetFile))
	}

	// PERFORMANCE OPTIMIZATION: Only analyze deletions from ANALYZE or CRITICAL tier processes
	// This prevents unnecessary directory scans for normal file operations (browser cache, temp files, etc.)
	tier := ds.velocityTracker.GetVelocityTier(event.ProcessGuid)

	shouldDeepAnalyze := (tier == domain.VelocityTierCritical || tier == domain.VelocityTierAnalyze)

	if !shouldDeepAnalyze {
		// MONITOR tier or below: skip deep directory analysis
		return
	}

	log.Printf("[DEEP ANALYSIS] File deleted by high I/O process: %s", event.TargetFile)

	// ENHANCED DETECTION 1: Progressive directory scan for ransomware extensions
	// FLAW #3 FIX: No 8-second delay - scan immediately with progressive re-scans
	// FLAW #7 FIX: Deduplication prevents goroutine explosion
	// When ransomware operates, it often encrypts entire directories
	// Strategy: Progressive scans (0s, 2s, 5s) catch encryption at different stages
	dirPath := filepath.Dir(event.TargetFile)

	// DEDUPLICATION: Check if scan already in progress for this directory
	ds.directoryScanMux.Lock()
	if ds.directoryScanInProgress[dirPath] {
		ds.directoryScanMux.Unlock()
		log.Printf("[PATH ANALYSIS] Scan already in progress for %s, skipping duplicate", dirPath)
		return // Scan already running for this directory
	}
	ds.directoryScanInProgress[dirPath] = true
	ds.directoryScanMux.Unlock()

	// Run progressive directory scan in parallel to avoid blocking event processing
	go func() {
		defer func() {
			// Cleanup: Remove from in-progress map when done
			ds.directoryScanMux.Lock()
			delete(ds.directoryScanInProgress, dirPath)
			ds.directoryScanMux.Unlock()
		}()

		log.Printf("[PATH ANALYSIS] Starting progressive scan for %s...", dirPath)

		// SCAN 1: IMMEDIATE (catch early encryption)
		log.Printf("[PATH ANALYSIS] Scan 1/3: Immediate check...")
		scan1Files, scan1Total := ds.scanDirectoryForRansomware(dirPath)
		if len(scan1Files) > 3 {
			// Early detection: 3+ suspicious files immediately
			log.Printf("[DETECTION] ⚡ IMMEDIATE DETECTION: %d suspicious files in %s", len(scan1Files), dirPath)
			ds.processDirectoryScanResult(event, dirPath, scan1Files, scan1Total, "IMMEDIATE")
			return // Alert immediately, no need to wait
		}

		// SCAN 2: After 2 seconds (catch in-progress encryption)
		time.Sleep(2 * time.Second)
		log.Printf("[PATH ANALYSIS] Scan 2/3: Re-checking after 2s...")
		scan2Files, scan2Total := ds.scanDirectoryForRansomware(dirPath)

		// Check if encryption is progressing
		if len(scan2Files) > len(scan1Files)+5 {
			// Encryption in progress: 5+ more files in 2 seconds
			log.Printf("[DETECTION] 🔥 ENCRYPTION IN PROGRESS: %d suspicious files (+%d in 2s) in %s",
				len(scan2Files), len(scan2Files)-len(scan1Files), dirPath)
			ds.processDirectoryScanResult(event, dirPath, scan2Files, scan2Total, "IN_PROGRESS")
			return // Alert on active encryption
		}

		// SCAN 3: After 5 more seconds (catch slow ransomware, total 7s from start)
		time.Sleep(3 * time.Second)
		log.Printf("[PATH ANALYSIS] Scan 3/3: Final check after 5s total...")
		scan3Files, scan3Total := ds.scanDirectoryForRansomware(dirPath)

		// Final check: Standard threshold
		if len(scan3Files) > 0 {
			log.Printf("[DETECTION] 🕒 SLOW ENCRYPTION: %d suspicious files in %s (detected over 5s)",
				len(scan3Files), dirPath)
			ds.processDirectoryScanResult(event, dirPath, scan3Files, scan3Total, "FINAL")
		} else {
			log.Printf("[PATH ANALYSIS] No significant threats detected in %s after 3 scans", dirPath)
		}
	}()

	// CRITICAL DETECTION: Check for modify-delete pattern
	// Classic ransomware behavior: modify file (encrypt in-place) → delete original → create .ENCRYPTED copy
	// This is a VERY strong indicator with low false positive rate
	ds.modifiedHighEntropyFilesMux.Lock()
	modifiedFile, wasRecentlyModified := ds.modifiedHighEntropyFiles[event.TargetFile]
	if wasRecentlyModified {
		// Remove from tracking map
		delete(ds.modifiedHighEntropyFiles, event.TargetFile)
	}
	ds.modifiedHighEntropyFilesMux.Unlock()

	if wasRecentlyModified {
		// File was modified with high entropy and NOW deleted - CRITICAL ransomware pattern!
		timeSinceModification := time.Since(modifiedFile.Timestamp)

		// Only trigger if deletion happened within 30 seconds of modification
		// (legitimate apps don't encrypt files then immediately delete them)
		if timeSinceModification < 30*time.Second {
			log.Printf("[DETECTION] 🚨 MODIFY-DELETE PATTERN DETECTED: %s", event.TargetFile)
			log.Printf("[DETECTION] 🚨 File modified with high entropy (%.3f) then deleted %.1f seconds later",
				modifiedFile.Entropy, timeSinceModification.Seconds())

			indicator := domain.Indicator{
				Type:        domain.IndicatorModifyDeletePattern,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorModifyDeletePattern],
				Description: fmt.Sprintf("CRITICAL: File modified with high entropy (%.3f) then deleted - classic ransomware pattern", modifiedFile.Entropy),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"file":                event.TargetFile,
					"entropy":             fmt.Sprintf("%.3f", modifiedFile.Entropy),
					"time_since_modify":   fmt.Sprintf("%.1fs", timeSinceModification.Seconds()),
					"pattern":             "MODIFY_HIGH_ENTROPY_THEN_DELETE",
					"confidence":          "VERY_HIGH",
					"false_positive_risk": "VERY_LOW",
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] 🔴 MODIFY-DELETE INDICATOR ADDED: %s (Score: %d)",
				filepath.Base(event.TargetFile), score)

			// Immediate evaluation - this is critical
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return
		}
	}

	// Check if a ransomware-renamed version exists
	// Common pattern: file.txt deleted -> file.txt.omega exists
	for _, ransomExt := range ds.ransomwareExtensions {
		renamedPath := event.TargetFile + ransomExt

		// Check if renamed file exists
		if _, err := os.Stat(renamedPath); err == nil {
			// Ransomware extension pattern detected via file rename
			indicator := domain.Indicator{
				Type:        domain.IndicatorRansomExtension,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
				Description: fmt.Sprintf("File renamed with ransomware extension (delete + rename pattern)"),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"deleted_file": event.TargetFile,
					"renamed_to":   renamedPath,
					"extension":    ransomExt,
				},
			}

			score := ds.threatScorer.AddIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] 🔴 Ransomware file rename detected: %s -> %s (Score: %d)",
				event.TargetFile, renamedPath, score)

			// Also check entropy of the renamed file
			ext := filepath.Ext(renamedPath)
			entropy, err := domain.AnalyzeFileEntropy(renamedPath, ext)
			if err == nil && entropy.IsLikelyEncrypted {
				entropyIndicator := domain.Indicator{
					Type:        domain.IndicatorHighEntropy,
					Severity:    domain.ThreatCritical,
					Points:      domain.IndicatorScores[domain.IndicatorHighEntropy],
					Description: fmt.Sprintf("High entropy in renamed file: %.3f", entropy.Entropy),
					Timestamp:   event.Timestamp,
					Evidence: map[string]string{
						"entropy":   fmt.Sprintf("%.3f", entropy.Entropy),
						"threshold": fmt.Sprintf("%.3f", entropy.Threshold),
						"file":      renamedPath,
					},
				}

				score = ds.threatScorer.AddIndicator(
					event.ProcessGuid,
					event.Image,
					event.ProcessID,
					entropyIndicator,
				)

				log.Printf("[DETECTION] 🔴 High entropy in renamed file: %s (%.3f > %.3f, Score: %d)",
					renamedPath, entropy.Entropy, entropy.Threshold, score)
			}

			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return
		}
	}
}

// CleanupOldModifiedFiles removes entries older than specified duration from modify-delete tracking
// This prevents memory leaks from accumulated tracking data
// Should be called periodically (e.g., every 5 minutes)
func (ds *DetectionService) CleanupOldModifiedFiles(maxAge time.Duration) int {
	ds.modifiedHighEntropyFilesMux.Lock()
	defer ds.modifiedHighEntropyFilesMux.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for filePath, record := range ds.modifiedHighEntropyFiles {
		if record.Timestamp.Before(cutoff) {
			delete(ds.modifiedHighEntropyFiles, filePath)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[CLEANUP] Removed %d old modified file entries (older than %v)", removed, maxAge)
	}

	return removed
}

// ProcessBackupPrivilege handles Windows Security events related to BackupRead/BackupWrite API usage
// This method processes events from the Security Event Log (Event IDs 4672, 4703, 4674)
// that indicate a process has enabled or is using SeBackupPrivilege/SeRestorePrivilege
func (ds *DetectionService) ProcessBackupPrivilege(ctx context.Context, event *domain.SecurityEvent) {
	log.Printf("[SECURITY] Processing backup privilege event: ID %d, Process: %s (PID: %s)",
		event.EventID, event.ProcessName, event.ProcessID)

	var indicator domain.Indicator

	switch event.EventID {
	case 4672: // Special privileges assigned
		indicator = domain.Indicator{
			Type:        domain.IndicatorBackupPrivilege,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorBackupPrivilege],
			Description: fmt.Sprintf("Backup privilege assigned to user: %s", event.UserName),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"event_id":   fmt.Sprintf("%d", event.EventID),
				"user":       event.UserName,
				"privileges": event.Privileges,
			},
		}

	case 4703: // Token privileges adjusted (process enabled backup privilege)
		indicator = domain.Indicator{
			Type:        domain.IndicatorBackupPrivilege,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorBackupPrivilege],
			Description: fmt.Sprintf("Process enabled backup privilege: %s (PID: %s)", event.ProcessName, event.ProcessID),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"event_id":     fmt.Sprintf("%d", event.EventID),
				"process_name": event.ProcessName,
				"process_id":   event.ProcessID,
				"privileges":   event.Privileges,
			},
		}

	case 4674: // Privileged operation attempted (BackupRead/BackupWrite API call)
		indicator = domain.Indicator{
			Type:        domain.IndicatorBackupAPIUsage,
			Severity:    domain.ThreatCritical,
			Points:      domain.IndicatorScores[domain.IndicatorBackupAPIUsage],
			Description: fmt.Sprintf("BackupRead/BackupWrite API call detected: %s targeting %s", event.ProcessName, event.ObjectName),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"event_id":     fmt.Sprintf("%d", event.EventID),
				"process_name": event.ProcessName,
				"process_id":   event.ProcessID,
				"target_file":  event.ObjectName,
				"privileges":   event.Privileges,
			},
		}

		log.Printf("[SECURITY] 🚨 CRITICAL: BackupRead/BackupWrite API usage detected!")
		log.Printf("[SECURITY] Process: %s (PID: %s)", event.ProcessName, event.ProcessID)
		log.Printf("[SECURITY] Target: %s", event.ObjectName)
	}

	// For security events, we may not have a ProcessGuid, so we'll create a pseudo-GUID
	// based on the process name and PID
	pseudoGuid := fmt.Sprintf("security-%s-%s", event.ProcessName, event.ProcessID)

	// Convert ProcessID string to int
	var pid int
	fmt.Sscanf(event.ProcessID, "%d", &pid)

	score := ds.threatScorer.AddIndicator(
		pseudoGuid,
		event.ProcessName,
		pid,
		indicator,
	)

	log.Printf("[SECURITY] Backup privilege event processed (Score: %d)", score)

	// Evaluate and potentially trigger alert
	ds.evaluateAndAlert(pseudoGuid, event.ProcessName, pid)
}

// scanDirectoriesForEncryptedFiles scans directories for encrypted files with ransomware extensions
// Triggered when rapid .txt file creation is detected in Tier 2 monitoring
// The .txt files are likely ransom notes - this function looks for ACTUAL ENCRYPTED FILES nearby
// Only adds indicators if encrypted files are found alongside ransom notes (high confidence)
func (ds *DetectionService) scanDirectoriesForEncryptedFiles(processGuid string, processImage string, processID int, directories []string, timestamp time.Time) {
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
			if domain.IsRansomwareExtension(fullPath, ds.ransomwareExtensions) {
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

		score := ds.threatScorer.AddIndicator(
			processGuid,
			processImage,
			processID,
			indicator,
		)

		log.Printf("[DIR SCAN] 🔴 ENCRYPTED FILES CONFIRMED: Added indicator based on directory scan (Score: %d)", score)

		// Immediate evaluation due to high confidence correlation
		ds.evaluateAndAlert(processGuid, processImage, processID)
	} else if len(encryptedFiles) > 0 {
		log.Printf("[DIR SCAN] ⚠️  Found %d encrypted files but below threshold (need 3+) or no ransom notes", len(encryptedFiles))
		log.Printf("[DIR SCAN] Continuing to monitor process...")
	} else {
		log.Printf("[DIR SCAN] ℹ️  No encrypted files found in scanned directories")
		log.Printf("[DIR SCAN] False positive: .txt files may not be ransom notes")
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
