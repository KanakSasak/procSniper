package usecase

import (
	"log"
	"path/filepath"
	"strings"
	"time"

	"procSniper/internal/domain"
)

// recordCanaryTouch records the ETW actor for canary-compromise attribution. On create it
// only attributes when the path matches a known canary (open/create of ordinary files is
// noise indexers/AV generate); modify and delete are destructive ops and always record.
// Consolidates the per-method canary touchpoints (Phase 6). op is the FILE_* event label.
func (ds *DetectionService) recordCanaryTouch(event *domain.MonitorEvent, op string) {
	if op == "FILE_CREATE" {
		if _, _, match := ds.canaryMgr.Match(event.TargetFile); !match {
			return
		}
	}
	ds.canaryMgr.RecordActor(event, op)
}

// trackRansomNote records a .txt file toward ransom-note campaign detection: it increments
// TxtFileCount and accumulates the unique directory set. On the create path (fullCreatePath)
// it also stamps LastUpdated, logs, and — at >=5 .txt files across >=3 directories — fires a
// directory scan for encrypted files (using a dirs snapshot taken under the counters lock so
// the scan goroutine never races future appends). The modify/rename path does neither, matching
// the pre-extraction behavior (which neither stamped LastUpdated nor triggered a scan). Phase 6.
func (ds *DetectionService) trackRansomNote(event *domain.MonitorEvent, fullCreatePath bool) {
	dirPath := filepath.Dir(event.TargetFile)
	var txtCount, dirCount int
	var txtDirs []string
	ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
		c.TxtFileCount++
		dirExists := false
		for _, existingDir := range c.TxtFileDirectories {
			if existingDir == dirPath {
				dirExists = true
				break
			}
		}
		if !dirExists {
			c.TxtFileDirectories = append(c.TxtFileDirectories, dirPath)
		}
		txtCount = c.TxtFileCount
		dirCount = len(c.TxtFileDirectories)
		txtDirs = append([]string(nil), c.TxtFileDirectories...)
		if fullCreatePath {
			c.LastUpdated = time.Now()
		}
	})

	if !fullCreatePath {
		return
	}

	log.Printf("[TIER 2] .txt file created: %s (%d total .txt files across %d directories)",
		filepath.Base(event.TargetFile), txtCount, dirCount)

	// TRIGGER: >= 5 .txt files across >= 3 directories is a strong ransom-note signal —
	// scan those directories for encrypted files alongside the notes.
	if txtCount >= 5 && dirCount >= 3 {
		log.Printf("[TIER 2] 🔍 RANSOM NOTE PATTERN DETECTED: %d .txt files across %d directories",
			txtCount, dirCount)
		log.Printf("[TIER 2] Triggering directory scan to find encrypted files alongside ransom notes...")
		go ds.dirScanner.ScanDirectoriesForEncryptedFiles(event.ProcessGuid, event.Image, event.ProcessID, txtDirs, event.Timestamp)
	}
}

// recordMLFeatures accumulates the shared per-file ML counters from any file event: the set
// of unique directories touched, the extension-frequency distribution (for the Shannon-entropy
// feature), and — for deletes — the delete count. It is the deduplicated core previously
// inlined in ProcessFileCreate/Modified/Delete (Phase 6).
//
// The .txt ransom-note tracking is intentionally NOT here — it has per-method gating (scan
// trigger on create, rename-only on modify) and lives with that logic. op is "create",
// "modify", or "delete".
func (ds *DetectionService) recordMLFeatures(event *domain.MonitorEvent, op string) {
	ext := filepath.Ext(event.TargetFile)
	isRename := op == "modify" && isRenameMonitorEvent(event)
	ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
		if op == "delete" {
			c.DeleteCount++
		}
		c.DirectorySet[filepath.Dir(event.TargetFile)] = struct{}{}
		if ext != "" {
			c.ExtensionCounts[strings.ToLower(ext)]++
			// Rename events also track the original (inner) extension so Shannon entropy is
			// non-zero (e.g. "document.pdf.CONTI" -> both ".conti" and ".pdf").
			if isRename {
				base := strings.TrimSuffix(event.TargetFile, ext)
				if innerExt := filepath.Ext(base); innerExt != "" {
					c.ExtensionCounts[strings.ToLower(innerExt)]++
				}
			}
		}
	})
}
