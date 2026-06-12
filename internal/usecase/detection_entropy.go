package usecase

import (
	"fmt"
	"log"
	"path/filepath"
	"time"

	"procSniper/internal/domain"
)

// analyzeCreatedFileEntropy performs the deep entropy/extension analysis for a CREATED file
// from a deep-analysis-eligible (ANALYZE/CRITICAL tier) process. Extracted verbatim from the
// tail of ProcessFileCreate (Phase 6 S8): it owns its own early returns and its terminal
// evaluateAndAlert, so the orchestrator calls it last and does nothing after. ext is the
// file extension already computed by the caller; the counters entry was created by the
// caller's recordMLFeatures, and the Mutate calls here get-or-init under the store lock anyway.
func (ds *DetectionService) analyzeCreatedFileEntropy(event *domain.MonitorEvent, ext string) {
	log.Printf("[DEEP ANALYSIS] Analyzing file from high I/O process: %s", event.TargetFile)

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

		score := ds.addRuleIndicator(
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

		score := ds.addRuleIndicator(
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
		var combinedCount int
		ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
			c.CombinedEntropyAndExtCount++
			c.HighEntropyCount++
			c.RansomExtensionCount++
			c.LastUpdated = time.Now()
			combinedCount = c.CombinedEntropyAndExtCount
		})

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

			ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, entropyIndicator)
			finalScore := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, extensionIndicator)

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
		var currentCount int
		ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
			c.RansomExtensionCount++
			c.LastUpdated = time.Now()
			currentCount = c.RansomExtensionCount
		})

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

			score := ds.addRuleIndicator(
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
		var currentCount int
		ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
			c.HighEntropyCount++
			c.LastUpdated = time.Now()
			currentCount = c.HighEntropyCount
		})

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

			score := ds.addRuleIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] 🔴 HIGH ENTROPY THRESHOLD REACHED: %d files (Score: %d)",
				currentCount, score)
		}
	}

	// Evaluate overall threat for flagged processes
	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// analyzeModifiedFileEntropy performs the rename-fast-kill check and the depth/delta entropy
// analysis for a MODIFIED file. Extracted verbatim from the tail of ProcessFileModified
// (Phase 6 S7): it owns the rename-extension fast-kill, the TierNone early-exit, and all the
// entropy-stage early returns, so the orchestrator calls it after the canary write/rename gate
// and does nothing after. tier is the velocity tier already computed by the caller.
func (ds *DetectionService) analyzeModifiedFileEntropy(event *domain.MonitorEvent, tier domain.VelocityTier) {
	ext := filepath.Ext(event.TargetFile)

	// Fast-kill path: rename to known ransomware extension (scope: rename-only).
	// This preserves unknown-extension detection via high-entropy threshold (10 files).
	if isRenameMonitorEvent(event) && domain.IsRansomwareExtension(event.TargetFile, ds.ransomwareExtensions) {
		now := event.Timestamp
		if now.IsZero() {
			now = time.Now()
		}

		const renameWindow = 60 * time.Second

		var renameCount, extensionCount int
		ds.counters.Mutate(event.ProcessGuid, func(counters *ProcessFileCounters) {
			if counters.RenameRansomExtHits == nil {
				counters.RenameRansomExtHits = make([]time.Time, 0, ds.renameExtThreshold+2)
			}
			counters.RenameRansomExtHits = trimRenameHits(counters.RenameRansomExtHits, now, renameWindow)
			counters.RenameRansomExtHits = append(counters.RenameRansomExtHits, now)
			// Keep ML feature counters current before triggering inference.
			counters.RansomExtensionCount++
			renameCount = len(counters.RenameRansomExtHits)
			extensionCount = counters.RansomExtensionCount
			counters.LastUpdated = now
		})

		log.Printf("[DETECTION] Rename-to-ransom-extension observed: %s (%d/%d in %s, extension_count=%d)",
			event.TargetFile, renameCount, ds.renameExtThreshold, renameWindow, extensionCount)

		if renameCount >= ds.renameExtThreshold {
			indicator := domain.Indicator{
				Type:        domain.IndicatorRansomExtension,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
				Description: fmt.Sprintf("Rename-based ransomware extension threshold reached: %d files", renameCount),
				Timestamp:   now,
				Evidence: map[string]string{
					"file":             event.TargetFile,
					"count":            fmt.Sprintf("%d", renameCount),
					"threshold":        fmt.Sprintf("%d", ds.renameExtThreshold),
					"window_seconds":   "60",
					"detection_method": "RENAME_EXTENSION_FAST_KILL",
				},
			}

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] RENAME EXTENSION FAST-KILL THRESHOLD REACHED (Score: %d)", score)
			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
			return
		}
	}

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
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

		score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
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

		// NOTE: this path intentionally does NOT touch LastUpdated — preserved from the
		// pre-counterStore behavior (changing it would alter eviction timing for these processes).
		var currentCount int
		ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
			c.HighEntropyCount++
			currentCount = c.HighEntropyCount
		})

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 HIGH ENTROPY MODIFICATION THRESHOLD REACHED: %d files (Score: %d)",
				currentCount, score)

			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		}
	}
}
