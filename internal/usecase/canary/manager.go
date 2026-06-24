package canary

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

// AlertEmitter is the seam the canary subsystem uses to feed the detection/response
// pipeline. Implemented by usecase.DetectionService (RaiseIndicator -> addRuleIndicator,
// Evaluate -> evaluateAndAlert, SendAlert -> the non-blocking alertChan send + drop
// accounting). Keeping it an interface lets the canary logic be tested with a fake.
type AlertEmitter interface {
	RaiseIndicator(processGuid, image string, pid int, indicator domain.Indicator) int
	Evaluate(processGuid, image string, pid int)
	SendAlert(alert *domain.Alert)
}

// RelatedActorProvider returns high-confidence related processes for canary containment.
// Implemented by DetectionService (reads its velocity-actor state, which stays in usecase).
type RelatedActorProvider interface {
	RelatedActors(canaryPath, attributedGuid string, now time.Time) []domain.RelatedProcess
}

// TxtActivityProvider reports ransom-note-style .txt activity for a process, used to
// raise confidence on a real-time canary write/rename. Implemented by DetectionService
// (reads its per-process file counters).
type TxtActivityProvider interface {
	TxtActivity(processGuid string) (txtFileCount, txtDirCount int)
}

// Actor records the most recent ETW-attributed process that touched a canary, so a
// periodic-scan compromise (which has no direct actor context) can be correlated to a
// concrete process.
type Actor struct {
	ProcessID   int
	ProcessGuid string
	Image       string
	TargetPath  string
	EventType   string
	SeenAt      time.Time
}

// Manager owns procSniper's canary (honeypot) subsystem: the file registry, recent-actor
// attribution, the alert-dedup latches, and the configured response action. It depends on
// the detection pipeline only through the injected seams above.
type Manager struct {
	emitter AlertEmitter
	related RelatedActorProvider
	txt     TxtActivityProvider

	latches *LatchSet

	filesMu sync.RWMutex
	files   map[string]*domain.CanaryFile // FilePath -> canary metadata

	actorsMu sync.RWMutex
	actors   map[string]Actor // normalized canonical canary path -> actor

	// responseAction is the canary response action. It can be changed at runtime via the API/GUI
	// while the canary monitor + ETW workers read it on the hot path, so it is mutex-guarded.
	responseAction   string
	responseActionMu sync.RWMutex
}

// NewManager builds a canary Manager wired to the detection-pipeline seams.
func NewManager(emitter AlertEmitter, related RelatedActorProvider, txt TxtActivityProvider) *Manager {
	return &Manager{
		emitter: emitter,
		related: related,
		txt:     txt,
		latches: NewLatchSet(),
		files:   make(map[string]*domain.CanaryFile),
		actors:  make(map[string]Actor),
	}
}

// SetResponseAction sets the canary response action ("terminate"/"suspend"/"alert_only").
func (m *Manager) SetResponseAction(action string) {
	m.responseActionMu.Lock()
	defer m.responseActionMu.Unlock()
	switch action {
	case "terminate", "suspend", "alert_only":
		m.responseAction = action
	default:
		m.responseAction = "terminate"
	}
	log.Printf("[CONFIG] Canary response action set to: %s", m.responseAction)
}

// ResponseAction returns the current canary response action (default "terminate"). Read on the
// hot path while the API/GUI may write it, so it is mutex-guarded.
func (m *Manager) ResponseAction() string {
	m.responseActionMu.RLock()
	defer m.responseActionMu.RUnlock()
	if m.responseAction == "" {
		return "terminate"
	}
	return m.responseAction
}

// IsCanaryFile reports whether filePath is a tracked canary and returns its metadata.
func (m *Manager) IsCanaryFile(filePath string) (*domain.CanaryFile, bool) {
	m.filesMu.RLock()
	defer m.filesMu.RUnlock()
	canary, exists := m.files[filePath]
	return canary, exists
}

// Count returns the number of tracked canary files.
func (m *Manager) Count() int {
	m.filesMu.RLock()
	defer m.filesMu.RUnlock()
	return len(m.files)
}

// Stats is a snapshot of canary deployment state.
type Stats struct {
	TotalCanaries int
}

// Stats returns canary statistics for the GUI/CLI.
func (m *Manager) Stats() Stats {
	return Stats{TotalCanaries: m.Count()}
}

// Match resolves a target path to a tracked canonical canary path.
// Match types: exact, renamed_prefix.
func (m *Manager) Match(targetPath string) (string, string, bool) {
	targetNorm := NormalizePath(targetPath)
	if targetNorm == "" {
		return "", "", false
	}

	m.filesMu.RLock()
	defer m.filesMu.RUnlock()

	targetDir := NormalizePath(filepath.Dir(targetPath))
	targetBase := strings.ToLower(filepath.Base(targetPath))

	for canaryPath, canary := range m.files {
		canonicalNorm := NormalizePath(canaryPath)
		if targetNorm == canonicalNorm {
			return canaryPath, "exact", true
		}

		// Rename pattern: ~canary_name.ext -> ~canary_name.ext.CONTI
		canaryDir := NormalizePath(filepath.Dir(canaryPath))
		if canaryDir != targetDir {
			continue
		}

		baseName := strings.ToLower(filepath.Base(canaryPath))
		baseNoExt := strings.TrimSuffix(baseName, strings.ToLower(canary.Extension))
		if strings.HasPrefix(targetBase, baseNoExt) && targetBase != baseName {
			return canaryPath, "renamed_prefix", true
		}
	}

	return "", "", false
}

// RecordActor attributes a recent ETW file event to a canary (when the target matches a
// tracked canary), keeping the most recent actor per canonical canary path.
func (m *Manager) RecordActor(event *domain.MonitorEvent, eventType string) {
	if event == nil {
		return
	}

	canonicalPath, matchType, ok := m.Match(event.TargetFile)
	if !ok {
		return
	}

	seenAt := event.Timestamp
	if seenAt.IsZero() {
		seenAt = time.Now()
	}

	actor := Actor{
		ProcessID:   event.ProcessID,
		ProcessGuid: event.ProcessGuid,
		Image:       event.Image,
		TargetPath:  event.TargetFile,
		EventType:   fmt.Sprintf("%s:%s", eventType, matchType),
		SeenAt:      seenAt,
	}

	key := NormalizePath(canonicalPath)
	m.actorsMu.Lock()
	existing, exists := m.actors[key]
	if !exists || actor.SeenAt.After(existing.SeenAt) {
		m.actors[key] = actor
	}
	m.actorsMu.Unlock()
}

// ResolveActor returns the recent actor attributed to a canary, within the attribution
// TTL. Stale entries are evicted.
func (m *Manager) ResolveActor(canonicalCanaryPath, renamedPath string) (Actor, bool) {
	const attributionTTL = 120 * time.Second

	key := NormalizePath(canonicalCanaryPath)
	if key == "" {
		return Actor{}, false
	}

	m.actorsMu.Lock()
	defer m.actorsMu.Unlock()

	actor, ok := m.actors[key]
	if !ok {
		return Actor{}, false
	}

	if time.Since(actor.SeenAt) > attributionTTL {
		delete(m.actors, key)
		return Actor{}, false
	}

	if renamedPath != "" {
		renamedNorm := NormalizePath(renamedPath)
		if renamedNorm != "" && NormalizePath(actor.TargetPath) != renamedNorm {
			// Keep attribution even if path differs, but prefer matching paths when available.
			// No-op fallback: actor is still recent and canary-specific.
		}
	}

	return actor, true
}

// Setup creates/tracks honeypot files in the user and system canary locations. Resets the
// latch state so recreated canaries can alert again.
func (m *Manager) Setup() error {
	log.Println("[CANARY] Setting up honeypot files for ransomware detection...")
	// Full setup resets latch state so recreated canaries can alert again.
	m.latches.ResetAll()

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
			m.Track(filePath, &domain.CanaryFile{
				Path:            filePath,
				OriginalEntropy: entropy.Entropy,
				FileSize:        entropy.FileSize,
				Created:         time.Now(),
				LastChecked:     time.Now(),
				Extension:       location.Extension,
			})
			m.latches.Reset(filePath)

			log.Printf("[CANARY] OK Tracked existing canary: %s (entropy: %.3f)", filePath, entropy.Entropy)
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
		m.Track(filePath, &domain.CanaryFile{
			Path:            filePath,
			OriginalEntropy: entropy.Entropy,
			FileSize:        entropy.FileSize,
			Created:         time.Now(),
			LastChecked:     time.Now(),
			Extension:       location.Extension,
		})
		m.latches.Reset(filePath)

		log.Printf("[CANARY] OK Created canary: %s (entropy: %.3f, size: %d bytes)",
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
			m.Track(filePath, &domain.CanaryFile{
				Path:            filePath,
				OriginalEntropy: entropy.Entropy,
				FileSize:        entropy.FileSize,
				Created:         time.Now(),
				LastChecked:     time.Now(),
				Extension:       location.Extension,
			})
			m.latches.Reset(filePath)

			log.Printf("[CANARY] OK Tracked existing system canary: %s (entropy: %.3f)", filePath, entropy.Entropy)
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
		m.Track(filePath, &domain.CanaryFile{
			Path:            filePath,
			OriginalEntropy: entropy.Entropy,
			FileSize:        entropy.FileSize,
			Created:         time.Now(),
			LastChecked:     time.Now(),
			Extension:       location.Extension,
		})
		m.latches.Reset(filePath)

		log.Printf("[CANARY] OK Created system canary: %s (entropy: %.3f, size: %d bytes)",
			filepath.Base(filePath), entropy.Entropy, entropy.FileSize)
		successCount++
	}

	log.Printf("[CANARY] Setup complete: %d created/tracked, %d failed", successCount, failCount)

	if successCount == 0 {
		return fmt.Errorf("failed to create any canary files")
	}

	return nil
}

// Track registers (or replaces) a canary file in the registry.
func (m *Manager) Track(path string, cf *domain.CanaryFile) {
	m.filesMu.Lock()
	m.files[path] = cf
	m.filesMu.Unlock()
}

// StartMonitoring runs the periodic canary check every 30 seconds until ctx is cancelled.
func (m *Manager) StartMonitoring(stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("[CANARY] Starting periodic monitoring (every 30 seconds)...")

	for {
		select {
		case <-stop:
			log.Println("[CANARY] Monitoring stopped (context cancelled)")
			return
		case <-ticker.C:
			m.CheckFiles()
		}
	}
}

// Cleanup removes all canary files and clears registry + latch state on shutdown.
func (m *Manager) Cleanup() {
	m.filesMu.Lock()
	defer m.filesMu.Unlock()

	log.Printf("[CANARY] Cleaning up %d honeypot files...", len(m.files))

	for path := range m.files {
		if err := os.Remove(path); err != nil {
			log.Printf("[CANARY] Failed to remove %s: %v", path, err)
		} else {
			log.Printf("[CANARY] Removed: %s", path)
		}
	}

	clear(m.files)
	m.latches.ResetAll()

	log.Println("[CANARY] Cleanup complete")
}

// CheckFiles periodically checks if canary files have been compromised (called on a
// timer). Returns true if any canary was compromised. The registry write-lock is held
// across the scan, matching the original DetectionService.CheckCanaryFiles behavior.
func (m *Manager) CheckFiles() bool {
	m.filesMu.RLock()
	canaryCount := len(m.files)
	m.filesMu.RUnlock()

	if canaryCount == 0 {
		return false
	}

	log.Printf("[CANARY] Checking %d honeypot files...", canaryCount)

	compromised := false
	suppressedCanaryAlerts := 0

	m.filesMu.Lock()
	defer m.filesMu.Unlock()

	for path, canary := range m.files {
		canary.LastChecked = time.Now()

		fileInfo, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				dirPath := filepath.Dir(path)
				baseName := filepath.Base(path)
				baseNameWithoutExt := strings.TrimSuffix(baseName, canary.Extension)

				renamed := false
				renamedPath := ""

				entries, readErr := os.ReadDir(dirPath)
				if readErr == nil {
					for _, entry := range entries {
						if entry.IsDir() {
							continue
						}

						entryName := entry.Name()
						if strings.HasPrefix(entryName, baseNameWithoutExt) && entryName != baseName {
							renamedPath = filepath.Join(dirPath, entryName)
							newExt := filepath.Ext(entryName)

							log.Printf("[DETECTION] CANARY RENAMED: %s -> %s", path, renamedPath)
							log.Printf("[DETECTION] Extension changed from %s to %s", canary.Extension, newExt)
							log.Printf("[DETECTION] This is a classic ransomware behavior!")

							entropy, entropyErr := domain.AnalyzeFileEntropy(renamedPath, newExt)
							if entropyErr == nil {
								entropyDelta := entropy.Entropy - canary.OriginalEntropy
								log.Printf("[DETECTION] Renamed file entropy: %.3f (original: %.3f, delta +%.3f)",
									entropy.Entropy, canary.OriginalEntropy, entropyDelta)

								if entropyDelta >= 2.0 {
									if !m.alertCompromised(
										path,
										fmt.Sprintf("RENAMED_AND_ENCRYPTED (-> %s)", filepath.Base(renamedPath)),
										entropy.Entropy,
										canary.OriginalEntropy,
										renamedPath,
									) {
										suppressedCanaryAlerts++
									}
								} else {
									if !m.alertCompromised(
										path,
										fmt.Sprintf("RENAMED (-> %s)", filepath.Base(renamedPath)),
										0,
										canary.OriginalEntropy,
										renamedPath,
									) {
										suppressedCanaryAlerts++
									}
								}
							} else {
								if !m.alertCompromised(
									path,
									fmt.Sprintf("RENAMED (-> %s)", filepath.Base(renamedPath)),
									0,
									canary.OriginalEntropy,
									renamedPath,
								) {
									suppressedCanaryAlerts++
								}
							}

							renamed = true
							compromised = true
							break
						}
					}
				}

				if !renamed {
					log.Printf("[DETECTION] CANARY DELETED: %s", path)
					log.Printf("[DETECTION] This honeypot file was deleted by malicious process!")
					if !m.alertCompromised(path, "DELETED", 0, canary.OriginalEntropy, "") {
						suppressedCanaryAlerts++
					}
					compromised = true
				}
				continue
			}

			log.Printf("[DETECTION] CANARY ACCESS DENIED: %s (error: %v)", path, err)
			if !m.alertCompromised(path, "ACCESS_DENIED", 0, canary.OriginalEntropy, "") {
				suppressedCanaryAlerts++
			}
			compromised = true
			continue
		}

		if fileInfo.Size() != canary.FileSize {
			log.Printf("[DETECTION] CANARY SIZE CHANGED: %s (was: %d bytes, now: %d bytes)",
				path, canary.FileSize, fileInfo.Size())
			if !m.alertCompromised(path, "SIZE_CHANGED", 0, canary.OriginalEntropy, "") {
				suppressedCanaryAlerts++
			}
			compromised = true
			continue
		}

		entropy, entropyErr := domain.AnalyzeFileEntropy(path, canary.Extension)
		if entropyErr != nil {
			log.Printf("[CANARY] Failed to analyze %s: %v", path, entropyErr)
			continue
		}

		entropyDelta := entropy.Entropy - canary.OriginalEntropy
		if entropyDelta >= 2.0 {
			log.Printf("[DETECTION] CANARY ENCRYPTED: %s", path)
			log.Printf("[DETECTION] Entropy jumped from %.3f -> %.3f (delta +%.3f)",
				canary.OriginalEntropy, entropy.Entropy, entropyDelta)
			log.Printf("[DETECTION] This honeypot file was encrypted by ransomware!")

			if !m.alertCompromised(path, "ENCRYPTED", entropy.Entropy, canary.OriginalEntropy, "") {
				suppressedCanaryAlerts++
			}
			compromised = true
			continue
		}
	}

	if !compromised {
		log.Printf("[CANARY] All %d honeypot files intact", canaryCount)
	}
	if suppressedCanaryAlerts > 0 {
		log.Printf("[CANARY] Suppressed %d repeated canary compromise alerts (latched)", suppressedCanaryAlerts)
	}

	return compromised
}

// alertCompromised builds and emits a CRITICAL alert when a canary file is compromised.
// Returns false when the alert was latch-suppressed (already reported).
func (m *Manager) alertCompromised(filePath string, compromiseType string, currentEntropy, originalEntropy float64, relatedPath string) bool {
	log.Printf("[DETECTION] CRITICAL: CANARY FILE COMPROMISED")
	log.Printf("[DETECTION] File: %s", filePath)
	log.Printf("[DETECTION] Type: %s", compromiseType)

	processGuid := "UNKNOWN"
	processID := 0
	image := "UNKNOWN"
	attributionMethod := "CANARY_HONEYPOT_PERIODIC"

	// Periodic canary scan does not have direct actor context by itself.
	// Correlate with recent ETW activity when available.
	if actor, ok := m.ResolveActor(filePath, relatedPath); ok {
		processGuid = actor.ProcessGuid
		processID = actor.ProcessID
		image = actor.Image
		attributionMethod = "CANARY_HONEYPOT_ETW_CORRELATED"
		log.Printf("[CANARY] ETW attribution resolved: %s (PID: %d, GUID: %s, Event: %s)",
			image, processID, processGuid, actor.EventType)
	}

	if !m.latches.ShouldEmit(filePath, compromiseType, relatedPath, processGuid, time.Now()) {
		return false
	}

	action := m.ResponseAction()
	alert := &domain.Alert{
		ID:          fmt.Sprintf("CANARY_%d", time.Now().Unix()),
		Timestamp:   time.Now(),
		Severity:    domain.ThreatCritical,
		Category:    "RANSOMWARE",
		ProcessGuid: processGuid,
		ProcessID:   processID,
		Image:       image,
		Description: fmt.Sprintf("CANARY FILE COMPROMISED: %s (%s)", filepath.Base(filePath), compromiseType),
		Score:       100,
		Indicators: []domain.Indicator{
			{
				Type:        domain.IndicatorType(fmt.Sprintf("CANARY_%s", compromiseType)),
				Severity:    domain.ThreatCritical,
				Points:      100,
				Description: fmt.Sprintf("Honeypot file compromised: %s", compromiseType),
				Timestamp:   time.Now(),
				Evidence: map[string]string{
					"canary_path":         filePath,
					"compromise_type":     compromiseType,
					"original_entropy":    fmt.Sprintf("%.3f", originalEntropy),
					"current_entropy":     fmt.Sprintf("%.3f", currentEntropy),
					"entropy_delta":       fmt.Sprintf("%.3f", currentEntropy-originalEntropy),
					"detection_method":    attributionMethod,
					"false_positive_rate": "< 0.01%",
					"related_path":        relatedPath,
				},
			},
		},
		Evidence: map[string]interface{}{
			"canary_path":      filePath,
			"compromise_type":  compromiseType,
			"detection_method": attributionMethod,
			"attributed_pid":   fmt.Sprintf("%d", processID),
			"attributed_image": image,
			"related_path":     relatedPath,
		},
		AutoRespond: action != "alert_only",
		Strategy:    domain.StrategyForCanaryAction(action),
	}
	m.AttachRelated(alert, filePath, processGuid)

	m.emitter.SendAlert(alert)
	return true
}

// HandleWriteOrRename handles a real-time write/rename observed on a canary file. Returns
// true when the event targeted a canary (so the caller can stop further processing).
func (m *Manager) HandleWriteOrRename(event *domain.MonitorEvent) bool {
	canary, isCanary := m.IsCanaryFile(event.TargetFile)
	if !isCanary {
		return false
	}

	action := m.ResponseAction()
	log.Printf("[CANARY] REAL-TIME DETECTION: Canary file WRITE/RENAME observed: %s (response_action=%s)", event.TargetFile, action)
	log.Printf("[CANARY] Process: %s (PID: %d, GUID: %s)", event.Image, event.ProcessID, event.ProcessGuid)

	// Indicator points reflect CONFIDENCE (a canary compromise is high-confidence ransomware),
	// not response intent — the intent is carried as the alert's ResponseStrategy (Phase 6
	// finding #3). alert_only stays 0 so it never reaches Critical/auto-respond; suspend and
	// terminate are both 100 (Critical -> AutoRespond) and are distinguished by the strategy the
	// detection-service alert builder sets from the canary action.
	var canaryPoints int
	switch action {
	case "alert_only":
		canaryPoints = 0 // alert only, no auto-response (AutoRespond stays false)
	default: // "suspend" or "terminate" — both warrant auto-response; strategy decides which
		canaryPoints = 100
	}

	// Correlate with ransom-note style .txt activity for very high confidence.
	txtFileCount, txtDirCount := m.txt.TxtActivity(event.ProcessGuid)

	if txtFileCount >= 3 {
		log.Printf("[CANARY] CORRELATION DETECTED: Canary write/rename + %d ransom-note files across %d directories",
			txtFileCount, txtDirCount)

		indicator := domain.Indicator{
			Type:        domain.IndicatorCanaryCompromised,
			Severity:    domain.ThreatCritical,
			Points:      canaryPoints,
			Description: fmt.Sprintf("CORRELATED: Canary file write/rename + %d ransom notes (high confidence ransomware)", txtFileCount),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"canary_path":      event.TargetFile,
				"detection_method": "REAL_TIME_CANARY_WRITE_RENAME_WITH_RANSOM_NOTES",
				"txt_file_count":   fmt.Sprintf("%d", txtFileCount),
				"txt_directories":  fmt.Sprintf("%d", txtDirCount),
				"correlation":      "CANARY_WRITE_RENAME_AND_RANSOM_NOTES",
				"confidence":       "VERY_HIGH",
				"response_action":  action,
			},
		}

		score := m.emitter.RaiseIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[CANARY] CORRELATED INDICATOR ADDED: Score: %d (action=%s)", score, action)

		m.emitter.Evaluate(event.ProcessGuid, event.Image, event.ProcessID)
		return true
	}

	// No strong correlation yet: verify content change on canary.
	canaryEntropy, err := domain.AnalyzeFileEntropy(event.TargetFile, canary.Extension)
	if err != nil {
		log.Printf("[CANARY] Canary write/rename observed but entropy check failed: %v", err)
		return true
	}

	entropyDelta := canaryEntropy.Entropy - canary.OriginalEntropy
	if entropyDelta >= 2.0 || canaryEntropy.IsLikelyEncrypted {
		log.Printf("[CANARY] Canary ENCRYPTED via write/rename: entropy %.3f -> %.3f (delta +%.3f)",
			canary.OriginalEntropy, canaryEntropy.Entropy, entropyDelta)

		indicator := domain.Indicator{
			Type:        domain.IndicatorCanaryCompromised,
			Severity:    domain.ThreatCritical,
			Points:      canaryPoints,
			Description: "Honeypot file modified/encrypted (canary compromise)",
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"canary_path":      event.TargetFile,
				"original_entropy": fmt.Sprintf("%.3f", canary.OriginalEntropy),
				"current_entropy":  fmt.Sprintf("%.3f", canaryEntropy.Entropy),
				"entropy_delta":    fmt.Sprintf("%.3f", entropyDelta),
				"detection_method": "REAL_TIME_CANARY_WRITE_RENAME",
				"response_action":  action,
			},
		}

		score := m.emitter.RaiseIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[CANARY] ENCRYPTED CANARY DETECTED: Score: %d (action=%s)", score, action)

		m.emitter.Evaluate(event.ProcessGuid, event.Image, event.ProcessID)
	}

	return true
}

// AttachRelated populates alert.RelatedProcesses for canary alerts via the injected
// RelatedActorProvider. Exported so the rule-based alert path (evaluateAndAlert) can
// attach related processes to canary-indicator alerts too.
func (m *Manager) AttachRelated(alert *domain.Alert, canaryPathOverride string, attributedGuidOverride string) {
	if alert == nil {
		return
	}

	hasCanaryIndicator := false
	for _, indicator := range alert.Indicators {
		if isCanaryIndicatorType(indicator.Type) {
			hasCanaryIndicator = true
			break
		}
	}

	if !hasCanaryIndicator && strings.TrimSpace(canaryPathOverride) == "" {
		return
	}

	canaryPath := extractCanaryPathFromAlert(alert)
	if strings.TrimSpace(canaryPath) == "" {
		canaryPath = canaryPathOverride
	}
	if strings.TrimSpace(canaryPath) == "" {
		return
	}

	attributedGuid := strings.TrimSpace(alert.ProcessGuid)
	if strings.EqualFold(attributedGuid, "UNKNOWN") {
		attributedGuid = ""
	}
	overrideGuid := strings.TrimSpace(attributedGuidOverride)
	if strings.EqualFold(overrideGuid, "UNKNOWN") {
		overrideGuid = ""
	}
	if attributedGuid == "" {
		attributedGuid = overrideGuid
	}

	alert.RelatedProcesses = m.related.RelatedActors(canaryPath, attributedGuid, time.Now())
}

func isCanaryIndicatorType(indicatorType domain.IndicatorType) bool {
	if indicatorType == domain.IndicatorCanaryCompromised {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(string(indicatorType)), "CANARY_")
}

func extractCanaryPathFromAlert(alert *domain.Alert) string {
	if alert == nil {
		return ""
	}

	if path, ok := alert.Evidence["canary_path"]; ok {
		if asText, ok := path.(string); ok {
			return asText
		}
	}

	for _, indicator := range alert.Indicators {
		if !isCanaryIndicatorType(indicator.Type) {
			continue
		}
		if path, ok := indicator.Evidence["canary_path"]; ok {
			return path
		}
		if path, ok := indicator.Evidence["file"]; ok {
			return path
		}
	}

	return ""
}
