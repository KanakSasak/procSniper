package usecase

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"procSniper/internal/domain"
	"procSniper/internal/usecase/canary"
	"procSniper/internal/usecase/dirscan"
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
	RenameRansomExtHits        []time.Time
	LastUpdated                time.Time

	// ML feature tracking (additional counters for ExtractFeatureVector)
	DeleteCount          int                 // total file deletes by this process
	DirectorySet         map[string]struct{} // all unique directories touched
	ExtensionCounts      map[string]int      // extension frequency distribution (for Shannon entropy)
	ShadowCopyDeleteHit  bool                // process attempted shadow-copy deletion / recovery disable
	BrowserCredentialHit bool                // process accessed browser credential stores
	LSASSAccessHit       bool                // process accessed LSASS memory
	BrowserHistoryHit    bool                // non-browser process accessed browser history paths
	SSHKeyHit            bool                // process accessed .ssh/ key paths
	SystemInfoHit        bool                // command line contained systeminfo/whoami/hostname/ipconfig
}

// VelocityTargetObservation tracks recent file paths touched by a high-velocity actor.
type VelocityTargetObservation struct {
	Path              string
	SeenAt            time.Time
	RenameToRansomExt bool
}

// VelocityActorState stores rolling create/modify behavior for canary-time containment.
type VelocityActorState struct {
	ProcessGuid    string
	ProcessID      int
	Image          string
	LastSeen       time.Time
	LastCreateSeen time.Time
	LastModifySeen time.Time
	CreateOps60s   int
	ModifyOps60s   int
	TotalOps60s    int
	Tier           string
	RecentTargets  []VelocityTargetObservation

	createHitTimes []time.Time
	modifyHitTimes []time.Time
	deleteHitTimes []time.Time

	CumulativeFileCount   int // total file ops since process start (for ML feature[1])
	CumulativeCreateCount int // total create ops since process start
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

// CanaryActor stores ETW-attributed actor context for recent canary touches.
// DetectionService orchestrates threat detection and response
type DetectionService struct {
	velocityTracker *domain.FileOperationTracker
	threatScorer    *domain.ThreatScorer
	alertChan       chan *domain.Alert

	// Multi-tier velocity tracking — which processes reached MONITOR/ANALYZE/CRITICAL.
	tiers             *tierStore
	velocityActors    map[string]*VelocityActorState
	velocityActorsMux sync.RWMutex

	// File counters for threshold-based detection (owns the map + its lock; Phase 6)
	counters *counterStore

	// Entropy tracking for detecting encryption
	entropyTracker *domain.EntropyTracker // Tracks entropy changes over time

	// Modified high-entropy files tracking (for modify-delete pattern detection)
	modifiedHighEntropyFiles    map[string]*ModifiedHighEntropyFile // FilePath -> details
	modifiedHighEntropyFilesMux sync.RWMutex                        // Protects modifiedHighEntropyFiles map

	// Directory scanning for ransomware bulk-encryption / ransom-note correlation.
	// Owns its own per-directory dedup state; emits via the AlertEmitter seam (Phase 6).
	dirScanner *dirscan.Scanner

	// Canary (honeypot) subsystem — owns the file registry, ETW actor attribution, the
	// alert-dedup latches, and the response action. Reaches back into detection only via
	// the AlertEmitter/RelatedActorProvider/TxtActivityProvider seams that DetectionService
	// implements (Phase 6 slices 2–4).
	canaryMgr *canary.Manager

	// Detection thresholds from config
	entropyFileThreshold   int
	extensionFileThreshold int
	combinedThreshold      int // Files with BOTH entropy AND extension before immediate termination
	renameExtThreshold     int

	// Feature flags
	enableRansomNoteDetection bool // Enable/disable ransom note detection (default: false, focus on behavioral)

	// Detection data from config
	ransomwareExtensions []string // List of ransomware extensions to detect

	// Trusted process allowlist (case-insensitive)
	trustedProcessNames map[string]struct{} // Basename matches (e.g., "searchprotocolhost.exe")
	trustedProcessPaths map[string]struct{} // Full path matches (e.g., "c:\\windows\\system32\\searchprotocolhost.exe")

	// ML inference subsystem (predictor, gate, cooldown, decision policy). Detection-mode
	// orchestration stays on the service; the ML mechanics live in mlEngine (Phase 6).
	ml            *mlEngine
	detectionMode string // "rules_only", "hybrid", "ml_only"

	// Alert-drop accounting (atomic). Dropped alerts were previously log-only and invisible.
	alertsDropped         uint64 // total alerts dropped because alertChan was full
	alertsDroppedCritical uint64
	alertsDroppedHigh     uint64
	alertsDroppedOther    uint64
}

// DetectionConfig carries the tunables for NewDetectionService. Using a named struct
// instead of positional args prevents silently transposing the four same-typed int
// thresholds (a compile-clean, detection-mis-tuning hazard).
type DetectionConfig struct {
	EntropyFileThreshold      int      // high-entropy file count before adding entropy indicator
	ExtensionFileThreshold    int      // ransomware-extension file count before adding extension indicator
	CombinedThreshold         int      // files with BOTH high entropy AND ransomware extension (immediate)
	RenameExtThreshold        int      // rename-to-ransomware-extension threshold (defaults to 3 if <= 0)
	EnableRansomNoteDetection bool     // enable ransom-note filename detection (default false: behavioral focus)
	RansomwareExtensions      []string // ransomware file extensions to score
	TrustedProcesses          []string // process names/paths exempt from detection

	// I/O velocity tier thresholds in files/minute. <=0 keeps the domain default
	// (10/30/100). Critical is sourced from io_velocity_threshold_per_minute.
	IOVelocityMonitorThreshold  float64
	IOVelocityAnalyzeThreshold  float64
	IOVelocityCriticalThreshold float64
}

// NewDetectionService creates a new detection service from a DetectionConfig.
func NewDetectionService(cfg DetectionConfig) *DetectionService {
	renameExtThreshold := cfg.RenameExtThreshold
	if renameExtThreshold <= 0 {
		renameExtThreshold = 3
	}

	ds := &DetectionService{
		velocityTracker:           domain.NewFileOperationTracker(60 * time.Second),
		threatScorer:              domain.NewThreatScorer(),
		alertChan:                 make(chan *domain.Alert, 100),
		velocityActors:            make(map[string]*VelocityActorState),
		counters:                  newCounterStore(),
		entropyTracker:            domain.NewEntropyTracker(10 * time.Minute), // Track entropy for 10 minutes
		modifiedHighEntropyFiles:  make(map[string]*ModifiedHighEntropyFile),  // Track modified high-entropy files
		entropyFileThreshold:      cfg.EntropyFileThreshold,
		extensionFileThreshold:    cfg.ExtensionFileThreshold,
		combinedThreshold:         cfg.CombinedThreshold,
		renameExtThreshold:        renameExtThreshold,
		enableRansomNoteDetection: cfg.EnableRansomNoteDetection,
		ransomwareExtensions:      cfg.RansomwareExtensions,
		trustedProcessNames:       make(map[string]struct{}),
		trustedProcessPaths:       make(map[string]struct{}),
	}

	ds.setTrustedProcesses(cfg.TrustedProcesses)
	ds.velocityTracker.SetThresholds(cfg.IOVelocityMonitorThreshold, cfg.IOVelocityAnalyzeThreshold, cfg.IOVelocityCriticalThreshold)
	// DetectionService implements the canary seams (AlertEmitter / RelatedActorProvider /
	// TxtActivityProvider), so it wires itself into the manager.
	ds.canaryMgr = canary.NewManager(ds, ds, ds)
	ds.dirScanner = dirscan.NewScanner(ds, ds.ransomwareExtensions)
	ds.ml = newMLEngine()
	ds.tiers = newTierStore()

	return ds
}

// --- canary seams (implemented by DetectionService, consumed by canary.Manager) ---

// RaiseIndicator implements canary.AlertEmitter.
func (ds *DetectionService) RaiseIndicator(processGuid, image string, pid int, indicator domain.Indicator) int {
	return ds.addRuleIndicator(processGuid, image, pid, indicator)
}

// Evaluate implements canary.AlertEmitter.
func (ds *DetectionService) Evaluate(processGuid, image string, pid int) {
	ds.evaluateAndAlert(processGuid, image, pid)
}

// SendAlert implements canary.AlertEmitter: non-blocking send with drop accounting.
func (ds *DetectionService) SendAlert(alert *domain.Alert) {
	select {
	case ds.alertChan <- alert:
		log.Printf("[ALERT] Canary compromise alert sent: %s (related suspects: %d)",
			alert.Description, len(alert.RelatedProcesses))
	default:
		ds.recordDroppedAlert(alert.Severity)
		log.Printf("[ALERT] Alert channel full, canary alert dropped (severity=%s, total dropped=%d)",
			alert.Severity, atomic.LoadUint64(&ds.alertsDropped))
	}
}

// RelatedActors implements canary.RelatedActorProvider.
func (ds *DetectionService) RelatedActors(canaryPath, attributedGuid string, now time.Time) []domain.RelatedProcess {
	return ds.collectRelatedVelocityActors(canaryPath, attributedGuid, now)
}

// TxtActivity implements canary.TxtActivityProvider.
func (ds *DetectionService) TxtActivity(processGuid string) (int, int) {
	var txtCount, dirCount int
	ds.counters.Read(processGuid, func(counters *ProcessFileCounters, ok bool) {
		if ok {
			txtCount = counters.TxtFileCount
			dirCount = len(counters.TxtFileDirectories)
		}
	})
	return txtCount, dirCount
}

func (ds *DetectionService) setTrustedProcesses(processes []string) {
	for _, proc := range processes {
		proc = strings.TrimSpace(proc)
		if proc == "" {
			continue
		}

		lower := strings.ToLower(proc)
		if strings.ContainsAny(lower, "\\/") {
			ds.trustedProcessPaths[lower] = struct{}{}
		} else {
			ds.trustedProcessNames[lower] = struct{}{}
		}
	}
}

func (ds *DetectionService) isTrustedProcess(imageOrName string) bool {
	if len(ds.trustedProcessNames) == 0 && len(ds.trustedProcessPaths) == 0 {
		return false
	}

	imageOrName = strings.TrimSpace(imageOrName)
	if imageOrName == "" {
		return false
	}

	lower := strings.ToLower(imageOrName)
	if _, ok := ds.trustedProcessPaths[lower]; ok {
		return true
	}

	base := strings.ToLower(filepath.Base(imageOrName))
	if _, ok := ds.trustedProcessNames[base]; ok {
		return true
	}

	return false
}

// ProcessFileCreate handles file creation events with staged detection
// Stage 1: Check I/O velocity as trigger
// Stage 2: Only analyze files from high I/O processes (entropy + extensions)
func (ds *DetectionService) ProcessFileCreate(ctx context.Context, event *domain.MonitorEvent) {
	if ds.isTrustedProcess(event.Image) {
		return
	}

	// DEBUG: Print ALL file creations to verify ransomware activity
	ext := filepath.Ext(event.TargetFile)
	processImage := event.Image
	if strings.TrimSpace(processImage) == "" {
		processImage = "UNKNOWN"
	}
	log.Printf("[FILE_CREATED] %s (ext: %s) by %s (PID: %d, GUID: %s)",
		event.TargetFile, ext, processImage, event.ProcessID, event.ProcessGuid)

	// Track canary touches from ETW create/open telemetry for periodic scan attribution.
	if _, _, canaryMatch := ds.canaryMgr.Match(event.TargetFile); canaryMatch {
		ds.canaryMgr.RecordActor(event, "FILE_CREATE")
	}

	// Canary files are frequently opened/read by legitimate indexers/AV engines.
	// Ignore create/open-style canary events and only react on write/rename/delete paths.
	if _, isCanary := ds.canaryMgr.IsCanaryFile(event.TargetFile); isCanary {
		log.Printf("[CANARY] Ignoring create/open access on canary (waiting for write/rename/delete): %s", event.TargetFile)
		return
	}

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

		score := ds.addRuleIndicator(
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

	// ML feature tracking: detect browser credential / history / SSH key access.
	// Run before velocity tiering so low-velocity creates are still checked — stealer
	// access is independent of I/O velocity, and this matches ProcessFileModified (which
	// previously detected it while ProcessFileCreate skipped it via the TierNone return).
	ds.checkBrowserAndSSHAccess(event)

	// STAGE 1: Multi-Tier Velocity Detection
	// Implements graduated response based on I/O velocity
	tier, velocity, tierName := ds.velocityTracker.DetectAnomalousActivity(event.ProcessGuid)
	ds.trackVelocityActor(event, "create", tier, false)

	// Handle each tier with appropriate response
	switch tier {
	case domain.VelocityTierCritical:
		// TIER 3: CRITICAL (>=100 files/min)
		// Immediate deep analysis + indicator + alert evaluation
		if ds.tiers.MarkHighIO(event.ProcessGuid) {

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 TIER 3 CRITICAL: %.2f files/min - %s (Score: %d)", velocity, event.Image, score)
		}

	case domain.VelocityTierAnalyze:
		// TIER 2: ANALYZE (30-99 files/min)
		// Deep analysis enabled, but lower severity indicator
		if ds.tiers.MarkAnalyzed(event.ProcessGuid) {

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] ⚠️  TIER 2 ANALYZE: %.2f files/min - %s (Score: %d)", velocity, event.Image, score)
		}

	case domain.VelocityTierMonitor:
		// TIER 1: MONITOR (10-29 files/min)
		// Lightweight tracking, no entropy analysis yet
		if ds.tiers.MarkMonitored(event.ProcessGuid) {

			log.Printf("[MONITORING] 👁️  TIER 1 MONITOR: %.2f files/min - %s (watching for escalation)", velocity, event.Image)
			// No indicator added yet - just tracking
		}

	case domain.VelocityTierNone:
		// TIER 0: NONE (<10 files/min)
		// Normal activity, no action needed
		return
	}

	// ML feature tracking: accumulate directory + extension stats for every file create
	ds.counters.Mutate(event.ProcessGuid, func(c *ProcessFileCounters) {
		c.DirectorySet[filepath.Dir(event.TargetFile)] = struct{}{}
		if ext != "" {
			c.ExtensionCounts[strings.ToLower(ext)]++
		}
	})

	// STAGE 2: Determine analysis level based on tier
	// CRITICAL and ANALYZE tiers get deep file analysis
	// MONITOR tier gets lightweight tracking only
	shouldDeepAnalyze := (tier == domain.VelocityTierCritical || tier == domain.VelocityTierAnalyze)

	// IMPORTANT: Track .txt files BEFORE entropy analysis (which has early returns)
	// This ensures ransom note detection happens even if ransomware creates encrypted files first
	// Note: ext variable already declared at function start (line 168)

	// Track .txt file creation for ransom note detection.
	// Pattern: Ransomware creates .txt files across multiple directories alongside encrypted files.
	// In ML mode, track at ALL tiers so the txt_file_count feature is populated early.
	// In rule-based mode, only track at Tier 2/3 to avoid noise.
	txtTrackingEnabled := ds.isMLModeEnabled() || tier == domain.VelocityTierAnalyze || tier == domain.VelocityTierCritical
	if ext == ".txt" && txtTrackingEnabled {
		dirPath := filepath.Dir(event.TargetFile)

		var txtCount, dirCount int
		var txtDirs []string
		ds.counters.Mutate(event.ProcessGuid, func(counters *ProcessFileCounters) {
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

			txtCount = counters.TxtFileCount
			dirCount = len(counters.TxtFileDirectories)
			txtDirs = append([]string(nil), counters.TxtFileDirectories...)
			counters.LastUpdated = time.Now()
		})

		log.Printf("[TIER 2] .txt file created: %s (%d total .txt files across %d directories)",
			filepath.Base(event.TargetFile), txtCount, dirCount)

		// TRIGGER: If >= 5 .txt files created across multiple directories
		// This is a STRONG INDICATOR to inspect directories for encrypted files
		if txtCount >= 5 && dirCount >= 3 {
			log.Printf("[TIER 2] 🔍 RANSOM NOTE PATTERN DETECTED: %d .txt files across %d directories",
				txtCount, dirCount)
			log.Printf("[TIER 2] Triggering directory scan to find encrypted files alongside ransom notes...")

			// Trigger directory scan to find ENCRYPTED FILES (snapshot the dirs taken under
			// the counters lock so the goroutine never races future appends).
			go ds.dirScanner.ScanDirectoriesForEncryptedFiles(event.ProcessGuid, event.Image, event.ProcessID, txtDirs, event.Timestamp)
		}
	}

	if !shouldDeepAnalyze {
		// For MONITOR tier or below: skip expensive entropy analysis
		return
	}

	log.Printf("[DEEP ANALYSIS] Analyzing file from high I/O process: %s", event.TargetFile)

	// The counters entry was already created by the ML tracking block above; the deep-analysis
	// increments below go through ds.counters.Mutate, which get-or-inits under the store lock
	// regardless (no escaped pointer reused across separate lock acquisitions).

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

	// NOTE: .txt tracking is now done BEFORE entropy analysis to avoid early returns

	// Evaluate overall threat for flagged processes
	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// updateVelocityTierForOperation tracks file activity and updates multi-tier velocity state.
// This is used by non-create paths (modify/delete) so rename-heavy ransomware still escalates.
func (ds *DetectionService) updateVelocityTierForOperation(event *domain.MonitorEvent, operation string) domain.VelocityTier {
	op := domain.FileOperation{
		Timestamp:   event.Timestamp,
		ProcessGuid: event.ProcessGuid,
		ProcessID:   event.ProcessID,
		Operation:   operation,
		FilePath:    event.TargetFile,
		Image:       event.Image,
	}
	ds.velocityTracker.AddOperation(op)

	tier, velocity, tierName := ds.velocityTracker.DetectAnomalousActivity(event.ProcessGuid)

	switch tier {
	case domain.VelocityTierCritical:
		if ds.tiers.MarkHighIO(event.ProcessGuid) {

			indicator := domain.Indicator{
				Type:        domain.IndicatorIOVelocity,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[domain.IndicatorIOVelocity],
				Description: fmt.Sprintf("CRITICAL I/O velocity: %.2f files/min (fast ransomware)", velocity),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"velocity":  fmt.Sprintf("%.2f", velocity),
					"tier":      tierName,
					"operation": operation,
				},
			}

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] TIER 3 CRITICAL: %.2f files/min - %s (op=%s, Score: %d)", velocity, event.Image, operation, score)
		}

	case domain.VelocityTierAnalyze:
		if ds.tiers.MarkAnalyzed(event.ProcessGuid) {

			indicator := domain.Indicator{
				Type:        domain.IndicatorIOVelocity,
				Severity:    domain.ThreatHigh,
				Points:      domain.IndicatorScores[domain.IndicatorIOVelocity] - 5,
				Description: fmt.Sprintf("High I/O velocity: %.2f files/min (moderate ransomware)", velocity),
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"velocity":  fmt.Sprintf("%.2f", velocity),
					"tier":      tierName,
					"operation": operation,
				},
			}

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] TIER 2 ANALYZE: %.2f files/min - %s (op=%s, Score: %d)", velocity, event.Image, operation, score)
		}

	case domain.VelocityTierMonitor:
		if ds.tiers.MarkMonitored(event.ProcessGuid) {
			log.Printf("[MONITORING] TIER 1 MONITOR: %.2f files/min - %s (op=%s)", velocity, event.Image, operation)
		}
	}

	renameToRansomExt := operation == "modify" &&
		isRenameMonitorEvent(event) &&
		domain.IsRansomwareExtension(event.TargetFile, ds.ransomwareExtensions)
	ds.trackVelocityActor(event, operation, tier, renameToRansomExt)

	return tier
}

// ProcessFileModified handles file modification events (Event ID 2)
// This is CRITICAL for detecting in-place encryption where ransomware modifies existing files
// without creating new files or changing extensions
func (ds *DetectionService) ProcessFileModified(ctx context.Context, event *domain.MonitorEvent) {
	if ds.isTrustedProcess(event.Image) {
		return
	}

	ext := filepath.Ext(event.TargetFile)
	processImage := event.Image
	if strings.TrimSpace(processImage) == "" {
		processImage = "UNKNOWN"
	}
	log.Printf("[FILE_MODIFIED] %s (ext: %s) by %s (PID: %d, GUID: %s)",
		event.TargetFile, ext, processImage, event.ProcessID, event.ProcessGuid)

	// Keep recent ETW actor context for periodic canary compromise attribution.
	ds.canaryMgr.RecordActor(event, "FILE_MODIFIED")

	// Track modify operations so rename/encrypt bursts participate in velocity tiers.
	tier := ds.updateVelocityTierForOperation(event, "modify")

	// ML feature tracking: directory + extension from modify events
	isRename := isRenameMonitorEvent(event)
	ds.counters.Mutate(event.ProcessGuid, func(modMLCounters *ProcessFileCounters) {
		modMLCounters.DirectorySet[filepath.Dir(event.TargetFile)] = struct{}{}
		if ext != "" {
			modMLCounters.ExtensionCounts[strings.ToLower(ext)]++
			// For rename events, also track the original (inner) extension so Shannon
			// entropy is non-zero. E.g., "document.pdf.CONTI" → track both ".conti" and ".pdf".
			if isRename {
				base := strings.TrimSuffix(event.TargetFile, ext)
				if innerExt := filepath.Ext(base); innerExt != "" {
					modMLCounters.ExtensionCounts[strings.ToLower(innerExt)]++
				}
			}
		}
		// Track .txt files from rename events (ransomware may rename tmp → README.txt)
		if isRename && strings.EqualFold(ext, ".txt") {
			modMLCounters.TxtFileCount++
			dirPath := filepath.Dir(event.TargetFile)
			dirExists := false
			for _, d := range modMLCounters.TxtFileDirectories {
				if d == dirPath {
					dirExists = true
					break
				}
			}
			if !dirExists {
				modMLCounters.TxtFileDirectories = append(modMLCounters.TxtFileDirectories, dirPath)
			}
		}
	})

	// ML feature tracking: detect browser credential / history / SSH key access
	ds.checkBrowserAndSSHAccess(event)

	// Real-time canary response is limited to destructive I/O paths (write/rename).
	// Read/open-style accesses are intentionally ignored in ProcessFileCreate.
	if ds.canaryMgr.HandleWriteOrRename(event) {
		return
	}

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

// handleCanaryWriteOrRename handles real-time canary detection for write/overwrite/rename operations.
// Returns true when the event targets a canary and should not continue through normal file-modified flow.
// ProcessProcessCreate handles process creation events
func (ds *DetectionService) ProcessProcessCreate(ctx context.Context, event *domain.MonitorEvent) {
	commandAnalyzer{sink: ds}.analyze(event)
}

// ProcessLSASSAccess handles LSASS memory access events
func (ds *DetectionService) ProcessLSASSAccess(ctx context.Context, event *domain.MonitorEvent) {
	lsassAnalyzer{sink: ds}.analyze(event)
}

// checkBrowserAndSSHAccess detects non-browser processes touching browser credential,
// history, or SSH key paths and sets the corresponding ML feature flags.
// Called from ProcessFileModified and ProcessFileCreate to wire up features 9-11.
func (ds *DetectionService) checkBrowserAndSSHAccess(event *domain.MonitorEvent) {
	credentialAccessAnalyzer{sink: ds}.analyze(event)
}

// evaluateAndAlert evaluates threat level and creates alerts.
// Two-stage pipeline: rule-based indicators accumulate first, then ML inference fires
// once enough non-zero features have been gathered (mlMinIndicators threshold).
//
// Detection modes:
//   - rules_only: Pure rule-based scoring. ML completely disabled.
//   - hybrid: Both rules AND ML. Rule indicators generate alerts. ML provides additional classification.
//   - ml_only: ML is sole decision-maker. Rule indicators feed ML features but don't generate alerts.
func (ds *DetectionService) evaluateAndAlert(processGuid string, image string, pid int) {
	mode := ds.GetDetectionMode()

	// Stage 1: Rule-based evaluation (always runs to accumulate indicators)
	level, score := ds.threatScorer.EvaluateThreat(processGuid)

	if level == domain.ThreatNone {
		return
	}

	// In rules_only mode, skip ThreatLow (not suspicious enough)
	if level == domain.ThreatLow && mode == "rules_only" {
		return
	}

	// In ml_only or hybrid mode, ThreatLow processes still reach the ML gate for accumulation

	// Stage 2: ML inference (runs in hybrid and ml_only modes when ML is loaded)
	mlDecisionMade := false
	if ds.isMLModeEnabled() && (mode == "ml_only" || mode == "hybrid") {
		features := ds.ExtractFeatureVector(processGuid)
		nonZeroCount := 0
		for _, f := range features {
			if f != 0 {
				nonZeroCount++
			}
		}
		if nonZeroCount < ds.ml.MinIndicators() {
			log.Printf("[ML][GATE] process=%s pid=%d features=%d/%d — accumulating (mode=%s)",
				image, pid, nonZeroCount, ds.ml.MinIndicators(), mode)
			ds.logFeatureVector(image, pid, features)
			if mode == "ml_only" {
				return // ml_only: nothing else to do until ML gate passes
			}
			// hybrid: fall through to rule-based alert path below
		} else {
			log.Printf("[ML][GATE] process=%s pid=%d features=%d/%d — PASSED, firing inference (mode=%s)",
				image, pid, nonZeroCount, ds.ml.MinIndicators(), mode)
			ds.logFeatureVector(image, pid, features)

			// Cooldown: don't re-infer too quickly on the same process
			if ds.ml.InCooldown(processGuid) {
				if mode == "ml_only" {
					return
				}
				// hybrid: fall through to rule-based path
			} else {
				// Enough features accumulated — run ML inference
				activity := ds.ml.Decide(processGuid, image, pid, features)
				if activity != nil && activity.Stage == "decision" && activity.Prediction != nil {
					ds.ml.RecordInference(processGuid)
					ds.emitMLDecisionAlert(activity.Prediction)
					mlDecisionMade = true
				}

				if !mlDecisionMade && mode == "ml_only" {
					// ml_only: no fallback to rules
					log.Printf("[ML][NO_FALLBACK] ML inference did not produce decision (level=%s score=%d) — rule-based fallback disabled",
						level, score)
					return
				}
				// hybrid: fall through to also emit rule-based alert if warranted
			}
		}
	}

	// Stage 3: Rule-based alert path (runs in rules_only mode, or hybrid when ML didn't decide)
	if mode == "ml_only" {
		return // ml_only never emits rule-based alerts
	}

	// rules_only or hybrid: emit rule-based alert for ThreatMedium+
	if level == domain.ThreatLow {
		return // ThreatLow not actionable for rule-based alerts
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

	ds.canaryMgr.AttachRelated(alert, "", processGuid)

	// Determine if auto-response is warranted
	alert.AutoRespond = ds.threatScorer.ShouldAutoRespond(processGuid)

	// Send alert
	select {
	case ds.alertChan <- alert:
		log.Printf("[ALERT] %s - %s (PID: %d, Score: %d, Auto-Respond: %v, Mode: %s)",
			alert.Severity, alert.Description, pid, score, alert.AutoRespond, mode)
	default:
		ds.recordDroppedAlert(alert.Severity)
		log.Printf("[WARNING] Alert channel full, dropping alert (severity=%s, total dropped=%d)",
			alert.Severity, atomic.LoadUint64(&ds.alertsDropped))
	}
}

func (ds *DetectionService) emitMLDecisionAlert(prediction *domain.MLPrediction) {
	if prediction == nil {
		return
	}

	pol, ok := mlDecisionPolicy[prediction.Label]
	if !ok { // benign / unknown label — no alert
		return
	}
	category := pol.Category
	severity := pol.Severity
	score := pol.Score
	indicatorType := pol.IndicatorType

	description := fmt.Sprintf("ML decision: %s (%.1f%% confidence)", prediction.LabelName, prediction.Confidence*100)
	maliciousProb := prediction.Probabilities[1] + prediction.Probabilities[2]
	alert := domain.NewAlert(
		category,
		severity,
		prediction.ProcessGuid,
		prediction.ProcessID,
		prediction.Image,
		description,
		score,
	)

	alert.AddIndicator(domain.Indicator{
		Type:        indicatorType,
		Severity:    severity,
		Points:      score,
		Description: description,
		Timestamp:   prediction.Timestamp,
		Evidence: map[string]string{
			"decision_mode":  "ml_only",
			"confidence":     fmt.Sprintf("%.4f", prediction.Confidence),
			"malicious_prob": fmt.Sprintf("%.4f", maliciousProb),
			"prob_benign":    fmt.Sprintf("%.4f", prediction.Probabilities[0]),
			"prob_ransom":    fmt.Sprintf("%.4f", prediction.Probabilities[1]),
			"prob_steal":     fmt.Sprintf("%.4f", prediction.Probabilities[2]),
		},
	})

	// Policy (single source: mlDecisionPolicy): ransomware => terminate-eligible,
	// stealer => alert-only.
	alert.AutoRespond = pol.AutoRespond
	log.Printf("[ML][DECISION] process=%s pid=%d label=%s confidence=%.4f malicious_prob=%.4f prob_ransom=%.4f prob_steal=%.4f score=%d auto_respond=%v",
		prediction.Image,
		prediction.ProcessID,
		prediction.LabelName,
		prediction.Confidence,
		maliciousProb,
		prediction.Probabilities[1],
		prediction.Probabilities[2],
		score,
		alert.AutoRespond,
	)

	select {
	case ds.alertChan <- alert:
		log.Printf("[ALERT][ML] %s - %s (PID: %d, Score: %d, Auto-Respond: %v)",
			alert.Severity, alert.Description, alert.ProcessID, alert.Score, alert.AutoRespond)
	default:
		ds.recordDroppedAlert(alert.Severity)
		log.Printf("[WARNING][ML] Alert channel full, dropping ML alert (severity=%s, total dropped=%d)",
			alert.Severity, atomic.LoadUint64(&ds.alertsDropped))
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

// ---------------------------------------------------------------------------
// ML Inference Integration
// ---------------------------------------------------------------------------

// SetMLPredictor sets the ML predictor for inference.
func (ds *DetectionService) SetMLPredictor(p domain.MLPredictor) {
	ds.ml.SetPredictor(p)
}

// SetMLEnabled enables or disables ML detection.
// Rule-based indicators continue accumulating and serve as the gate for ML inference.
func (ds *DetectionService) SetMLEnabled(enabled bool) {
	ds.ml.SetEnabled(enabled)
}

// SetMLConfidence sets the minimum malicious probability threshold for ML decisions.
func (ds *DetectionService) SetMLConfidence(threshold float64) {
	ds.ml.SetConfidence(threshold)
}

// SetMLMinIndicators sets the minimum number of non-zero features in the
// feature vector before ML inference is triggered for a process.
func (ds *DetectionService) SetMLMinIndicators(n int) {
	ds.ml.SetMinIndicators(n)
}

// SetMLPredictionCallback sets a callback invoked on every ML inference activity.
func (ds *DetectionService) SetMLPredictionCallback(cb func(*domain.MLInferenceActivity)) {
	ds.ml.SetPredictionCallback(cb)
}

func (ds *DetectionService) isMLModeEnabled() bool {
	return ds.ml.Enabled()
}

// SetDetectionMode sets the detection mode: "rules_only", "hybrid", or "ml_only".
func (ds *DetectionService) SetDetectionMode(mode string) {
	switch mode {
	case "rules_only", "hybrid", "ml_only":
		ds.detectionMode = mode
	default:
		ds.detectionMode = "rules_only"
	}
	log.Printf("[CONFIG] Detection mode set to: %s", ds.detectionMode)
}

// GetDetectionMode returns the current detection mode.
func (ds *DetectionService) GetDetectionMode() string {
	if ds.detectionMode == "" {
		return "rules_only"
	}
	return ds.detectionMode
}

// SetCanaryResponseAction sets the canary response action: "terminate", "suspend", or "alert_only".
func (ds *DetectionService) SetCanaryResponseAction(action string) {
	ds.canaryMgr.SetResponseAction(action)
}

// GetCanaryResponseAction returns the current canary response action.
func (ds *DetectionService) GetCanaryResponseAction() string {
	return ds.canaryMgr.ResponseAction()
}

// addRuleIndicator records a rule-based indicator. In ML mode, indicators serve as
// the accumulation mechanism — the ML gate fires inference after enough indicators gather.
func (ds *DetectionService) addRuleIndicator(processGuid, image string, pid int, indicator domain.Indicator) int {
	return ds.threatScorer.AddIndicator(processGuid, image, pid, indicator)
}

// logFeatureVector logs all 14 ML feature values for debugging/observability.
func (ds *DetectionService) logFeatureVector(image string, pid int, features [14]float64) {
	log.Printf("[ML][FEATURES] process=%s pid=%d Features: [velocity=%.2f, file_count=%.2f, "+
		"txt_file_count=%.2f, directory_count=%.2f, file_delete_count=%.2f, is_signed=%.2f, "+
		"extension_match=%.2f, extension_entropy=%.2f, shadow_copy_delete=%.2f, "+
		"browser_credential_access=%.2f, browser_history_access=%.2f, ssh_key_access=%.2f, "+
		"lsass_access=%.2f, system_info_queries=%.2f]",
		image, pid,
		features[0], features[1], features[2], features[3], features[4], features[5],
		features[6], features[7], features[8], features[9], features[10], features[11],
		features[12], features[13])
}

// ExtractFeatureVector builds the 14-feature vector for a process from accumulated state.
// Feature order matches MODEL_FEATURES in train_model.py exactly.
func (ds *DetectionService) ExtractFeatureVector(processGuid string) [14]float64 {
	var features [14]float64

	// Feature 0: velocity (files/min in last 60s). Read under velocityActorsMux only; the
	// cumulative count for feature 1 is copied out as a value so no pointer escapes the lock.
	var cumulativeFileCount int
	ds.velocityActorsMux.RLock()
	if actor, hasActor := ds.velocityActors[processGuid]; hasActor {
		features[0] = float64(actor.TotalOps60s)
		cumulativeFileCount = actor.CumulativeFileCount
	}
	ds.velocityActorsMux.RUnlock()

	// Feature 5: is_signed (default 0 for v1 — PE signature check not implemented yet)
	features[5] = 0

	// Features 1-4 and 6-13 from file counters — read entirely inside the store's read lock
	// so the counters pointer (and the ExtensionCounts map iterated below) never escapes it.
	ds.counters.Read(processGuid, func(counters *ProcessFileCounters, hasCounters bool) {
		if !hasCounters {
			return
		}
		// Feature 1: file_count (cumulative total file ops since process start)
		features[1] = float64(cumulativeFileCount)
		// Feature 2: txt_file_count
		features[2] = float64(counters.TxtFileCount)
		// Feature 3: directory_count
		features[3] = float64(len(counters.DirectorySet))
		// Feature 4: file_delete_count
		features[4] = float64(counters.DeleteCount)

		// Feature 6: extension_match (boolean: 1 if ransomware extensions observed, 0 otherwise)
		if counters.RansomExtensionCount > 0 {
			features[6] = 1.0
		}

		// Feature 7: extension_entropy (Shannon entropy of the extension frequency distribution)
		if counters.ExtensionCounts != nil {
			total := 0
			for _, c := range counters.ExtensionCounts {
				total += c
			}
			if total > 0 {
				entropy := 0.0
				for _, c := range counters.ExtensionCounts {
					p := float64(c) / float64(total)
					if p > 0 {
						entropy -= p * math.Log2(p)
					}
				}
				features[7] = entropy
			}
		}

		// Features 8-13: boolean indicators (1.0 if present, 0.0 otherwise)
		if counters.ShadowCopyDeleteHit {
			features[8] = 1 // shadow_copy_delete
		}
		if counters.BrowserCredentialHit {
			features[9] = 1 // browser_credential_access
		}
		if counters.BrowserHistoryHit {
			features[10] = 1 // browser_history_access
		}
		if counters.SSHKeyHit {
			features[11] = 1 // ssh_key_access
		}
		if counters.LSASSAccessHit {
			features[12] = 1 // lsass_access
		}
		if counters.SystemInfoHit {
			features[13] = 1 // system_info_queries
		}
	})

	return features
}

// setMLCounter locks the counters map and applies set to the process's ProcessFileCounters
// (initializing it if needed). It is the analyzerSink hook for analyzers that mutate ML
// feature flags.
func (ds *DetectionService) setMLCounter(processGuid string, set func(*ProcessFileCounters)) {
	ds.counters.Mutate(processGuid, set)
}

// SetupCanaryFiles creates honeypot files in common ransomware target directories
// Canary files are decoy files with known low entropy that trigger alerts if encrypted/deleted
// This catches slow-moving ransomware that doesn't trigger velocity thresholds
func (ds *DetectionService) SetupCanaryFiles() error {
	return ds.canaryMgr.Setup()
}

// normalizeCanaryPath delegates to the canary package; kept as a thin wrapper so the
// many in-package callers (matchCanaryPath, recordCanaryActor, ...) stay untouched.
func normalizeCanaryPath(path string) string {
	return canary.NormalizePath(path)
}

func isRenameMonitorEvent(event *domain.MonitorEvent) bool {
	if event == nil || event.RawData == nil {
		return false
	}

	if value, ok := event.RawData["set_info_type"]; ok {
		if text, ok := value.(string); ok && strings.EqualFold(text, "rename") {
			return true
		}
	}
	if value, ok := event.RawData["event_source"]; ok {
		if text, ok := value.(string); ok && strings.EqualFold(text, "rename_path") {
			return true
		}
	}
	return false
}

func trimRenameHits(hits []time.Time, now time.Time, window time.Duration) []time.Time {
	if len(hits) == 0 {
		return hits
	}
	cutoff := now.Add(-window)
	filtered := make([]time.Time, 0, len(hits))
	for _, ts := range hits {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	return filtered
}

const (
	velocityActorWindow       = 60 * time.Second
	velocityActorRetention    = 120 * time.Second
	velocityActorTargetLimit  = 32
	relatedVelocityMinScore   = 50
	relatedVelocityFreshLimit = 10 * time.Second
)

func trimTimeHitsInWindow(hits []time.Time, now time.Time, window time.Duration) []time.Time {
	if len(hits) == 0 {
		return hits
	}
	cutoff := now.Add(-window)
	filtered := make([]time.Time, 0, len(hits))
	for _, ts := range hits {
		if ts.After(cutoff) || ts.Equal(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	return filtered
}

func trimRecentTargets(targets []VelocityTargetObservation, now time.Time, window time.Duration, limit int) []VelocityTargetObservation {
	if len(targets) == 0 {
		return targets
	}

	cutoff := now.Add(-window)
	filtered := make([]VelocityTargetObservation, 0, len(targets))
	for _, target := range targets {
		if target.SeenAt.After(cutoff) || target.SeenAt.Equal(cutoff) {
			filtered = append(filtered, target)
		}
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered
}

func isPathInDirectorySubtree(path, directory string) bool {
	pathNorm := normalizeCanaryPath(path)
	dirNorm := normalizeCanaryPath(directory)
	if pathNorm == "" || dirNorm == "" {
		return false
	}
	if pathNorm == dirNorm {
		return true
	}
	sep := string(filepath.Separator)
	if strings.HasSuffix(dirNorm, sep) {
		return strings.HasPrefix(pathNorm, dirNorm)
	}
	return strings.HasPrefix(pathNorm, dirNorm+sep)
}

func isVelocityTierEligible(tier string) bool {
	return strings.EqualFold(tier, domain.VelocityTierAnalyze.String()) ||
		strings.EqualFold(tier, domain.VelocityTierCritical.String())
}

func (ds *DetectionService) pruneVelocityActorsLocked(now time.Time, maxAge time.Duration) int {
	if len(ds.velocityActors) == 0 {
		return 0
	}
	cutoff := now.Add(-maxAge)
	removed := 0
	for guid, actor := range ds.velocityActors {
		if actor == nil || actor.LastSeen.Before(cutoff) {
			delete(ds.velocityActors, guid)
			removed++
		}
	}
	return removed
}

func (ds *DetectionService) pruneVelocityActors(maxAge time.Duration) int {
	now := time.Now()
	ds.velocityActorsMux.Lock()
	defer ds.velocityActorsMux.Unlock()
	return ds.pruneVelocityActorsLocked(now, maxAge)
}

func (ds *DetectionService) trackVelocityActor(event *domain.MonitorEvent, operation string, tier domain.VelocityTier, renameToRansomExt bool) {
	if event == nil {
		return
	}
	if operation != "create" && operation != "modify" && operation != "delete" {
		return
	}
	if strings.TrimSpace(event.ProcessGuid) == "" {
		return
	}

	now := event.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	ds.velocityActorsMux.Lock()
	defer ds.velocityActorsMux.Unlock()

	ds.pruneVelocityActorsLocked(now, velocityActorRetention)

	actor, exists := ds.velocityActors[event.ProcessGuid]
	if !exists || actor == nil {
		actor = &VelocityActorState{
			ProcessGuid:    event.ProcessGuid,
			RecentTargets:  make([]VelocityTargetObservation, 0, velocityActorTargetLimit),
			createHitTimes: make([]time.Time, 0, 16),
			modifyHitTimes: make([]time.Time, 0, 16),
			deleteHitTimes: make([]time.Time, 0, 16),
		}
		ds.velocityActors[event.ProcessGuid] = actor
	}

	actor.ProcessGuid = event.ProcessGuid
	if event.ProcessID > 0 {
		actor.ProcessID = event.ProcessID
	}
	if strings.TrimSpace(event.Image) != "" {
		actor.Image = event.Image
	}
	actor.LastSeen = now
	actor.Tier = tier.String()

	// Cumulative counter — always incremented, never windowed (for ML file_count feature)
	actor.CumulativeFileCount++
	switch operation {
	case "create":
		actor.CumulativeCreateCount++
		actor.LastCreateSeen = now
		actor.createHitTimes = append(actor.createHitTimes, now)
		actor.createHitTimes = trimTimeHitsInWindow(actor.createHitTimes, now, velocityActorWindow)
	case "modify":
		actor.LastModifySeen = now
		actor.modifyHitTimes = append(actor.modifyHitTimes, now)
		actor.modifyHitTimes = trimTimeHitsInWindow(actor.modifyHitTimes, now, velocityActorWindow)
	case "delete":
		actor.deleteHitTimes = append(actor.deleteHitTimes, now)
		actor.deleteHitTimes = trimTimeHitsInWindow(actor.deleteHitTimes, now, velocityActorWindow)
	}

	actor.CreateOps60s = len(actor.createHitTimes)
	actor.ModifyOps60s = len(actor.modifyHitTimes)
	actor.TotalOps60s = actor.CreateOps60s + actor.ModifyOps60s + len(actor.deleteHitTimes)

	targetPath := normalizeCanaryPath(event.TargetFile)
	if targetPath != "" {
		actor.RecentTargets = append(actor.RecentTargets, VelocityTargetObservation{
			Path:              targetPath,
			SeenAt:            now,
			RenameToRansomExt: renameToRansomExt,
		})
		actor.RecentTargets = trimRecentTargets(actor.RecentTargets, now, velocityActorWindow, velocityActorTargetLimit)
	}
}

// resolveParentGuid looks up the ProcessGuid for a given PID by scanning velocityActors.
// Used to propagate ML feature flags from child processes to their parent (e.g., vssadmin → ransomware).
func (ds *DetectionService) resolveParentGuid(parentPID int) string {
	ds.velocityActorsMux.RLock()
	defer ds.velocityActorsMux.RUnlock()
	for guid, actor := range ds.velocityActors {
		if actor != nil && actor.ProcessID == parentPID {
			return guid
		}
	}
	return ""
}

// propagateMLFlagToParent resolves the parent PID from the event's RawData and
// propagates ML feature flags (shadow_copy_delete, system_info, lsass_access) to the parent process.
func (ds *DetectionService) propagateMLFlagToParent(event *domain.MonitorEvent, shadowCopy, systemInfo, lsassAccess bool) {
	if event == nil || event.RawData == nil {
		return
	}
	parentPIDRaw, ok := event.RawData["parent_process_id"]
	if !ok {
		return
	}
	var parentPID int
	switch v := parentPIDRaw.(type) {
	case uint32:
		parentPID = int(v)
	case int:
		parentPID = v
	case int64:
		parentPID = int(v)
	case float64:
		parentPID = int(v)
	default:
		return
	}
	if parentPID == 0 {
		// Layer 2 safety net: PPID unknown even after Toolhelp32 fallback,
		// broadcast to all active velocity actors (processes with recent file I/O).
		if shadowCopy || systemInfo || lsassAccess {
			ds.broadcastMLFlagToActiveActors(event, shadowCopy, systemInfo, lsassAccess)
		}
		return
	}
	parentGuid := ds.resolveParentGuid(parentPID)
	if parentGuid == "" {
		// Parent PID known but not tracked as a velocity actor — broadcast as fallback
		if shadowCopy || systemInfo || lsassAccess {
			ds.broadcastMLFlagToActiveActors(event, shadowCopy, systemInfo, lsassAccess)
		}
		return
	}
	ds.counters.Mutate(parentGuid, func(parentCounters *ProcessFileCounters) {
		if shadowCopy {
			parentCounters.ShadowCopyDeleteHit = true
		}
		if systemInfo {
			parentCounters.SystemInfoHit = true
		}
		if lsassAccess {
			parentCounters.LSASSAccessHit = true
		}
	})
	log.Printf("[ML][PARENT_PROPAGATE] child_pid=%d parent_guid=%s shadow=%v sysinfo=%v lsass=%v",
		event.ProcessID, parentGuid, shadowCopy, systemInfo, lsassAccess)
}

// broadcastMLFlagToActiveActors sets ML feature flags on all velocity actors
// that have been active within the velocity window. Used as a fallback when
// parent PID resolution fails (ETW PPID=0 and Toolhelp32 also failed).
func (ds *DetectionService) broadcastMLFlagToActiveActors(event *domain.MonitorEvent, shadowCopy, systemInfo, lsassAccess bool) {
	now := time.Now()
	cutoff := now.Add(-velocityActorWindow)

	ds.velocityActorsMux.RLock()
	var activeGuids []string
	for guid, actor := range ds.velocityActors {
		if actor != nil && actor.LastSeen.After(cutoff) && actor.TotalOps60s > 0 {
			activeGuids = append(activeGuids, guid)
		}
	}
	ds.velocityActorsMux.RUnlock()

	if len(activeGuids) == 0 {
		log.Printf("[ML][BROADCAST] No active velocity actors to propagate flags to (child_pid=%d shadow=%v sysinfo=%v lsass=%v)",
			event.ProcessID, shadowCopy, systemInfo, lsassAccess)
		return
	}

	ds.counters.MutateMany(activeGuids, func(counters *ProcessFileCounters) {
		if shadowCopy {
			counters.ShadowCopyDeleteHit = true
		}
		if systemInfo {
			counters.SystemInfoHit = true
		}
		if lsassAccess {
			counters.LSASSAccessHit = true
		}
	})

	log.Printf("[ML][BROADCAST] Propagated flags to %d active actors (child_pid=%d shadow=%v sysinfo=%v lsass=%v)",
		len(activeGuids), event.ProcessID, shadowCopy, systemInfo, lsassAccess)
}

func actorHasRecentDirectoryTouch(actor *VelocityActorState, canaryDirectory string, now time.Time) bool {
	if actor == nil || len(actor.RecentTargets) == 0 {
		return false
	}
	cutoff := now.Add(-velocityActorWindow)
	for _, target := range actor.RecentTargets {
		if target.SeenAt.Before(cutoff) {
			continue
		}
		if isPathInDirectorySubtree(target.Path, canaryDirectory) {
			return true
		}
	}
	return false
}

func actorHasRecentRenameRansomExtension(actor *VelocityActorState, now time.Time) bool {
	if actor == nil || len(actor.RecentTargets) == 0 {
		return false
	}
	cutoff := now.Add(-velocityActorWindow)
	for _, target := range actor.RecentTargets {
		if target.SeenAt.Before(cutoff) {
			continue
		}
		if target.RenameToRansomExt {
			return true
		}
	}
	return false
}

// collectRelatedVelocityActors returns high-confidence related processes for canary containment.
func (ds *DetectionService) collectRelatedVelocityActors(canaryPath string, attributedGuid string, now time.Time) []domain.RelatedProcess {
	if now.IsZero() {
		now = time.Now()
	}

	attributedGuid = strings.TrimSpace(attributedGuid)
	if strings.EqualFold(attributedGuid, "UNKNOWN") {
		attributedGuid = ""
	}

	canaryDirectory := filepath.Dir(canaryPath)
	results := make([]domain.RelatedProcess, 0)

	ds.velocityActorsMux.RLock()
	defer ds.velocityActorsMux.RUnlock()

	for _, actor := range ds.velocityActors {
		if actor == nil {
			continue
		}
		if actor.ProcessID <= 0 {
			continue
		}
		if ds.isTrustedProcess(actor.Image) {
			continue
		}
		if now.Sub(actor.LastSeen) > velocityActorWindow {
			continue
		}
		if !isVelocityTierEligible(actor.Tier) {
			continue
		}
		if actor.CreateOps60s <= 0 || actor.ModifyOps60s <= 0 {
			continue
		}

		score := 0
		reasons := make([]string, 0, 5)

		if attributedGuid != "" && strings.EqualFold(actor.ProcessGuid, attributedGuid) {
			score += 100
			reasons = append(reasons, "exact_guid_match")
		}

		if canaryDirectory != "" && actorHasRecentDirectoryTouch(actor, canaryDirectory, now) {
			score += 40
			reasons = append(reasons, "same_directory_subtree")
		}

		if actorHasRecentRenameRansomExtension(actor, now) {
			score += 20
			reasons = append(reasons, "rename_to_ransom_ext")
		}

		if strings.EqualFold(actor.Tier, domain.VelocityTierCritical.String()) {
			score += 20
			reasons = append(reasons, "tier_critical")
		} else if strings.EqualFold(actor.Tier, domain.VelocityTierAnalyze.String()) {
			score += 10
			reasons = append(reasons, "tier_analyze")
		}

		if now.Sub(actor.LastSeen) <= relatedVelocityFreshLimit {
			score += 10
			reasons = append(reasons, "recent_activity")
		}

		if score < relatedVelocityMinScore {
			continue
		}

		results = append(results, domain.RelatedProcess{
			ProcessGuid:   actor.ProcessGuid,
			ProcessID:     actor.ProcessID,
			Image:         actor.Image,
			RelationScore: score,
			CreateOps60s:  actor.CreateOps60s,
			ModifyOps60s:  actor.ModifyOps60s,
			Tier:          actor.Tier,
			LastSeen:      actor.LastSeen,
			Reason:        strings.Join(reasons, ","),
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].RelationScore != results[j].RelationScore {
			return results[i].RelationScore > results[j].RelationScore
		}
		return results[i].LastSeen.After(results[j].LastSeen)
	})

	return results
}

// CheckCanaryFiles periodically checks if canary files have been compromised
// This function should be called on a timer (e.g., every 30 seconds)
// Returns true if any canary was compromised (triggers immediate alert)
func (ds *DetectionService) CheckCanaryFiles() bool {
	return ds.canaryMgr.CheckFiles()
}

// StartCanaryMonitoring starts periodic canary file checking
// Checks every 30 seconds for compromised honeypot files
func (ds *DetectionService) StartCanaryMonitoring(ctx context.Context) {
	ds.canaryMgr.StartMonitoring(ctx.Done())
}

// CleanupCanaryFiles removes all canary files on shutdown
func (ds *DetectionService) CleanupCanaryFiles() {
	ds.canaryMgr.Cleanup()
}

// GetCanaryStats returns statistics about canary files
func (ds *DetectionService) GetCanaryStats() map[string]interface{} {
	return ds.canaryMgr.Stats()
}

// CleanupOldHighIOFlags removes high I/O flags for processes inactive for specified duration
// This prevents memory leaks and ensures stale flags don't affect detection
func (ds *DetectionService) CleanupOldHighIOFlags(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := ds.tiers.EvictHighIO(cutoff)

	removedVelocityActors := ds.pruneVelocityActors(velocityActorRetention)

	if removed > 0 || removedVelocityActors > 0 {
		log.Printf("[CLEANUP] Removed %d old high I/O flags, %d stale velocity actors", removed, removedVelocityActors)
	}

	return removed + removedVelocityActors
}

// GetHighIOProcessCount returns the number of processes currently flagged for deep monitoring
func (ds *DetectionService) GetHighIOProcessCount() int {
	return ds.tiers.HighIOCount()
}

// GetEntropyStats returns entropy tracker statistics
func (ds *DetectionService) GetEntropyStats() map[string]interface{} {
	if ds.entropyTracker == nil {
		return map[string]interface{}{
			"tracked_files":         0,
			"modified_files":        0,
			"significant_increases": 0,
		}
	}
	return ds.entropyTracker.GetStats()
}

// IsProcessFlagged checks if a process is currently flagged for deep monitoring
func (ds *DetectionService) IsProcessFlagged(processGuid string) bool {
	return ds.tiers.IsHighIO(processGuid)
}

// ProcessFileDelete handles file deletion events
// This is critical for detecting ransomware that renames files (e.g., file.txt -> file.txt.omega)
// Windows file renames appear as: delete original + create new (but create event may not fire for renames)
func (ds *DetectionService) ProcessFileDelete(ctx context.Context, event *domain.MonitorEvent) {
	if ds.isTrustedProcess(event.Image) {
		return
	}

	// DEBUG: Print ALL file deletions to verify ransomware activity
	ext := filepath.Ext(event.TargetFile)
	log.Printf("[FILE_DELETED] %s (ext: %s) by %s (PID: %d)",
		event.TargetFile, ext, filepath.Base(event.Image), event.ProcessID)

	// Keep recent ETW actor context for periodic canary compromise attribution.
	ds.canaryMgr.RecordActor(event, "FILE_DELETE")

	// Track delete operations so delete+rename ransomware patterns raise velocity tiers.
	tier := ds.updateVelocityTierForOperation(event, "delete")

	// ML feature tracking: increment delete counter, track directory + extension
	ds.counters.Mutate(event.ProcessGuid, func(delCounters *ProcessFileCounters) {
		delCounters.DeleteCount++
		delCounters.DirectorySet[filepath.Dir(event.TargetFile)] = struct{}{}
		if ext != "" {
			delCounters.ExtensionCounts[strings.ToLower(ext)]++
		}
	})

	// REAL-TIME CANARY DETECTION: Check if deleted file is a honeypot
	// This catches ransomware that deletes original canary files before/during encryption
	if canary, isCanary := ds.canaryMgr.IsCanaryFile(event.TargetFile); isCanary {
		log.Printf("[CANARY] 🚨 REAL-TIME DETECTION: Canary file DELETED: %s", event.TargetFile)
		log.Printf("[CANARY] Process: %s (PID: %d, GUID: %s)", event.Image, event.ProcessID, event.ProcessGuid)

		// Check for correlation with .txt file creation
		var txtFileCount int
		var txtDirCount int
		ds.counters.Read(event.ProcessGuid, func(counters *ProcessFileCounters, hasCounters bool) {
			if hasCounters {
				txtFileCount = counters.TxtFileCount
				txtDirCount = len(counters.TxtFileDirectories)
			}
		})

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
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

		score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[CANARY] ⚠️  THREAT SCORE: %d (Indicator: +50 points)", score)

		// Evaluate for potential termination
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		// Continue processing - might be combined with other indicators
	}

	// CRITICAL: Check for ransomware rename IMMEDIATELY on ALL deletions
	// This catches ransomware in early stages before I/O velocity threshold is reached
	// When Conti renames document.docx → document.docx.conti:
	//   - ETW fires Event ID 23 (FileDelete) for "document.docx"
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

			score := ds.addRuleIndicator(
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
	// Progressive directory scan (deduped per directory), now owned by dirscan.Scanner.
	// If a scan is already running for this directory, preserve the original behavior of
	// skipping the rest of delete handling.
	if !ds.dirScanner.ScanDeletedFileDir(event) {
		return
	}

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

			score := ds.addRuleIndicator(
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

			score := ds.addRuleIndicator(
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

				score = ds.addRuleIndicator(
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

	removedVelocityActors := ds.pruneVelocityActors(velocityActorRetention)

	if removed > 0 || removedVelocityActors > 0 {
		log.Printf("[CLEANUP] Removed %d old modified file entries, %d stale velocity actors", removed, removedVelocityActors)
	}

	return removed + removedVelocityActors
}

// recordDroppedAlert increments the total and per-severity alert-drop counters.
// Alert drops were previously log-only; this makes detection-integrity loss observable.
func (ds *DetectionService) recordDroppedAlert(sev domain.ThreatLevel) {
	atomic.AddUint64(&ds.alertsDropped, 1)
	switch sev {
	case domain.ThreatCritical:
		atomic.AddUint64(&ds.alertsDroppedCritical, 1)
	case domain.ThreatHigh:
		atomic.AddUint64(&ds.alertsDroppedHigh, 1)
	default:
		atomic.AddUint64(&ds.alertsDroppedOther, 1)
	}
}

// GetDropStats returns a snapshot of alert-drop counters for statistics reporting.
func (ds *DetectionService) GetDropStats() map[string]uint64 {
	return map[string]uint64{
		"alerts_dropped_total":    atomic.LoadUint64(&ds.alertsDropped),
		"alerts_dropped_critical": atomic.LoadUint64(&ds.alertsDroppedCritical),
		"alerts_dropped_high":     atomic.LoadUint64(&ds.alertsDroppedHigh),
		"alerts_dropped_other":    atomic.LoadUint64(&ds.alertsDroppedOther),
	}
}

// StartMaintenance runs periodic eviction of stale per-process detection state to bound
// memory on long-running agents. Mirrors KernelETWConsumer.cleanupCaches; ctx-cancellable.
// Without this, fileCounters / monitoredProcesses / analyzedProcesses / mlLastInference /
// threat scores grow unbounded (one entry per unique ProcessGuid, forever).
func (ds *DetectionService) StartMaintenance(ctx context.Context) {
	const (
		interval = 5 * time.Minute
		maxAge   = 10 * time.Minute
	)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("[MAINTENANCE] Started (interval=%s, per-process state TTL=%s)", interval, maxAge)

	for {
		select {
		case <-ctx.Done():
			log.Println("[MAINTENANCE] Stopped (context cancelled)")
			return
		case <-ticker.C:
			highIO := ds.CleanupOldHighIOFlags(maxAge)
			modified := ds.CleanupOldModifiedFiles(maxAge)
			scores := ds.threatScorer.CleanupOldScores(maxAge)
			procState := ds.cleanupStaleProcessState(maxAge)
			if highIO+modified+scores+procState > 0 {
				log.Printf("[MAINTENANCE] Evicted: highIO=%d modified=%d scores=%d procState=%d (alerts dropped lifetime=%d)",
					highIO, modified, scores, procState, atomic.LoadUint64(&ds.alertsDropped))
			}
		}
	}
}

// cleanupStaleProcessState evicts the per-process maps that have no other eviction path:
// monitoredProcesses, analyzedProcesses, fileCounters, mlLastInference. Each is keyed by a
// per-process-unique ProcessGuid, so without this they leak permanently.
func (ds *DetectionService) cleanupStaleProcessState(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	removed += ds.tiers.EvictStale(cutoff)
	removed += ds.counters.Evict(cutoff)
	removed += ds.ml.EvictStale(cutoff)

	return removed
}

// ProcessBackupPrivilege handles Windows Security events related to BackupRead/BackupWrite API usage
// This method processes events from the Security Event Log (Event IDs 4672, 4703, 4674)
// that indicate a process has enabled or is using SeBackupPrivilege/SeRestorePrivilege
func (ds *DetectionService) ProcessBackupPrivilege(ctx context.Context, event *domain.SecurityEvent) {
	if ds.isTrustedProcess(event.ProcessName) {
		return
	}

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

	score := ds.addRuleIndicator(
		pseudoGuid,
		event.ProcessName,
		pid,
		indicator,
	)

	log.Printf("[SECURITY] Backup privilege event processed (Score: %d)", score)

	// Evaluate and potentially trigger alert
	ds.evaluateAndAlert(pseudoGuid, event.ProcessName, pid)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
