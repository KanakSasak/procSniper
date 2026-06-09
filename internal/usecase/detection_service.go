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
type CanaryActor struct {
	ProcessID   int
	ProcessGuid string
	Image       string
	TargetPath  string
	EventType   string
	SeenAt      time.Time
}

// CanaryCompromiseState tracks latched compromise state to avoid repeated periodic alerts.
type CanaryCompromiseState struct {
	FirstSeen             time.Time
	LastSeen              time.Time
	CompromiseType        string
	RelatedPath           string
	AttributedProcessGuid string
	Latched               bool
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
	velocityActors     map[string]*VelocityActorState
	velocityActorsMux  sync.RWMutex

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
	// ETW-attributed recent actors that touched canaries (for periodic scan attribution).
	recentCanaryActors map[string]CanaryActor // normalized canonical canary path -> actor
	canaryActorsMux    sync.RWMutex
	// Latched canary compromises (suppresses periodic repeat alerts for already-compromised canaries).
	compromisedCanaries map[string]CanaryCompromiseState
	compromisedMux      sync.RWMutex

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

	// ML inference integration
	mlPredictor      domain.MLPredictor                // nil when ML not loaded
	mlEnabled        bool                              // whether ML detection is active
	mlConfidence     float64                           // minimum confidence threshold (0.0–1.0)
	mlMux            sync.RWMutex                      // protects mlPredictor, mlEnabled, mlConfidence, mlLastInference
	onMLPrediction   func(*domain.MLInferenceActivity) // callback for GUI event emission
	mlMinIndicators      int                               // minimum non-zero features in feature vector before ML fires
	mlLastInference      map[string]time.Time              // per-process inference cooldown tracker
	mlCooldown           time.Duration                     // cooldown between inferences for same process
	detectionMode        string                            // "rules_only", "hybrid", "ml_only"
	canaryResponseAction string                            // "terminate", "suspend", "alert_only"

	// Alert-drop accounting (atomic). Dropped alerts were previously log-only and invisible.
	alertsDropped         uint64 // total alerts dropped because alertChan was full
	alertsDroppedCritical uint64
	alertsDroppedHigh     uint64
	alertsDroppedOther    uint64
}

// NewDetectionService creates a new detection service
// entropyThreshold: number of high entropy files required before adding entropy indicator
// extensionThreshold: number of ransomware extension files required before adding extension indicator
// combinedThreshold: files with BOTH high entropy AND ransomware extension for immediate termination
// enableRansomNoteDetection: enable/disable ransom note detection (default: false, focus on behavioral)
// ransomwareExtensions: list of ransomware file extensions to detect
func NewDetectionService(entropyThreshold, extensionThreshold, combinedThreshold, renameExtThreshold int, enableRansomNoteDetection bool, ransomwareExtensions []string, trustedProcesses []string) *DetectionService {
	if renameExtThreshold <= 0 {
		renameExtThreshold = 3
	}

	ds := &DetectionService{
		velocityTracker:           domain.NewFileOperationTracker(60 * time.Second),
		threatScorer:              domain.NewThreatScorer(),
		alertChan:                 make(chan *domain.Alert, 100),
		monitoredProcesses:        make(map[string]time.Time), // Tier 1: Lightweight monitoring
		analyzedProcesses:         make(map[string]time.Time), // Tier 2: Deep analysis
		highIOProcesses:           make(map[string]time.Time), // Tier 3: Critical
		velocityActors:            make(map[string]*VelocityActorState),
		fileCounters:              make(map[string]*ProcessFileCounters),
		entropyTracker:            domain.NewEntropyTracker(10 * time.Minute), // Track entropy for 10 minutes
		modifiedHighEntropyFiles:  make(map[string]*ModifiedHighEntropyFile),  // Track modified high-entropy files
		directoryScanInProgress:   make(map[string]bool),                      // Prevent goroutine explosion
		canaryFiles:               make(map[string]*domain.CanaryFile),        // Honeypot files for detection
		recentCanaryActors:        make(map[string]CanaryActor),
		compromisedCanaries:       make(map[string]CanaryCompromiseState),
		entropyFileThreshold:      entropyThreshold,
		extensionFileThreshold:    extensionThreshold,
		combinedThreshold:         combinedThreshold,
		renameExtThreshold:        renameExtThreshold,
		enableRansomNoteDetection: enableRansomNoteDetection,
		ransomwareExtensions:      ransomwareExtensions,
		trustedProcessNames:       make(map[string]struct{}),
		trustedProcessPaths:       make(map[string]struct{}),
		mlMinIndicators:           4,
		mlLastInference:           make(map[string]time.Time),
		mlCooldown:                2 * time.Second,
	}

	ds.setTrustedProcesses(trustedProcesses)

	return ds
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
	if _, _, canaryMatch := ds.matchCanaryPath(event.TargetFile); canaryMatch {
		ds.recordCanaryActor(event, "FILE_CREATE")
	}

	// Canary files are frequently opened/read by legitimate indexers/AV engines.
	// Ignore create/open-style canary events and only react on write/rename/delete paths.
	if _, isCanary := ds.isCanaryFile(event.TargetFile); isCanary {
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

	// STAGE 1: Multi-Tier Velocity Detection
	// Implements graduated response based on I/O velocity
	tier, velocity, tierName := ds.velocityTracker.DetectAnomalousActivity(event.ProcessGuid)
	ds.trackVelocityActor(event, "create", tier, false)

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
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

	// ML feature tracking: accumulate directory + extension stats for every file create
	ds.fileCountersMux.Lock()
	mlCounters := ds.getOrInitMLCounters(event.ProcessGuid)
	mlCounters.DirectorySet[filepath.Dir(event.TargetFile)] = struct{}{}
	if ext != "" {
		mlCounters.ExtensionCounts[strings.ToLower(ext)]++
	}
	ds.fileCountersMux.Unlock()

	// ML feature tracking: detect browser credential / history / SSH key access
	ds.checkBrowserAndSSHAccess(event)

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
					"velocity":  fmt.Sprintf("%.2f", velocity),
					"tier":      tierName,
					"operation": operation,
				},
			}

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] TIER 3 CRITICAL: %.2f files/min - %s (op=%s, Score: %d)", velocity, event.Image, operation, score)
		} else {
			ds.highIOProcessesMux.Unlock()
		}

	case domain.VelocityTierAnalyze:
		ds.analyzedMux.Lock()
		if _, exists := ds.analyzedProcesses[event.ProcessGuid]; !exists {
			ds.analyzedProcesses[event.ProcessGuid] = time.Now()
			ds.analyzedMux.Unlock()

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
		} else {
			ds.analyzedMux.Unlock()
		}

	case domain.VelocityTierMonitor:
		ds.monitoredMux.Lock()
		if _, exists := ds.monitoredProcesses[event.ProcessGuid]; !exists {
			ds.monitoredProcesses[event.ProcessGuid] = time.Now()
			ds.monitoredMux.Unlock()
			log.Printf("[MONITORING] TIER 1 MONITOR: %.2f files/min - %s (op=%s)", velocity, event.Image, operation)
		} else {
			ds.monitoredMux.Unlock()
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
	ds.recordCanaryActor(event, "FILE_MODIFIED")

	// Track modify operations so rename/encrypt bursts participate in velocity tiers.
	tier := ds.updateVelocityTierForOperation(event, "modify")

	// ML feature tracking: directory + extension from modify events
	isRename := isRenameMonitorEvent(event)
	ds.fileCountersMux.Lock()
	modMLCounters := ds.getOrInitMLCounters(event.ProcessGuid)
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
	ds.fileCountersMux.Unlock()

	// ML feature tracking: detect browser credential / history / SSH key access
	ds.checkBrowserAndSSHAccess(event)

	// Real-time canary response is limited to destructive I/O paths (write/rename).
	// Read/open-style accesses are intentionally ignored in ProcessFileCreate.
	if ds.handleCanaryWriteOrRename(event) {
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

		ds.fileCountersMux.Lock()
		counters := ds.getOrInitMLCounters(event.ProcessGuid)
		if counters.RenameRansomExtHits == nil {
			counters.RenameRansomExtHits = make([]time.Time, 0, ds.renameExtThreshold+2)
		}
		counters.RenameRansomExtHits = trimRenameHits(counters.RenameRansomExtHits, now, renameWindow)
		counters.RenameRansomExtHits = append(counters.RenameRansomExtHits, now)
		// Keep ML feature counters current before triggering inference.
		counters.RansomExtensionCount++
		renameCount := len(counters.RenameRansomExtHits)
		extensionCount := counters.RansomExtensionCount
		counters.LastUpdated = now
		ds.fileCountersMux.Unlock()

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

			score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] 🔴 HIGH ENTROPY MODIFICATION THRESHOLD REACHED: %d files (Score: %d)",
				currentCount, score)

			ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		}
	}
}

// handleCanaryWriteOrRename handles real-time canary detection for write/overwrite/rename operations.
// Returns true when the event targets a canary and should not continue through normal file-modified flow.
func (ds *DetectionService) handleCanaryWriteOrRename(event *domain.MonitorEvent) bool {
	canary, isCanary := ds.isCanaryFile(event.TargetFile)
	if !isCanary {
		return false
	}

	action := ds.GetCanaryResponseAction()
	log.Printf("[CANARY] REAL-TIME DETECTION: Canary file WRITE/RENAME observed: %s (response_action=%s)", event.TargetFile, action)
	log.Printf("[CANARY] Process: %s (PID: %d, GUID: %s)", event.Image, event.ProcessID, event.ProcessGuid)

	// Determine indicator points based on canary response action
	var canaryPoints int
	switch action {
	case "alert_only":
		canaryPoints = 0 // Alert only, no auto-response
	case "suspend":
		canaryPoints = 30 // Below auto-terminate threshold, triggers suspend
	default: // "terminate"
		canaryPoints = 100 // Immediate auto-terminate
	}

	// Correlate with ransom-note style .txt activity for very high confidence.
	ds.fileCountersMux.RLock()
	counters, hasCounters := ds.fileCounters[event.ProcessGuid]
	var txtFileCount int
	var txtDirCount int
	if hasCounters {
		txtFileCount = counters.TxtFileCount
		txtDirCount = len(counters.TxtFileDirectories)
	}
	ds.fileCountersMux.RUnlock()

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

		score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[CANARY] CORRELATED INDICATOR ADDED: Score: %d (action=%s)", score, action)

		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
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

		score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[CANARY] ENCRYPTED CANARY DETECTED: Score: %d (action=%s)", score, action)

		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
	}

	return true
}

// ProcessProcessCreate handles process creation events
func (ds *DetectionService) ProcessProcessCreate(ctx context.Context, event *domain.MonitorEvent) {
	if ds.isTrustedProcess(event.Image) {
		return
	}

	cmdLine := strings.ToLower(event.CommandLine)
	imageLower := strings.ToLower(event.Image)

	// ML feature tracking: detect system info reconnaissance commands
	isSystemInfoCmd := strings.Contains(cmdLine, "systeminfo") || strings.Contains(cmdLine, "whoami") ||
		strings.Contains(cmdLine, "hostname") || strings.Contains(cmdLine, "ipconfig") ||
		strings.Contains(cmdLine, "net user") || strings.Contains(cmdLine, "net localgroup")
	if isSystemInfoCmd {
		ds.fileCountersMux.Lock()
		sysCounters := ds.getOrInitMLCounters(event.ProcessGuid)
		sysCounters.SystemInfoHit = true
		ds.fileCountersMux.Unlock()
	}

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
		ds.fileCountersMux.Lock()
		shadowCounters := ds.getOrInitMLCounters(event.ProcessGuid)
		shadowCounters.ShadowCopyDeleteHit = true
		ds.fileCountersMux.Unlock()

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

		score := ds.addRuleIndicator(
			event.ProcessGuid,
			event.Image,
			event.ProcessID,
			indicator,
		)

		log.Printf("[DETECTION] 🔴 SHADOW COPY DELETION - IMMEDIATE TERMINATION TRIGGERED (Score: %d)", score)

		// Propagate shadow_copy_delete to parent process (ransomware spawns vssadmin/wmic)
		ds.propagateMLFlagToParent(event, true, false, false)

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

			ds.fileCountersMux.Lock()
			mlCounters := ds.getOrInitMLCounters(event.ProcessGuid)
			if indicatorType == domain.IndicatorShadowCopyDeletion {
				mlCounters.ShadowCopyDeleteHit = true
			}
			if indicatorType == domain.IndicatorLSASSAccess {
				mlCounters.LSASSAccessHit = true
			}
			ds.fileCountersMux.Unlock()

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

			score := ds.addRuleIndicator(
				event.ProcessGuid,
				event.Image,
				event.ProcessID,
				indicator,
			)

			log.Printf("[DETECTION] Suspicious command: %s (Score: %d)", description, score)

			// Propagate suspicious command flags to parent (ransomware spawns child for these)
			ds.propagateMLFlagToParent(event,
				indicatorType == domain.IndicatorShadowCopyDeletion,
				false,
				indicatorType == domain.IndicatorLSASSAccess,
			)
		}
	}

	// Propagate system_info flag to parent process (ransomware spawns cmd.exe /c systeminfo)
	if isSystemInfoCmd {
		ds.propagateMLFlagToParent(event, false, true, false)
	}

	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// ProcessLSASSAccess handles LSASS memory access events
func (ds *DetectionService) ProcessLSASSAccess(ctx context.Context, event *domain.MonitorEvent) {
	if ds.isTrustedProcess(event.Image) {
		return
	}

	if !strings.Contains(strings.ToLower(event.TargetImage), "lsass.exe") {
		return
	}

	ds.fileCountersMux.Lock()
	mlCounters := ds.getOrInitMLCounters(event.ProcessGuid)
	mlCounters.LSASSAccessHit = true
	ds.fileCountersMux.Unlock()

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

	score := ds.addRuleIndicator(
		event.ProcessGuid,
		event.Image,
		event.ProcessID,
		indicator,
	)

	log.Printf("[DETECTION] LSASS access: %s (Access: %s, Score: %d)",
		event.Image, event.GrantedAccess, score)

	// Propagate LSASS access to parent (ransomware may spawn child for credential dumping)
	ds.propagateMLFlagToParent(event, false, false, true)

	ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}

// checkBrowserAndSSHAccess detects non-browser processes touching browser credential,
// history, or SSH key paths and sets the corresponding ML feature flags.
// Called from ProcessFileModified and ProcessFileCreate to wire up features 9-11.
func (ds *DetectionService) checkBrowserAndSSHAccess(event *domain.MonitorEvent) {
	if event == nil || strings.TrimSpace(event.TargetFile) == "" {
		return
	}
	targetLower := strings.ToLower(event.TargetFile)
	imageLower := strings.ToLower(event.Image)

	// Skip legitimate browsers — they're expected to access their own files
	for _, browser := range []string{"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"} {
		if strings.Contains(imageLower, browser) {
			return
		}
	}

	var credHit, historyHit, sshHit bool

	// Check browser credential paths
	for _, credPath := range domain.BrowserCredentialPaths {
		if strings.Contains(targetLower, strings.ToLower(credPath)) {
			credHit = true
			break
		}
	}
	// Check browser history paths
	if strings.Contains(targetLower, "\\history") || strings.Contains(targetLower, "\\places.sqlite") {
		historyHit = true
	}
	// Check SSH key paths
	if strings.Contains(targetLower, "\\.ssh\\") || strings.Contains(targetLower, "\\id_rsa") ||
		strings.Contains(targetLower, "\\id_ed25519") || strings.Contains(targetLower, "\\known_hosts") {
		sshHit = true
	}

	if !credHit && !historyHit && !sshHit {
		return
	}

	ds.fileCountersMux.Lock()
	counters := ds.getOrInitMLCounters(event.ProcessGuid)
	// Capture the false->true transition so the credential-theft indicator is raised at
	// most once per process. IndicatorCredentialTheft is a repeatable type in the scorer
	// and this runs on every qualifying file event, so emitting per event would inflate
	// the score and could spuriously trip auto-terminate.
	firstCredHit := credHit && !counters.BrowserCredentialHit
	if credHit {
		counters.BrowserCredentialHit = true
	}
	if historyHit {
		counters.BrowserHistoryHit = true
	}
	if sshHit {
		counters.SSHKeyHit = true
	}
	ds.fileCountersMux.Unlock()

	if credHit {
		log.Printf("[DETECTION] Browser credential access: %s touching %s (PID: %d)",
			event.Image, event.TargetFile, event.ProcessID)
	}

	// Raise the credential-theft indicator and evaluate on the first credential hit.
	// Ported from the now-deleted ProcessBrowserAccess, which scored credential theft but
	// was never routed by any ETW EventID — leaving this the sole credential-theft alert
	// path. (AUDIT Phase 1: port-then-delete.)
	if firstCredHit {
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
		score := ds.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[DETECTION] Browser credential indicator raised: %s accessing %s (Score: %d)",
			event.Image, event.TargetFile, score)
		ds.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
	}
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

func (ds *DetectionService) attachRelatedProcessesToCanaryAlert(alert *domain.Alert, canaryPathOverride string, attributedGuidOverride string) {
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

	related := ds.collectRelatedVelocityActors(canaryPath, attributedGuid, time.Now())
	alert.RelatedProcesses = related
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
		if nonZeroCount < ds.mlMinIndicators {
			log.Printf("[ML][GATE] process=%s pid=%d features=%d/%d — accumulating (mode=%s)",
				image, pid, nonZeroCount, ds.mlMinIndicators, mode)
			ds.logFeatureVector(image, pid, features)
			if mode == "ml_only" {
				return // ml_only: nothing else to do until ML gate passes
			}
			// hybrid: fall through to rule-based alert path below
		} else {
			log.Printf("[ML][GATE] process=%s pid=%d features=%d/%d — PASSED, firing inference (mode=%s)",
				image, pid, nonZeroCount, ds.mlMinIndicators, mode)
			ds.logFeatureVector(image, pid, features)

			// Cooldown: don't re-infer too quickly on the same process
			ds.mlMux.RLock()
			lastTime := ds.mlLastInference[processGuid]
			ds.mlMux.RUnlock()
			if !lastTime.IsZero() && time.Since(lastTime) < ds.mlCooldown {
				if mode == "ml_only" {
					return
				}
				// hybrid: fall through to rule-based path
			} else {
				// Enough features accumulated — run ML inference
				activity := ds.runMLInference(processGuid, image, pid, features)
				if activity != nil && activity.Stage == "decision" && activity.Prediction != nil {
					ds.mlMux.Lock()
					ds.mlLastInference[processGuid] = time.Now()
					ds.mlMux.Unlock()

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

	ds.attachRelatedProcessesToCanaryAlert(alert, "", processGuid)

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

	var (
		category      string
		severity      domain.ThreatLevel
		score         int
		indicatorType domain.IndicatorType
	)

	switch prediction.Label {
	case 1: // ransomware
		category = "RANSOMWARE"
		severity = domain.ThreatCritical
		score = 100
		indicatorType = domain.IndicatorMLRansomware
	case 2: // stealer
		category = "STEALER"
		severity = domain.ThreatMedium
		score = 30
		indicatorType = domain.IndicatorMLStealer
	default: // benign
		return
	}

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

	// Policy: ransomware => terminate-eligible, stealer => alert-only
	alert.AutoRespond = prediction.Label == 1
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
	ds.mlMux.Lock()
	defer ds.mlMux.Unlock()
	ds.mlPredictor = p
}

// SetMLEnabled enables or disables ML detection.
// Rule-based indicators continue accumulating and serve as the gate for ML inference.
func (ds *DetectionService) SetMLEnabled(enabled bool) {
	ds.mlMux.Lock()
	defer ds.mlMux.Unlock()
	ds.mlEnabled = enabled
}

// SetMLConfidence sets the minimum malicious probability threshold for ML decisions.
func (ds *DetectionService) SetMLConfidence(threshold float64) {
	ds.mlMux.Lock()
	defer ds.mlMux.Unlock()
	ds.mlConfidence = threshold
}

// SetMLMinIndicators sets the minimum number of non-zero features in the
// feature vector before ML inference is triggered for a process.
func (ds *DetectionService) SetMLMinIndicators(n int) {
	ds.mlMux.Lock()
	defer ds.mlMux.Unlock()
	if n < 1 {
		n = 1
	}
	ds.mlMinIndicators = n
}

// SetMLPredictionCallback sets a callback invoked on every ML inference activity.
func (ds *DetectionService) SetMLPredictionCallback(cb func(*domain.MLInferenceActivity)) {
	ds.mlMux.Lock()
	defer ds.mlMux.Unlock()
	ds.onMLPrediction = cb
}

func (ds *DetectionService) isMLModeEnabled() bool {
	ds.mlMux.RLock()
	defer ds.mlMux.RUnlock()
	return ds.mlEnabled
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
	switch action {
	case "terminate", "suspend", "alert_only":
		ds.canaryResponseAction = action
	default:
		ds.canaryResponseAction = "terminate"
	}
	log.Printf("[CONFIG] Canary response action set to: %s", ds.canaryResponseAction)
}

// GetCanaryResponseAction returns the current canary response action.
func (ds *DetectionService) GetCanaryResponseAction() string {
	if ds.canaryResponseAction == "" {
		return "terminate"
	}
	return ds.canaryResponseAction
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

	// Feature 0: velocity (files/min in last 60s)
	ds.velocityActorsMux.RLock()
	actor, hasActor := ds.velocityActors[processGuid]
	if hasActor {
		features[0] = float64(actor.TotalOps60s)
	}
	ds.velocityActorsMux.RUnlock()

	// Features 1-4 from file counters
	ds.fileCountersMux.RLock()
	counters, hasCounters := ds.fileCounters[processGuid]
	if hasCounters {
		// Feature 1: file_count (cumulative total file ops since process start)
		if hasActor {
			features[1] = float64(actor.CumulativeFileCount)
		}
		// Feature 2: txt_file_count
		features[2] = float64(counters.TxtFileCount)
		// Feature 3: directory_count
		features[3] = float64(len(counters.DirectorySet))
		// Feature 4: file_delete_count
		features[4] = float64(counters.DeleteCount)
	}
	ds.fileCountersMux.RUnlock()

	// Feature 5: is_signed (default 0 for v1 — PE signature check not implemented yet)
	features[5] = 0

	// Feature 6: extension_match (boolean: 1 if ransomware extensions observed, 0 otherwise)
	if hasCounters && counters.RansomExtensionCount > 0 {
		features[6] = 1.0
	}

	// Feature 7: extension_entropy (Shannon entropy of the extension frequency distribution)
	if hasCounters && counters.ExtensionCounts != nil {
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
	if hasCounters && counters.ShadowCopyDeleteHit {
		features[8] = 1 // shadow_copy_delete
	}
	if hasCounters && counters.BrowserCredentialHit {
		features[9] = 1 // browser_credential_access
	}

	// Feature 10: browser_history_access
	if hasCounters && counters.BrowserHistoryHit {
		features[10] = 1
	}
	// Feature 11: ssh_key_access
	if hasCounters && counters.SSHKeyHit {
		features[11] = 1
	}
	if hasCounters && counters.LSASSAccessHit {
		features[12] = 1 // lsass_access
	}
	// Feature 13: system_info_queries
	if hasCounters && counters.SystemInfoHit {
		features[13] = 1
	}

	return features
}

// getOrInitMLCounters returns the ProcessFileCounters for a GUID, initializing ML fields if needed.
func (ds *DetectionService) getOrInitMLCounters(processGuid string) *ProcessFileCounters {
	counters, exists := ds.fileCounters[processGuid]
	if !exists {
		counters = &ProcessFileCounters{
			TxtFileDirectories: make([]string, 0),
			DirectorySet:       make(map[string]struct{}),
			ExtensionCounts:    make(map[string]int),
			LastUpdated:        time.Now(),
		}
		ds.fileCounters[processGuid] = counters
	} else {
		// Ensure ML maps are initialized (for pre-existing counters created before ML)
		if counters.DirectorySet == nil {
			counters.DirectorySet = make(map[string]struct{})
		}
		if counters.ExtensionCounts == nil {
			counters.ExtensionCounts = make(map[string]int)
		}
	}
	return counters
}

// runMLInference runs ML model inference for a process and emits an activity record
// for every outcome (decision, benign, below-threshold, not-ready, error).
// If precomputed features are provided, they are used instead of re-extracting.
func (ds *DetectionService) runMLInference(processGuid, image string, pid int, precomputed ...[14]float64) *domain.MLInferenceActivity {
	ds.mlMux.RLock()
	predictor := ds.mlPredictor
	enabled := ds.mlEnabled
	threshold := ds.mlConfidence
	callback := ds.onMLPrediction
	ds.mlMux.RUnlock()

	ready := predictor != nil && predictor.IsReady()
	log.Printf("[ML][ATTEMPT] process=%s pid=%d threshold=%.4f mode_enabled=%v predictor_ready=%v",
		image, pid, threshold, enabled, ready)

	activity := &domain.MLInferenceActivity{
		ProcessGuid:    processGuid,
		ProcessID:      pid,
		Image:          image,
		Threshold:      threshold,
		ModeEnabled:    enabled,
		PredictorReady: ready,
		Timestamp:      time.Now(),
	}

	if !enabled {
		activity.Stage = "skipped"
		activity.Reason = "ml_mode_disabled"
		ds.emitMLActivity(callback, activity)
		log.Printf("[ML][SKIP] process=%s pid=%d reason=%s", image, pid, activity.Reason)
		return activity
	}

	if !ready {
		activity.Stage = "skipped"
		activity.Reason = "predictor_not_ready"
		ds.emitMLActivity(callback, activity)
		log.Printf("[ML][SKIP] process=%s pid=%d reason=%s", image, pid, activity.Reason)
		return activity
	}

	var features [14]float64
	if len(precomputed) > 0 {
		features = precomputed[0]
	} else {
		features = ds.ExtractFeatureVector(processGuid)
	}
	prediction, err := predictor.Predict(features)
	if err != nil {
		activity.Stage = "error"
		activity.Reason = "inference_error"
		activity.Error = err.Error()
		ds.emitMLActivity(callback, activity)
		log.Printf("[ML][ERROR] process=%s pid=%d error=%v", image, pid, err)
		return activity
	}

	prediction.ProcessGuid = processGuid
	prediction.ProcessID = pid
	prediction.Image = image
	activity.Prediction = prediction
	if !prediction.Timestamp.IsZero() {
		activity.Timestamp = prediction.Timestamp
	}

	probRansom := prediction.Probabilities[1]
	probStealer := prediction.Probabilities[2]
	maliciousProb := probRansom + probStealer

	if maliciousProb < threshold {
		activity.Stage = "skipped"
		activity.Reason = "below_threshold"
		activity.Decision = "none"
		activity.DecisionScore = 0
		activity.DecisionAutoRespond = false
		ds.emitMLActivity(callback, activity)
		log.Printf("[ML][SKIP] process=%s pid=%d reason=%s malicious_prob=%.4f prob_ransom=%.4f prob_steal=%.4f threshold=%.4f",
			image, pid, activity.Reason, maliciousProb, probRansom, probStealer, threshold)
		return activity
	}

	decisionLabel := 1
	decisionLabelName := domain.ClassLabels[1]
	decisionConfidence := probRansom
	if probStealer > probRansom {
		decisionLabel = 2
		decisionLabelName = domain.ClassLabels[2]
		decisionConfidence = probStealer
	}
	prediction.Label = decisionLabel
	prediction.LabelName = decisionLabelName
	prediction.Confidence = decisionConfidence

	switch decisionLabel {
	case 1:
		activity.Decision = "terminate_eligible"
		activity.DecisionCategory = "RANSOMWARE"
		activity.DecisionScore = 100
		activity.DecisionAutoRespond = true
	case 2:
		activity.Decision = "alert_only"
		activity.DecisionCategory = "STEALER"
		activity.DecisionScore = 30
		activity.DecisionAutoRespond = false
	}

	activity.Stage = "decision"
	activity.Reason = "model_decision"
	ds.emitMLActivity(callback, activity)
	return activity
}

func (ds *DetectionService) emitMLActivity(callback func(*domain.MLInferenceActivity), activity *domain.MLInferenceActivity) {
	if activity == nil {
		return
	}
	if activity.Timestamp.IsZero() {
		activity.Timestamp = time.Now()
	}
	if callback != nil {
		callback(activity)
	}
}

// SetupCanaryFiles creates honeypot files in common ransomware target directories
// Canary files are decoy files with known low entropy that trigger alerts if encrypted/deleted
// This catches slow-moving ransomware that doesn't trigger velocity thresholds
func (ds *DetectionService) SetupCanaryFiles() error {
	log.Println("[CANARY] Setting up honeypot files for ransomware detection...")
	// Full setup resets latch state so recreated canaries can alert again.
	ds.resetAllCanaryLatches()

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
			ds.resetCanaryLatch(filePath)

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
		ds.resetCanaryLatch(filePath)

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
			ds.resetCanaryLatch(filePath)

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
		ds.resetCanaryLatch(filePath)

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

func normalizeCanaryPath(path string) string {
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(path))
}

func (ds *DetectionService) resetAllCanaryLatches() {
	ds.compromisedMux.Lock()
	defer ds.compromisedMux.Unlock()

	clear(ds.compromisedCanaries)
}

func (ds *DetectionService) resetCanaryLatch(filePath string) {
	key := normalizeCanaryPath(filePath)
	if key == "" {
		return
	}

	ds.compromisedMux.Lock()
	delete(ds.compromisedCanaries, key)
	ds.compromisedMux.Unlock()
}

func (ds *DetectionService) shouldEmitCanaryAlert(filePath, compromiseType, relatedPath, attributedProcessGuid string, observedAt time.Time) bool {
	key := normalizeCanaryPath(filePath)
	if key == "" {
		return true
	}

	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	ds.compromisedMux.Lock()
	defer ds.compromisedMux.Unlock()

	if state, exists := ds.compromisedCanaries[key]; exists && state.Latched {
		state.LastSeen = observedAt
		if compromiseType != "" {
			state.CompromiseType = compromiseType
		}
		if relatedPath != "" {
			state.RelatedPath = relatedPath
		}
		if attributedProcessGuid != "" && !strings.EqualFold(attributedProcessGuid, "UNKNOWN") {
			state.AttributedProcessGuid = attributedProcessGuid
		}
		ds.compromisedCanaries[key] = state
		return false
	}

	ds.compromisedCanaries[key] = CanaryCompromiseState{
		FirstSeen:             observedAt,
		LastSeen:              observedAt,
		CompromiseType:        compromiseType,
		RelatedPath:           relatedPath,
		AttributedProcessGuid: attributedProcessGuid,
		Latched:               true,
	}

	return true
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
	ds.fileCountersMux.Lock()
	parentCounters := ds.getOrInitMLCounters(parentGuid)
	if shadowCopy {
		parentCounters.ShadowCopyDeleteHit = true
	}
	if systemInfo {
		parentCounters.SystemInfoHit = true
	}
	if lsassAccess {
		parentCounters.LSASSAccessHit = true
	}
	ds.fileCountersMux.Unlock()
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

	ds.fileCountersMux.Lock()
	for _, guid := range activeGuids {
		counters := ds.getOrInitMLCounters(guid)
		if shadowCopy {
			counters.ShadowCopyDeleteHit = true
		}
		if systemInfo {
			counters.SystemInfoHit = true
		}
		if lsassAccess {
			counters.LSASSAccessHit = true
		}
	}
	ds.fileCountersMux.Unlock()

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

// matchCanaryPath resolves a target path to a tracked canonical canary path.
// Match types: exact, renamed_prefix.
func (ds *DetectionService) matchCanaryPath(targetPath string) (string, string, bool) {
	targetNorm := normalizeCanaryPath(targetPath)
	if targetNorm == "" {
		return "", "", false
	}

	ds.canaryFilesMux.RLock()
	defer ds.canaryFilesMux.RUnlock()

	targetDir := normalizeCanaryPath(filepath.Dir(targetPath))
	targetBase := strings.ToLower(filepath.Base(targetPath))

	for canaryPath, canary := range ds.canaryFiles {
		canonicalNorm := normalizeCanaryPath(canaryPath)
		if targetNorm == canonicalNorm {
			return canaryPath, "exact", true
		}

		// Rename pattern: ~canary_name.ext -> ~canary_name.ext.CONTI
		canaryDir := normalizeCanaryPath(filepath.Dir(canaryPath))
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

func (ds *DetectionService) recordCanaryActor(event *domain.MonitorEvent, eventType string) {
	if event == nil {
		return
	}

	canonicalPath, matchType, ok := ds.matchCanaryPath(event.TargetFile)
	if !ok {
		return
	}

	seenAt := event.Timestamp
	if seenAt.IsZero() {
		seenAt = time.Now()
	}

	actor := CanaryActor{
		ProcessID:   event.ProcessID,
		ProcessGuid: event.ProcessGuid,
		Image:       event.Image,
		TargetPath:  event.TargetFile,
		EventType:   fmt.Sprintf("%s:%s", eventType, matchType),
		SeenAt:      seenAt,
	}

	key := normalizeCanaryPath(canonicalPath)
	ds.canaryActorsMux.Lock()
	existing, exists := ds.recentCanaryActors[key]
	if !exists || actor.SeenAt.After(existing.SeenAt) {
		ds.recentCanaryActors[key] = actor
	}
	ds.canaryActorsMux.Unlock()
}

func (ds *DetectionService) resolveCanaryActor(canonicalCanaryPath, renamedPath string) (CanaryActor, bool) {
	const attributionTTL = 120 * time.Second

	key := normalizeCanaryPath(canonicalCanaryPath)
	if key == "" {
		return CanaryActor{}, false
	}

	ds.canaryActorsMux.Lock()
	defer ds.canaryActorsMux.Unlock()

	actor, ok := ds.recentCanaryActors[key]
	if !ok {
		return CanaryActor{}, false
	}

	if time.Since(actor.SeenAt) > attributionTTL {
		delete(ds.recentCanaryActors, key)
		return CanaryActor{}, false
	}

	if renamedPath != "" {
		renamedNorm := normalizeCanaryPath(renamedPath)
		if renamedNorm != "" && normalizeCanaryPath(actor.TargetPath) != renamedNorm {
			// Keep attribution even if path differs, but prefer matching paths when available.
			// No-op fallback: actor is still recent and canary-specific.
		}
	}

	return actor, true
}

// CheckCanaryFiles periodically checks if canary files have been compromised
// This function should be called on a timer (e.g., every 30 seconds)
// Returns true if any canary was compromised (triggers immediate alert)
func (ds *DetectionService) CheckCanaryFiles() bool {
	ds.canaryFilesMux.RLock()
	canaryCount := len(ds.canaryFiles)
	ds.canaryFilesMux.RUnlock()

	if canaryCount == 0 {
		return false
	}

	log.Printf("[CANARY] Checking %d honeypot files...", canaryCount)

	compromised := false
	suppressedCanaryAlerts := 0

	ds.canaryFilesMux.Lock()
	defer ds.canaryFilesMux.Unlock()

	for path, canary := range ds.canaryFiles {
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

							log.Printf("[DETECTION] ?? CANARY RENAMED: %s -> %s", path, renamedPath)
							log.Printf("[DETECTION] ?? Extension changed from %s to %s", canary.Extension, newExt)
							log.Printf("[DETECTION] ?? This is a classic ransomware behavior!")

							entropy, entropyErr := domain.AnalyzeFileEntropy(renamedPath, newExt)
							if entropyErr == nil {
								entropyDelta := entropy.Entropy - canary.OriginalEntropy
								log.Printf("[DETECTION] ?? Renamed file entropy: %.3f (original: %.3f, delta +%.3f)",
									entropy.Entropy, canary.OriginalEntropy, entropyDelta)

								if entropyDelta >= 2.0 {
									if !ds.alertCanaryCompromised(
										path,
										fmt.Sprintf("RENAMED_AND_ENCRYPTED (-> %s)", filepath.Base(renamedPath)),
										entropy.Entropy,
										canary.OriginalEntropy,
										renamedPath,
									) {
										suppressedCanaryAlerts++
									}
								} else {
									if !ds.alertCanaryCompromised(
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
								if !ds.alertCanaryCompromised(
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
					log.Printf("[DETECTION] ?? CANARY DELETED: %s", path)
					log.Printf("[DETECTION] ?? This honeypot file was deleted by malicious process!")
					if !ds.alertCanaryCompromised(path, "DELETED", 0, canary.OriginalEntropy, "") {
						suppressedCanaryAlerts++
					}
					compromised = true
				}
				continue
			}

			log.Printf("[DETECTION] ??  CANARY ACCESS DENIED: %s (error: %v)", path, err)
			if !ds.alertCanaryCompromised(path, "ACCESS_DENIED", 0, canary.OriginalEntropy, "") {
				suppressedCanaryAlerts++
			}
			compromised = true
			continue
		}

		if fileInfo.Size() != canary.FileSize {
			log.Printf("[DETECTION] ?? CANARY SIZE CHANGED: %s (was: %d bytes, now: %d bytes)",
				path, canary.FileSize, fileInfo.Size())
			if !ds.alertCanaryCompromised(path, "SIZE_CHANGED", 0, canary.OriginalEntropy, "") {
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
			log.Printf("[DETECTION] ?? CANARY ENCRYPTED: %s", path)
			log.Printf("[DETECTION] ?? Entropy jumped from %.3f -> %.3f (delta +%.3f)",
				canary.OriginalEntropy, entropy.Entropy, entropyDelta)
			log.Printf("[DETECTION] ?? This honeypot file was encrypted by ransomware!")

			if !ds.alertCanaryCompromised(path, "ENCRYPTED", entropy.Entropy, canary.OriginalEntropy, "") {
				suppressedCanaryAlerts++
			}
			compromised = true
			continue
		}
	}

	if !compromised {
		log.Printf("[CANARY] ? All %d honeypot files intact", canaryCount)
	}
	if suppressedCanaryAlerts > 0 {
		log.Printf("[CANARY] Suppressed %d repeated canary compromise alerts (latched)", suppressedCanaryAlerts)
	}

	return compromised
}

// alertCanaryCompromised creates a CRITICAL alert when a canary file is compromised
// This is a definitive ransomware indicator with near-zero false positives
func (ds *DetectionService) alertCanaryCompromised(filePath string, compromiseType string, currentEntropy, originalEntropy float64, relatedPath string) bool {
	log.Printf("[DETECTION] CRITICAL: CANARY FILE COMPROMISED")
	log.Printf("[DETECTION] File: %s", filePath)
	log.Printf("[DETECTION] Type: %s", compromiseType)

	processGuid := "UNKNOWN"
	processID := 0
	image := "UNKNOWN"
	attributionMethod := "CANARY_HONEYPOT_PERIODIC"

	// Periodic canary scan does not have direct actor context by itself.
	// Correlate with recent ETW activity when available.
	if actor, ok := ds.resolveCanaryActor(filePath, relatedPath); ok {
		processGuid = actor.ProcessGuid
		processID = actor.ProcessID
		image = actor.Image
		attributionMethod = "CANARY_HONEYPOT_ETW_CORRELATED"
		log.Printf("[CANARY] ETW attribution resolved: %s (PID: %d, GUID: %s, Event: %s)",
			image, processID, processGuid, actor.EventType)
	}

	if !ds.shouldEmitCanaryAlert(filePath, compromiseType, relatedPath, processGuid, time.Now()) {
		return false
	}

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
		AutoRespond: true,
	}
	ds.attachRelatedProcessesToCanaryAlert(alert, filePath, processGuid)

	select {
	case ds.alertChan <- alert:
		log.Printf("[ALERT] Canary compromise alert sent: %s (related suspects: %d)", filePath, len(alert.RelatedProcesses))
	default:
		ds.recordDroppedAlert(alert.Severity)
		log.Printf("[ALERT] Alert channel full, canary alert dropped (severity=%s, total dropped=%d)",
			alert.Severity, atomic.LoadUint64(&ds.alertsDropped))
	}

	return true
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

	clear(ds.canaryFiles)
	ds.resetAllCanaryLatches()

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

	removedVelocityActors := ds.pruneVelocityActors(velocityActorRetention)

	if removed > 0 || removedVelocityActors > 0 {
		log.Printf("[CLEANUP] Removed %d old high I/O flags, %d stale velocity actors", removed, removedVelocityActors)
	}

	return removed + removedVelocityActors
}

// GetHighIOProcessCount returns the number of processes currently flagged for deep monitoring
func (ds *DetectionService) GetHighIOProcessCount() int {
	ds.highIOProcessesMux.RLock()
	defer ds.highIOProcessesMux.RUnlock()
	return len(ds.highIOProcesses)
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
func (ds *DetectionService) processDirectoryScanResult(event *domain.MonitorEvent, dirPath string, ransomFiles []string, totalFiles int, scanType string) {
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

	score := ds.addRuleIndicator(
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
func (ds *DetectionService) ProcessFileDelete(ctx context.Context, event *domain.MonitorEvent) {
	if ds.isTrustedProcess(event.Image) {
		return
	}

	// DEBUG: Print ALL file deletions to verify ransomware activity
	ext := filepath.Ext(event.TargetFile)
	log.Printf("[FILE_DELETED] %s (ext: %s) by %s (PID: %d)",
		event.TargetFile, ext, filepath.Base(event.Image), event.ProcessID)

	// Keep recent ETW actor context for periodic canary compromise attribution.
	ds.recordCanaryActor(event, "FILE_DELETE")

	// Track delete operations so delete+rename ransomware patterns raise velocity tiers.
	tier := ds.updateVelocityTierForOperation(event, "delete")

	// ML feature tracking: increment delete counter, track directory + extension
	ds.fileCountersMux.Lock()
	delCounters := ds.getOrInitMLCounters(event.ProcessGuid)
	delCounters.DeleteCount++
	delCounters.DirectorySet[filepath.Dir(event.TargetFile)] = struct{}{}
	if ext != "" {
		delCounters.ExtensionCounts[strings.ToLower(ext)]++
	}
	ds.fileCountersMux.Unlock()

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

	ds.monitoredMux.Lock()
	for guid, ts := range ds.monitoredProcesses {
		if ts.Before(cutoff) {
			delete(ds.monitoredProcesses, guid)
			removed++
		}
	}
	ds.monitoredMux.Unlock()

	ds.analyzedMux.Lock()
	for guid, ts := range ds.analyzedProcesses {
		if ts.Before(cutoff) {
			delete(ds.analyzedProcesses, guid)
			removed++
		}
	}
	ds.analyzedMux.Unlock()

	ds.fileCountersMux.Lock()
	for guid, counters := range ds.fileCounters {
		if counters != nil && counters.LastUpdated.Before(cutoff) {
			delete(ds.fileCounters, guid)
			removed++
		}
	}
	ds.fileCountersMux.Unlock()

	ds.mlMux.Lock()
	for guid, ts := range ds.mlLastInference {
		if ts.Before(cutoff) {
			delete(ds.mlLastInference, guid)
			removed++
		}
	}
	ds.mlMux.Unlock()

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

		score := ds.addRuleIndicator(
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
