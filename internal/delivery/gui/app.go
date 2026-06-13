//go:build windows

package gui

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"procSniper/config"
	"procSniper/internal/delivery/gui/events"
	"procSniper/internal/delivery/gui/logger"
	"procSniper/internal/delivery/gui/models"
	"procSniper/internal/domain"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

// App is the main application struct for the GUI
type App struct {
	ctx context.Context

	// Services
	detectionService     *usecase.DetectionService
	responseOrchestrator *usecase.ResponseOrchestrator
	etwConsumer          *infrastructure.KernelETWConsumer
	securityLogConsumer  *infrastructure.SecurityLogConsumer
	responseActions      *infrastructure.ResponseActions

	// Configuration
	cfg         *config.Config
	responseCfg *config.ResponseConfig

	// Event emitter for real-time updates
	eventEmitter *events.Emitter

	// Log capture for streaming logs to frontend
	logCapture *logger.LogCapture

	// State
	isProtecting bool
	protectMux   sync.RWMutex

	// Background goroutine control
	stopStats     chan struct{}
	stopLogs      chan struct{}
	protectCancel context.CancelFunc // cancels the per-run protection context on Stop

	// ML Model state
	mlModelStatus models.MLModelStatus
	mlPredictor   domain.MLPredictor
	mlMux         sync.RWMutex
}

// NewApp creates a new App instance
func NewApp() *App {
	return &App{
		stopStats:  make(chan struct{}),
		stopLogs:   make(chan struct{}),
		logCapture: logger.GetLogCapture(),
	}
}

// Startup is called when the app starts
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.eventEmitter = events.NewEmitter(ctx)

	// Load configuration
	a.cfg = config.Load()

	var err error
	a.responseCfg, err = config.LoadResponseConfig("config/ransomware_extensions.json")
	if err != nil {
		log.Printf("[GUI] Failed to load response config: %v", err)
		runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
			Type:    runtime.ErrorDialog,
			Title:   "Configuration Error",
			Message: "Failed to load ransomware_extensions.json. Please check the config folder.",
		})
	}

	if a.responseCfg != nil {
		// Single source of truth: extensions come from the parsed ResponseConfig.
		a.cfg.RansomwareExtensions = a.responseCfg.RansomwareExtensions
	}

	log.Println("[GUI] procSniper GUI started")
}

// Shutdown is called when the app is closing
func (a *App) Shutdown(ctx context.Context) {
	log.Println("[GUI] Shutting down...")

	// Stop protection if running
	if a.isProtecting {
		a.StopProtection()
	}

	log.Println("[GUI] Shutdown complete")
}

// StartProtection starts the ransomware protection
func (a *App) StartProtection() models.OperationResult {
	a.protectMux.Lock()
	defer a.protectMux.Unlock()

	if a.isProtecting {
		return models.OperationResult{
			Success: false,
			Message: "Protection is already running",
		}
	}

	ctx, cancel := context.WithCancel(a.ctx)

	// Initialize detection service
	a.detectionService = usecase.NewDetectionService(usecase.DetectionConfig{
		EntropyFileThreshold:        a.responseCfg.DetectionThresholds.HighEntropyFileThreshold,
		ExtensionFileThreshold:      a.responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold,
		CombinedThreshold:           a.responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
		RenameExtThreshold:          a.responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold,
		EnableRansomNoteDetection:   a.cfg.EnableRansomNoteDetection,
		RansomwareExtensions:        a.cfg.RansomwareExtensions,
		TrustedProcesses:            a.responseCfg.Whitelist.Processes,
		IOVelocityMonitorThreshold:  float64(a.responseCfg.DetectionThresholds.IOVelocityMonitorThreshold),
		IOVelocityAnalyzeThreshold:  float64(a.responseCfg.DetectionThresholds.IOVelocityAnalyzeThreshold),
		IOVelocityCriticalThreshold: float64(a.responseCfg.DetectionThresholds.IOVelocityThresholdPerMinute),
	})

	// Wire ML settings/callback into the fresh DetectionService.
	a.mlMux.RLock()
	a.applyMLSettingsToDetectionServiceLocked()
	a.mlMux.RUnlock()

	// Apply detection mode and canary response from config
	if a.responseCfg != nil {
		if a.responseCfg.ResponseSettings.DetectionMode != "" {
			a.detectionService.SetDetectionMode(a.responseCfg.ResponseSettings.DetectionMode)
		}
		if a.responseCfg.ResponseSettings.CanaryResponseAction != "" {
			a.detectionService.SetCanaryResponseAction(a.responseCfg.ResponseSettings.CanaryResponseAction)
		}
	}

	// Setup canary files
	if err := a.detectionService.SetupCanaryFiles(); err != nil {
		log.Printf("[GUI] WARNING: Failed to setup canary files: %v", err)
	} else {
		go a.detectionService.StartCanaryMonitoring(ctx)
	}

	// Start periodic maintenance: evicts stale per-process detection state to bound memory.
	go a.detectionService.StartMaintenance(ctx)

	// Initialize response actions
	var err error
	a.responseActions, err = infrastructure.NewResponseActions()
	if err != nil {
		cancel()
		return models.OperationResult{
			Success: false,
			Message: "Failed to initialize response actions: " + err.Error(),
		}
	}

	// Enable process self-protection (DACL hardening)
	if err := infrastructure.ProtectCurrentProcess(); err != nil {
		log.Printf("[GUI] WARNING: Failed to enable self-protection: %v", err)
	}

	// Initialize response orchestrator
	a.responseOrchestrator = usecase.NewResponseOrchestrator(
		a.detectionService,
		a.responseActions,
		a.responseCfg,
	)

	// Initialize Kernel ETW consumer
	a.etwConsumer = infrastructure.NewKernelETWConsumer(
		a.detectionService,
		a.cfg.WorkerPoolSize,
	)

	// Route successful termination outcomes into ETW dead-PID suppression.
	a.responseOrchestrator.SetProcessTerminationSink(a.etwConsumer)

	if err := a.responseOrchestrator.Start(ctx); err != nil {
		cancel()
		return models.OperationResult{
			Success: false,
			Message: "Failed to start response orchestrator: " + err.Error(),
		}
	}
	if err := a.etwConsumer.Start(ctx); err != nil {
		cancel()
		a.responseOrchestrator.Stop()
		return models.OperationResult{
			Success: false,
			Message: "Failed to start ETW consumer: " + err.Error(),
		}
	}

	// Initialize Security Log consumer
	a.securityLogConsumer = infrastructure.NewSecurityLogConsumer(a.detectionService, a.cfg)
	if err := a.securityLogConsumer.Start(ctx); err != nil {
		log.Printf("[GUI] WARNING: Security Log consumer failed: %v", err)
		a.securityLogConsumer = nil
	}

	a.isProtecting = true
	a.protectCancel = cancel // stored so StopProtection can cancel ctx-bound goroutines
	a.stopStats = make(chan struct{})

	// Start statistics reporter
	go a.reportStatistics(ctx)

	// Start alert streaming to frontend
	go a.streamAlerts(ctx)

	// Harden all current OS threads (must run after goroutines are started)
	if err := infrastructure.ProtectCurrentThreads(); err != nil {
		log.Printf("[GUI] WARNING: Failed to enable thread protection: %v", err)
	}
	go infrastructure.StartPeriodicThreadProtection(ctx)

	log.Println("[GUI] Protection started successfully")

	return models.OperationResult{
		Success: true,
		Message: "Protection started successfully",
	}
}

// StopProtection stops the ransomware protection
func (a *App) StopProtection() models.OperationResult {
	a.protectMux.Lock()
	defer a.protectMux.Unlock()

	if !a.isProtecting {
		return models.OperationResult{
			Success: false,
			Message: "Protection is not running",
		}
	}

	close(a.stopStats)

	// Cancel the per-run context so ctx-bound goroutines (canary monitor, maintenance,
	// stats reporter, alert streamer, periodic thread protection) actually exit. Previously
	// cancel was never stored, so these leaked and accumulated on every Stop/Start cycle.
	if a.protectCancel != nil {
		a.protectCancel()
		a.protectCancel = nil
	}

	// Stop components in reverse order
	if a.securityLogConsumer != nil {
		a.securityLogConsumer.Stop()
	}

	if a.etwConsumer != nil {
		a.etwConsumer.Stop()
	}

	if a.responseOrchestrator != nil {
		a.responseOrchestrator.Stop()
	}

	// Cleanup canary files
	if a.detectionService != nil {
		a.detectionService.CleanupCanaryFiles()
	}

	a.isProtecting = false

	log.Println("[GUI] Protection stopped")

	return models.OperationResult{
		Success: true,
		Message: "Protection stopped successfully",
	}
}

// IsProtecting returns whether protection is active
func (a *App) IsProtecting() bool {
	a.protectMux.RLock()
	defer a.protectMux.RUnlock()
	return a.isProtecting
}

// GetDashboardStats returns current statistics for the dashboard
func (a *App) GetDashboardStats() models.DashboardStats {
	stats := models.DashboardStats{
		ProtectionStatus: "Stopped",
	}

	a.protectMux.RLock()
	isProtecting := a.isProtecting
	a.protectMux.RUnlock()

	if !isProtecting {
		return stats
	}

	stats.ProtectionStatus = "Active"

	// Get ETW stats
	if a.etwConsumer != nil {
		etwStats := a.etwConsumer.GetStats()
		if running, ok := etwStats["running"].(bool); ok {
			stats.ETWConnected = running
		}
		if queueLen, ok := etwStats["channel_length"].(int); ok {
			stats.WorkerQueueDepth = queueLen
		}
		// ETW diagnostics
		if v, ok := etwStats["events_received"].(uint64); ok {
			stats.ETWDiagnostics.EventsReceived = v
		}
		if v, ok := etwStats["events_dropped"].(uint64); ok {
			stats.ETWDiagnostics.EventsDropped = v
		}
		if v, ok := etwStats["events_suppressed_dead_pid"].(uint64); ok {
			stats.ETWDiagnostics.EventsSuppressedDeadPID = v
		}
		if v, ok := etwStats["worker_pool_size"].(int); ok {
			stats.ETWDiagnostics.WorkerPoolSize = v
		}
		if v, ok := etwStats["channel_capacity"].(int); ok {
			stats.ETWDiagnostics.ChannelCapacity = v
		}
		if v, ok := etwStats["channel_length"].(int); ok {
			stats.ETWDiagnostics.ChannelLength = v
		}
	}

	// Get orchestrator stats
	if a.responseOrchestrator != nil {
		orchStats := a.responseOrchestrator.GetStats()
		if alerts, ok := orchStats["alerts_processed"].(int); ok {
			stats.AlertsProcessed = alerts
		}
		if terminated, ok := orchStats["processes_terminated"].(int); ok {
			stats.ProcessesTerminated = terminated
		}
		if quarantined, ok := orchStats["files_quarantined"].(int); ok {
			stats.FilesQuarantined = quarantined
		}
		if blocked, ok := orchStats["auto_responses_blocked"].(int); ok {
			stats.AutoResponsesBlocked = blocked
		}
	}

	// Get canary stats and detection service stats
	if a.detectionService != nil {
		canaryStats := a.detectionService.GetCanaryStats()
		if total, ok := canaryStats["total_canaries"].(int); ok {
			stats.CanaryFilesCount = total
		}

		// Active threats count
		threats := a.detectionService.GetAllThreats()
		stats.ActiveThreatsCount = len(threats)

		// High I/O process count
		stats.HighIOProcessCount = a.detectionService.GetHighIOProcessCount()

		// Entropy stats
		entropyStats := a.detectionService.GetEntropyStats()
		if v, ok := entropyStats["tracked_files"].(int); ok {
			stats.EntropyStats.TrackedFiles = v
		}
		if v, ok := entropyStats["modified_files"].(int); ok {
			stats.EntropyStats.ModifiedFiles = v
		}
		if v, ok := entropyStats["significant_increases"].(int); ok {
			stats.EntropyStats.SignificantIncreases = v
		}
	}

	return stats
}

// GetConfiguration returns the current configuration
func (a *App) GetConfiguration() models.ConfigViewModel {
	if a.responseCfg == nil {
		return models.ConfigViewModel{}
	}

	return models.ConfigViewModel{
		Version:     a.responseCfg.Version,
		LastUpdated: a.responseCfg.LastUpdated,
		DetectionThresholds: models.DetectionThresholdsVM{
			HighEntropyFileThreshold:             a.responseCfg.DetectionThresholds.HighEntropyFileThreshold,
			RansomwareExtensionFileThreshold:     a.responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold,
			RansomwareExtensionRenameThreshold:   a.responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold,
			CombinedEntropyAndExtensionThreshold: a.responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
			IOVelocityThresholdPerMinute:         a.responseCfg.DetectionThresholds.IOVelocityThresholdPerMinute,
		},
		ResponseSettings: models.ResponseSettingsVM{
			AutoTerminateEnabled:      a.responseCfg.ResponseSettings.AutoTerminateEnabled,
			CriticalScoreThreshold:    a.responseCfg.ResponseSettings.CriticalScoreThreshold,
			InvestigationMode:         a.responseCfg.ResponseSettings.InvestigationMode,
			QuarantineFiles:           a.responseCfg.ResponseSettings.QuarantineFiles,
			QuarantineDirectory:       a.responseCfg.ResponseSettings.QuarantineDirectory,
			ImmediateResponse:         a.responseCfg.ResponseSettings.ImmediateResponse,
			TerminateOnExtensionMatch: a.responseCfg.ResponseSettings.TerminateOnExtensionMatch,
			SuspendBeforeTerminate:    a.responseCfg.ResponseSettings.SuspendBeforeTerminate,
			DetectionMode:             a.responseCfg.ResponseSettings.DetectionMode,
			CanaryResponseAction:      a.responseCfg.ResponseSettings.CanaryResponseAction,
		},
		Whitelist: models.WhitelistVM{
			Enabled:   a.responseCfg.Whitelist.Enabled,
			Paths:     a.responseCfg.Whitelist.Paths,
			Processes: a.responseCfg.Whitelist.Processes,
		},
		RansomwareExtensions: a.responseCfg.RansomwareExtensions,
	}
}

// SaveConfiguration saves the configuration
func (a *App) SaveConfiguration(cfg models.ConfigViewModel) models.OperationResult {
	if a.responseCfg == nil {
		return models.OperationResult{
			Success: false,
			Message: "Configuration not loaded",
		}
	}

	// Update config values
	a.responseCfg.DetectionThresholds.HighEntropyFileThreshold = cfg.DetectionThresholds.HighEntropyFileThreshold
	a.responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold = cfg.DetectionThresholds.RansomwareExtensionFileThreshold
	a.responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold = cfg.DetectionThresholds.RansomwareExtensionRenameThreshold
	a.responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold = cfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold
	a.responseCfg.DetectionThresholds.IOVelocityThresholdPerMinute = cfg.DetectionThresholds.IOVelocityThresholdPerMinute

	a.responseCfg.ResponseSettings.AutoTerminateEnabled = cfg.ResponseSettings.AutoTerminateEnabled
	a.responseCfg.ResponseSettings.CriticalScoreThreshold = cfg.ResponseSettings.CriticalScoreThreshold
	a.responseCfg.ResponseSettings.InvestigationMode = cfg.ResponseSettings.InvestigationMode
	a.responseCfg.ResponseSettings.QuarantineFiles = cfg.ResponseSettings.QuarantineFiles
	a.responseCfg.ResponseSettings.QuarantineDirectory = cfg.ResponseSettings.QuarantineDirectory
	a.responseCfg.ResponseSettings.ImmediateResponse = cfg.ResponseSettings.ImmediateResponse
	a.responseCfg.ResponseSettings.TerminateOnExtensionMatch = cfg.ResponseSettings.TerminateOnExtensionMatch
	a.responseCfg.ResponseSettings.SuspendBeforeTerminate = cfg.ResponseSettings.SuspendBeforeTerminate
	a.responseCfg.ResponseSettings.DetectionMode = cfg.ResponseSettings.DetectionMode
	a.responseCfg.ResponseSettings.CanaryResponseAction = cfg.ResponseSettings.CanaryResponseAction

	a.responseCfg.Whitelist.Enabled = cfg.Whitelist.Enabled
	a.responseCfg.Whitelist.Paths = cfg.Whitelist.Paths
	a.responseCfg.Whitelist.Processes = cfg.Whitelist.Processes

	a.responseCfg.RansomwareExtensions = cfg.RansomwareExtensions

	// Save to file
	if err := a.responseCfg.SaveConfig("config/ransomware_extensions.json"); err != nil {
		return models.OperationResult{
			Success: false,
			Message: "Failed to save configuration: " + err.Error(),
		}
	}

	return models.OperationResult{
		Success: true,
		Message: "Configuration saved successfully",
	}
}

// GetActiveThreats returns all processes with threat scores > 0
func (a *App) GetActiveThreats() []models.ThreatViewModel {
	a.protectMux.RLock()
	isProtecting := a.isProtecting
	a.protectMux.RUnlock()

	if !isProtecting || a.detectionService == nil {
		return []models.ThreatViewModel{}
	}

	domainThreats := a.detectionService.GetAllThreats()
	threats := make([]models.ThreatViewModel, 0, len(domainThreats))
	for _, t := range domainThreats {
		threats = append(threats, models.ThreatFromDomain(t))
	}
	return threats
}

// GetEntropyStats returns entropy tracker statistics
func (a *App) GetEntropyStats() models.EntropyStatsVM {
	a.protectMux.RLock()
	isProtecting := a.isProtecting
	a.protectMux.RUnlock()

	if !isProtecting || a.detectionService == nil {
		return models.EntropyStatsVM{}
	}

	stats := a.detectionService.GetEntropyStats()
	result := models.EntropyStatsVM{}
	if v, ok := stats["tracked_files"].(int); ok {
		result.TrackedFiles = v
	}
	if v, ok := stats["modified_files"].(int); ok {
		result.ModifiedFiles = v
	}
	if v, ok := stats["significant_increases"].(int); ok {
		result.SignificantIncreases = v
	}
	return result
}

// LoadMLModel loads an ONNX model file and initializes the inference session.
func (a *App) LoadMLModel(filePath string) models.OperationResult {
	a.mlMux.Lock()
	defer a.mlMux.Unlock()

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return models.OperationResult{
			Success: false,
			Message: "Model file not found: " + filePath,
		}
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".onnx" {
		return models.OperationResult{
			Success: false,
			Message: "Only ONNX models are supported. Got: " + ext,
		}
	}

	// Close any previously loaded model
	if a.mlPredictor != nil {
		a.mlPredictor.Close()
		a.mlPredictor = nil
	}

	// Create ONNX predictor (looks for onnxruntime.dll next to exe, model dir, or PATH)
	predictor, err := infrastructure.NewONNXPredictor(filePath, "")
	if err != nil {
		log.Printf("[GUI] Failed to load ONNX model: %v", err)
		return models.OperationResult{
			Success: false,
			Message: "Failed to load ONNX model: " + err.Error(),
		}
	}

	a.mlPredictor = predictor
	modelName := filepath.Base(filePath)

	a.mlModelStatus = models.MLModelStatus{
		Loaded:              true,
		FilePath:            filePath,
		ModelName:           modelName,
		ModelType:           "ONNX Runtime",
		LoadedAt:            time.Now().Format(time.RFC3339),
		Enabled:             false,
		FeatureCount:        14,
		ConfidenceThreshold: 0.75,
	}

	// Wire predictor + callback into detection service if protection is running.
	a.applyMLSettingsToDetectionServiceLocked()

	log.Printf("[GUI] ML model loaded: %s (ONNX, 14 features)", modelName)

	return models.OperationResult{
		Success: true,
		Message: "Model loaded: " + modelName,
	}
}

// UnloadMLModel closes the ONNX session and clears the loaded model.
func (a *App) UnloadMLModel() models.OperationResult {
	a.mlMux.Lock()
	defer a.mlMux.Unlock()

	if a.mlPredictor != nil {
		a.mlPredictor.Close()
		a.mlPredictor = nil
	}

	// Disconnect from detection service
	if a.detectionService != nil {
		a.detectionService.SetMLPredictor(nil)
		a.detectionService.SetMLEnabled(false)
	}

	a.mlModelStatus = models.MLModelStatus{}

	log.Println("[GUI] ML model unloaded")

	return models.OperationResult{
		Success: true,
		Message: "Model unloaded successfully",
	}
}

// applyMLSettingsToDetectionServiceLocked forwards ML predictor/settings/callback into the running detection service.
// Caller must hold a.mlMux (read or write).
func (a *App) applyMLSettingsToDetectionServiceLocked() {
	if a.detectionService == nil {
		return
	}

	a.detectionService.SetMLPredictor(a.mlPredictor)
	a.detectionService.SetMLEnabled(a.mlModelStatus.Enabled)
	a.detectionService.SetMLConfidence(a.mlModelStatus.ConfidenceThreshold)
	a.detectionService.SetMLPredictionCallback(func(activity *domain.MLInferenceActivity) {
		if activity == nil || a.eventEmitter == nil {
			return
		}
		a.eventEmitter.EmitMLPrediction(a.mlPredictionVMFromActivity(activity))
	})
}

func (a *App) mlPredictionVMFromActivity(activity *domain.MLInferenceActivity) models.MLPredictionVM {
	processName := "UNKNOWN"
	processID := activity.ProcessID
	label := "unknown"
	confidence := 0.0
	probabilities := [3]float64{}
	timestamp := activity.Timestamp

	if strings.TrimSpace(activity.Image) != "" {
		processName = filepath.Base(activity.Image)
	}

	if pred := activity.Prediction; pred != nil {
		if strings.TrimSpace(pred.Image) != "" {
			processName = filepath.Base(pred.Image)
		}
		processID = pred.ProcessID
		if strings.TrimSpace(pred.LabelName) != "" {
			label = pred.LabelName
		}
		confidence = pred.Confidence
		probabilities = pred.Probabilities
		if timestamp.IsZero() {
			timestamp = pred.Timestamp
		}
	}

	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	return models.MLPredictionVM{
		ProcessName:         processName,
		ProcessID:           processID,
		Label:               label,
		Confidence:          confidence,
		Probabilities:       probabilities,
		Stage:               activity.Stage,
		Reason:              activity.Reason,
		Decision:            activity.Decision,
		DecisionCategory:    activity.DecisionCategory,
		DecisionScore:       activity.DecisionScore,
		DecisionAutoRespond: activity.DecisionAutoRespond,
		Threshold:           activity.Threshold,
		ModeEnabled:         activity.ModeEnabled,
		PredictorReady:      activity.PredictorReady,
		Error:               activity.Error,
		Timestamp:           timestamp.Format(time.RFC3339),
	}
}

// GetMLModelStatus returns current ML model info
func (a *App) GetMLModelStatus() models.MLModelStatus {
	a.mlMux.RLock()
	defer a.mlMux.RUnlock()
	return a.mlModelStatus
}

// SetMLDetectionEnabled toggles ML-based detection
func (a *App) SetMLDetectionEnabled(enabled bool) models.OperationResult {
	a.mlMux.Lock()
	defer a.mlMux.Unlock()

	if !a.mlModelStatus.Loaded && enabled {
		return models.OperationResult{
			Success: false,
			Message: "Cannot enable ML detection: no model loaded",
		}
	}

	a.mlModelStatus.Enabled = enabled

	// Forward to detection service
	if a.detectionService != nil {
		a.detectionService.SetMLEnabled(enabled)
	}

	log.Printf("[GUI] ML detection enabled: %v", enabled)

	status := "disabled"
	if enabled {
		status = "enabled"
	}
	return models.OperationResult{
		Success: true,
		Message: fmt.Sprintf("ML detection %s", status),
	}
}

// SetMLConfidenceThreshold sets the ML confidence threshold
func (a *App) SetMLConfidenceThreshold(threshold float64) models.OperationResult {
	a.mlMux.Lock()
	defer a.mlMux.Unlock()

	if threshold < 0.0 || threshold > 1.0 {
		return models.OperationResult{
			Success: false,
			Message: "Threshold must be between 0.0 and 1.0",
		}
	}

	a.mlModelStatus.ConfidenceThreshold = threshold

	// Forward to detection service
	if a.detectionService != nil {
		a.detectionService.SetMLConfidence(threshold)
	}

	return models.OperationResult{
		Success: true,
		Message: fmt.Sprintf("Confidence threshold set to %.2f", threshold),
	}
}

// SetDetectionMode sets the detection mode: rules_only, hybrid, or ml_only.
func (a *App) SetDetectionMode(mode string) models.OperationResult {
	if !config.IsValidDetectionMode(mode) {
		return models.OperationResult{
			Success: false,
			Message: "Invalid detection mode. Must be rules_only, hybrid, or ml_only",
		}
	}

	// hybrid and ml_only require an ML model
	a.mlMux.RLock()
	mlLoaded := a.mlModelStatus.Loaded
	a.mlMux.RUnlock()
	if config.DetectionModeRequiresML(mode) && !mlLoaded {
		return models.OperationResult{
			Success: false,
			Message: fmt.Sprintf("Cannot set %s mode: no ML model loaded", mode),
		}
	}

	if a.detectionService != nil {
		a.detectionService.SetDetectionMode(mode)
	}

	// Persist to config
	if a.responseCfg != nil {
		a.responseCfg.ResponseSettings.DetectionMode = mode
	}

	return models.OperationResult{
		Success: true,
		Message: fmt.Sprintf("Detection mode set to %s", mode),
	}
}

// GetDetectionMode returns the current detection mode.
func (a *App) GetDetectionMode() string {
	if a.detectionService != nil {
		return a.detectionService.GetDetectionMode()
	}
	if a.responseCfg != nil && a.responseCfg.ResponseSettings.DetectionMode != "" {
		return a.responseCfg.ResponseSettings.DetectionMode
	}
	return "rules_only"
}

// SetCanaryResponseAction sets the canary response action: terminate, suspend, or alert_only.
func (a *App) SetCanaryResponseAction(action string) models.OperationResult {
	if action != "terminate" && action != "suspend" && action != "alert_only" {
		return models.OperationResult{
			Success: false,
			Message: "Invalid canary response action. Must be terminate, suspend, or alert_only",
		}
	}

	if a.detectionService != nil {
		a.detectionService.SetCanaryResponseAction(action)
	}

	// Persist to config
	if a.responseCfg != nil {
		a.responseCfg.ResponseSettings.CanaryResponseAction = action
	}

	return models.OperationResult{
		Success: true,
		Message: fmt.Sprintf("Canary response action set to %s", action),
	}
}

// GetCanaryResponseAction returns the current canary response action.
func (a *App) GetCanaryResponseAction() string {
	if a.detectionService != nil {
		return a.detectionService.GetCanaryResponseAction()
	}
	if a.responseCfg != nil && a.responseCfg.ResponseSettings.CanaryResponseAction != "" {
		return a.responseCfg.ResponseSettings.CanaryResponseAction
	}
	return "terminate"
}

// SelectMLModelFile opens a file dialog to select an ML model file
func (a *App) SelectMLModelFile() string {
	selection, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select ML Model File",
		Filters: []runtime.FileFilter{
			{DisplayName: "ML Models", Pattern: "*.onnx;*.pkl;*.joblib;*.pt;*.pth;*.h5"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
	if err != nil {
		log.Printf("[GUI] File dialog error: %v", err)
		return ""
	}
	return selection
}

// reportStatistics periodically emits statistics to the frontend
func (a *App) reportStatistics(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopStats:
			return
		case <-ticker.C:
			stats := a.GetDashboardStats()
			a.eventEmitter.EmitStatsUpdate(stats)

			// Emit threat updates
			threats := a.GetActiveThreats()
			a.eventEmitter.EmitThreatUpdate(threats)
		}
	}
}

// streamAlerts streams alerts to the frontend
func (a *App) streamAlerts(ctx context.Context) {
	if a.detectionService == nil {
		return
	}

	alertChan := a.detectionService.GetAlertChannel()
	if alertChan == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopStats:
			return
		case alert, ok := <-alertChan:
			if !ok {
				return
			}
			a.eventEmitter.EmitAlert(models.AlertFromDomain(alert))
			// Forward to syslog (alerts are split between orchestrator and GUI stream)
			if a.responseOrchestrator != nil {
				a.responseOrchestrator.ForwardAlertToSyslog(alert)
			}
		}
	}
}

// GetLogs returns recent log entries
func (a *App) GetLogs(limit int) []logger.LogEntry {
	if limit <= 0 {
		limit = 100
	}
	return a.logCapture.GetEntries(limit)
}

// ClearLogs clears all log entries
func (a *App) ClearLogs() {
	a.logCapture.Clear()
}

// StartLogStream starts streaming logs to the frontend
func (a *App) StartLogStream() {
	a.stopLogs = make(chan struct{})
	go a.streamLogs()
}

// StopLogStream stops the log streaming
func (a *App) StopLogStream() {
	select {
	case <-a.stopLogs:
		// Already closed
	default:
		close(a.stopLogs)
	}
}

// streamLogs streams log entries to the frontend
func (a *App) streamLogs() {
	logChan := a.logCapture.Subscribe()
	defer a.logCapture.Unsubscribe(logChan)

	for {
		select {
		case <-a.stopLogs:
			return
		case entry, ok := <-logChan:
			if !ok {
				return
			}
			a.eventEmitter.EmitLogEntry(entry)
		}
	}
}
