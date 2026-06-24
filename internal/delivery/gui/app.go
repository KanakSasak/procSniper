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
	"procSniper/internal/app"
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

	// Composition root + the components it wires (cached so the read/setter methods below can
	// read them directly; the agent owns construction, lifecycle, and teardown).
	agent                *app.Agent
	detectionService     *usecase.DetectionService
	responseOrchestrator *usecase.ResponseOrchestrator
	etwConsumer          *infrastructure.KernelETWConsumer
	securityLogConsumer  *infrastructure.SecurityLogConsumer

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

	// Background streaming goroutines (dashboard stats, alerts, logs).
	streamer *streamer

	// ML Model state
	mlModelStatus models.MLModelStatus
	mlPredictor   domain.MLPredictor
	mlMux         sync.RWMutex
}

// NewApp creates a new App instance
func NewApp() *App {
	return &App{
		logCapture: logger.GetLogCapture(),
	}
}

// Startup is called when the app starts
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.eventEmitter = events.NewEmitter(ctx)
	a.streamer = newStreamer(a.eventEmitter, a.logCapture)

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

	// Build the protection graph via the shared composition root (internal/app). Detection mode and
	// canary action fall back to config inside app.New (matching the prior GUI behavior). A loaded ML
	// model is owned by the GUI across Start/Stop cycles, so it is INJECTED — the agent must not close
	// it on Stop (ownsPredictor stays false). Without a model loaded, ML stays disabled (as before).
	var opts []app.Option
	a.mlMux.RLock()
	if a.mlPredictor != nil {
		callback := func(activity *domain.MLInferenceActivity) {
			if activity == nil || a.eventEmitter == nil {
				return
			}
			a.eventEmitter.EmitMLPrediction(models.MLPredictionVMFromActivity(activity))
		}
		opts = append(opts, app.WithMLPredictor(a.mlPredictor, a.mlModelStatus.Enabled, a.mlModelStatus.ConfidenceThreshold, callback))
	}
	a.mlMux.RUnlock()

	agent, err := app.New(a.cfg, a.responseCfg, opts...)
	if err != nil {
		return models.OperationResult{
			Success: false,
			Message: err.Error(),
		}
	}

	if err := agent.Start(a.ctx); err != nil {
		return models.OperationResult{
			Success: false,
			Message: err.Error(),
		}
	}

	a.agent = agent
	// Cache the wired components so the GUI's stats/threat/ML-setter methods read them directly.
	a.detectionService = agent.DetectionService()
	a.responseOrchestrator = agent.Orchestrator()
	a.etwConsumer = agent.ETWConsumer()
	a.securityLogConsumer = agent.SecurityLogConsumer()

	a.isProtecting = true

	// GUI presentation streams (frontend dashboard stats + alert streaming) — stopped in StopProtection.
	a.streamer.startProtectionStreams(
		a.detectionService.GetAlertChannel(),
		a.responseOrchestrator.ForwardAlertToSyslog,
		a.GetDashboardStats,
		a.GetActiveThreats,
	)

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

	// Stop the GUI presentation goroutines first (they read the components the agent is about to
	// stop), then tear down the whole graph via the composition root. The agent cancels the run
	// context, JOINS its background goroutines (canary monitor, maintenance, periodic thread
	// protection) via a WaitGroup — a real join in place of the old fixed 2s sleep — stops the
	// components in reverse order, and removes the canary files. The GUI-owned ML predictor is NOT
	// closed here; it persists across Start/Stop via LoadMLModel/UnloadMLModel.
	a.streamer.stopProtectionStreams()

	if a.agent != nil {
		a.agent.Stop()
		a.agent = nil
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

// GetDashboardStats returns current statistics for the dashboard.
func (a *App) GetDashboardStats() models.DashboardStats {
	a.protectMux.RLock()
	isProtecting := a.isProtecting
	a.protectMux.RUnlock()

	if !isProtecting {
		return models.DashboardStats{ProtectionStatus: "Stopped"}
	}

	var (
		etw         infrastructure.ETWConsumerStats
		orch        usecase.OrchestrationStats
		entropy     domain.EntropyStats
		canaryCount int
		threatCount int
		highIO      int
	)
	if a.etwConsumer != nil {
		etw = a.etwConsumer.GetStats()
	}
	if a.responseOrchestrator != nil {
		orch = a.responseOrchestrator.GetStats()
	}
	if a.detectionService != nil {
		canaryCount = a.detectionService.GetCanaryStats().TotalCanaries
		threatCount = len(a.detectionService.GetAllThreats())
		highIO = a.detectionService.GetHighIOProcessCount()
		entropy = a.detectionService.GetEntropyStats()
	}

	stats := models.DashboardStatsFromStats(etw, orch, canaryCount, entropy)
	stats.ActiveThreatsCount = threatCount
	stats.HighIOProcessCount = highIO
	return stats
}

// GetConfiguration returns the current configuration.
func (a *App) GetConfiguration() models.ConfigViewModel {
	return models.ConfigViewModelFromResponseConfig(a.responseCfg)
}

// SaveConfiguration writes the edited configuration back and persists it.
func (a *App) SaveConfiguration(cfg models.ConfigViewModel) models.OperationResult {
	if a.responseCfg == nil {
		return models.OperationResult{
			Success: false,
			Message: "Configuration not loaded",
		}
	}

	cfg.ApplyToResponseConfig(a.responseCfg)

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

	return models.EntropyStatsVMFromStats(a.detectionService.GetEntropyStats())
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
		a.eventEmitter.EmitMLPrediction(models.MLPredictionVMFromActivity(activity))
	})
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

// StartLogStream starts streaming logs to the frontend.
func (a *App) StartLogStream() {
	a.streamer.startLogStream()
}

// StopLogStream stops the log streaming.
func (a *App) StopLogStream() {
	a.streamer.stopLogStream()
}
