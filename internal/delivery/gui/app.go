//go:build windows

package gui

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"procSniper/config"
	"procSniper/internal/delivery/gui/events"
	"procSniper/internal/delivery/gui/logger"
	"procSniper/internal/delivery/gui/models"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

// App is the main application struct for the GUI
type App struct {
	ctx context.Context

	// Services
	detectionService     *usecase.DetectionService
	responseOrchestrator *usecase.ResponseOrchestrator
	sysmonConsumer       *infrastructure.SysmonConsumer
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
	stopStats chan struct{}
	stopLogs  chan struct{}
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
	a.detectionService = usecase.NewDetectionService(
		a.responseCfg.DetectionThresholds.HighEntropyFileThreshold,
		a.responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold,
		a.responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
		a.cfg.EnableRansomNoteDetection,
		a.cfg.RansomwareExtensions,
	)

	// Setup canary files
	if err := a.detectionService.SetupCanaryFiles(); err != nil {
		log.Printf("[GUI] WARNING: Failed to setup canary files: %v", err)
	} else {
		go a.detectionService.StartCanaryMonitoring(ctx)
	}

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

	// Initialize response orchestrator
	a.responseOrchestrator = usecase.NewResponseOrchestrator(
		a.detectionService,
		a.responseActions,
		a.responseCfg,
	)
	if err := a.responseOrchestrator.Start(ctx); err != nil {
		cancel()
		return models.OperationResult{
			Success: false,
			Message: "Failed to start response orchestrator: " + err.Error(),
		}
	}

	// Initialize Sysmon consumer
	a.sysmonConsumer = infrastructure.NewSysmonConsumer(
		a.detectionService,
		a.cfg.WorkerPoolSize,
	)
	if err := a.sysmonConsumer.Start(ctx); err != nil {
		cancel()
		a.responseOrchestrator.Stop()
		return models.OperationResult{
			Success: false,
			Message: "Failed to start Sysmon consumer: " + err.Error(),
		}
	}

	// Initialize Security Log consumer
	a.securityLogConsumer = infrastructure.NewSecurityLogConsumer(a.detectionService, a.cfg)
	if err := a.securityLogConsumer.Start(ctx); err != nil {
		log.Printf("[GUI] WARNING: Security Log consumer failed: %v", err)
		a.securityLogConsumer = nil
	}

	a.isProtecting = true
	a.stopStats = make(chan struct{})

	// Start statistics reporter
	go a.reportStatistics(ctx)

	// Start alert streaming to frontend
	go a.streamAlerts(ctx)

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

	// Stop components in reverse order
	if a.securityLogConsumer != nil {
		a.securityLogConsumer.Stop()
	}

	if a.sysmonConsumer != nil {
		a.sysmonConsumer.Stop()
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

	// Get Sysmon stats
	if a.sysmonConsumer != nil {
		sysmonStats := a.sysmonConsumer.GetStats()
		if running, ok := sysmonStats["running"].(bool); ok {
			stats.SysmonConnected = running
		}
		if queueLen, ok := sysmonStats["channel_length"].(int); ok {
			stats.WorkerQueueDepth = queueLen
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
	}

	// Get canary stats
	if a.detectionService != nil {
		canaryStats := a.detectionService.GetCanaryStats()
		if total, ok := canaryStats["total_canaries"].(int); ok {
			stats.CanaryFilesCount = total
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
			CombinedEntropyAndExtensionThreshold: a.responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
		},
		ResponseSettings: models.ResponseSettingsVM{
			AutoTerminateEnabled:   a.responseCfg.ResponseSettings.AutoTerminateEnabled,
			CriticalScoreThreshold: a.responseCfg.ResponseSettings.CriticalScoreThreshold,
			InvestigationMode:      a.responseCfg.ResponseSettings.InvestigationMode,
			QuarantineFiles:        a.responseCfg.ResponseSettings.QuarantineFiles,
			QuarantineDirectory:    a.responseCfg.ResponseSettings.QuarantineDirectory,
		},
		Whitelist: models.WhitelistVM{
			Enabled: a.responseCfg.Whitelist.Enabled,
			Paths:   a.responseCfg.Whitelist.Paths,
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
	a.responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold = cfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold

	a.responseCfg.ResponseSettings.AutoTerminateEnabled = cfg.ResponseSettings.AutoTerminateEnabled
	a.responseCfg.ResponseSettings.CriticalScoreThreshold = cfg.ResponseSettings.CriticalScoreThreshold
	a.responseCfg.ResponseSettings.InvestigationMode = cfg.ResponseSettings.InvestigationMode
	a.responseCfg.ResponseSettings.QuarantineFiles = cfg.ResponseSettings.QuarantineFiles
	a.responseCfg.ResponseSettings.QuarantineDirectory = cfg.ResponseSettings.QuarantineDirectory

	a.responseCfg.Whitelist.Enabled = cfg.Whitelist.Enabled
	a.responseCfg.Whitelist.Paths = cfg.Whitelist.Paths

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
