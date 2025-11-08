package usecase

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"procSniper/config"
	"procSniper/internal/domain"
	"procSniper/internal/infrastructure"
	"strings"
	"sync"
	"time"
)

// ResponseOrchestrator manages automated response to detected threats
type ResponseOrchestrator struct {
	detectionService *DetectionService
	responseActions  *infrastructure.ResponseActions
	responseConfig   *config.ResponseConfig
	wg               sync.WaitGroup
	mu               sync.RWMutex
	running          bool

	// Statistics
	stats struct {
		processesTerminated int
		filesQuarantined    int
		alertsProcessed     int
		autoResponsesBlocked int
	}
}

// NewResponseOrchestrator creates a new response orchestrator
func NewResponseOrchestrator(
	detectionService *DetectionService,
	responseActions *infrastructure.ResponseActions,
	responseConfig *config.ResponseConfig,
) *ResponseOrchestrator {
	return &ResponseOrchestrator{
		detectionService: detectionService,
		responseActions:  responseActions,
		responseConfig:   responseConfig,
		running:          false,
	}
}

// Start begins processing alerts and executing automated responses
func (ro *ResponseOrchestrator) Start(ctx context.Context) error {
	ro.mu.Lock()
	if ro.running {
		ro.mu.Unlock()
		return fmt.Errorf("response orchestrator already running")
	}
	ro.running = true
	ro.mu.Unlock()

	log.Println("[*] Starting automated response orchestrator...")
	log.Printf("[*] Auto-terminate enabled: %v\n", ro.responseConfig.ResponseSettings.AutoTerminateEnabled)
	log.Printf("[*] Critical score threshold: %d\n", ro.responseConfig.ResponseSettings.CriticalScoreThreshold)
	log.Printf("[*] Terminate on extension match: %v\n", ro.responseConfig.ResponseSettings.TerminateOnExtensionMatch)
	log.Printf("[*] Investigation mode: %v\n", ro.responseConfig.ResponseSettings.InvestigationMode)

	// Enable SeDebugPrivilege for process termination
	if err := ro.responseActions.EnableDebugPrivilege(); err != nil {
		log.Printf("[!] WARNING: Failed to enable SeDebugPrivilege: %v\n", err)
		log.Println("[!] Process termination may fail for system processes")
	} else {
		log.Println("[+] SeDebugPrivilege enabled successfully")
	}

	// Start alert processing worker
	ro.wg.Add(1)
	go ro.alertProcessor(ctx)

	log.Println("[+] Response orchestrator started successfully")
	return nil
}

// Stop gracefully shuts down the orchestrator
func (ro *ResponseOrchestrator) Stop() {
	ro.mu.Lock()
	if !ro.running {
		ro.mu.Unlock()
		return
	}
	ro.running = false
	ro.mu.Unlock()

	log.Println("[*] Stopping response orchestrator...")
	ro.wg.Wait()

	// Print statistics
	ro.mu.RLock()
	log.Printf("[*] Response Orchestrator Statistics:\n")
	log.Printf("    - Alerts processed: %d\n", ro.stats.alertsProcessed)
	log.Printf("    - Processes terminated: %d\n", ro.stats.processesTerminated)
	log.Printf("    - Files quarantined: %d\n", ro.stats.filesQuarantined)
	log.Printf("    - Auto-responses blocked (whitelist/investigation): %d\n", ro.stats.autoResponsesBlocked)
	ro.mu.RUnlock()

	log.Println("[+] Response orchestrator stopped")
}

// alertProcessor processes alerts and executes automated responses
func (ro *ResponseOrchestrator) alertProcessor(ctx context.Context) {
	defer ro.wg.Done()

	log.Println("[+] Alert processor started")

	// Get alert channel from detection service
	alertChannel := ro.detectionService.GetAlertChannel()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] Alert processor stopped (context cancelled)")
			return
		case alert, ok := <-alertChannel:
			if !ok {
				log.Println("[*] Alert processor stopped (channel closed)")
				return
			}

			ro.processAlert(ctx, alert)
		}
	}
}

// processAlert processes a single alert and decides on response
func (ro *ResponseOrchestrator) processAlert(ctx context.Context, alert *domain.Alert) {
	ro.mu.Lock()
	ro.stats.alertsProcessed++
	ro.mu.Unlock()

	// Log alert
	ro.logAlert(alert)

	// Check if auto-response should be triggered
	extensionMatch := ro.hasRansomwareExtension(alert)
	imagePath := alert.Image

	shouldTerminate := ro.responseConfig.ShouldAutoTerminate(
		alert.Score,
		extensionMatch,
		imagePath,
	)

	if !shouldTerminate {
		// No auto-response needed
		if ro.responseConfig.ResponseSettings.InvestigationMode {
			log.Printf("[*] INVESTIGATION MODE: Would terminate PID %d (Score: %d, Level: %s)\n",
				alert.ProcessID, alert.Score, alert.Severity)
		}

		ro.mu.Lock()
		ro.stats.autoResponsesBlocked++
		ro.mu.Unlock()
		return
	}

	// Execute automated response
	ro.executeAutomatedResponse(ctx, alert, extensionMatch)
}

// executeAutomatedResponse performs the actual response actions
func (ro *ResponseOrchestrator) executeAutomatedResponse(ctx context.Context, alert *domain.Alert, extensionMatch bool) {
	log.Printf("\n╔════════════════════════════════════════════════════════════╗\n")
	log.Printf("║           AUTOMATED RESPONSE TRIGGERED                     ║\n")
	log.Printf("╚════════════════════════════════════════════════════════════╝\n")
	log.Printf("[!] Process: %s (PID: %d)\n", alert.Image, alert.ProcessID)
	log.Printf("[!] Threat Level: %s (Score: %d)\n", alert.Severity, alert.Score)
	log.Printf("[!] Category: %s\n", alert.Category)
	log.Printf("[!] Extension Match: %v\n", extensionMatch)

	// Optional: Suspend before terminate for forensics
	if ro.responseConfig.ResponseSettings.SuspendBeforeTerminate {
		log.Printf("[*] Suspending process PID %d before termination...\n", alert.ProcessID)
		if err := ro.responseActions.SuspendProcess(uint32(alert.ProcessID)); err != nil {
			log.Printf("[!] Failed to suspend process: %v\n", err)
		} else {
			log.Println("[+] Process suspended successfully")
			time.Sleep(2 * time.Second) // Brief pause for logging/forensics
		}
	}

	// Quarantine files if configured
	if ro.responseConfig.ResponseSettings.QuarantineFiles {
		ro.quarantineRelatedFiles(alert)
	}

	// Terminate the process
	log.Printf("[!] TERMINATING PROCESS: PID %d\n", alert.ProcessID)
	if err := ro.responseActions.TerminateProcess(uint32(alert.ProcessID)); err != nil {
		log.Printf("[!] FAILED TO TERMINATE PROCESS: %v\n", err)
	} else {
		log.Printf("[+] PROCESS TERMINATED SUCCESSFULLY\n")
		ro.mu.Lock()
		ro.stats.processesTerminated++
		ro.mu.Unlock()
	}

	log.Printf("╔════════════════════════════════════════════════════════════╗\n")
	log.Printf("║           AUTOMATED RESPONSE COMPLETE                      ║\n")
	log.Printf("╚════════════════════════════════════════════════════════════╝\n\n")
}

// quarantineRelatedFiles quarantines files mentioned in alert evidence
func (ro *ResponseOrchestrator) quarantineRelatedFiles(alert *domain.Alert) {
	quarantineDir := ro.responseConfig.GetQuarantineDirectory()

	for _, indicator := range alert.Indicators {
		// Check evidence for file paths
		if filePath, exists := indicator.Evidence["file"]; exists {
			log.Printf("[*] Quarantining file: %s\n", filePath)

			if err := ro.responseActions.QuarantineFile(filePath, quarantineDir); err != nil {
				log.Printf("[!] Failed to quarantine file: %v\n", err)
			} else {
				log.Printf("[+] File quarantined: %s\n", filePath)
				ro.mu.Lock()
				ro.stats.filesQuarantined++
				ro.mu.Unlock()
			}
		}
	}
}

// hasRansomwareExtension checks if alert involves ransomware extensions
func (ro *ResponseOrchestrator) hasRansomwareExtension(alert *domain.Alert) bool {
	// Check indicators for ransomware extension evidence
	for _, indicator := range alert.Indicators {
		if indicator.Type == domain.IndicatorRansomExtension {
			return true
		}

		// Check evidence for file paths with ransomware extensions
		if filePath, exists := indicator.Evidence["file"]; exists {
			ext := strings.ToLower(filepath.Ext(filePath))
			if ro.responseConfig.IsRansomwareExtension(ext) {
				return true
			}
		}

		if targetFile, exists := indicator.Evidence["target_file"]; exists {
			ext := strings.ToLower(filepath.Ext(targetFile))
			if ro.responseConfig.IsRansomwareExtension(ext) {
				return true
			}
		}
	}

	return false
}

// logAlert writes alert to log file
func (ro *ResponseOrchestrator) logAlert(alert *domain.Alert) {
	if !ro.responseConfig.AlertSettings.VerboseLogging {
		return
	}

	log.Printf("\n[ALERT] Threat Detected\n")
	log.Printf("  Process: %s (PID: %d, GUID: %s)\n",
		alert.Image, alert.ProcessID, alert.ProcessGuid)
	log.Printf("  Threat Level: %s (Score: %d)\n", alert.Severity, alert.Score)
	log.Printf("  Category: %s\n", alert.Category)
	log.Printf("  Indicators: %d\n", len(alert.Indicators))

	for i, indicator := range alert.Indicators {
		log.Printf("    [%d] %s (Severity: %s, Points: %d)\n",
			i+1, indicator.Description, indicator.Severity, indicator.Points)
		log.Printf("        Type: %s\n", indicator.Type)

		if len(indicator.Evidence) > 0 {
			log.Printf("        Evidence:\n")
			for key, value := range indicator.Evidence {
				log.Printf("          - %s: %s\n", key, value)
			}
		}
	}
	log.Println()
}

// GetStats returns orchestrator statistics
func (ro *ResponseOrchestrator) GetStats() map[string]interface{} {
	ro.mu.RLock()
	defer ro.mu.RUnlock()

	return map[string]interface{}{
		"running":                ro.running,
		"alerts_processed":       ro.stats.alertsProcessed,
		"processes_terminated":   ro.stats.processesTerminated,
		"files_quarantined":      ro.stats.filesQuarantined,
		"auto_responses_blocked": ro.stats.autoResponsesBlocked,
	}
}

// UpdateResponseConfig updates the response configuration at runtime
func (ro *ResponseOrchestrator) UpdateResponseConfig(newConfig *config.ResponseConfig) {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	ro.responseConfig = newConfig
	log.Println("[*] Response configuration updated")
}
