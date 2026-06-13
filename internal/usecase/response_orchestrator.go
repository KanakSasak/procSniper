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

// ProcessTerminationSink receives successful process-termination outcomes for cross-component coordination.
type ProcessTerminationSink interface {
	MarkProcessTerminated(pid uint32, processGuid string, image string, at time.Time, source string)
}

// ResponseOrchestrator manages automated response to detected threats
type ResponseOrchestrator struct {
	detectionService *DetectionService
	responseActions  *infrastructure.ResponseActions
	responseConfig   *config.ResponseConfig
	wg               sync.WaitGroup
	mu               sync.RWMutex
	running          bool
	responseDedup    map[string]time.Time
	responseDedupTTL time.Duration
	recentSuspends   map[uint32]time.Time
	recentSuspendTTL time.Duration
	terminationSink  ProcessTerminationSink
	syslogClient     *infrastructure.SyslogClient

	// Statistics
	stats struct {
		processesTerminated     int
		processesSuspended      int // offending processes frozen via the Suspend response strategy
		filesQuarantined        int
		alertsProcessed         int
		autoResponsesBlocked    int
		relatedSuspendAttempted int
		relatedSuspendSuccess   int
		relatedSuspendFailed    int
	}
}

// NewResponseOrchestrator creates a new response orchestrator
func NewResponseOrchestrator(
	detectionService *DetectionService,
	responseActions *infrastructure.ResponseActions,
	responseConfig *config.ResponseConfig,
) *ResponseOrchestrator {
	ro := &ResponseOrchestrator{
		detectionService: detectionService,
		responseActions:  responseActions,
		responseConfig:   responseConfig,
		running:          false,
		responseDedup:    make(map[string]time.Time),
		responseDedupTTL: 10 * time.Second,
		recentSuspends:   make(map[uint32]time.Time),
		recentSuspendTTL: 30 * time.Second,
	}

	// Initialize syslog client if enabled
	if responseConfig.AlertSettings.SendSyslog && responseConfig.AlertSettings.SyslogServer != "" {
		syslogCfg := infrastructure.SyslogConfig{
			Server:   responseConfig.AlertSettings.SyslogServer,
			Port:     responseConfig.AlertSettings.SyslogPort,
			Protocol: responseConfig.AlertSettings.SyslogProtocol,
			Facility: infrastructure.SyslogFacility(responseConfig.AlertSettings.SyslogFacility),
			Tag:      responseConfig.AlertSettings.SyslogTag,
		}
		client, err := infrastructure.NewSyslogClient(syslogCfg)
		if err != nil {
			log.Printf("[!] WARNING: Failed to initialize syslog client: %v", err)
			log.Println("[!] Syslog forwarding will be disabled")
		} else {
			ro.syslogClient = client
			log.Printf("[+] Syslog client initialized: %s:%d (%s)",
				syslogCfg.Server, syslogCfg.Port, syslogCfg.Protocol)
		}
	}

	return ro
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
	log.Printf("[*] Suspend related on canary: %v (min score: %d, window: %ds)\n",
		ro.responseConfig.ResponseSettings.SuspendRelatedOnCanary,
		ro.responseConfig.ResponseSettings.RelatedSuspicionMinScore,
		ro.responseConfig.ResponseSettings.RelatedActorWindowSeconds,
	)
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
	log.Printf("    - Related suspends attempted: %d\n", ro.stats.relatedSuspendAttempted)
	log.Printf("    - Related suspends successful: %d\n", ro.stats.relatedSuspendSuccess)
	log.Printf("    - Related suspends failed: %d\n", ro.stats.relatedSuspendFailed)
	ro.mu.RUnlock()

	// Close syslog connection
	if ro.syslogClient != nil {
		ro.syslogClient.Close()
		log.Println("[*] Syslog client closed")
	}

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

	// Forward to syslog if configured
	ro.sendSyslogAlert(alert)

	// PRIMARY GATE (Phase 4): the detection layer owns the respond/no-respond verdict.
	// alert.AutoRespond is set upstream by ShouldAutoRespond (rule path, ThreatCritical),
	// the ML decision policy, or the canary manager. The config checks below are
	// VETO-ONLY: they may downgrade a true verdict to no-action, but must NEVER upgrade a
	// false one. Checking it here — before ShouldAutoTerminate — makes that structural:
	// termination is unreachable for any AutoRespond=false alert, whatever its score or
	// extension match.
	if !alert.AutoRespond {
		ro.mu.Lock()
		ro.stats.autoResponsesBlocked++
		ro.mu.Unlock()
		return
	}

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
	if ro.isDuplicateAutoResponse(alert) {
		log.Printf("[*] Skipping duplicate auto-response for %s (PID: %d)\n", alert.ProcessGuid, alert.ProcessID)
		ro.mu.Lock()
		ro.stats.autoResponsesBlocked++
		ro.mu.Unlock()
		return
	}

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

	if ro.responseConfig.ResponseSettings.SuspendRelatedOnCanary && ro.isCanaryCompromiseAlert(alert) {
		ro.suspendRelatedProcesses(alert)
	}

	if alert.ProcessID <= 0 {
		log.Printf("[!] Skipping termination: invalid PID %d (Process: %s)\n", alert.ProcessID, alert.Image)
		ro.mu.Lock()
		ro.stats.autoResponsesBlocked++
		ro.mu.Unlock()
		return
	}

	// Response strategy: a Suspend-strategy alert (canary-response=suspend) freezes the offending
	// process for reversible containment / forensics instead of killing it (Phase 6 finding #3).
	// A suspended process is NOT marked dead — it may be resumed, so its ETW events must keep
	// flowing (no notifyProcessTerminated). Default/Terminate strategy falls through to terminate.
	if alert.Strategy == domain.ResponseStrategySuspend {
		log.Printf("[!] SUSPENDING PROCESS (strategy=suspend): PID %d\n", alert.ProcessID)
		if err := ro.responseActions.SuspendProcess(uint32(alert.ProcessID)); err != nil {
			log.Printf("[!] FAILED TO SUSPEND PROCESS: %v\n", err)
		} else {
			log.Printf("[+] PROCESS SUSPENDED (reversible containment): PID %d\n", alert.ProcessID)
			ro.mu.Lock()
			ro.stats.processesSuspended++
			ro.mu.Unlock()
		}
		log.Printf("╔════════════════════════════════════════════════════════════╗\n")
		log.Printf("║           AUTOMATED RESPONSE COMPLETE                      ║\n")
		log.Printf("╚════════════════════════════════════════════════════════════╝\n\n")
		return
	}

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

	// Terminate the process with verification and escalation.
	log.Printf("[!] TERMINATING PROCESS: PID %d\n", alert.ProcessID)
	terminated, alreadyExited, err := ro.responseActions.TerminateProcessVerified(
		uint32(alert.ProcessID),
		3,
		250*time.Millisecond,
		true, // locked decision: retry + suspend escalation
	)
	if err != nil {
		log.Printf("[!] FAILED TO TERMINATE PROCESS: %v\n", err)
		if alive, checkErr := ro.responseActions.IsProcessAlive(uint32(alert.ProcessID)); checkErr == nil {
			if alive {
				log.Printf("[!] PROCESS STILL ALIVE AFTER VERIFIED TERMINATION ATTEMPTS: PID %d\n", alert.ProcessID)
			} else {
				log.Printf("[+] Process exited despite termination error state (PID: %d)\n", alert.ProcessID)
			}
		} else {
			log.Printf("[!] Could not verify final process state for PID %d: %v\n", alert.ProcessID, checkErr)
		}
	} else if alreadyExited {
		log.Printf("[+] PROCESS ALREADY EXITED (PID: %d)\n", alert.ProcessID)
		ro.notifyProcessTerminated(alert, "already_exited")
	} else if terminated {
		log.Printf("[+] PROCESS TERMINATED AND VERIFIED\n")
		ro.mu.Lock()
		ro.stats.processesTerminated++
		ro.mu.Unlock()
		ro.notifyProcessTerminated(alert, "terminate_verified")
	} else {
		log.Printf("[!] Termination finished without a definitive outcome (PID: %d)\n", alert.ProcessID)
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

func isCanaryIndicatorTypeForResponse(indicatorType domain.IndicatorType) bool {
	if indicatorType == domain.IndicatorCanaryCompromised {
		return true
	}
	return strings.HasPrefix(strings.ToUpper(string(indicatorType)), "CANARY_")
}

func (ro *ResponseOrchestrator) isCanaryCompromiseAlert(alert *domain.Alert) bool {
	if alert == nil {
		return false
	}

	for _, indicator := range alert.Indicators {
		if isCanaryIndicatorTypeForResponse(indicator.Type) {
			return true
		}
	}
	return false
}

func (ro *ResponseOrchestrator) cleanupRecentSuspendsLocked(now time.Time) {
	for pid, ts := range ro.recentSuspends {
		if now.Sub(ts) > ro.recentSuspendTTL {
			delete(ro.recentSuspends, pid)
		}
	}
}

func (ro *ResponseOrchestrator) shouldSkipRecentSuspend(pid uint32, now time.Time) bool {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	ro.cleanupRecentSuspendsLocked(now)
	if ts, exists := ro.recentSuspends[pid]; exists && now.Sub(ts) <= ro.recentSuspendTTL {
		return true
	}
	return false
}

func (ro *ResponseOrchestrator) markRecentSuspend(pid uint32, now time.Time) {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	ro.cleanupRecentSuspendsLocked(now)
	ro.recentSuspends[pid] = now
}

func (ro *ResponseOrchestrator) suspendRelatedProcesses(alert *domain.Alert) (attempted int, suspended int) {
	if alert == nil || len(alert.RelatedProcesses) == 0 {
		return 0, 0
	}

	now := time.Now()
	minScore := ro.responseConfig.ResponseSettings.RelatedSuspicionMinScore
	if minScore <= 0 {
		minScore = 50
	}
	windowSec := ro.responseConfig.ResponseSettings.RelatedActorWindowSeconds
	if windowSec <= 0 {
		windowSec = 60
	}
	relatedWindow := time.Duration(windowSec) * time.Second

	skippedDuplicates := 0
	failed := 0
	localSeen := make(map[int]struct{}, len(alert.RelatedProcesses)+1)
	if alert.ProcessID > 0 {
		localSeen[alert.ProcessID] = struct{}{}
	}
	attemptedPIDs := make([]string, 0, len(alert.RelatedProcesses))

	for _, related := range alert.RelatedProcesses {
		pid := related.ProcessID
		if pid <= 4 {
			continue
		}
		if _, exists := localSeen[pid]; exists {
			skippedDuplicates++
			continue
		}
		localSeen[pid] = struct{}{}

		if related.RelationScore < minScore {
			continue
		}
		if !related.LastSeen.IsZero() && now.Sub(related.LastSeen) > relatedWindow {
			continue
		}
		if ro.responseConfig.IsWhitelisted(related.Image) {
			continue
		}

		pid32 := uint32(pid)
		if ro.shouldSkipRecentSuspend(pid32, now) {
			skippedDuplicates++
			continue
		}

		attempted++
		attemptedPIDs = append(attemptedPIDs, fmt.Sprintf("%d", pid))
		if err := ro.responseActions.SuspendProcess(pid32); err != nil {
			failed++
			log.Printf("[!] Failed to suspend related process PID %d (%s): %v\n", pid, related.Image, err)
			ro.markRecentSuspend(pid32, now)
			continue
		}

		suspended++
		ro.markRecentSuspend(pid32, now)
		log.Printf("[+] RELATED PROCESS SUSPENDED: %s (PID: %d, score: %d, reason: %s)\n",
			related.Image, related.ProcessID, related.RelationScore, related.Reason)
	}

	ro.mu.Lock()
	ro.stats.relatedSuspendAttempted += attempted
	ro.stats.relatedSuspendSuccess += suspended
	ro.stats.relatedSuspendFailed += failed
	ro.mu.Unlock()

	if attempted > 0 || skippedDuplicates > 0 {
		log.Printf("[*] Related suspension summary: attempted=%d, suspended=%d, failed=%d, skipped=%d, pids=[%s]\n",
			attempted, suspended, failed, skippedDuplicates, strings.Join(attemptedPIDs, ","))
	}

	return attempted, suspended
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

// sendSyslogAlert forwards an alert to the remote syslog server.
// Failures are logged but never block alert processing.
func (ro *ResponseOrchestrator) sendSyslogAlert(alert *domain.Alert) {
	if ro.syslogClient == nil {
		return
	}
	if err := ro.syslogClient.SendAlert(alert); err != nil {
		log.Printf("[!] Syslog send failed: %v", err)
	}
}

// ForwardAlertToSyslog sends an alert to syslog without processing it for response.
// Used by GUI mode where alerts are split between orchestrator and frontend stream.
func (ro *ResponseOrchestrator) ForwardAlertToSyslog(alert *domain.Alert) {
	ro.sendSyslogAlert(alert)
}

// GetStats returns orchestrator statistics
func (ro *ResponseOrchestrator) GetStats() map[string]interface{} {
	ro.mu.RLock()
	defer ro.mu.RUnlock()

	return map[string]interface{}{
		"running":                   ro.running,
		"alerts_processed":          ro.stats.alertsProcessed,
		"processes_terminated":      ro.stats.processesTerminated,
		"processes_suspended":       ro.stats.processesSuspended,
		"files_quarantined":         ro.stats.filesQuarantined,
		"auto_responses_blocked":    ro.stats.autoResponsesBlocked,
		"related_suspend_attempted": ro.stats.relatedSuspendAttempted,
		"related_suspend_success":   ro.stats.relatedSuspendSuccess,
		"related_suspend_failed":    ro.stats.relatedSuspendFailed,
	}
}

// UpdateResponseConfig updates the response configuration at runtime
func (ro *ResponseOrchestrator) UpdateResponseConfig(newConfig *config.ResponseConfig) {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	ro.responseConfig = newConfig
	log.Println("[*] Response configuration updated")
}

// SetProcessTerminationSink wires optional process-termination notifications to external consumers.
func (ro *ResponseOrchestrator) SetProcessTerminationSink(sink ProcessTerminationSink) {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	ro.terminationSink = sink
}

func (ro *ResponseOrchestrator) responseKey(alert *domain.Alert) string {
	if alert == nil {
		return ""
	}

	guid := strings.TrimSpace(alert.ProcessGuid)
	if guid != "" && !strings.EqualFold(guid, "UNKNOWN") {
		return "guid:" + guid
	}
	if alert.ProcessID > 0 {
		return fmt.Sprintf("pid:%d", alert.ProcessID)
	}
	return ""
}

func (ro *ResponseOrchestrator) isDuplicateAutoResponse(alert *domain.Alert) bool {
	key := ro.responseKey(alert)
	if key == "" {
		return false
	}

	now := time.Now()

	ro.mu.Lock()
	defer ro.mu.Unlock()

	for existingKey, ts := range ro.responseDedup {
		if now.Sub(ts) > ro.responseDedupTTL {
			delete(ro.responseDedup, existingKey)
		}
	}

	if ts, exists := ro.responseDedup[key]; exists && now.Sub(ts) <= ro.responseDedupTTL {
		return true
	}

	ro.responseDedup[key] = now
	return false
}

func (ro *ResponseOrchestrator) notifyProcessTerminated(alert *domain.Alert, source string) {
	if alert == nil || alert.ProcessID <= 0 {
		return
	}

	ro.mu.RLock()
	sink := ro.terminationSink
	ro.mu.RUnlock()

	if sink == nil {
		return
	}

	sink.MarkProcessTerminated(
		uint32(alert.ProcessID),
		alert.ProcessGuid,
		alert.Image,
		time.Now(),
		source,
	)
}
