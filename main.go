//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"procSniper/config"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

func main() {
	// Setup logging to both console and file
	logFile, err := infrastructure.SetupLogging("logs")
	if err != nil {
		// Fallback to console-only logging if file setup fails
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
		log.Printf("[!] Failed to setup file logging: %v\n", err)
		log.Println("[*] Using console-only logging")
	} else {
		// Ensure log file is closed on exit
		defer logFile.Close()
	}

	// Load application configuration
	cfg := config.Load()

	// Load response configuration (ransomware extensions, auto-response settings)
	responseCfg, err := config.LoadResponseConfig("config/ransomware_extensions.json")
	if err != nil {
		log.Fatalf("[!] Failed to load response configuration: %v\n", err)
	}

	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║                    procSniper v1.0                         ║")
	log.Println("║         Real-Time Ransomware & Stealer Detection           ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
	log.Println()

	// Parse command
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "protect":
		runProtectionMode(cfg, responseCfg)
	case "config":
		showConfiguration(responseCfg)
	case "version":
		showVersion()
	default:
		printUsage()
		os.Exit(1)
	}
}

// runProtectionMode starts real-time protection
func runProtectionMode(cfg *config.Config, responseCfg *config.ResponseConfig) {
	log.Println("[*] Initializing real-time protection...")

	// Cleanup old log files (keep logs from last 7 days)
	if err := infrastructure.CleanupOldLogs("logs", 7*24*time.Hour); err != nil {
		log.Printf("[!] Failed to cleanup old logs: %v\n", err)
	}

	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Declare detection service and security log consumer at function scope for cleanup access
	var detectionService *usecase.DetectionService
	var securityLogConsumer *infrastructure.SecurityLogConsumer

	// Initialize detection service with thresholds from config
	log.Println("[*] Initializing detection engine...")
	log.Printf("[*] Detection thresholds:")
	log.Printf("    - High Entropy: %d files", responseCfg.DetectionThresholds.HighEntropyFileThreshold)
	log.Printf("    - Ransomware Extension: %d files", responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold)
	log.Printf("    - Combined (High Entropy + Extension): %d files (IMMEDIATE TERMINATION)",
		responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold)
	log.Printf("[*] Detection mode:")
	log.Printf("    - Ransom Note Detection: %v (focus on behavioral detection)", cfg.EnableRansomNoteDetection)

	detectionService = usecase.NewDetectionService(
		responseCfg.DetectionThresholds.HighEntropyFileThreshold,
		responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold,
		responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
		cfg.EnableRansomNoteDetection,
		cfg.RansomwareExtensions,
	)
	log.Println("[+] Detection engine initialized")

	// Setup canary files (honeypot detection)
	log.Println("[*] Setting up canary files for honeypot detection...")
	if err := detectionService.SetupCanaryFiles(); err != nil {
		log.Printf("[!] WARNING: Failed to setup canary files: %v\n", err)
		log.Println("[!] Honeypot detection will be disabled")
	} else {
		log.Println("[+] Canary files deployed successfully")
		// Start canary monitoring in background
		go detectionService.StartCanaryMonitoring(ctx)
	}

	// Initialize response actions
	log.Println("[*] Initializing response actions...")
	responseActions, err := infrastructure.NewResponseActions()
	if err != nil {
		log.Fatalf("[!] Failed to initialize response actions: %v\n", err)
	}
	log.Println("[+] Response actions initialized")

	// Initialize response orchestrator
	log.Println("[*] Initializing response orchestrator...")
	responseOrchestrator := usecase.NewResponseOrchestrator(
		detectionService,
		responseActions,
		responseCfg,
	)
	if err := responseOrchestrator.Start(ctx); err != nil {
		log.Fatalf("[!] Failed to start response orchestrator: %v\n", err)
	}

	// Initialize Sysmon event consumer
	log.Println("[*] Initializing Sysmon event consumer...")
	sysmonConsumer := infrastructure.NewSysmonConsumer(
		detectionService,
		cfg.WorkerPoolSize,
	)
	if err := sysmonConsumer.Start(ctx); err != nil {
		log.Fatalf("[!] Failed to start Sysmon consumer: %v\n", err)
	}

	// Initialize Security Log consumer for BackupRead/BackupWrite API detection
	log.Println("[*] Initializing Windows Security Log consumer...")
	log.Println("[*] Monitoring for BackupRead/BackupWrite API usage (Sysmon Event ID 11 evasion)...")
	securityLogConsumer = infrastructure.NewSecurityLogConsumer(detectionService, cfg)
	if err := securityLogConsumer.Start(ctx); err != nil {
		log.Printf("[!] WARNING: Failed to start Security Log consumer: %v\n", err)
		log.Println("[!] BackupRead/BackupWrite API detection will be disabled")
		log.Println("[!] NOTE: Requires Administrator privileges and Security log access")
		securityLogConsumer = nil // Set to nil so we don't try to stop it later
	} else {
		log.Println("[+] Security Log consumer started successfully")
	}

	// Print configuration summary
	log.Println()
	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║              PROTECTION MODE ACTIVE                        ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
	log.Printf("[*] Auto-terminate: %v\n", responseCfg.ResponseSettings.AutoTerminateEnabled)
	log.Printf("[*] Critical score threshold: %d\n", responseCfg.ResponseSettings.CriticalScoreThreshold)
	log.Printf("[*] Terminate on extension match: %v\n", responseCfg.ResponseSettings.TerminateOnExtensionMatch)
	log.Printf("[*] Investigation mode: %v\n", responseCfg.ResponseSettings.InvestigationMode)
	log.Printf("[*] Ransomware extensions monitored: %d\n", len(responseCfg.RansomwareExtensions))
	log.Printf("[*] Worker pool size: %d\n", cfg.WorkerPoolSize)
	log.Println()
	log.Println("[+] procSniper is now protecting your system")
	log.Println("[*] Press Ctrl+C to stop...")
	log.Println()

	// Start statistics reporter
	stopStats := make(chan struct{})
	go reportStatistics(ctx, sysmonConsumer, responseOrchestrator, detectionService, stopStats)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	log.Println()
	log.Println("[*] Shutdown signal received, stopping protection...")
	close(stopStats)

	// Cancel context to stop all components
	cancel()

	// Wait a moment for graceful shutdown
	time.Sleep(2 * time.Second)

	// Stop components in reverse order
	if securityLogConsumer != nil {
		log.Println("[*] Stopping Security Log consumer...")
		securityLogConsumer.Stop()
	}

	log.Println("[*] Stopping Sysmon consumer...")
	sysmonConsumer.Stop()

	log.Println("[*] Stopping response orchestrator...")
	responseOrchestrator.Stop()

	// Cleanup canary files
	log.Println("[*] Cleaning up canary files...")
	detectionService.CleanupCanaryFiles()

	log.Println()
	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║              PROTECTION MODE STOPPED                       ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
	log.Println("[+] procSniper shutdown complete")
}

// reportStatistics periodically reports system statistics
func reportStatistics(
	ctx context.Context,
	sysmonConsumer *infrastructure.SysmonConsumer,
	responseOrchestrator *usecase.ResponseOrchestrator,
	detectionService *usecase.DetectionService,
	stop chan struct{},
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			sysmonStats := sysmonConsumer.GetStats()
			orchestratorStats := responseOrchestrator.GetStats()
			canaryStats := detectionService.GetCanaryStats()

			log.Println()
			log.Println("═══════════════════ STATISTICS ═══════════════════")
			log.Printf("[Sysmon] Running: %v, Queue: %d/%d, Workers: %d\n",
				sysmonStats["running"],
				sysmonStats["channel_length"],
				sysmonStats["channel_capacity"],
				sysmonStats["worker_pool_size"],
			)
			log.Printf("[Response] Alerts: %d, Terminated: %d, Quarantined: %d, Blocked: %d\n",
				orchestratorStats["alerts_processed"],
				orchestratorStats["processes_terminated"],
				orchestratorStats["files_quarantined"],
				orchestratorStats["auto_responses_blocked"],
			)
			log.Printf("[Canary] Honeypot files deployed: %d\n",
				canaryStats["total_canaries"],
			)
			log.Println("══════════════════════════════════════════════════")
			log.Println()
		}
	}
}

// showConfiguration displays current configuration
func showConfiguration(responseCfg *config.ResponseConfig) {
	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║              CONFIGURATION SUMMARY                         ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
	log.Println()

	log.Printf("Version: %s\n", responseCfg.Version)
	log.Printf("Last Updated: %s\n", responseCfg.LastUpdated)
	log.Println()

	log.Println("Response Settings:")
	log.Printf("  Auto-terminate enabled: %v\n", responseCfg.ResponseSettings.AutoTerminateEnabled)
	log.Printf("  Immediate response: %v\n", responseCfg.ResponseSettings.ImmediateResponse)
	log.Printf("  Terminate on extension match: %v\n", responseCfg.ResponseSettings.TerminateOnExtensionMatch)
	log.Printf("  Terminate on critical score: %v\n", responseCfg.ResponseSettings.TerminateOnCriticalScore)
	log.Printf("  Critical score threshold: %d\n", responseCfg.ResponseSettings.CriticalScoreThreshold)
	log.Printf("  Quarantine files: %v\n", responseCfg.ResponseSettings.QuarantineFiles)
	log.Printf("  Quarantine directory: %s\n", responseCfg.ResponseSettings.QuarantineDirectory)
	log.Printf("  Investigation mode: %v\n", responseCfg.ResponseSettings.InvestigationMode)
	log.Println()

	log.Printf("Ransomware Extensions Monitored: %d\n", len(responseCfg.RansomwareExtensions))
	log.Println("  First 20:")
	for i := 0; i < len(responseCfg.RansomwareExtensions) && i < 20; i++ {
		log.Printf("    - %s\n", responseCfg.RansomwareExtensions[i])
	}
	if len(responseCfg.RansomwareExtensions) > 20 {
		log.Printf("    ... and %d more\n", len(responseCfg.RansomwareExtensions)-20)
	}
	log.Println()

	log.Printf("Ransom Note Filenames Monitored: %d\n", len(responseCfg.RansomNoteFilenames))
	log.Println()

	log.Println("Alert Settings:")
	log.Printf("  Log file: %s\n", responseCfg.AlertSettings.LogFile)
	log.Printf("  Verbose logging: %v\n", responseCfg.AlertSettings.VerboseLogging)
	log.Println()

	if responseCfg.Whitelist.Enabled {
		log.Println("Whitelist:")
		log.Printf("  Enabled: %v\n", responseCfg.Whitelist.Enabled)
		log.Printf("  Whitelisted paths: %d\n", len(responseCfg.Whitelist.Paths))
		for _, path := range responseCfg.Whitelist.Paths {
			log.Printf("    - %s\n", path)
		}
	}
}

// showVersion displays version information
func showVersion() {
	fmt.Println("procSniper v1.0")
	fmt.Println("Real-Time Ransomware & Information Stealer Detection")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Println("  - Shannon entropy-based encryption detection")
	fmt.Println("  - I/O velocity anomaly detection")
	fmt.Println("  - LSASS memory access detection")
	fmt.Println("  - Browser credential theft detection")
	fmt.Println("  - Multi-indicator threat correlation")
	fmt.Println("  - Automated process termination")
	fmt.Println("  - File quarantine capabilities")
	fmt.Println()
	fmt.Println("Copyright (c) 2025")
}

// printUsage displays usage information
func printUsage() {
	fmt.Println("procSniper - Real-Time Ransomware & Stealer Detection")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  procSniper protect       - Start real-time protection (requires admin)")
	fmt.Println("  procSniper config        - Show current configuration")
	fmt.Println("  procSniper version       - Show version information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  procSniper protect       # Start monitoring Sysmon events")
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  - Requires Administrator privileges")
	fmt.Println("  - Requires Sysmon to be installed and running")
	fmt.Println("  - Configuration: config/ransomware_extensions.json")
	fmt.Println()
}
