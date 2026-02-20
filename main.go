//go:build windows && !gui

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
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
		// Parse protect-specific flags
		mlModelPath := ""
		mlConfidence := 0.75
		mlMinIndicators := 4
		detectionMode := "" // will be resolved after parsing
		canaryResponse := ""
		for i := 2; i < len(os.Args); i++ {
			switch os.Args[i] {
			case "--ml":
				if i+1 < len(os.Args) {
					mlModelPath = os.Args[i+1]
					i++
				} else {
					fmt.Println("Error: --ml requires a model path")
					os.Exit(1)
				}
			case "--ml-confidence":
				if i+1 < len(os.Args) {
					v, err := strconv.ParseFloat(os.Args[i+1], 64)
					if err != nil || v < 0 || v > 1 {
						fmt.Println("Error: --ml-confidence requires a value between 0.0 and 1.0")
						os.Exit(1)
					}
					mlConfidence = v
					i++
				}
			case "--ml-min-indicators":
				if i+1 < len(os.Args) {
					v, err := strconv.Atoi(os.Args[i+1])
					if err != nil || v < 1 {
						fmt.Println("Error: --ml-min-indicators requires a positive integer")
						os.Exit(1)
					}
					mlMinIndicators = v
					i++
				}
			case "--detection-mode":
				if i+1 < len(os.Args) {
					detectionMode = os.Args[i+1]
					if detectionMode != "rules_only" && detectionMode != "hybrid" && detectionMode != "ml_only" {
						fmt.Println("Error: --detection-mode must be rules_only, hybrid, or ml_only")
						os.Exit(1)
					}
					i++
				} else {
					fmt.Println("Error: --detection-mode requires a value (rules_only, hybrid, ml_only)")
					os.Exit(1)
				}
			case "--canary-response":
				if i+1 < len(os.Args) {
					canaryResponse = os.Args[i+1]
					if canaryResponse != "terminate" && canaryResponse != "suspend" && canaryResponse != "alert_only" {
						fmt.Println("Error: --canary-response must be terminate, suspend, or alert_only")
						os.Exit(1)
					}
					i++
				} else {
					fmt.Println("Error: --canary-response requires a value (terminate, suspend, alert_only)")
					os.Exit(1)
				}
			}
		}
		// Resolve detection mode defaults
		if detectionMode == "" {
			if mlModelPath != "" {
				detectionMode = "ml_only" // ML model provided → default to ml_only
			} else {
				detectionMode = responseCfg.ResponseSettings.DetectionMode
				if detectionMode == "" {
					detectionMode = "rules_only"
				}
			}
		}
		// Validate: hybrid and ml_only require ML model
		if (detectionMode == "hybrid" || detectionMode == "ml_only") && mlModelPath == "" {
			fmt.Printf("Error: --detection-mode %s requires --ml <model_path>\n", detectionMode)
			os.Exit(1)
		}
		// Resolve canary response default
		if canaryResponse == "" {
			canaryResponse = responseCfg.ResponseSettings.CanaryResponseAction
			if canaryResponse == "" {
				canaryResponse = "terminate"
			}
		}
		runProtectionMode(cfg, responseCfg, mlModelPath, mlConfidence, mlMinIndicators, detectionMode, canaryResponse)
	case "config":
		showConfiguration(responseCfg)
	case "ml-test":
		runMLTest()
	case "version":
		showVersion()
	default:
		printUsage()
		os.Exit(1)
	}
}

// runProtectionMode starts real-time protection
func runProtectionMode(cfg *config.Config, responseCfg *config.ResponseConfig, mlModelPath string, mlConfidence float64, mlMinIndicators int, detectionMode string, canaryResponse string) {
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
	log.Printf("    - Rename to Known Ransomware Extension: %d files in 60s (IMMEDIATE TERMINATION)",
		responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold)
	log.Printf("    - Combined (High Entropy + Extension): %d files (IMMEDIATE TERMINATION)",
		responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold)
	log.Printf("[*] Detection mode:")
	log.Printf("    - Ransom Note Detection: %v (focus on behavioral detection)", cfg.EnableRansomNoteDetection)

	detectionService = usecase.NewDetectionService(
		responseCfg.DetectionThresholds.HighEntropyFileThreshold,
		responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold,
		responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
		responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold,
		cfg.EnableRansomNoteDetection,
		cfg.RansomwareExtensions,
		responseCfg.Whitelist.Processes,
	)
	log.Println("[+] Detection engine initialized")

	// Apply detection mode and canary response settings
	detectionService.SetDetectionMode(detectionMode)
	detectionService.SetCanaryResponseAction(canaryResponse)

	// Load ML model if specified
	var mlPredictor *infrastructure.ONNXPredictor
	if mlModelPath != "" {
		log.Printf("[*] Loading ML model: %s", mlModelPath)
		predictor, err := infrastructure.NewONNXPredictor(mlModelPath, "")
		if err != nil {
			log.Fatalf("[!] Failed to load ML model: %v", err)
		}
		mlPredictor = predictor
		detectionService.SetMLPredictor(predictor)
		detectionService.SetMLEnabled(true)
		detectionService.SetMLConfidence(mlConfidence)
		detectionService.SetMLMinIndicators(mlMinIndicators)
		log.Printf("[+] ML model loaded successfully")
		log.Printf("[*] ML detection mode:")
		log.Printf("    - Confidence threshold: %.2f", mlConfidence)
		log.Printf("    - Min features before inference: %d", mlMinIndicators)
	}

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

	// Enable process self-protection (DACL hardening)
	// This prevents ransomware from killing procSniper via TerminateProcess
	log.Println("[*] Enabling process self-protection...")
	if err := infrastructure.ProtectCurrentProcess(); err != nil {
		log.Printf("[!] WARNING: Failed to enable self-protection: %v", err)
		log.Println("[!] procSniper may be vulnerable to process termination by malware")
	}

	// Initialize response orchestrator
	log.Println("[*] Initializing response orchestrator...")
	responseOrchestrator := usecase.NewResponseOrchestrator(
		detectionService,
		responseActions,
		responseCfg,
	)

	// Initialize Kernel ETW event consumer
	log.Println("[*] Initializing Kernel ETW event consumer...")
	etwConsumer := infrastructure.NewKernelETWConsumer(
		detectionService,
		cfg.WorkerPoolSize,
	)

	// Route successful termination outcomes into ETW dead-PID suppression.
	responseOrchestrator.SetProcessTerminationSink(etwConsumer)

	if err := responseOrchestrator.Start(ctx); err != nil {
		log.Fatalf("[!] Failed to start response orchestrator: %v\n", err)
	}
	if err := etwConsumer.Start(ctx); err != nil {
		responseOrchestrator.Stop()
		log.Fatalf("[!] Failed to start ETW consumer: %v\n", err)
	}

	// Initialize Security Log consumer for BackupRead/BackupWrite API detection
	log.Println("[*] Initializing Windows Security Log consumer...")
	log.Println("[*] Monitoring for BackupRead/BackupWrite API usage (file creation detection bypass)...")
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
	log.Printf("[*] Suspend related on canary: %v\n", responseCfg.ResponseSettings.SuspendRelatedOnCanary)
	log.Printf("[*] Related suspicion min score: %d\n", responseCfg.ResponseSettings.RelatedSuspicionMinScore)
	log.Printf("[*] Related actor window: %ds\n", responseCfg.ResponseSettings.RelatedActorWindowSeconds)
	log.Printf("[*] Investigation mode: %v\n", responseCfg.ResponseSettings.InvestigationMode)
	log.Printf("[*] Detection mode: %s\n", detectionMode)
	log.Printf("[*] Canary response action: %s\n", canaryResponse)
	log.Printf("[*] Ransomware extensions monitored: %d\n", len(responseCfg.RansomwareExtensions))
	log.Printf("[*] Worker pool size: %d\n", cfg.WorkerPoolSize)
	log.Printf("[*] ML detection: %v\n", mlPredictor != nil)
	log.Println()
	log.Println("[+] procSniper is now protecting your system")
	log.Println("[*] Press Ctrl+C to stop...")
	log.Println()

	// Start statistics reporter
	stopStats := make(chan struct{})
	go reportStatistics(ctx, etwConsumer, responseOrchestrator, detectionService, stopStats)

	// Harden all current OS threads (must run after goroutines are started)
	if err := infrastructure.ProtectCurrentThreads(); err != nil {
		log.Printf("[!] WARNING: Failed to enable thread protection: %v", err)
	}
	go infrastructure.StartPeriodicThreadProtection(ctx)

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

	log.Println("[*] Stopping ETW consumer...")
	etwConsumer.Stop()

	log.Println("[*] Stopping response orchestrator...")
	responseOrchestrator.Stop()

	if mlPredictor != nil {
		log.Println("[*] Closing ML model...")
		mlPredictor.Close()
	}

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
	etwConsumer *infrastructure.KernelETWConsumer,
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
			etwStats := etwConsumer.GetStats()
			orchestratorStats := responseOrchestrator.GetStats()
			canaryStats := detectionService.GetCanaryStats()

			log.Println()
			log.Println("═══════════════════ STATISTICS ═══════════════════")
			log.Printf("[ETW] Running: %v, Queue: %d/%d, Workers: %d\n",
				etwStats["running"],
				etwStats["channel_length"],
				etwStats["channel_capacity"],
				etwStats["worker_pool_size"],
			)
			log.Printf("[Response] Alerts: %d, Terminated: %d, Quarantined: %d, Blocked: %d\n",
				orchestratorStats["alerts_processed"],
				orchestratorStats["processes_terminated"],
				orchestratorStats["files_quarantined"],
				orchestratorStats["auto_responses_blocked"],
			)
			log.Printf("[Response] Related Suspends: attempted=%d success=%d failed=%d\n",
				orchestratorStats["related_suspend_attempted"],
				orchestratorStats["related_suspend_success"],
				orchestratorStats["related_suspend_failed"],
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
	log.Printf("  Suspend related on canary: %v\n", responseCfg.ResponseSettings.SuspendRelatedOnCanary)
	log.Printf("  Related suspicion min score: %d\n", responseCfg.ResponseSettings.RelatedSuspicionMinScore)
	log.Printf("  Related actor window (seconds): %d\n", responseCfg.ResponseSettings.RelatedActorWindowSeconds)
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

// runMLTest runs standalone ML model testing
func runMLTest() {
	modelPath := "ml-2/models/procsniper_rf_ml2_v1.onnx"
	csvPath := ""
	verbose := false

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--model", "-m":
			if i+1 < len(os.Args) {
				modelPath = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: --model requires a path argument")
				os.Exit(1)
			}
		case "--csv", "-c":
			if i+1 < len(os.Args) {
				csvPath = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: --csv requires a path argument")
				os.Exit(1)
			}
		case "--verbose", "-v":
			verbose = true
		case "--help", "-h":
			printMLTestUsage()
			return
		default:
			fmt.Printf("Unknown ml-test argument: %s\n", os.Args[i])
			printMLTestUsage()
			os.Exit(1)
		}
	}

	fmt.Println("==========================================================")
	fmt.Println(" procSniper ML Model Tester")
	fmt.Println("==========================================================")
	fmt.Printf(" Loading model: %s\n", modelPath)

	predictor, err := infrastructure.NewONNXPredictor(modelPath, "")
	if err != nil {
		fmt.Printf(" [!] Failed to load model: %v\n", err)
		os.Exit(1)
	}
	defer predictor.Close()

	fmt.Println(" [+] Model loaded successfully")
	fmt.Println()

	scenarios := usecase.BuiltinScenarios()

	if csvPath != "" {
		fmt.Printf(" Loading custom scenarios from: %s\n", csvPath)
		csvScenarios, err := usecase.LoadScenariosFromCSV(csvPath)
		if err != nil {
			fmt.Printf(" [!] Failed to load CSV: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf(" [+] Loaded %d custom scenarios\n", len(csvScenarios))
		scenarios = append(scenarios, csvScenarios...)
	}

	summary := usecase.RunMLTestScenarios(predictor, scenarios)
	usecase.PrintMLTestResults(summary, modelPath, verbose)

	if summary.Failed > 0 || summary.Errors > 0 {
		os.Exit(1)
	}
}

func printMLTestUsage() {
	fmt.Println("Usage: procSniper ml-test [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --model, -m PATH     Path to ONNX model (default: ml-2/models/procsniper_rf_ml2_v1.onnx)")
	fmt.Println("  --csv, -c PATH       Load additional test vectors from CSV file")
	fmt.Println("  --verbose, -v        Show feature vectors in output")
	fmt.Println("  --help, -h           Show this help")
	fmt.Println()
	fmt.Println("CSV Format (16 columns):")
	fmt.Println("  name, expected_label, velocity, file_count, txt_file_count, directory_count,")
	fmt.Println("  file_delete_count, is_signed, extension_match, extension_entropy,")
	fmt.Println("  shadow_copy_delete, browser_credential_access, browser_history_access,")
	fmt.Println("  ssh_key_access, lsass_access, system_info_queries")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  procSniper ml-test")
	fmt.Println("  procSniper ml-test --model ml/models/procsniper_rf.onnx")
	fmt.Println("  procSniper ml-test --csv my_test_vectors.csv --verbose")
}

// printUsage displays usage information
func printUsage() {
	fmt.Println("procSniper - Real-Time Ransomware & Stealer Detection")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  procSniper protect       - Start real-time protection (requires admin)")
	fmt.Println("  procSniper config        - Show current configuration")
	fmt.Println("  procSniper ml-test       - Test ML model with predefined scenarios")
	fmt.Println("  procSniper version       - Show version information")
	fmt.Println()
	fmt.Println("Protect Options:")
	fmt.Println("  --ml PATH              Enable ML detection with ONNX model")
	fmt.Println("  --ml-confidence FLOAT  ML confidence threshold (default: 0.75)")
	fmt.Println("  --ml-min-indicators N  Min non-zero features before ML fires (default: 4)")
	fmt.Println("  --detection-mode MODE  Detection mode: rules_only, hybrid, ml_only")
	fmt.Println("                         Default: ml_only when --ml provided, else rules_only")
	fmt.Println("  --canary-response ACT  Canary response: terminate, suspend, alert_only")
	fmt.Println("                         Default: from config or terminate")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  procSniper protect                                          # Rule-based only")
	fmt.Println("  procSniper protect --ml ml-2/models/procsniper_rf_ml2_v2.onnx  # ML only (2-class)")
	fmt.Println("  procSniper protect --ml ml-2/models/procsniper_rf_ml2_v2.onnx --detection-mode hybrid")
	fmt.Println("  procSniper protect --canary-response alert_only             # Canary: alert only")
	fmt.Println("  procSniper protect --ml ml-2/models/procsniper_rf_ml2_v2.onnx --ml-confidence 0.08 --ml-min-indicators 3")
	fmt.Println()
	fmt.Println("  procSniper ml-test                                          # Test default ML model")
	fmt.Println("  procSniper ml-test --model ml/models/procsniper_rf.onnx     # Test 3-class model")
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  - Requires Administrator privileges for protect mode")
	fmt.Println("  - Uses native Windows kernel ETW providers (no Sysmon required)")
	fmt.Println("  - ML mode: rule-based indicators accumulate, then ML inference fires")
	fmt.Println("  - Configuration: config/ransomware_extensions.json")
	fmt.Println()
}
