//go:build windows && !gui

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"

	"procSniper/config"
	"procSniper/internal/app"
	"procSniper/internal/delivery/api"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

func main() {
	// If the Windows SCM launched us as a service, our cwd is System32 — re-root to the exe
	// directory so the config/logs/model/canary relative paths resolve against the install dir.
	if isService, _ := svc.IsWindowsService(); isService {
		if exe, err := os.Executable(); err == nil {
			_ = os.Chdir(filepath.Dir(exe))
		}
	}

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

	// Single source of truth: detection consumes the same extension list parsed into
	// ResponseConfig (was previously a second, drift-prone loader on Config).
	cfg.RansomwareExtensions = responseCfg.RansomwareExtensions

	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║                    procSniper v2.0                         ║")
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
		// Parse protect-specific flags via stdlib flag into the shared ProtectOptions, then
		// resolve config-backed defaults and validate in one place (config.ProtectOptions).
		opts := config.DefaultProtectOptions()
		fs := flag.NewFlagSet("protect", flag.ExitOnError)
		fs.StringVar(&opts.MLModelPath, "ml", "", "path to the ONNX ML model (enables ML detection)")
		fs.Float64Var(&opts.MLConfidence, "ml-confidence", opts.MLConfidence, "ML malicious-probability threshold (0.0-1.0)")
		fs.IntVar(&opts.MLMinIndicators, "ml-min-indicators", opts.MLMinIndicators, "minimum accumulated indicators before ML inference")
		fs.StringVar(&opts.DetectionMode, "detection-mode", "", "rules_only | hybrid | ml_only")
		fs.StringVar(&opts.CanaryResponse, "canary-response", "", "terminate | suspend | alert_only")
		_ = fs.Parse(os.Args[2:])

		opts.Resolve(responseCfg)
		if err := opts.Validate(); err != nil {
			fmt.Println("Error: " + err.Error())
			os.Exit(1)
		}
		runProtectionMode(cfg, responseCfg, opts.MLModelPath, opts.MLConfidence, opts.MLMinIndicators, opts.DetectionMode, opts.CanaryResponse)
	case "serve":
		runServe(cfg, responseCfg)
	case "service":
		runService(cfg, responseCfg)
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

// runProtectionMode starts real-time protection via the shared composition root (internal/app).
// It owns only the CLI-specific concerns — console banners, the stats console reporter, and signal
// handling; the object graph and its lifecycle live in app.Agent (shared with the GUI surface).
func runProtectionMode(cfg *config.Config, responseCfg *config.ResponseConfig, mlModelPath string, mlConfidence float64, mlMinIndicators int, detectionMode string, canaryResponse string) {
	log.Println("[*] Initializing real-time protection...")

	// Cleanup old log files (keep logs from last 7 days)
	if err := infrastructure.CleanupOldLogs("logs", 7*24*time.Hour); err != nil {
		log.Printf("[!] Failed to cleanup old logs: %v\n", err)
	}

	// Detection threshold summary (console context before the engine comes up).
	log.Printf("[*] Detection thresholds:")
	log.Printf("    - High Entropy: %d files", responseCfg.DetectionThresholds.HighEntropyFileThreshold)
	log.Printf("    - Ransomware Extension: %d files", responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold)
	log.Printf("    - Rename to Known Ransomware Extension: %d files in 60s (IMMEDIATE TERMINATION)",
		responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold)
	log.Printf("    - Combined (High Entropy + Extension): %d files (IMMEDIATE TERMINATION)",
		responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold)
	log.Printf("    - Ransom Note Detection: %v (focus on behavioral detection)", cfg.EnableRansomNoteDetection)

	// Build the protection graph via the shared composition root.
	opts := []app.Option{app.WithDetectionMode(detectionMode, canaryResponse)}
	if mlModelPath != "" {
		opts = append(opts, app.WithMLModelPath(mlModelPath, mlConfidence, mlMinIndicators))
	}
	agent, err := app.New(cfg, responseCfg, opts...)
	if err != nil {
		log.Fatalf("[!] Failed to initialize protection: %v\n", err)
	}
	if mlModelPath != "" {
		log.Printf("[*] ML detection: confidence threshold %.2f, min features before inference %d", mlConfidence, mlMinIndicators)
	}

	// Context for graceful shutdown; the agent derives a child of it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		log.Fatalf("[!] Failed to start protection: %v\n", err)
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
	log.Printf("[*] ML detection: %v\n", mlModelPath != "")
	log.Println()
	log.Println("[+] procSniper is now protecting your system")
	log.Println("[*] Press Ctrl+C to stop...")
	log.Println()

	// Start statistics reporter (CLI console output)
	stopStats := make(chan struct{})
	go reportStatistics(agent, stopStats)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	log.Println()
	log.Println("[*] Shutdown signal received, stopping protection...")
	close(stopStats)

	// Tear down the whole graph (cancels ctx, joins background goroutines, stops components in
	// reverse order, closes the owned ML predictor, removes canary files).
	agent.Stop()

	log.Println()
	log.Println("╔════════════════════════════════════════════════════════════╗")
	log.Println("║              PROTECTION MODE STOPPED                       ║")
	log.Println("╚════════════════════════════════════════════════════════════╝")
	log.Println("[+] procSniper shutdown complete")
}

// reportStatistics periodically reports system statistics, reading the live components through the
// composition root. Stops when the stop channel is closed (during shutdown, before agent.Stop()).
func reportStatistics(agent *app.Agent, stop chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			etwStats := agent.ETWConsumer().GetStats()
			orchestratorStats := agent.Orchestrator().GetStats()
			canaryStats := agent.DetectionService().GetCanaryStats()
			dropStats := agent.DetectionService().GetDropStats()

			log.Println()
			log.Println("═══════════════════ STATISTICS ═══════════════════")
			log.Printf("[ETW] Running: %v, Queue: %d/%d, Workers: %d\n",
				etwStats.Running,
				etwStats.ChannelLength,
				etwStats.ChannelCapacity,
				etwStats.WorkerPoolSize,
			)
			log.Printf("[ETW] Events dropped: total=%d by_id=%v\n",
				etwStats.EventsDropped,
				etwStats.EventsDroppedByID,
			)
			log.Printf("[Detect] Alerts dropped: total=%d critical=%d high=%d other=%d\n",
				dropStats.AlertsDroppedTotal,
				dropStats.AlertsDroppedCritical,
				dropStats.AlertsDroppedHigh,
				dropStats.AlertsDroppedOther,
			)
			log.Printf("[Response] Alerts: %d, Terminated: %d, Quarantined: %d, Blocked: %d\n",
				orchestratorStats.AlertsProcessed,
				orchestratorStats.ProcessesTerminated,
				orchestratorStats.FilesQuarantined,
				orchestratorStats.AutoResponsesBlocked,
			)
			log.Printf("[Response] Related Suspends: attempted=%d success=%d failed=%d\n",
				orchestratorStats.RelatedSuspendAttempted,
				orchestratorStats.RelatedSuspendSuccess,
				orchestratorStats.RelatedSuspendFailed,
			)
			log.Printf("[Canary] Honeypot files deployed: %d\n",
				canaryStats.TotalCanaries,
			)
			log.Println("══════════════════════════════════════════════════")
			log.Println()
		}
	}
}

// runServe runs the local HTTP+SSE API server (foreground). This is the headless delivery surface
// the Windows service will host; in the foreground it's the dev/iteration path (browser console over
// http://127.0.0.1:PORT). The detection engine is the same internal/app.Agent the CLI/service use.
func runServe(cfg *config.Config, responseCfg *config.ResponseConfig) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (loopback only)")
	auto := fs.Bool("auto", false, "start protection immediately on boot")
	tokenFile := fs.String("token-file", "", "write the API bearer token to this path (for the tray/operator)")
	_ = fs.Parse(os.Args[2:])

	staticFS, err := frontendFS()
	if err != nil {
		log.Printf("[API] WARNING: frontend assets unavailable, serving API only: %v", err)
		staticFS = nil
	}

	srv, err := api.NewServer(*addr, cfg, responseCfg, staticFS)
	if err != nil {
		log.Fatalf("[API] failed to initialize server: %v", err)
	}
	if *tokenFile != "" {
		if err := srv.WriteTokenFile(*tokenFile); err != nil {
			log.Printf("[API] WARNING: could not write token file: %v", err)
		}
	}
	// Never persist the token to the (file-backed) log. With --token-file, the token goes only to
	// that file (the service path); otherwise, in foreground/dev, print the tokenized console URL
	// to stdout ONLY (fmt bypasses the log file), so it isn't written to logs/.
	log.Printf("[API] console listening on http://%s/ (bearer token required)", *addr)
	if *tokenFile == "" {
		fmt.Printf("[API] open console: http://%s/#token=%s\n", *addr, srv.Token())
	}

	if *auto {
		// Start protection in the background so the API listener comes up immediately — the console
		// must be reachable even while protection is starting (or if ETW fails to start).
		go func() {
			if res := srv.StartProtection(); !res.Success {
				log.Printf("[API] auto-start protection: %s", res.Message)
			}
		}()
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("[API] shutdown signal received")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[API] server error: %v", err)
	}
	log.Println("[API] server stopped")
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
	fmt.Println("procSniper v2.0")
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
	fmt.Println("  procSniper serve         - Run the local HTTP/SSE API + browser console (headless)")
	fmt.Println("  procSniper service ...   - Manage the Windows service (install|remove|start|stop)")
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
