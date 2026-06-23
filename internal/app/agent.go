//go:build windows

// Package app is the single composition root for procSniper's protection runtime.
//
// Both delivery surfaces — the CLI (main.go) and the Wails GUI (internal/delivery/gui) —
// previously constructed and wired the identical object graph (detection service, response
// orchestrator, ETW consumer, security-log consumer, canary monitor, maintenance, self-
// protection) in two places that drifted (see the audit's composition-root findings). This
// package owns that graph once: New builds it, Start runs the ctx-bound components, and Stop
// tears them down in reverse order with a real WaitGroup join (replacing the old fixed
// time.Sleep(2s) drain). Surface-specific concerns (CLI console banners, GUI frontend
// streaming/stats emission, runtime ML re-wiring) stay in the delivery layer and read the
// components through the accessors below.
package app

import (
	"context"
	"fmt"
	"log"
	"sync"

	"procSniper/config"
	"procSniper/internal/domain"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

// Agent is the assembled protection runtime: the wired object graph plus its lifecycle.
type Agent struct {
	cfg         *config.Config
	responseCfg *config.ResponseConfig

	// Configuration captured from options, applied to the detection service in New.
	detectionMode   string // "" => fall back to responseCfg.ResponseSettings.DetectionMode
	canaryResponse  string // "" => fall back to responseCfg.ResponseSettings.CanaryResponseAction
	mlModelPath     string // non-empty => New loads the ONNX predictor and OWNS it
	mlPredictor     domain.MLPredictor
	mlEnabled       bool
	mlConfidence    float64
	mlMinIndicators int
	mlMinIndSet     bool
	mlCallback      func(*domain.MLInferenceActivity)
	ownsPredictor   bool // CLI loads its own predictor per run (close on Stop); GUI owns it across runs (do not close)

	// Built components (constructed in New; nil until then).
	detectionService     *usecase.DetectionService
	responseOrchestrator *usecase.ResponseOrchestrator
	etwConsumer          *infrastructure.KernelETWConsumer
	securityLogConsumer  *infrastructure.SecurityLogConsumer
	responseActions      *infrastructure.ResponseActions

	// Lifecycle.
	mu      sync.Mutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup // joins the ctx-bound background goroutines on Stop
	started bool
}

// Option configures an Agent before its graph is built.
type Option func(*Agent)

// WithDetectionMode sets the detection mode and canary response action explicitly (CLI path).
// Empty strings fall back to the values in responseCfg.ResponseSettings (GUI default).
func WithDetectionMode(mode, canaryResponse string) Option {
	return func(a *Agent) {
		a.detectionMode = mode
		a.canaryResponse = canaryResponse
	}
}

// WithMLModelPath enables ML detection by loading the ONNX model at path during New (CLI path).
// The Agent OWNS the loaded predictor and closes it on Stop. Detection is enabled with the given
// confidence threshold and minimum-indicator gate.
func WithMLModelPath(path string, confidence float64, minIndicators int) Option {
	return func(a *Agent) {
		a.mlModelPath = path
		a.mlConfidence = confidence
		a.mlMinIndicators = minIndicators
		a.mlMinIndSet = true
	}
}

// WithMLPredictor wires a pre-built predictor the caller owns across runs (GUI path): the Agent
// does NOT close it on Stop. enabled/confidence/callback mirror the GUI's runtime ML state; the
// minimum-indicator gate keeps the detection service default (the GUI does not set it).
func WithMLPredictor(p domain.MLPredictor, enabled bool, confidence float64, callback func(*domain.MLInferenceActivity)) Option {
	return func(a *Agent) {
		a.mlPredictor = p
		a.mlEnabled = enabled
		a.mlConfidence = confidence
		a.mlCallback = callback
		a.ownsPredictor = false
	}
}

// New builds the full protection object graph. It performs all construction that can fail without
// a context — loading the ML model (if WithMLModelPath was given) and initializing response actions
// — returning an error so each caller chooses its own failure policy (CLI log.Fatalf, GUI
// OperationResult). It does NOT start any goroutine or touch the filesystem beyond model load /
// privilege acquisition; call Start(ctx) for that.
func New(cfg *config.Config, responseCfg *config.ResponseConfig, opts ...Option) (*Agent, error) {
	a := &Agent{
		cfg:          cfg,
		responseCfg:  responseCfg,
		mlConfidence: 0.75,
	}
	for _, opt := range opts {
		opt(a)
	}

	if cfg == nil || responseCfg == nil {
		return nil, fmt.Errorf("app.New: cfg and responseCfg are required")
	}

	// Detection engine.
	a.detectionService = usecase.NewDetectionService(usecase.DetectionConfig{
		EntropyFileThreshold:        responseCfg.DetectionThresholds.HighEntropyFileThreshold,
		ExtensionFileThreshold:      responseCfg.DetectionThresholds.RansomwareExtensionFileThreshold,
		CombinedThreshold:           responseCfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
		RenameExtThreshold:          responseCfg.DetectionThresholds.RansomwareExtensionRenameThreshold,
		EnableRansomNoteDetection:   cfg.EnableRansomNoteDetection,
		RansomwareExtensions:        cfg.RansomwareExtensions,
		TrustedProcesses:            responseCfg.Whitelist.Processes,
		IOVelocityMonitorThreshold:  float64(responseCfg.DetectionThresholds.IOVelocityMonitorThreshold),
		IOVelocityAnalyzeThreshold:  float64(responseCfg.DetectionThresholds.IOVelocityAnalyzeThreshold),
		IOVelocityCriticalThreshold: float64(responseCfg.DetectionThresholds.IOVelocityThresholdPerMinute),
	})
	log.Println("[+] Detection engine initialized")

	// ML wiring. WithMLModelPath loads (and owns) the predictor; WithMLPredictor injects a caller-
	// owned one. Either way the detection service is configured identically below.
	if a.mlModelPath != "" {
		log.Printf("[*] Loading ML model: %s", a.mlModelPath)
		predictor, err := infrastructure.NewONNXPredictor(a.mlModelPath, "")
		if err != nil {
			return nil, fmt.Errorf("load ML model %q: %w", a.mlModelPath, err)
		}
		a.mlPredictor = predictor
		a.ownsPredictor = true
		a.mlEnabled = true
		log.Println("[+] ML model loaded successfully")
	}
	if a.mlPredictor != nil {
		a.detectionService.SetMLPredictor(a.mlPredictor)
		a.detectionService.SetMLEnabled(a.mlEnabled)
		a.detectionService.SetMLConfidence(a.mlConfidence)
		if a.mlMinIndSet {
			a.detectionService.SetMLMinIndicators(a.mlMinIndicators)
		}
		if a.mlCallback != nil {
			a.detectionService.SetMLPredictionCallback(a.mlCallback)
		}
	}

	// Detection mode + canary response: explicit option wins, else fall back to config.
	mode := a.detectionMode
	if mode == "" {
		mode = responseCfg.ResponseSettings.DetectionMode
	}
	if mode != "" {
		a.detectionService.SetDetectionMode(mode)
	}
	canary := a.canaryResponse
	if canary == "" {
		canary = responseCfg.ResponseSettings.CanaryResponseAction
	}
	if canary != "" {
		a.detectionService.SetCanaryResponseAction(canary)
	}

	// Response actions (privileged OS surface). Hard failure — surface to the caller.
	responseActions, err := infrastructure.NewResponseActions()
	if err != nil {
		if a.ownsPredictor && a.mlPredictor != nil {
			a.mlPredictor.Close() // avoid leaking the model we just loaded
		}
		return nil, fmt.Errorf("init response actions: %w", err)
	}
	a.responseActions = responseActions

	// Response orchestrator + ETW consumer, wired with the post-kill dead-PID suppression sink.
	a.responseOrchestrator = usecase.NewResponseOrchestrator(a.detectionService, a.responseActions, responseCfg)
	a.etwConsumer = infrastructure.NewKernelETWConsumer(a.detectionService, cfg.WorkerPoolSize)
	a.responseOrchestrator.SetProcessTerminationSink(a.etwConsumer)

	return a, nil
}

// Start runs the ctx-bound components and background goroutines in dependency order. It returns an
// error if the orchestrator or ETW consumer fail to start (with the already-started pieces rolled
// back); softer failures (self-protection, canary setup, security-log consumer) are logged and the
// run continues, matching the prior CLI/GUI behavior. The passed ctx governs the run; Stop cancels
// a child of it.
func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.started {
		return fmt.Errorf("agent already started")
	}

	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	// Self-protection: harden the current process against termination before sensors come up.
	if err := infrastructure.ProtectCurrentProcess(); err != nil {
		log.Printf("[!] WARNING: Failed to enable self-protection: %v", err)
		log.Println("[!] procSniper may be vulnerable to process termination by malware")
	}

	// Canary honeypots + their monitor (only if deployment succeeded).
	if err := a.detectionService.SetupCanaryFiles(); err != nil {
		log.Printf("[!] WARNING: Failed to setup canary files: %v", err)
		log.Println("[!] Honeypot detection will be disabled")
	} else {
		log.Println("[+] Canary files deployed successfully")
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.detectionService.StartCanaryMonitoring(runCtx)
		}()
	}

	// Periodic eviction of stale per-process detection state (bounds memory).
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.detectionService.StartMaintenance(runCtx)
	}()

	// Orchestrator must be consuming alerts before the ETW firehose opens.
	if err := a.responseOrchestrator.Start(runCtx); err != nil {
		cancel()
		return fmt.Errorf("start response orchestrator: %w", err)
	}
	if err := a.etwConsumer.Start(runCtx); err != nil {
		a.responseOrchestrator.Stop()
		cancel()
		return fmt.Errorf("start ETW consumer: %w", err)
	}

	// Security-log consumer (BackupRead/Write detection) is best-effort — needs admin + log access.
	a.securityLogConsumer = infrastructure.NewSecurityLogConsumer(a.detectionService, a.cfg)
	if err := a.securityLogConsumer.Start(runCtx); err != nil {
		log.Printf("[!] WARNING: Failed to start Security Log consumer: %v", err)
		log.Println("[!] BackupRead/BackupWrite API detection will be disabled (requires Administrator + Security log access)")
		a.securityLogConsumer = nil
	} else {
		log.Println("[+] Security Log consumer started successfully")
	}

	// Harden OS threads now that the background goroutines exist, then keep re-hardening new ones.
	if err := infrastructure.ProtectCurrentThreads(); err != nil {
		log.Printf("[!] WARNING: Failed to enable thread protection: %v", err)
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		infrastructure.StartPeriodicThreadProtection(runCtx)
	}()

	a.started = true
	return nil
}

// Stop tears the runtime down in reverse order. It cancels the run context and joins the background
// goroutines (canary monitor, maintenance, periodic thread protection) via the WaitGroup — a real
// join in place of the old fixed 2-second sleep — then stops the components, closes the ML
// predictor only if this Agent owns it, and removes the canary files. Safe to call more than once.
func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.started {
		return
	}

	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}

	// Join the ctx-bound background goroutines before stopping the components they touch.
	a.wg.Wait()

	if a.securityLogConsumer != nil {
		a.securityLogConsumer.Stop()
	}
	if a.etwConsumer != nil {
		a.etwConsumer.Stop()
	}
	if a.responseOrchestrator != nil {
		a.responseOrchestrator.Stop()
	}

	// Only close the predictor we loaded ourselves (CLI). A GUI-injected predictor outlives the run.
	if a.ownsPredictor && a.mlPredictor != nil {
		a.mlPredictor.Close()
		a.mlPredictor = nil
	}

	if a.detectionService != nil {
		a.detectionService.CleanupCanaryFiles()
	}

	a.started = false
}

// DetectionService returns the wired detection service (for stats reads and runtime ML re-wiring).
func (a *Agent) DetectionService() *usecase.DetectionService { return a.detectionService }

// Orchestrator returns the response orchestrator (for stats reads and syslog forwarding).
func (a *Agent) Orchestrator() *usecase.ResponseOrchestrator { return a.responseOrchestrator }

// ETWConsumer returns the kernel ETW consumer (for stats reads).
func (a *Agent) ETWConsumer() *infrastructure.KernelETWConsumer { return a.etwConsumer }

// SecurityLogConsumer returns the security-log consumer, or nil if it failed to start.
func (a *Agent) SecurityLogConsumer() *infrastructure.SecurityLogConsumer { return a.securityLogConsumer }
