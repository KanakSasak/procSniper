//go:build windows

package app

import (
	"testing"

	"procSniper/config"
)

func testConfigs() (*config.Config, *config.ResponseConfig) {
	cfg := &config.Config{WorkerPoolSize: 4}
	rc := &config.ResponseConfig{}
	return cfg, rc
}

// New must build the full graph and expose the wired components.
func TestNew_BuildsGraph(t *testing.T) {
	cfg, rc := testConfigs()
	agent, err := New(cfg, rc)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if agent.DetectionService() == nil {
		t.Error("DetectionService() is nil")
	}
	if agent.Orchestrator() == nil {
		t.Error("Orchestrator() is nil")
	}
	if agent.ETWConsumer() == nil {
		t.Error("ETWConsumer() is nil")
	}
	// SecurityLogConsumer is only created in Start, so it is expected nil before Start.
	if agent.SecurityLogConsumer() != nil {
		t.Error("SecurityLogConsumer() should be nil before Start")
	}
}

// New must reject missing required configuration.
func TestNew_NilConfig(t *testing.T) {
	_, rc := testConfigs()
	if _, err := New(nil, rc); err == nil {
		t.Error("New(nil cfg) should error")
	}
	cfg, _ := testConfigs()
	if _, err := New(cfg, nil); err == nil {
		t.Error("New(nil responseCfg) should error")
	}
}

// WithDetectionMode must apply the explicit mode + canary action to the detection service,
// overriding the (empty) config fallback.
func TestNew_WithDetectionModeOption(t *testing.T) {
	cfg, rc := testConfigs()
	agent, err := New(cfg, rc, WithDetectionMode("rules_only", "alert_only"))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if got := agent.DetectionService().GetDetectionMode(); got != "rules_only" {
		t.Errorf("detection mode = %q, want rules_only", got)
	}
	if got := agent.DetectionService().GetCanaryResponseAction(); got != "alert_only" {
		t.Errorf("canary response = %q, want alert_only", got)
	}
}

// An explicit WithDetectionMode of "" must fall back to the config's DetectionMode.
func TestNew_DetectionModeConfigFallback(t *testing.T) {
	cfg, rc := testConfigs()
	rc.ResponseSettings.DetectionMode = "hybrid"
	rc.ResponseSettings.CanaryResponseAction = "suspend"
	agent, err := New(cfg, rc)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if got := agent.DetectionService().GetDetectionMode(); got != "hybrid" {
		t.Errorf("detection mode = %q, want hybrid (config fallback)", got)
	}
	if got := agent.DetectionService().GetCanaryResponseAction(); got != "suspend" {
		t.Errorf("canary response = %q, want suspend (config fallback)", got)
	}
}
