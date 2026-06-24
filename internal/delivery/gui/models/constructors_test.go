//go:build windows

package models

import (
	"testing"

	"procSniper/config"
	"procSniper/internal/domain"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

func TestDashboardStatsFromStats(t *testing.T) {
	etw := infrastructure.ETWConsumerStats{
		Running: true, WorkerPoolSize: 8, ChannelLength: 5, ChannelCapacity: 1000,
		EventsReceived: 100, EventsDropped: 2, EventsSuppressedDeadPID: 3,
	}
	orch := usecase.OrchestrationStats{
		AlertsProcessed: 7, ProcessesTerminated: 1, FilesQuarantined: 4, AutoResponsesBlocked: 2,
	}
	entropy := domain.EntropyStats{TrackedFiles: 11, ModifiedFiles: 6, SignificantIncreases: 1}

	got := DashboardStatsFromStats(etw, orch, 42, entropy)

	if got.ProtectionStatus != "Active" {
		t.Errorf("ProtectionStatus = %q, want Active", got.ProtectionStatus)
	}
	if !got.ETWConnected || got.WorkerQueueDepth != 5 {
		t.Errorf("ETWConnected=%v WorkerQueueDepth=%d, want true/5", got.ETWConnected, got.WorkerQueueDepth)
	}
	if got.AlertsProcessed != 7 || got.ProcessesTerminated != 1 || got.FilesQuarantined != 4 || got.AutoResponsesBlocked != 2 {
		t.Errorf("orchestrator fields not mapped: %+v", got)
	}
	if got.CanaryFilesCount != 42 {
		t.Errorf("CanaryFilesCount = %d, want 42", got.CanaryFilesCount)
	}
	if got.ETWDiagnostics.EventsReceived != 100 || got.ETWDiagnostics.EventsDropped != 2 ||
		got.ETWDiagnostics.EventsSuppressedDeadPID != 3 || got.ETWDiagnostics.WorkerPoolSize != 8 ||
		got.ETWDiagnostics.ChannelCapacity != 1000 || got.ETWDiagnostics.ChannelLength != 5 {
		t.Errorf("ETW diagnostics not mapped: %+v", got.ETWDiagnostics)
	}
	if got.EntropyStats.TrackedFiles != 11 || got.EntropyStats.ModifiedFiles != 6 || got.EntropyStats.SignificantIncreases != 1 {
		t.Errorf("entropy not mapped: %+v", got.EntropyStats)
	}
	// ActiveThreatsCount/HighIOProcessCount are filled by the caller, not this constructor.
	if got.ActiveThreatsCount != 0 || got.HighIOProcessCount != 0 {
		t.Errorf("caller-filled fields should be zero from the constructor: %+v", got)
	}
}

func TestEntropyStatsVMFromStats(t *testing.T) {
	got := EntropyStatsVMFromStats(domain.EntropyStats{TrackedFiles: 1, ModifiedFiles: 2, SignificantIncreases: 3})
	if got.TrackedFiles != 1 || got.ModifiedFiles != 2 || got.SignificantIncreases != 3 {
		t.Errorf("EntropyStatsVMFromStats = %+v, want {1 2 3}", got)
	}
}

// Config round-trips through the view model: read into a VM, then apply back onto a fresh config.
func TestConfigViewModelRoundTrip(t *testing.T) {
	src := &config.ResponseConfig{Version: "2.0", LastUpdated: "2026-06-23"}
	src.DetectionThresholds.HighEntropyFileThreshold = 12
	src.DetectionThresholds.IOVelocityThresholdPerMinute = 100
	src.ResponseSettings.AutoTerminateEnabled = true
	src.ResponseSettings.CriticalScoreThreshold = 49
	src.ResponseSettings.DetectionMode = "hybrid"
	src.ResponseSettings.CanaryResponseAction = "suspend"
	src.Whitelist.Enabled = true
	src.Whitelist.Paths = []string{`c:\trusted`}
	src.RansomwareExtensions = []string{".locked", ".enc"}

	vm := ConfigViewModelFromResponseConfig(src)
	if vm.Version != "2.0" || vm.DetectionThresholds.HighEntropyFileThreshold != 12 ||
		vm.ResponseSettings.DetectionMode != "hybrid" || vm.ResponseSettings.CanaryResponseAction != "suspend" {
		t.Fatalf("ConfigViewModelFromResponseConfig lost fields: %+v", vm)
	}

	dst := &config.ResponseConfig{}
	vm.ApplyToResponseConfig(dst)
	if dst.DetectionThresholds.HighEntropyFileThreshold != 12 ||
		dst.DetectionThresholds.IOVelocityThresholdPerMinute != 100 ||
		!dst.ResponseSettings.AutoTerminateEnabled ||
		dst.ResponseSettings.CriticalScoreThreshold != 49 ||
		dst.ResponseSettings.DetectionMode != "hybrid" ||
		dst.ResponseSettings.CanaryResponseAction != "suspend" ||
		!dst.Whitelist.Enabled || len(dst.Whitelist.Paths) != 1 ||
		len(dst.RansomwareExtensions) != 2 {
		t.Errorf("ApplyToResponseConfig round-trip mismatch: %+v", dst.ResponseSettings)
	}
}

func TestConfigViewModelFromResponseConfig_Nil(t *testing.T) {
	if got := ConfigViewModelFromResponseConfig(nil); got.Version != "" || len(got.RansomwareExtensions) != 0 {
		t.Errorf("nil config should yield empty view model, got %+v", got)
	}
}

// With no nested Prediction, the activity's own fields and sane defaults are used; a zero timestamp
// is defaulted to a non-empty formatted value.
func TestMLPredictionVMFromActivity_NoPrediction(t *testing.T) {
	got := MLPredictionVMFromActivity(&domain.MLInferenceActivity{
		ProcessID: 7,
		Image:     `C:\path\proc.exe`,
		Stage:     "skipped",
		Reason:    "predictor_not_ready",
	})
	if got.ProcessName != "proc.exe" {
		t.Errorf("ProcessName = %q, want proc.exe", got.ProcessName)
	}
	if got.ProcessID != 7 || got.Label != "unknown" || got.Stage != "skipped" {
		t.Errorf("activity fields not mapped: %+v", got)
	}
	if got.Timestamp == "" {
		t.Error("zero activity timestamp should be defaulted to a non-empty value")
	}
}
