package usecase

import (
	"context"
	"testing"
	"time"

	"procSniper/config"
	"procSniper/internal/domain"
)

// fakeResponder implements processResponder, recording calls without touching real processes —
// so the orchestrator's response EXECUTION (terminate vs suspend, etc.) is unit-testable. This is
// what the responder seam unlocked: previously executeAutomatedResponse could only be
// build-verified because it depended on the concrete cgo *infrastructure.ResponseActions.
type fakeResponder struct {
	terminateCalls  int
	suspendCalls    int
	quarantineCalls int
	terminated      bool
	alreadyExited   bool
	terminateErr    error
	suspendErr      error
	alive           bool
}

func (f *fakeResponder) EnableDebugPrivilege() error    { return nil }
func (f *fakeResponder) SuspendProcess(uint32) error    { f.suspendCalls++; return f.suspendErr }
func (f *fakeResponder) IsProcessAlive(uint32) (bool, error) { return f.alive, nil }
func (f *fakeResponder) QuarantineFile(string, string) error { f.quarantineCalls++; return nil }
func (f *fakeResponder) TerminateProcessVerified(uint32, int, time.Duration, bool) (bool, bool, error) {
	f.terminateCalls++
	return f.terminated, f.alreadyExited, f.terminateErr
}

func execTestAlert(strategy domain.ResponseStrategy) *domain.Alert {
	return &domain.Alert{
		ProcessGuid: "guid-exec",
		ProcessID:   4242, // valid PID; safe because the fake never touches a real process
		Image:       `C:\malware.exe`,
		Score:       100,
		Severity:    domain.ThreatCritical,
		AutoRespond: true,
		Strategy:    strategy,
	}
}

// Default/Terminate strategy terminates and does not suspend.
func TestExecuteResponse_TerminateStrategy(t *testing.T) {
	fake := &fakeResponder{terminated: true}
	rc := &config.ResponseConfig{ResponseSettings: config.ResponseSetting{AutoTerminateEnabled: true}}
	ro := NewResponseOrchestrator(nil, fake, rc)

	ro.processAlert(context.Background(), execTestAlert(domain.ResponseStrategyTerminate))

	if fake.terminateCalls != 1 {
		t.Errorf("terminateCalls = %d, want 1", fake.terminateCalls)
	}
	if fake.suspendCalls != 0 {
		t.Errorf("suspendCalls = %d, want 0 (default strategy terminates, not suspends)", fake.suspendCalls)
	}
	if got := ro.GetStats().ProcessesTerminated; got != 1 {
		t.Errorf("processes_terminated = %d, want 1", got)
	}
}

// Suspend strategy (finding #3) suspends the process and must NOT terminate it.
func TestExecuteResponse_SuspendStrategy(t *testing.T) {
	fake := &fakeResponder{}
	rc := &config.ResponseConfig{ResponseSettings: config.ResponseSetting{AutoTerminateEnabled: true}}
	ro := NewResponseOrchestrator(nil, fake, rc)

	ro.processAlert(context.Background(), execTestAlert(domain.ResponseStrategySuspend))

	if fake.suspendCalls != 1 {
		t.Errorf("suspendCalls = %d, want 1", fake.suspendCalls)
	}
	if fake.terminateCalls != 0 {
		t.Errorf("terminateCalls = %d, want 0 (suspend strategy must NOT terminate)", fake.terminateCalls)
	}
	if got := ro.GetStats().ProcessesSuspended; got != 1 {
		t.Errorf("processes_suspended = %d, want 1", got)
	}
	if got := ro.GetStats().ProcessesTerminated; got != 0 {
		t.Errorf("processes_terminated = %d, want 0", got)
	}
}

// A config veto (AutoTerminateEnabled=false) suppresses BOTH terminate and suspend — the
// responder is never invoked.
func TestExecuteResponse_VetoInvokesNoResponder(t *testing.T) {
	fake := &fakeResponder{}
	rc := &config.ResponseConfig{ResponseSettings: config.ResponseSetting{AutoTerminateEnabled: false}}
	ro := NewResponseOrchestrator(nil, fake, rc)

	ro.processAlert(context.Background(), execTestAlert(domain.ResponseStrategySuspend))

	if fake.suspendCalls != 0 || fake.terminateCalls != 0 {
		t.Errorf("veto must invoke no responder action; suspend=%d terminate=%d", fake.suspendCalls, fake.terminateCalls)
	}
}
