package usecase

import (
	"context"
	"testing"

	"procSniper/config"
	"procSniper/internal/domain"
)

// Phase 4 response-contract regression suite.
//
// These tests pin the post-Phase-4 gate: alert.AutoRespond is the PRIMARY response
// authority (checked first in processAlert) and the config controls are veto-only. They
// drive the real processAlert path. responseActions is nil throughout — which is safe
// because every AutoRespond=false alert returns at the primary gate, every veto returns at
// the ShouldAutoTerminate block, and the single true-verdict case uses ProcessID=-1 to stop
// at the invalid-PID guard before the (nil) Windows terminator is ever dereferenced.

func newGateTestOrchestrator(rc *config.ResponseConfig) *ResponseOrchestrator {
	// nil detectionService + nil responseActions: NewResponseOrchestrator only dereferences
	// responseConfig (the SendSyslog branch), which these rc literals leave unset.
	return NewResponseOrchestrator(nil, nil, rc)
}

func statInt(t *testing.T, stats map[string]interface{}, key string) int {
	t.Helper()
	v, ok := stats[key]
	if !ok {
		t.Fatalf("stat %q missing", key)
	}
	n, ok := v.(int)
	if !ok {
		t.Fatalf("stat %q is %T, want int", key, v)
	}
	return n
}

// The documented hazard fix: a false detection verdict must not be upgraded to termination
// by score >= CriticalScoreThreshold, ThreatHigh/Critical level, or an extension match.
func TestProcessAlert_AutoRespondFalseSuppressesTerminationAtHighScore(t *testing.T) {
	cases := []struct {
		name  string
		score int
		sev   domain.ThreatLevel
	}{
		{"ThreatHigh score 61", 61, domain.ThreatHigh},
		{"ThreatCritical score 100", 100, domain.ThreatCritical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &config.ResponseConfig{ResponseSettings: config.ResponseSetting{
				AutoTerminateEnabled:      true,
				TerminateOnCriticalScore:  true,
				CriticalScoreThreshold:    49,
				TerminateOnExtensionMatch: true,
			}}
			ro := newGateTestOrchestrator(rc)

			alert := &domain.Alert{
				ProcessGuid: "guid-x",
				ProcessID:   4242,
				Image:       `C:\victim\proc.exe`,
				Score:       tc.score,
				Severity:    tc.sev,
				AutoRespond: false,
				Indicators:  []domain.Indicator{{Type: domain.IndicatorRansomExtension}},
			}
			ro.processAlert(context.Background(), alert)

			stats := ro.GetStats()
			if got := statInt(t, stats, "processes_terminated"); got != 0 {
				t.Errorf("processes_terminated = %d, want 0 (false verdict must not terminate)", got)
			}
			if got := statInt(t, stats, "auto_responses_blocked"); got != 1 {
				t.Errorf("auto_responses_blocked = %d, want 1", got)
			}
		})
	}
}

// A true verdict at a qualifying level clears both gates and enters the response pipeline.
func TestProcessAlert_AutoRespondTruePassesGateAtQualifyingLevel(t *testing.T) {
	rc := &config.ResponseConfig{ResponseSettings: config.ResponseSetting{
		AutoTerminateEnabled: true,
	}}
	ro := newGateTestOrchestrator(rc)

	// ProcessID = -1 is the seam: the alert clears BOTH gates, enters
	// executeAutomatedResponse, and returns at the invalid-PID guard (PID <= 0) before the
	// nil Windows terminator is invoked. auto_responses_blocked is incremented there.
	alert := &domain.Alert{
		ProcessGuid: "guid-ransom",
		ProcessID:   -1,
		Image:       `C:\malware.exe`,
		Score:       100,
		Severity:    domain.ThreatCritical,
		AutoRespond: true,
	}
	ro.processAlert(context.Background(), alert)

	stats := ro.GetStats()
	if got := statInt(t, stats, "alerts_processed"); got != 1 {
		t.Errorf("alerts_processed = %d, want 1", got)
	}
	if got := statInt(t, stats, "processes_terminated"); got != 0 {
		t.Errorf("processes_terminated = %d, want 0 (PID guard, no live kill)", got)
	}
	// Incremented by the invalid-PID guard, proving execution passed BOTH gates.
	if got := statInt(t, stats, "auto_responses_blocked"); got != 1 {
		t.Errorf("auto_responses_blocked = %d, want 1 (reached the invalid-PID guard)", got)
	}
}

// The three config safety controls retain veto power: they downgrade a true verdict to
// no-action, but (see the next test) can never upgrade a false one.
func TestProcessAlert_ConfigVetoDowngradesTrueVerdict(t *testing.T) {
	base := func() *domain.Alert {
		return &domain.Alert{
			ProcessGuid: "guid-v",
			ProcessID:   4242,
			Image:       `C:\Windows\System32\trusted.exe`,
			Score:       100,
			Severity:    domain.ThreatCritical,
			AutoRespond: true,
		}
	}
	cases := []struct {
		name string
		rc   *config.ResponseConfig
	}{
		{"global kill-switch off", &config.ResponseConfig{ResponseSettings: config.ResponseSetting{
			AutoTerminateEnabled: false,
		}}},
		{"investigation mode", &config.ResponseConfig{ResponseSettings: config.ResponseSetting{
			AutoTerminateEnabled: true,
			InvestigationMode:    true,
		}}},
		{"whitelisted image", &config.ResponseConfig{
			ResponseSettings: config.ResponseSetting{AutoTerminateEnabled: true},
			Whitelist: config.WhitelistConfig{
				Enabled: true,
				Paths:   []string{`c:\windows\system32`},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ro := newGateTestOrchestrator(tc.rc)
			ro.processAlert(context.Background(), base())

			stats := ro.GetStats()
			if got := statInt(t, stats, "processes_terminated"); got != 0 {
				t.Errorf("processes_terminated = %d, want 0 (config veto must suppress a true verdict)", got)
			}
			if got := statInt(t, stats, "auto_responses_blocked"); got != 1 {
				t.Errorf("auto_responses_blocked = %d, want 1", got)
			}
		})
	}
}

// Forbidden-upgrade property: no combination of config flags/thresholds, nor an extension
// match, can turn AutoRespond=false into a termination.
func TestProcessAlert_NoConfigFlagCanUpgradeFalseVerdict(t *testing.T) {
	bools := []bool{false, true}
	thresholds := []int{0, 49, 100}
	combos := 0
	for _, ate := range bools {
		for _, tcs := range bools {
			for _, tem := range bools {
				for _, thr := range thresholds {
					combos++
					rc := &config.ResponseConfig{ResponseSettings: config.ResponseSetting{
						AutoTerminateEnabled:      ate,
						TerminateOnCriticalScore:  tcs,
						TerminateOnExtensionMatch: tem,
						CriticalScoreThreshold:    thr,
					}}
					ro := newGateTestOrchestrator(rc)
					alert := &domain.Alert{
						ProcessGuid: "guid-f",
						ProcessID:   4242,
						Image:       `C:\victim\proc.exe`,
						Score:       100,
						Severity:    domain.ThreatCritical,
						AutoRespond: false,
						Indicators:  []domain.Indicator{{Type: domain.IndicatorRansomExtension}},
					}
					ro.processAlert(context.Background(), alert)
					if got := statInt(t, ro.GetStats(), "processes_terminated"); got != 0 {
						t.Fatalf("ate=%v tcs=%v tem=%v thr=%d: processes_terminated=%d, want 0",
							ate, tcs, tem, thr, got)
					}
				}
			}
		}
	}
	t.Logf("verified forbidden-upgrade across %d config combinations", combos)
}
