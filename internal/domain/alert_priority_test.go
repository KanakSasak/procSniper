package domain

import "testing"

// TestAlert_IsHighPriority pins the priority classification driving Phase 5 reserved-capacity
// shedding: Critical severity is always protected; EventID 1 (process create) / 10 (process
// access) are protected regardless of severity; everything else is low-priority.
func TestAlert_IsHighPriority(t *testing.T) {
	cases := []struct {
		name     string
		severity ThreatLevel
		eventID  int
		want     bool
	}{
		{"critical severity", ThreatCritical, 0, true},
		{"high severity, no originating event", ThreatHigh, 0, false},
		{"high severity, process-create event", ThreatHigh, 1, true},
		{"medium severity, process-access event", ThreatMedium, 10, true},
		{"low severity, other event", ThreatLow, 2, false},
		{"none", ThreatNone, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Alert{Severity: tc.severity, EventID: tc.eventID}
			if got := a.IsHighPriority(); got != tc.want {
				t.Errorf("IsHighPriority(severity=%s, eventID=%d) = %v, want %v",
					tc.severity, tc.eventID, got, tc.want)
			}
		})
	}
}
