package usecase

import (
	"context"
	"fmt"
	"testing"
	"time"

	"procSniper/internal/domain"
)

// TestDetectionService_VelocityTierFlagging pins the velocity-tier flagging behavior
// before the ProcessState refactor. Key invariants (currently driven by the
// monitoredProcesses/analyzedProcesses/highIOProcesses maps):
//   - A process that crosses the CRITICAL threshold (>=100 files/min) is high-IO flagged
//     (insert-only: it stays flagged) and counted by GetHighIOProcessCount.
//   - A process that only reaches the ANALYZE tier (30-99 files/min) is NOT high-IO flagged.
//   - The IOVelocity indicator is recorded at most once per process.
func TestDetectionService_VelocityTierFlagging(t *testing.T) {
	ds := newMLTestDetectionService()
	ctx := context.Background()

	driveCreates := func(guid string, n int) {
		base := time.Now()
		for i := 0; i < n; i++ {
			ds.ProcessFileCreate(ctx, &domain.MonitorEvent{
				Timestamp:   base.Add(time.Duration(i) * time.Millisecond),
				ProcessGuid: guid,
				ProcessID:   1000,
				Image:       `C:\proc.exe`,
				TargetFile:  fmt.Sprintf(`C:\victim\f%d.dat`, i),
			})
		}
	}

	// CRITICAL: >=100 files within the 60s window.
	driveCreates("guid-critical", 105)
	if !ds.IsProcessFlagged("guid-critical") {
		t.Error("process exceeding CRITICAL velocity should be high-IO flagged")
	}

	// ANALYZE only: 55 files/min — tracked but not high-IO flagged.
	driveCreates("guid-analyze", 55)
	if ds.IsProcessFlagged("guid-analyze") {
		t.Error("ANALYZE-tier process should not be high-IO flagged")
	}

	if got := ds.GetHighIOProcessCount(); got != 1 {
		t.Errorf("GetHighIOProcessCount = %d, want 1 (only the CRITICAL process)", got)
	}

	// IOVelocity indicator recorded once for the CRITICAL process.
	score := ds.GetThreatScore("guid-critical")
	if score == nil {
		t.Fatal("expected a threat score for the CRITICAL process")
	}
	ioCount := 0
	for _, ind := range score.Indicators {
		if ind.Type == domain.IndicatorIOVelocity {
			ioCount++
		}
	}
	if ioCount != 1 {
		t.Errorf("IOVelocity indicators = %d, want exactly 1", ioCount)
	}
}

// TestDetectionService_CreateTierNoneSkipsAccumulation pins the ordering invariant preserved
// across the velocity-tier dedupe (Phase 6 S5): a single low-velocity create is TierNone, so
// ProcessFileCreate must return BEFORE the ML feature accumulation — it must not create a
// counters entry. (updateVelocityTierForOperation still tracks the velocity actor for None.)
func TestDetectionService_CreateTierNoneSkipsAccumulation(t *testing.T) {
	ds := newMLTestDetectionService()
	ds.ProcessFileCreate(context.Background(), &domain.MonitorEvent{
		Timestamp:   time.Now(),
		ProcessGuid: "guid-none",
		ProcessID:   1000,
		Image:       `C:\proc.exe`,
		TargetFile:  `C:\victim\only.docx`,
	})

	if f := ds.ExtractFeatureVector("guid-none"); f[3] != 0 {
		t.Errorf("directory_count = %v, want 0 (TierNone create must not accumulate ML counters)", f[3])
	}
	if ds.IsProcessFlagged("guid-none") {
		t.Error("a single create should not be high-IO flagged")
	}
}
