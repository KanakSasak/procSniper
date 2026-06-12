package domain

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestFileOperationTracker_ConcurrentPerProcess pins that the ProcessGuid striping (Phase 5)
// preserves per-process velocity/tier/count under concurrent AddOperation across many
// processes (different shards) plus concurrent readers. Run under -race to confirm the
// striped locking is sound and no two processes' counts bleed across a shard.
func TestFileOperationTracker_ConcurrentPerProcess(t *testing.T) {
	fot := NewFileOperationTracker(60 * time.Second) // 60s window -> files/min == op count

	type proc struct {
		guid     string
		ops      int
		wantTier VelocityTier
	}
	tiered := []proc{
		{"p-crit", 120, VelocityTierCritical},
		{"p-analyze", 50, VelocityTierAnalyze},
		{"p-monitor", 15, VelocityTierMonitor},
		{"p-none", 5, VelocityTierNone},
	}
	procs := append([]proc{}, tiered...)
	// Many background processes to exercise shard distribution + lock interleaving.
	for i := 0; i < 60; i++ {
		procs = append(procs, proc{guid: fmt.Sprintf("bg-%d", i), ops: 11 + i})
	}

	base := time.Now()
	var wg sync.WaitGroup
	for _, p := range procs {
		p := p
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < p.ops; j++ {
				fot.AddOperation(FileOperation{
					Timestamp:   base.Add(time.Duration(j) * time.Millisecond),
					ProcessGuid: p.guid,
					ProcessID:   1,
					Operation:   "create",
					FilePath:    fmt.Sprintf("f%d", j),
				})
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 50; k++ {
				_ = fot.GetVelocity(p.guid)
				_ = fot.GetVelocityTier(p.guid)
			}
		}()
	}
	wg.Wait()

	// Each process's velocity == its op count (60s window), count exact, no cross-process bleed.
	for _, p := range procs {
		if got := fot.GetVelocity(p.guid); got != float64(p.ops) {
			t.Errorf("%s: velocity = %.1f, want %.1f", p.guid, got, float64(p.ops))
		}
		if got := fot.GetOperationCount(p.guid); got != p.ops {
			t.Errorf("%s: op count = %d, want %d", p.guid, got, p.ops)
		}
	}
	for _, p := range tiered {
		if got := fot.GetVelocityTier(p.guid); got != p.wantTier {
			t.Errorf("%s: tier = %v, want %v", p.guid, got, p.wantTier)
		}
	}
}
