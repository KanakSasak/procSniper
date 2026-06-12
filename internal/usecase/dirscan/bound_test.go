package dirscan

import (
	"fmt"
	"testing"

	"procSniper/internal/domain"
)

// TestScanner_BoundsConcurrentScans pins the Phase 5 concurrency bound: with a small bound,
// only `bound` distinct-directory scans start (their goroutines hold the slots through the
// progressive-scan sleeps), over-bound calls return false, and — critically — the dedup mark
// is rolled back so a bound-deferred directory stays eligible for a later scan (no permanent
// detection hole).
func TestScanner_BoundsConcurrentScans(t *testing.T) {
	s := NewScanner(&fakeEmitter{}, []string{".locked"})
	s.SetScanConcurrency(2)

	const n = 5
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		// Distinct, non-existent directories: each scan's goroutine reads an empty/error dir,
		// finds nothing, and holds its slot through the progressive-scan sleeps.
		ev := &domain.MonitorEvent{TargetFile: fmt.Sprintf(`C:\nonexistent-scan-%d\f.txt`, i)}
		results[i] = s.ScanDeletedFileDir(ev)
	}

	started := 0
	for _, r := range results {
		if r {
			started++
		}
	}
	if started != 2 {
		t.Errorf("started scans = %d, want 2 (bounded by SetScanConcurrency(2))", started)
	}

	// Bound-deferred (false) directories must NOT remain marked in-progress (dedup rolled back),
	// or the directory would be permanently un-scannable.
	s.inProgressMu.Lock()
	defer s.inProgressMu.Unlock()
	for i, r := range results {
		dir := fmt.Sprintf(`C:\nonexistent-scan-%d`, i)
		if !r && s.inProgress[dir] {
			t.Errorf("dir %d returned false (bound-deferred) but is still marked in-progress — dedup not rolled back", i)
		}
	}
}
