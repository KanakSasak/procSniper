package domain

import (
	"fmt"
	"sync"
	"testing"
)

// TestThreatScorer_ConcurrentSharded pins that ProcessGuid striping (Phase 5) preserves
// scoring semantics under concurrency: repeatable indicators accumulate without lost updates,
// non-repeatable indicators still dedupe atomically, distinct processes score independently
// across shards, and GetAllThreats is consistent. Run under -race.
func TestThreatScorer_ConcurrentSharded(t *testing.T) {
	t.Run("repeatable indicator accumulates under same-shard contention", func(t *testing.T) {
		ts := NewThreatScorer()
		const goroutines, perG = 8, 50
		var wg sync.WaitGroup
		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < perG; i++ {
					ts.AddIndicator("guid-hot", `C:\x.exe`, 1, Indicator{Type: IndicatorLSASSAccess, Points: 35})
				}
			}()
		}
		wg.Wait()

		// LSASSAccess is repeatable, so every add contributes — no lost updates under the shard lock.
		want := goroutines * perG * 35
		if got := ts.GetThreatScore("guid-hot"); got == nil || got.Score != want {
			t.Errorf("score = %v, want %d", got, want)
		}
	})

	t.Run("non-repeatable indicator deduped under concurrency", func(t *testing.T) {
		ts := NewThreatScorer()
		var wg sync.WaitGroup
		for g := 0; g < 16; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 25; i++ {
					ts.AddIndicator("guid-vel", `C:\x.exe`, 1, Indicator{Type: IndicatorIOVelocity, Points: 30})
				}
			}()
		}
		wg.Wait()

		// IOVelocity is non-repeatable: counted exactly once even under concurrent adds.
		if got := ts.GetThreatScore("guid-vel"); got == nil || got.Score != 30 {
			t.Errorf("score = %v, want 30", got)
		}
	})

	t.Run("distinct processes across shards + concurrent GetAllThreats", func(t *testing.T) {
		ts := NewThreatScorer()
		const n = 200
		var wg sync.WaitGroup
		for p := 0; p < n; p++ {
			p := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				ts.AddIndicator(fmt.Sprintf("g-%d", p), `C:\x.exe`, p, Indicator{Type: IndicatorCredentialTheft, Points: 40})
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				_ = ts.GetAllThreats()
			}
		}()
		wg.Wait()

		for p := 0; p < n; p++ {
			if _, score := ts.EvaluateThreat(fmt.Sprintf("g-%d", p)); score != 40 {
				t.Errorf("g-%d: score = %d, want 40", p, score)
			}
		}
		if got := len(ts.GetAllThreats()); got != n {
			t.Errorf("GetAllThreats count = %d, want %d", got, n)
		}
	})
}
