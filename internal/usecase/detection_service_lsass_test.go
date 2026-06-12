package usecase

import (
	"context"
	"testing"
	"time"

	"procSniper/internal/domain"
)

// TestDetectionService_LSASSAccess pins the LSASS credential-dumping detection after its
// migration into lsassAnalyzer (Phase 6). A non-trusted process opening lsass.exe memory
// must raise exactly one IndicatorLSASSAccess; a non-LSASS target must raise none.
func TestDetectionService_LSASSAccess(t *testing.T) {
	countLSASS := func(score *domain.ThreatScore) int {
		if score == nil {
			return 0
		}
		n := 0
		for _, ind := range score.Indicators {
			if ind.Type == domain.IndicatorLSASSAccess {
				n++
			}
		}
		return n
	}

	t.Run("non-trusted process opening lsass is flagged once", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ctx := context.Background()

		ev := &domain.MonitorEvent{
			Timestamp:     time.Now(),
			ProcessGuid:   "guid-lsass",
			ProcessID:     4242,
			Image:         `C:\Users\victim\evil.exe`,
			TargetImage:   `C:\Windows\System32\lsass.exe`,
			GrantedAccess: "0x1410",
		}
		ds.ProcessLSASSAccess(ctx, ev)

		if got := countLSASS(ds.GetThreatScore("guid-lsass")); got != 1 {
			t.Errorf("IndicatorLSASSAccess count = %d, want 1", got)
		}
	})

	t.Run("non-lsass target raises nothing", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ctx := context.Background()

		ds.ProcessLSASSAccess(ctx, &domain.MonitorEvent{
			Timestamp:     time.Now(),
			ProcessGuid:   "guid-benign",
			ProcessID:     4243,
			Image:         `C:\Users\victim\evil.exe`,
			TargetImage:   `C:\Windows\System32\svchost.exe`,
			GrantedAccess: "0x1410",
		})

		if got := countLSASS(ds.GetThreatScore("guid-benign")); got != 0 {
			t.Errorf("IndicatorLSASSAccess count = %d, want 0", got)
		}
	})
}
