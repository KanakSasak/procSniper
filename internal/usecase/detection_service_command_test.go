package usecase

import (
	"context"
	"testing"
	"time"

	"procSniper/internal/domain"
)

// TestDetectionService_ProcessCreateCommands pins the process-create command-line detection
// after its migration into commandAnalyzer (Phase 6): shadow-copy deletion raises the
// instant-kill indicator and sets the ML flag; a systeminfo recon command sets only the
// system_info ML feature; a benign command raises nothing.
func TestDetectionService_ProcessCreateCommands(t *testing.T) {
	t.Run("shadow copy deletion raises instant-kill indicator", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ds.ProcessProcessCreate(context.Background(), &domain.MonitorEvent{
			Timestamp:   time.Now(),
			ProcessGuid: "guid-vss",
			ProcessID:   666,
			Image:       `C:\Windows\System32\vssadmin.exe`,
			CommandLine: `vssadmin.exe delete shadows /all /quiet`,
		})

		score := ds.GetThreatScore("guid-vss")
		if score == nil {
			t.Fatal("expected a threat score for the shadow-copy process")
		}
		shadow := 0
		for _, ind := range score.Indicators {
			if ind.Type == domain.IndicatorShadowCopyDeletion {
				shadow++
			}
		}
		if shadow != 1 {
			t.Errorf("ShadowCopyDeletion indicators = %d, want 1", shadow)
		}
		if f := ds.ExtractFeatureVector("guid-vss"); f[8] != 1 {
			t.Errorf("shadow_copy_delete feature = %v, want 1", f[8])
		}
	})

	t.Run("systeminfo recon sets the ML flag without an indicator", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ds.ProcessProcessCreate(context.Background(), &domain.MonitorEvent{
			Timestamp:   time.Now(),
			ProcessGuid: "guid-recon",
			ProcessID:   667,
			Image:       `C:\Windows\System32\cmd.exe`,
			CommandLine: `cmd.exe /c systeminfo`,
		})

		if f := ds.ExtractFeatureVector("guid-recon"); f[13] != 1 {
			t.Errorf("system_info_queries feature = %v, want 1", f[13])
		}
	})

	t.Run("benign command raises nothing", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ds.ProcessProcessCreate(context.Background(), &domain.MonitorEvent{
			Timestamp:   time.Now(),
			ProcessGuid: "guid-benign",
			ProcessID:   668,
			Image:       `C:\Windows\System32\notepad.exe`,
			CommandLine: `notepad.exe C:\Users\victim\notes.txt`,
		})

		if score := ds.GetThreatScore("guid-benign"); score != nil && len(score.Indicators) != 0 {
			t.Errorf("benign command produced %d indicators, want 0", len(score.Indicators))
		}
	})
}
