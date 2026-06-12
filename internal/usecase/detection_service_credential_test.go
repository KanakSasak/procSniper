package usecase

import (
	"testing"
	"time"

	"procSniper/internal/domain"
)

// TestDetectionService_CredentialAccess pins the browser/SSH credential-theft detection
// after its migration into credentialAccessAnalyzer (Phase 6): a non-browser process
// touching a browser credential store raises IndicatorCredentialTheft exactly once (the
// first-hit transition), and a legitimate browser touching the same path raises nothing.
func TestDetectionService_CredentialAccess(t *testing.T) {
	const chromeLoginData = `C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Login Data`

	countCredTheft := func(score *domain.ThreatScore) int {
		if score == nil {
			return 0
		}
		n := 0
		for _, ind := range score.Indicators {
			if ind.Type == domain.IndicatorCredentialTheft {
				n++
			}
		}
		return n
	}

	t.Run("stealer reading browser credentials is flagged once", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ev := &domain.MonitorEvent{
			Timestamp:   time.Now(),
			ProcessGuid: "guid-stealer",
			ProcessID:   1234,
			Image:       `C:\Users\victim\stealer.exe`,
			TargetFile:  chromeLoginData,
		}
		ds.checkBrowserAndSSHAccess(ev)
		ds.checkBrowserAndSSHAccess(ev) // repeatable indicator type; first-hit guard keeps it at one

		if got := countCredTheft(ds.GetThreatScore("guid-stealer")); got != 1 {
			t.Errorf("IndicatorCredentialTheft count = %d, want 1", got)
		}
		if f := ds.ExtractFeatureVector("guid-stealer"); f[9] != 1 {
			t.Errorf("browser_credential_access feature = %v, want 1", f[9])
		}
	})

	t.Run("legitimate browser touching its own credentials raises nothing", func(t *testing.T) {
		ds := newMLTestDetectionService()
		ds.checkBrowserAndSSHAccess(&domain.MonitorEvent{
			Timestamp:   time.Now(),
			ProcessGuid: "guid-chrome",
			ProcessID:   1235,
			Image:       `C:\Program Files\Google\Chrome\Application\chrome.exe`,
			TargetFile:  chromeLoginData,
		})

		if got := countCredTheft(ds.GetThreatScore("guid-chrome")); got != 0 {
			t.Errorf("IndicatorCredentialTheft count = %d, want 0 (browser is skipped)", got)
		}
	})
}
