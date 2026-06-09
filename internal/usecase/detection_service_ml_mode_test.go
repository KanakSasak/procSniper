package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"procSniper/config"
	"procSniper/internal/domain"
)

type fakePredictor struct {
	ready      bool
	prediction *domain.MLPrediction
	err        error
}

func (f *fakePredictor) Predict(features [14]float64) (*domain.MLPrediction, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.prediction == nil {
		return &domain.MLPrediction{
			Label:         0,
			LabelName:     "benign",
			Confidence:    1.0,
			Probabilities: [3]float64{1.0, 0.0, 0.0},
			Features:      features,
			Timestamp:     time.Now(),
		}, nil
	}

	copyPred := *f.prediction
	copyPred.Features = features
	if copyPred.Timestamp.IsZero() {
		copyPred.Timestamp = time.Now()
	}
	return &copyPred, nil
}

func (f *fakePredictor) IsReady() bool {
	return f.ready
}

func (f *fakePredictor) Close() error {
	f.ready = false
	return nil
}

type capturingPredictor struct {
	ready      bool
	prediction *domain.MLPrediction
	lastFeat   [14]float64
	calls      int
}

func (c *capturingPredictor) Predict(features [14]float64) (*domain.MLPrediction, error) {
	c.calls++
	c.lastFeat = features
	if c.prediction == nil {
		return &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.9,
			Probabilities: [3]float64{0.1, 0.9, 0.0},
			Features:      features,
			Timestamp:     time.Now(),
		}, nil
	}
	copyPred := *c.prediction
	copyPred.Features = features
	if copyPred.Timestamp.IsZero() {
		copyPred.Timestamp = time.Now()
	}
	return &copyPred, nil
}

func (c *capturingPredictor) IsReady() bool {
	return c.ready
}

func (c *capturingPredictor) Close() error {
	c.ready = false
	return nil
}

func newMLTestDetectionService() *DetectionService {
	return NewDetectionService(DetectionConfig{
		EntropyFileThreshold:   10,
		ExtensionFileThreshold: 5,
		CombinedThreshold:      5,
		RenameExtThreshold:     3,
		RansomwareExtensions:   []string{".encrypted"},
	})
}

func mustReceiveAlert(t *testing.T, ch <-chan *domain.Alert) *domain.Alert {
	t.Helper()
	select {
	case alert := <-ch:
		return alert
	case <-time.After(300 * time.Millisecond):
		t.Fatal("expected alert but none received")
		return nil
	}
}

func mustNotReceiveAlert(t *testing.T, ch <-chan *domain.Alert) {
	t.Helper()
	select {
	case alert := <-ch:
		t.Fatalf("unexpected alert received: %s (score=%d)", alert.Description, alert.Score)
	case <-time.After(150 * time.Millisecond):
	}
}

func attachActivityCapture(ds *DetectionService) *[]*domain.MLInferenceActivity {
	activities := make([]*domain.MLInferenceActivity, 0, 4)
	ds.SetMLPredictionCallback(func(activity *domain.MLInferenceActivity) {
		if activity == nil {
			return
		}
		copyActivity := *activity
		activities = append(activities, &copyActivity)
	})
	return &activities
}

func mustLastActivity(t *testing.T, activities *[]*domain.MLInferenceActivity) *domain.MLInferenceActivity {
	t.Helper()
	if activities == nil || len(*activities) == 0 {
		t.Fatal("expected ML activity but none captured")
	}
	return (*activities)[len(*activities)-1]
}

// seedForMLGate populates velocity actors, file counters (for non-zero features to
// pass the ML gate), AND threat scorer indicators (for score/ThreatLevel assertions).
// nFeatures controls how many non-zero features are seeded (minimum 4).
func seedForMLGate(ds *DetectionService, guid, image string, pid int, nFeatures int) {
	// Seed velocity actors → features[0] (velocity), features[1] (file_count)
	ds.velocityActorsMux.Lock()
	ds.velocityActors[guid] = &VelocityActorState{
		ProcessGuid:           guid,
		ProcessID:             pid,
		Image:                 image,
		TotalOps60s:           100,
		CreateOps60s:          50,
		ModifyOps60s:          50,
		CumulativeFileCount:   200,
		CumulativeCreateCount: 100,
		LastSeen:              time.Now(),
	}
	ds.velocityActorsMux.Unlock()

	// Seed file counters → features[2..7+]
	ds.fileCountersMux.Lock()
	counters := &ProcessFileCounters{
		DirectorySet:         map[string]struct{}{"C:\\dir1": {}, "C:\\dir2": {}}, // feature[3]
		ExtensionCounts:      map[string]int{".encrypted": 10, ".exe": 5},        // feature[7]
		RansomExtensionCount: 10,                                                  // feature[6] (extension_match)
		LastUpdated:          time.Now(),
	}
	if nFeatures >= 5 {
		counters.TxtFileCount = 5 // feature[2]
	}
	if nFeatures >= 6 {
		counters.DeleteCount = 3 // feature[4]
	}
	if nFeatures >= 7 {
		counters.ShadowCopyDeleteHit = true // feature[8]
	}
	ds.fileCounters[guid] = counters
	ds.fileCountersMux.Unlock()

	// Seed threat scorer for score/level (needed for ThreatHigh+ assertions)
	indicatorTypes := []domain.IndicatorType{
		domain.IndicatorIOVelocity,
		domain.IndicatorHighEntropy,
		domain.IndicatorRansomExtension,
		domain.IndicatorShadowCopyDeletion,
	}
	for _, iType := range indicatorTypes {
		ds.threatScorer.AddIndicator(guid, image, pid, domain.Indicator{
			Type:        iType,
			Severity:    domain.ThreatHigh,
			Points:      domain.IndicatorScores[iType],
			Description: "seeded for ML gate",
			Timestamp:   time.Now(),
		})
	}
}

// seedFeaturesOnly populates velocity actors and file counters without adding
// threat scorer indicators. Used to test gate blocking with insufficient score.
func seedFeaturesOnly(ds *DetectionService, guid, image string, pid int, nFeatures int) {
	ds.velocityActorsMux.Lock()
	ds.velocityActors[guid] = &VelocityActorState{
		ProcessGuid:           guid,
		ProcessID:             pid,
		Image:                 image,
		TotalOps60s:           10,
		CreateOps60s:          5,
		ModifyOps60s:          5,
		CumulativeFileCount:   20,
		CumulativeCreateCount: 10,
		LastSeen:              time.Now(),
	}
	ds.velocityActorsMux.Unlock()

	ds.fileCountersMux.Lock()
	counters := &ProcessFileCounters{
		DirectorySet:    map[string]struct{}{"C:\\dir1": {}}, // feature[3]
		ExtensionCounts: map[string]int{".txt": 3},          // feature[7]
		LastUpdated:     time.Now(),
	}
	if nFeatures >= 3 {
		counters.TxtFileCount = 2 // feature[2]
	}
	ds.fileCounters[guid] = counters
	ds.fileCountersMux.Unlock()
}

func TestDetectionService_MLOnlyRansomwareDecision(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.98,
			Probabilities: [3]float64{0.01, 0.98, 0.01},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	// Seed features + indicators to pass the ML gate
	seedForMLGate(ds, "guid-ransom", `C:\malware.exe`, 1337, 4)

	ds.evaluateAndAlert("guid-ransom", `C:\malware.exe`, 1337)
	alert := mustReceiveAlert(t, ds.GetAlertChannel())

	if alert.Category != "RANSOMWARE" {
		t.Fatalf("category = %s, expected RANSOMWARE", alert.Category)
	}
	if alert.Severity != domain.ThreatCritical {
		t.Fatalf("severity = %s, expected CRITICAL", alert.Severity)
	}
	if alert.Score != 100 {
		t.Fatalf("score = %d, expected 100", alert.Score)
	}
	if !alert.AutoRespond {
		t.Fatal("expected AutoRespond=true for ML ransomware decision")
	}
	if len(alert.Indicators) != 1 || alert.Indicators[0].Type != domain.IndicatorMLRansomware {
		t.Fatalf("expected one ML ransomware indicator, got %+v", alert.Indicators)
	}
	activity := mustLastActivity(t, activities)
	if activity.Stage != "decision" {
		t.Fatalf("stage = %s, expected decision", activity.Stage)
	}
	if activity.Decision != "terminate_eligible" {
		t.Fatalf("decision = %s, expected terminate_eligible", activity.Decision)
	}
	if activity.DecisionScore != 100 {
		t.Fatalf("decision score = %d, expected 100", activity.DecisionScore)
	}
	if !activity.DecisionAutoRespond {
		t.Fatal("expected DecisionAutoRespond=true")
	}

	rc := &config.ResponseConfig{
		ResponseSettings: config.ResponseSetting{
			AutoTerminateEnabled:     true,
			TerminateOnCriticalScore: true,
			CriticalScoreThreshold:   49,
		},
	}
	if !rc.ShouldAutoTerminate(alert.Score, false, alert.Image) {
		t.Fatal("expected ML ransomware alert to be terminate-eligible")
	}
}

func TestDetectionService_MLOnlyStealerDecision(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         2,
			LabelName:     "stealer",
			Confidence:    0.92,
			Probabilities: [3]float64{0.03, 0.05, 0.92},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	seedForMLGate(ds, "guid-stealer", `C:\stealer.exe`, 2448, 4)

	ds.evaluateAndAlert("guid-stealer", `C:\stealer.exe`, 2448)
	alert := mustReceiveAlert(t, ds.GetAlertChannel())

	if alert.Category != "STEALER" {
		t.Fatalf("category = %s, expected STEALER", alert.Category)
	}
	if alert.Severity != domain.ThreatMedium {
		t.Fatalf("severity = %s, expected MEDIUM", alert.Severity)
	}
	if alert.Score != 30 {
		t.Fatalf("score = %d, expected 30", alert.Score)
	}
	if alert.AutoRespond {
		t.Fatal("expected AutoRespond=false for ML stealer decision")
	}
	if len(alert.Indicators) != 1 || alert.Indicators[0].Type != domain.IndicatorMLStealer {
		t.Fatalf("expected one ML stealer indicator, got %+v", alert.Indicators)
	}
	activity := mustLastActivity(t, activities)
	if activity.Stage != "decision" {
		t.Fatalf("stage = %s, expected decision", activity.Stage)
	}
	if activity.Decision != "alert_only" {
		t.Fatalf("decision = %s, expected alert_only", activity.Decision)
	}
	if activity.DecisionScore != 30 {
		t.Fatalf("decision score = %d, expected 30", activity.DecisionScore)
	}
	if activity.DecisionAutoRespond {
		t.Fatal("expected DecisionAutoRespond=false")
	}

	rc := &config.ResponseConfig{
		ResponseSettings: config.ResponseSetting{
			AutoTerminateEnabled:     true,
			TerminateOnCriticalScore: true,
			CriticalScoreThreshold:   49,
		},
	}
	if rc.ShouldAutoTerminate(alert.Score, false, alert.Image) {
		t.Fatal("expected ML stealer alert to be alert-only under default threshold")
	}
}

func TestDetectionService_MLOnlyBenignHighConfidenceBelowMaliciousThreshold(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         0,
			LabelName:     "benign",
			Confidence:    0.88,
			Probabilities: [3]float64{0.88, 0.12, 0.00},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.65)

	seedForMLGate(ds, "guid-benign", `C:\benign.exe`, 3112, 4)

	ds.evaluateAndAlert("guid-benign", `C:\benign.exe`, 3112)

	// ML says benign (below threshold) — with fallback disabled, NO alert is emitted.
	select {
	case a := <-ds.GetAlertChannel():
		t.Fatalf("expected no alert with fallback disabled, got severity=%s", a.Severity)
	default:
	}

	activity := mustLastActivity(t, activities)
	if activity.Stage != "skipped" {
		t.Fatalf("stage = %s, expected skipped", activity.Stage)
	}
	if activity.Reason != "below_threshold" {
		t.Fatalf("reason = %s, expected below_threshold", activity.Reason)
	}
}

func TestDetectionService_MLOnlyMaliciousSumAboveThresholdTriggersDecision(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         0,
			LabelName:     "benign",
			Confidence:    0.45,
			Probabilities: [3]float64{0.45, 0.35, 0.20},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.50)

	seedForMLGate(ds, "guid-malicious-sum", `C:\mixed.exe`, 3555, 4)

	ds.evaluateAndAlert("guid-malicious-sum", `C:\mixed.exe`, 3555)
	alert := mustReceiveAlert(t, ds.GetAlertChannel())
	if alert.Category != "RANSOMWARE" {
		t.Fatalf("category = %s, expected RANSOMWARE", alert.Category)
	}
	if alert.Score != 100 {
		t.Fatalf("score = %d, expected 100", alert.Score)
	}
	if !alert.AutoRespond {
		t.Fatal("expected AutoRespond=true for ransomware decision")
	}

	activity := mustLastActivity(t, activities)
	if activity.Stage != "decision" {
		t.Fatalf("stage = %s, expected decision", activity.Stage)
	}
	if activity.Decision != "terminate_eligible" {
		t.Fatalf("decision = %s, expected terminate_eligible", activity.Decision)
	}
	if activity.DecisionScore != 100 {
		t.Fatalf("decision score = %d, expected 100", activity.DecisionScore)
	}
}

func TestDetectionService_MLOnlyLowConfidenceNoDecision(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.40,
			Probabilities: [3]float64{0.55, 0.40, 0.05},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	seedForMLGate(ds, "guid-low-confidence", `C:\unknown.exe`, 4001, 4)

	ds.evaluateAndAlert("guid-low-confidence", `C:\unknown.exe`, 4001)

	// ML below threshold — with fallback disabled, NO alert is emitted.
	select {
	case a := <-ds.GetAlertChannel():
		t.Fatalf("expected no alert with fallback disabled, got severity=%s", a.Severity)
	default:
	}

	activity := mustLastActivity(t, activities)
	if activity.Stage != "skipped" {
		t.Fatalf("stage = %s, expected skipped", activity.Stage)
	}
	if activity.Reason != "below_threshold" {
		t.Fatalf("reason = %s, expected below_threshold", activity.Reason)
	}
}

func TestDetectionService_MLInferenceFailureNoFallback(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		err:   errors.New("inference failed"),
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	// Seed features + indicators to pass the ML gate (score = ThreatCritical)
	seedForMLGate(ds, "guid-rule-seeded", `C:\rule.exe`, 5050, 4)

	ds.evaluateAndAlert("guid-rule-seeded", `C:\rule.exe`, 5050)

	// ML inference errored — with fallback disabled, NO alert is emitted.
	select {
	case a := <-ds.GetAlertChannel():
		t.Fatalf("expected no alert with fallback disabled, got severity=%s", a.Severity)
	default:
	}

	activity := mustLastActivity(t, activities)
	if activity.Stage != "error" {
		t.Fatalf("stage = %s, expected error", activity.Stage)
	}
	if activity.Reason != "inference_error" {
		t.Fatalf("reason = %s, expected inference_error", activity.Reason)
	}
}

func TestDetectionService_MLPredictorNotReadyNoFallback(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{ready: false})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	seedForMLGate(ds, "guid-not-ready", `C:\rule.exe`, 7070, 4)

	ds.evaluateAndAlert("guid-not-ready", `C:\rule.exe`, 7070)

	// Predictor not ready — with fallback disabled, NO alert is emitted.
	select {
	case a := <-ds.GetAlertChannel():
		t.Fatalf("expected no alert with fallback disabled, got severity=%s", a.Severity)
	default:
	}

	activity := mustLastActivity(t, activities)
	if activity.Stage != "skipped" {
		t.Fatalf("stage = %s, expected skipped", activity.Stage)
	}
	if activity.Reason != "predictor_not_ready" {
		t.Fatalf("reason = %s, expected predictor_not_ready", activity.Reason)
	}
}

// TestDetectionService_RuleIndicatorsAccumulateInMLMode verifies that rule-based
// indicators are accumulated (not suppressed) in ML mode, as they serve as the
// gate for ML inference.
func TestDetectionService_RuleIndicatorsAccumulateInMLMode(t *testing.T) {
	ds := newMLTestDetectionService()
	ds.SetMLPredictor(&fakePredictor{ready: false})
	ds.SetMLEnabled(true)

	score := ds.addRuleIndicator("guid-accum", `C:\rule.exe`, 8080, domain.Indicator{
		Type:        domain.IndicatorRansomExtension,
		Severity:    domain.ThreatCritical,
		Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
		Description: "should accumulate in ML mode",
		Timestamp:   time.Now(),
	})

	if score == 0 {
		t.Fatal("expected score > 0; rule indicators should accumulate in ML mode for gate")
	}
	threat := ds.threatScorer.GetThreatScore("guid-accum")
	if threat == nil {
		t.Fatal("expected threat score to be recorded")
	}
	if len(threat.Indicators) != 1 {
		t.Fatalf("expected 1 indicator, got %d", len(threat.Indicators))
	}
}

func TestDetectionService_MLOnlyActivityWhenPredictorBecomesReady(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)

	predictor := &fakePredictor{
		ready: false,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.99,
			Probabilities: [3]float64{0.0, 0.99, 0.01},
		},
	}
	ds.SetMLPredictor(predictor)
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	seedForMLGate(ds, "guid-ready-transition", `C:\transition.exe`, 9001, 4)

	// First call: predictor not ready → skipped, no fallback alert (fallback disabled)
	ds.evaluateAndAlert("guid-ready-transition", `C:\transition.exe`, 9001)
	select {
	case a := <-ds.GetAlertChannel():
		t.Fatalf("expected no fallback alert, got severity=%s", a.Severity)
	default:
	}
	first := mustLastActivity(t, activities)
	if first.Stage != "skipped" || first.Reason != "predictor_not_ready" {
		t.Fatalf("expected first activity skipped/predictor_not_ready, got stage=%s reason=%s", first.Stage, first.Reason)
	}

	// Second call: predictor now ready → ML decision
	predictor.ready = true
	ds.evaluateAndAlert("guid-ready-transition", `C:\transition.exe`, 9001)
	alert := mustReceiveAlert(t, ds.GetAlertChannel())
	if alert.Category != "RANSOMWARE" {
		t.Fatalf("category = %s, expected RANSOMWARE", alert.Category)
	}
	last := mustLastActivity(t, activities)
	if last.Stage != "decision" || last.Decision != "terminate_eligible" {
		t.Fatalf("expected final decision activity, got stage=%s decision=%s", last.Stage, last.Decision)
	}
}

func TestDetectionService_MLOnlyRenameFastPathUpdatesExtensionFeatureBeforeInference(t *testing.T) {
	ds := newMLTestDetectionService()
	// Set mlMinIndicators to 1 so rename events can trigger ML with just 1 non-zero feature
	ds.SetMLMinIndicators(1)
	predictor := &capturingPredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.90,
			Probabilities: [3]float64{0.10, 0.90, 0.00},
		},
	}
	ds.SetMLPredictor(predictor)
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.50)

	baseTime := time.Now()
	for i := 0; i < 3; i++ {
		event := &domain.MonitorEvent{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Second),
			ProcessGuid: "guid-rename-feature",
			ProcessID:   4242,
			Image:       `C:\ransom.exe`,
			TargetFile:  `C:\victim\file.txt.encrypted`,
			RawData: map[string]interface{}{
				"set_info_type": "rename",
			},
		}
		ds.ProcessFileModified(context.Background(), event)
	}

	if predictor.calls == 0 {
		t.Fatal("expected ML inference to run after rename threshold was reached")
	}
	if predictor.lastFeat[6] <= 0 {
		t.Fatalf("expected extension_match feature > 0 before inference, got %.4f", predictor.lastFeat[6])
	}

	ds.fileCountersMux.RLock()
	counters := ds.fileCounters["guid-rename-feature"]
	ds.fileCountersMux.RUnlock()
	if counters == nil || counters.RansomExtensionCount < 3 {
		t.Fatalf("expected RansomExtensionCount >= 3, got %+v", counters)
	}
}

func TestDetectionService_CanaryAlertFiresInMLMode(t *testing.T) {
	ds := newMLTestDetectionService()
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.99,
			Probabilities: [3]float64{0.0, 0.99, 0.01},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.75)

	emitted := ds.alertCanaryCompromised(`C:\tmp\canary.txt`, "ENCRYPTED", 8.0, 4.0, "")
	if !emitted {
		t.Fatal("expected canary alert to fire even in ML mode (canary compromise is definitive)")
	}
	alert := mustReceiveAlert(t, ds.GetAlertChannel())
	if alert.Severity != domain.ThreatCritical {
		t.Fatalf("canary alert severity = %s, expected CRITICAL", alert.Severity)
	}
}

func TestDetectionService_RuleBasedRegressionWhenMLDisabled(t *testing.T) {
	ds := newMLTestDetectionService()
	ds.SetMLEnabled(false)

	ds.threatScorer.AddIndicator("guid-rule", `C:\rule.exe`, 6060, domain.Indicator{
		Type:        domain.IndicatorRansomExtension,
		Severity:    domain.ThreatCritical,
		Points:      domain.IndicatorScores[domain.IndicatorRansomExtension],
		Description: "rule indicator",
		Timestamp:   time.Now(),
	})

	ds.evaluateAndAlert("guid-rule", `C:\rule.exe`, 6060)
	alert := mustReceiveAlert(t, ds.GetAlertChannel())

	if alert.Category != "RANSOMWARE" {
		t.Fatalf("category = %s, expected RANSOMWARE", alert.Category)
	}
	if alert.Score != domain.IndicatorScores[domain.IndicatorRansomExtension] {
		t.Fatalf("score = %d, expected %d", alert.Score, domain.IndicatorScores[domain.IndicatorRansomExtension])
	}
}

func TestDetectionService_ExtractFeatureVector_UsesDirectMLFlags(t *testing.T) {
	ds := newMLTestDetectionService()

	ds.fileCountersMux.Lock()
	counters := ds.getOrInitMLCounters("guid-features")
	counters.ShadowCopyDeleteHit = true
	counters.BrowserCredentialHit = true
	counters.LSASSAccessHit = true
	ds.fileCountersMux.Unlock()

	features := ds.ExtractFeatureVector("guid-features")

	if features[8] != 1 {
		t.Fatalf("feature[8] shadow_copy_delete = %.0f, expected 1", features[8])
	}
	if features[9] != 1 {
		t.Fatalf("feature[9] browser_credential_access = %.0f, expected 1", features[9])
	}
	if features[12] != 1 {
		t.Fatalf("feature[12] lsass_access = %.0f, expected 1", features[12])
	}
}

// TestDetectionService_MLGateBlocksInsufficientFeatures verifies that ML inference
// is NOT triggered when a process has fewer non-zero features than mlMinIndicators.
func TestDetectionService_MLGateBlocksInsufficientFeatures(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.99,
			Probabilities: [3]float64{0.0, 0.99, 0.01},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.50)

	// Seed only 3 non-zero features (velocity, file_count, directory_count) — need 4
	seedFeaturesOnly(ds, "guid-gate-test", `C:\test.exe`, 1234, 2)
	// Add one indicator so score > 0 (ThreatLow) to reach the ML gate
	ds.threatScorer.AddIndicator("guid-gate-test", `C:\test.exe`, 1234, domain.Indicator{
		Type: domain.IndicatorHighEntropy, Severity: domain.ThreatLow,
		Points: domain.IndicatorScores[domain.IndicatorHighEntropy],
		Description: "seeded for score", Timestamp: time.Now(),
	})

	ds.evaluateAndAlert("guid-gate-test", `C:\test.exe`, 1234)
	mustNotReceiveAlert(t, ds.GetAlertChannel())

	// No ML activity should be captured (gate blocks before inference)
	if len(*activities) > 0 {
		t.Fatalf("expected no ML activity (gate should block), got %d activities", len(*activities))
	}
}

// TestDetectionService_MLGatePassesAtThreshold verifies that ML inference fires
// when the non-zero feature count reaches the mlMinIndicators threshold.
func TestDetectionService_MLGatePassesAtThreshold(t *testing.T) {
	ds := newMLTestDetectionService()
	activities := attachActivityCapture(ds)
	ds.SetMLPredictor(&fakePredictor{
		ready: true,
		prediction: &domain.MLPrediction{
			Label:         1,
			LabelName:     "ransomware",
			Confidence:    0.95,
			Probabilities: [3]float64{0.05, 0.95, 0.00},
		},
	})
	ds.SetMLEnabled(true)
	ds.SetMLConfidence(0.50)

	// Seed 5+ non-zero features (velocity, file_count, directory_count, extension_match, extension_entropy)
	seedForMLGate(ds, "guid-threshold", `C:\threshold.exe`, 5555, 4)

	ds.evaluateAndAlert("guid-threshold", `C:\threshold.exe`, 5555)
	alert := mustReceiveAlert(t, ds.GetAlertChannel())
	if alert.Category != "RANSOMWARE" {
		t.Fatalf("category = %s, expected RANSOMWARE", alert.Category)
	}

	activity := mustLastActivity(t, activities)
	if activity.Stage != "decision" {
		t.Fatalf("stage = %s, expected decision", activity.Stage)
	}
}

// TestDetectionService_MLBrowserAccessFromFileModified verifies that writing to a
// browser credential path sets the BrowserCredentialHit ML feature flag.
func TestDetectionService_MLBrowserAccessFromFileModified(t *testing.T) {
	ds := newMLTestDetectionService()
	ds.SetMLEnabled(true)

	event := &domain.MonitorEvent{
		Timestamp:   time.Now(),
		ProcessGuid: "guid-browser-test",
		ProcessID:   5000,
		Image:       `C:\malware.exe`,
		TargetFile:  `C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Login Data`,
	}
	ds.ProcessFileModified(context.Background(), event)

	ds.fileCountersMux.RLock()
	counters := ds.fileCounters["guid-browser-test"]
	ds.fileCountersMux.RUnlock()
	if counters == nil || !counters.BrowserCredentialHit {
		t.Fatal("expected BrowserCredentialHit=true after writing to Chrome Login Data path")
	}
}

// TestDetectionService_MLBrowserHistoryFromFileCreate verifies that creating a file
// at a browser history path sets the BrowserHistoryHit ML feature flag.
func TestDetectionService_MLBrowserHistoryFromFileCreate(t *testing.T) {
	ds := newMLTestDetectionService()
	ds.SetMLEnabled(true)

	event := &domain.MonitorEvent{
		Timestamp:   time.Now(),
		ProcessGuid: "guid-history-test",
		ProcessID:   5001,
		Image:       `C:\malware.exe`,
		TargetFile:  `C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\History`,
	}
	ds.ProcessFileCreate(context.Background(), event)

	ds.fileCountersMux.RLock()
	counters := ds.fileCounters["guid-history-test"]
	ds.fileCountersMux.RUnlock()
	if counters == nil || !counters.BrowserHistoryHit {
		t.Fatal("expected BrowserHistoryHit=true after creating file at Chrome History path")
	}
}

// TestDetectionService_MLParentPropagationShadowCopy verifies that when a child process
// runs vssadmin delete shadows, the parent's ShadowCopyDeleteHit flag is also set.
func TestDetectionService_MLParentPropagationShadowCopy(t *testing.T) {
	ds := newMLTestDetectionService()

	// Register parent process in velocityActors (simulates an active ransomware process)
	parentGuid := "guid-parent-ransom"
	ds.velocityActorsMux.Lock()
	ds.velocityActors[parentGuid] = &VelocityActorState{
		ProcessGuid:           parentGuid,
		ProcessID:             9000,
		Image:                 `C:\ransom.exe`,
		TotalOps60s:           50,
		CumulativeFileCount:   100,
		CumulativeCreateCount: 50,
		LastSeen:              time.Now(),
	}
	ds.velocityActorsMux.Unlock()

	// Child process: vssadmin.exe delete shadows (spawned by PID 9000)
	childEvent := &domain.MonitorEvent{
		EventID:     1,
		Timestamp:   time.Now(),
		ProcessGuid: "guid-child-vssadmin",
		ProcessID:   9100,
		Image:       `C:\Windows\System32\vssadmin.exe`,
		CommandLine: `vssadmin.exe delete shadows /all /quiet`,
		RawData: map[string]interface{}{
			"parent_process_id": uint32(9000),
		},
	}
	ds.ProcessProcessCreate(context.Background(), childEvent)

	// Verify parent got the ShadowCopyDeleteHit flag
	ds.fileCountersMux.RLock()
	parentCounters := ds.fileCounters[parentGuid]
	ds.fileCountersMux.RUnlock()
	if parentCounters == nil || !parentCounters.ShadowCopyDeleteHit {
		t.Fatal("expected parent ShadowCopyDeleteHit=true after child ran vssadmin delete shadows")
	}
}

// TestDetectionService_MLParentPropagationSystemInfo verifies that when a child process
// runs systeminfo, the parent's SystemInfoHit flag is also set.
func TestDetectionService_MLParentPropagationSystemInfo(t *testing.T) {
	ds := newMLTestDetectionService()

	// Register parent process in velocityActors
	parentGuid := "guid-parent-recon"
	ds.velocityActorsMux.Lock()
	ds.velocityActors[parentGuid] = &VelocityActorState{
		ProcessGuid:           parentGuid,
		ProcessID:             8000,
		Image:                 `C:\ransom.exe`,
		TotalOps60s:           10,
		CumulativeFileCount:   20,
		CumulativeCreateCount: 10,
		LastSeen:              time.Now(),
	}
	ds.velocityActorsMux.Unlock()

	// Child process: cmd.exe /c systeminfo (spawned by PID 8000)
	childEvent := &domain.MonitorEvent{
		EventID:     1,
		Timestamp:   time.Now(),
		ProcessGuid: "guid-child-cmd",
		ProcessID:   8100,
		Image:       `C:\Windows\System32\cmd.exe`,
		CommandLine: `cmd.exe /c systeminfo`,
		RawData: map[string]interface{}{
			"parent_process_id": uint32(8000),
		},
	}
	ds.ProcessProcessCreate(context.Background(), childEvent)

	// Verify parent got the SystemInfoHit flag
	ds.fileCountersMux.RLock()
	parentCounters := ds.fileCounters[parentGuid]
	ds.fileCountersMux.RUnlock()
	if parentCounters == nil || !parentCounters.SystemInfoHit {
		t.Fatal("expected parent SystemInfoHit=true after child ran systeminfo")
	}
}

// TestDetectionService_MLParentPropagationShadowCopy_PPID0 verifies that when ETW
// reports PPID=0 for a vssadmin child process, the shadow_copy_delete flag is
// broadcast to all active velocity actors as a fallback.
func TestDetectionService_MLParentPropagationShadowCopy_PPID0(t *testing.T) {
	ds := newMLTestDetectionService()

	// Register an active velocity actor (simulates ransomware doing file I/O)
	ransomGuid := "guid-ransom-active"
	ds.velocityActorsMux.Lock()
	ds.velocityActors[ransomGuid] = &VelocityActorState{
		ProcessGuid:           ransomGuid,
		ProcessID:             9000,
		Image:                 `C:\ransom.exe`,
		TotalOps60s:           50,
		CumulativeFileCount:   100,
		CumulativeCreateCount: 50,
		LastSeen:              time.Now(),
	}
	ds.velocityActorsMux.Unlock()

	// Child process: vssadmin.exe with PPID=0 (the PPID=0 bug scenario)
	childEvent := &domain.MonitorEvent{
		EventID:     1,
		Timestamp:   time.Now(),
		ProcessGuid: "guid-child-vssadmin-ppid0",
		ProcessID:   9100,
		Image:       `C:\Windows\System32\vssadmin.exe`,
		CommandLine: `vssadmin.exe delete shadows /all /quiet`,
		RawData: map[string]interface{}{
			"parent_process_id": uint32(0), // ETW reported PPID=0
		},
	}
	ds.ProcessProcessCreate(context.Background(), childEvent)

	// Verify the active velocity actor received the ShadowCopyDeleteHit flag via broadcast
	ds.fileCountersMux.RLock()
	ransomCounters := ds.fileCounters[ransomGuid]
	ds.fileCountersMux.RUnlock()
	if ransomCounters == nil || !ransomCounters.ShadowCopyDeleteHit {
		t.Fatal("expected active velocity actor to receive ShadowCopyDeleteHit=true when child PPID=0")
	}
}

// TestDetectionService_BroadcastSkipsInactiveActors verifies that the broadcast
// fallback does NOT set flags on velocity actors that are inactive (expired or
// no recent file I/O).
func TestDetectionService_BroadcastSkipsInactiveActors(t *testing.T) {
	ds := newMLTestDetectionService()

	// Register an INACTIVE velocity actor (LastSeen 2 minutes ago, TotalOps60s=0)
	inactiveGuid := "guid-inactive"
	ds.velocityActorsMux.Lock()
	ds.velocityActors[inactiveGuid] = &VelocityActorState{
		ProcessGuid:           inactiveGuid,
		ProcessID:             8000,
		Image:                 `C:\legit.exe`,
		TotalOps60s:           0,
		CumulativeFileCount:   10,
		CumulativeCreateCount: 5,
		LastSeen:              time.Now().Add(-2 * time.Minute),
	}
	ds.velocityActorsMux.Unlock()

	// Child process: vssadmin.exe with PPID=0
	childEvent := &domain.MonitorEvent{
		EventID:     1,
		Timestamp:   time.Now(),
		ProcessGuid: "guid-child-vss-inactive",
		ProcessID:   9200,
		Image:       `C:\Windows\System32\vssadmin.exe`,
		CommandLine: `vssadmin.exe delete shadows /all /quiet`,
		RawData: map[string]interface{}{
			"parent_process_id": uint32(0),
		},
	}
	ds.ProcessProcessCreate(context.Background(), childEvent)

	// Verify the inactive actor did NOT get the flag
	ds.fileCountersMux.RLock()
	inactiveCounters := ds.fileCounters[inactiveGuid]
	ds.fileCountersMux.RUnlock()
	if inactiveCounters != nil && inactiveCounters.ShadowCopyDeleteHit {
		t.Fatal("inactive velocity actor should NOT receive ShadowCopyDeleteHit via broadcast")
	}
}
