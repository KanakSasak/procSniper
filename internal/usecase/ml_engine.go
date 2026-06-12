package usecase

import (
	"log"
	"sync"
	"time"

	"procSniper/internal/domain"
)

// mlDecision is the per-class ML detection/response policy.
type mlDecision struct {
	Category      string
	Severity      domain.ThreatLevel
	Score         int
	IndicatorType domain.IndicatorType
	Decision      string // MLInferenceActivity decision label
	AutoRespond   bool
}

// mlDecisionPolicy is the single source of truth mapping an ML class label to its
// detection/response policy, consumed by both mlEngine.Decide (activity fields) and
// DetectionService.emitMLDecisionAlert (alert fields) so the two cannot silently diverge. Label 0 (benign)
// is intentionally absent — no alert and no decision.
var mlDecisionPolicy = map[int]mlDecision{
	1: {Category: "RANSOMWARE", Severity: domain.ThreatCritical, Score: 100, IndicatorType: domain.IndicatorMLRansomware, Decision: "terminate_eligible", AutoRespond: true},
	2: {Category: "STEALER", Severity: domain.ThreatMedium, Score: 30, IndicatorType: domain.IndicatorMLStealer, Decision: "alert_only", AutoRespond: false},
}

// mlEngine owns the ML inference subsystem state: the predictor, the enable flag, the
// confidence threshold, the min-indicator gate, the per-process inference cooldown, and
// the activity callback. DetectionService.evaluateAndAlert orchestrates the detection-mode
// flow and calls into the engine for the ML mechanics. Feature extraction stays on the
// service (it reads accumulated per-process state) and is passed into Decide.
type mlEngine struct {
	mu            sync.RWMutex
	predictor     domain.MLPredictor                // nil when ML not loaded
	enabled       bool                              // whether ML detection is active
	confidence    float64                           // minimum malicious probability threshold (0.0–1.0)
	minIndicators int                               // minimum non-zero features before inference fires
	lastInference map[string]time.Time              // per-process inference cooldown tracker
	cooldown      time.Duration                     // cooldown between inferences for same process
	onPrediction  func(*domain.MLInferenceActivity) // callback for GUI event emission
}

func newMLEngine() *mlEngine {
	return &mlEngine{
		minIndicators: 4,
		lastInference: make(map[string]time.Time),
		cooldown:      2 * time.Second,
	}
}

// --- configuration setters ---

func (e *mlEngine) SetPredictor(p domain.MLPredictor) {
	e.mu.Lock()
	e.predictor = p
	e.mu.Unlock()
}

func (e *mlEngine) SetEnabled(enabled bool) {
	e.mu.Lock()
	e.enabled = enabled
	e.mu.Unlock()
}

func (e *mlEngine) SetConfidence(threshold float64) {
	e.mu.Lock()
	e.confidence = threshold
	e.mu.Unlock()
}

func (e *mlEngine) SetMinIndicators(n int) {
	if n < 1 {
		n = 1
	}
	e.mu.Lock()
	e.minIndicators = n
	e.mu.Unlock()
}

func (e *mlEngine) SetPredictionCallback(cb func(*domain.MLInferenceActivity)) {
	e.mu.Lock()
	e.onPrediction = cb
	e.mu.Unlock()
}

func (e *mlEngine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

func (e *mlEngine) MinIndicators() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.minIndicators
}

// InCooldown reports whether the per-process inference cooldown is still active.
func (e *mlEngine) InCooldown(processGuid string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	last := e.lastInference[processGuid]
	return !last.IsZero() && time.Since(last) < e.cooldown
}

// RecordInference stamps the last-inference time for a process (starts its cooldown).
func (e *mlEngine) RecordInference(processGuid string) {
	e.mu.Lock()
	e.lastInference[processGuid] = time.Now()
	e.mu.Unlock()
}

// EvictStale removes cooldown entries older than cutoff, returning the count removed.
func (e *mlEngine) EvictStale(cutoff time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := 0
	for guid, ts := range e.lastInference {
		if ts.Before(cutoff) {
			delete(e.lastInference, guid)
			removed++
		}
	}
	return removed
}

// Decide runs ML inference on a precomputed feature vector and returns an activity record
// (also emitted via the prediction callback). The returned activity's Stage is "decision"
// when a malicious class was selected above the confidence threshold.
func (e *mlEngine) Decide(processGuid, image string, pid int, features [14]float64) *domain.MLInferenceActivity {
	e.mu.RLock()
	predictor := e.predictor
	enabled := e.enabled
	threshold := e.confidence
	callback := e.onPrediction
	e.mu.RUnlock()

	ready := predictor != nil && predictor.IsReady()
	log.Printf("[ML][ATTEMPT] process=%s pid=%d threshold=%.4f mode_enabled=%v predictor_ready=%v",
		image, pid, threshold, enabled, ready)

	activity := &domain.MLInferenceActivity{
		ProcessGuid:    processGuid,
		ProcessID:      pid,
		Image:          image,
		Threshold:      threshold,
		ModeEnabled:    enabled,
		PredictorReady: ready,
		Timestamp:      time.Now(),
	}

	if !enabled {
		activity.Stage = "skipped"
		activity.Reason = "ml_mode_disabled"
		e.emitActivity(callback, activity)
		log.Printf("[ML][SKIP] process=%s pid=%d reason=%s", image, pid, activity.Reason)
		return activity
	}

	if !ready {
		activity.Stage = "skipped"
		activity.Reason = "predictor_not_ready"
		e.emitActivity(callback, activity)
		log.Printf("[ML][SKIP] process=%s pid=%d reason=%s", image, pid, activity.Reason)
		return activity
	}

	prediction, err := predictor.Predict(features)
	if err != nil {
		activity.Stage = "error"
		activity.Reason = "inference_error"
		activity.Error = err.Error()
		e.emitActivity(callback, activity)
		log.Printf("[ML][ERROR] process=%s pid=%d error=%v", image, pid, err)
		return activity
	}

	prediction.ProcessGuid = processGuid
	prediction.ProcessID = pid
	prediction.Image = image
	activity.Prediction = prediction
	if !prediction.Timestamp.IsZero() {
		activity.Timestamp = prediction.Timestamp
	}

	probRansom := prediction.Probabilities[1]
	probStealer := prediction.Probabilities[2]
	maliciousProb := probRansom + probStealer

	if maliciousProb < threshold {
		activity.Stage = "skipped"
		activity.Reason = "below_threshold"
		activity.Decision = "none"
		activity.DecisionScore = 0
		activity.DecisionAutoRespond = false
		e.emitActivity(callback, activity)
		log.Printf("[ML][SKIP] process=%s pid=%d reason=%s malicious_prob=%.4f prob_ransom=%.4f prob_steal=%.4f threshold=%.4f",
			image, pid, activity.Reason, maliciousProb, probRansom, probStealer, threshold)
		return activity
	}

	decisionLabel := 1
	decisionLabelName := domain.ClassLabels[1]
	decisionConfidence := probRansom
	if probStealer > probRansom {
		decisionLabel = 2
		decisionLabelName = domain.ClassLabels[2]
		decisionConfidence = probStealer
	}
	prediction.Label = decisionLabel
	prediction.LabelName = decisionLabelName
	prediction.Confidence = decisionConfidence

	if pol, ok := mlDecisionPolicy[decisionLabel]; ok {
		activity.Decision = pol.Decision
		activity.DecisionCategory = pol.Category
		activity.DecisionScore = pol.Score
		activity.DecisionAutoRespond = pol.AutoRespond
	}

	activity.Stage = "decision"
	activity.Reason = "model_decision"
	e.emitActivity(callback, activity)
	return activity
}

func (e *mlEngine) emitActivity(callback func(*domain.MLInferenceActivity), activity *domain.MLInferenceActivity) {
	if activity == nil {
		return
	}
	if activity.Timestamp.IsZero() {
		activity.Timestamp = time.Now()
	}
	if callback != nil {
		callback(activity)
	}
}
