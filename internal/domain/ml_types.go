package domain

import "time"

// MLPrediction holds the result of a single ML inference run.
type MLPrediction struct {
	ProcessGuid   string
	ProcessID     int
	Image         string
	Label         int        // 0=benign, 1=ransomware, 2=stealer
	LabelName     string     // "benign", "ransomware", "stealer"
	Confidence    float64    // highest probability across classes
	Probabilities [3]float64 // [benign, ransomware, stealer]
	Features      [14]float64
	Timestamp     time.Time
}

// MLInferenceActivity captures one ML inference attempt and its outcome.
// Emitted for every ML-mode evaluation, including skipped/error/no-decision paths.
type MLInferenceActivity struct {
	ProcessGuid    string
	ProcessID      int
	Image          string
	Stage          string  // attempt, skipped, predicted, decision, error
	Reason         string  // predictor_not_ready, below_threshold, benign_label, inference_error, etc.
	Threshold      float64 // active minimum confidence threshold
	ModeEnabled    bool
	PredictorReady bool
	Error          string

	Prediction          *MLPrediction
	Decision            string // terminate_eligible, alert_only, none
	DecisionCategory    string // RANSOMWARE, STEALER
	DecisionScore       int
	DecisionAutoRespond bool
	Timestamp           time.Time
}

// MLPredictor is the interface for ML model inference.
// Implemented by infrastructure (ONNXPredictor), consumed by DetectionService.
type MLPredictor interface {
	Predict(features [14]float64) (*MLPrediction, error)
	IsReady() bool
	Close() error
}

// ClassLabels maps numeric labels to human-readable names.
var ClassLabels = map[int]string{
	0: "benign",
	1: "ransomware",
	2: "stealer",
}
