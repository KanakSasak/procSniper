//go:build integration_ml

package infrastructure

import "testing"

func TestMLRealDataFullQuality(t *testing.T) {
	rows := loadRealDataset(t)
	predictor := getSharedPredictor(t)
	modelCfg := modelConfigForCurrentModel(t)

	fullRows, err := deterministicStratifiedSample(
		rows,
		modelCfg.Full.MaxSamplesPerClass,
		modelCfg.Full.Seed,
		modelCfg.Full.MinSamplesPerClass,
	)
	if err != nil {
		t.Fatalf("full evaluation sampling failed: %v", err)
	}

	result := evaluateDatasetRows(t, predictor, fullRows, modelCfg.ExpectedLabels)
	assertMetricThresholds(t, result, modelCfg.Full, predictor.numClasses)

	t.Logf("full metrics: samples=%d accuracy=%.4f macro_f1=%.4f", result.Samples, result.Accuracy, result.MacroF1)
	for _, label := range result.Labels {
		t.Logf("full recall class=%d -> %.4f", label, result.RecallByClass[label])
	}
	t.Logf("full confusion matrix labels=%v matrix=%v", result.Labels, result.ConfusionMatrix)
}
