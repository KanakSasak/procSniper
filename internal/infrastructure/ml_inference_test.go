package infrastructure

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	realDatasetRelativePath  = "ml/data/cape_real_dataset.csv"
	defaultModelRelativePath = "ml/models/procsniper_rf.onnx"
	thresholdsRelativePath   = "internal/infrastructure/testdata/ml_quality_thresholds.json"
)

var requiredFeatureColumns = []string{
	"velocity",
	"file_count",
	"txt_file_count",
	"directory_count",
	"file_delete_count",
	"is_signed",
	"extension_match",
	"extension_entropy",
	"shadow_copy_delete",
	"browser_credential_access",
	"browser_history_access",
	"ssh_key_access",
	"lsass_access",
	"system_info_queries",
}

type datasetRow struct {
	Features [14]float64
	Label    int
}

type metricResult struct {
	Accuracy        float64
	MacroF1         float64
	RecallByClass   map[int]float64
	ConfusionMatrix [][]int
	Labels          []int
	Samples         int
}

type evalThresholds struct {
	Seed               int64              `json:"seed"`
	MaxSamplesPerClass int                `json:"max_samples_per_class"`
	MinSamplesPerClass int                `json:"min_samples_per_class"`
	MinAccuracy        float64            `json:"min_accuracy"`
	MinMacroF1         float64            `json:"min_macro_f1"`
	MinRecall          map[string]float64 `json:"min_recall"`
}

type modelThresholdConfig struct {
	ExpectedClassCount int            `json:"expected_class_count"`
	ExpectedLabels     []int          `json:"expected_labels"`
	Smoke              evalThresholds `json:"smoke"`
	Full               evalThresholds `json:"full"`
}

type thresholdConfig struct {
	Models map[string]modelThresholdConfig `json:"models"`
}

var (
	sharedPredictor     *ONNXPredictor
	sharedPredictorErr  error
	sharedPredictorOnce sync.Once
	datasetRowsCache    []datasetRow
	datasetRowsErr      error
	datasetRowsOnce     sync.Once
	thresholdsCache     thresholdConfig
	thresholdsErr       error
	thresholdsOnce      sync.Once
)

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedPredictor != nil {
		_ = sharedPredictor.Close()
	}
	os.Exit(code)
}

func projectRoot(t *testing.T) string {
	t.Helper()
	_, src, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(src), "..", "..")
}

func resolvedModelPath(t *testing.T) string {
	t.Helper()
	if override := strings.TrimSpace(os.Getenv("PROCSNIPER_ML_TEST_MODEL")); override != "" {
		if filepath.IsAbs(override) {
			return override
		}
		return filepath.Join(projectRoot(t), override)
	}
	return filepath.Join(projectRoot(t), defaultModelRelativePath)
}

func realDatasetPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(projectRoot(t), realDatasetRelativePath)
}

func thresholdsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(projectRoot(t), thresholdsRelativePath)
}

func dllDir(t *testing.T) string {
	t.Helper()
	root := projectRoot(t)
	for _, dir := range []string{root, filepath.Join(root, "build", "bin")} {
		if _, err := os.Stat(filepath.Join(dir, "onnxruntime.dll")); err == nil {
			return dir
		}
	}
	t.Fatalf("required onnxruntime.dll not found in %s or %s", root, filepath.Join(root, "build", "bin"))
	return ""
}

func requireRealDatasetFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("required real dataset missing at %s: provide CAPE-labeled CSV at this exact path", path)
	}
}

func loadThresholdConfig(t *testing.T) thresholdConfig {
	t.Helper()
	thresholdsOnce.Do(func() {
		cfgPath := thresholdsPath(t)
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			thresholdsErr = fmt.Errorf("failed to read threshold config %s: %w", cfgPath, err)
			return
		}
		if err := json.Unmarshal(raw, &thresholdsCache); err != nil {
			thresholdsErr = fmt.Errorf("failed to parse threshold config %s: %w", cfgPath, err)
			return
		}
		if len(thresholdsCache.Models) == 0 {
			thresholdsErr = fmt.Errorf("threshold config %s has no model entries", cfgPath)
		}
	})
	if thresholdsErr != nil {
		t.Fatalf("%v", thresholdsErr)
	}
	return thresholdsCache
}

func modelConfigForCurrentModel(t *testing.T) modelThresholdConfig {
	t.Helper()
	cfg := loadThresholdConfig(t)
	modelName := filepath.Base(resolvedModelPath(t))
	modelCfg, ok := cfg.Models[modelName]
	if !ok {
		t.Fatalf("threshold config missing entry for model %s (file: %s)", modelName, thresholdsPath(t))
	}
	if modelCfg.ExpectedClassCount <= 0 {
		t.Fatalf("model %s has invalid expected_class_count=%d", modelName, modelCfg.ExpectedClassCount)
	}
	if len(modelCfg.ExpectedLabels) == 0 {
		t.Fatalf("model %s has empty expected_labels", modelName)
	}
	sort.Ints(modelCfg.ExpectedLabels)
	return modelCfg
}

func getSharedPredictor(t *testing.T) *ONNXPredictor {
	t.Helper()
	sharedPredictorOnce.Do(func() {
		modelPath := resolvedModelPath(t)
		if _, err := os.Stat(modelPath); err != nil {
			sharedPredictorErr = fmt.Errorf("required ONNX model missing at %s: %w", modelPath, err)
			return
		}
		sharedPredictor, sharedPredictorErr = NewONNXPredictor(modelPath, dllDir(t))
	})
	if sharedPredictorErr != nil {
		t.Fatalf("failed to initialize shared ONNX predictor: %v", sharedPredictorErr)
	}
	if sharedPredictor == nil {
		t.Fatal("shared ONNX predictor is nil")
	}
	return sharedPredictor
}

func loadRealDataset(t *testing.T) []datasetRow {
	t.Helper()
	datasetRowsOnce.Do(func() {
		path := realDatasetPath(t)
		if _, err := os.Stat(path); err != nil {
			datasetRowsErr = fmt.Errorf("required real dataset missing at %s: provide CAPE-labeled CSV at this exact path", path)
			return
		}

		f, err := os.Open(path)
		if err != nil {
			datasetRowsErr = fmt.Errorf("failed to open dataset %s: %w", path, err)
			return
		}
		defer f.Close()

		r := csv.NewReader(f)
		r.FieldsPerRecord = -1

		headers, err := r.Read()
		if err != nil {
			datasetRowsErr = fmt.Errorf("failed to read dataset header from %s: %w", path, err)
			return
		}
		if len(headers) > 0 {
			headers[0] = strings.TrimPrefix(headers[0], "\ufeff")
		}

		colIndex := make(map[string]int, len(headers))
		for i, h := range headers {
			colIndex[strings.TrimSpace(h)] = i
		}

		for _, col := range requiredFeatureColumns {
			if _, ok := colIndex[col]; !ok {
				datasetRowsErr = fmt.Errorf("dataset missing required feature column %q", col)
				return
			}
		}
		if _, ok := colIndex["label"]; !ok {
			datasetRowsErr = fmt.Errorf("dataset missing required label column \"label\"")
			return
		}

		line := 1
		for {
			record, err := r.Read()
			if err != nil {
				if err == io.EOF {
					break
				}
				datasetRowsErr = fmt.Errorf("failed reading dataset row %d: %w", line+1, err)
				return
			}
			line++

			if len(record) == 0 {
				continue
			}

			var row datasetRow
			for i, col := range requiredFeatureColumns {
				idx := colIndex[col]
				if idx >= len(record) {
					datasetRowsErr = fmt.Errorf("dataset row %d missing value for feature %q", line, col)
					return
				}
				raw := strings.TrimSpace(record[idx])
				val, parseErr := strconv.ParseFloat(raw, 64)
				if parseErr != nil {
					datasetRowsErr = fmt.Errorf("non-numeric feature %q at dataset row %d: %q", col, line, raw)
					return
				}
				if math.IsNaN(val) || math.IsInf(val, 0) {
					datasetRowsErr = fmt.Errorf("invalid feature %q at dataset row %d: %v", col, line, val)
					return
				}
				row.Features[i] = val
			}

			labelIdx := colIndex["label"]
			if labelIdx >= len(record) {
				datasetRowsErr = fmt.Errorf("dataset row %d missing value for label", line)
				return
			}
			labelRaw := strings.TrimSpace(record[labelIdx])
			labelFloat, parseErr := strconv.ParseFloat(labelRaw, 64)
			if parseErr != nil {
				datasetRowsErr = fmt.Errorf("non-numeric label at dataset row %d: %q", line, labelRaw)
				return
			}
			if math.IsNaN(labelFloat) || math.IsInf(labelFloat, 0) {
				datasetRowsErr = fmt.Errorf("invalid label at dataset row %d: %v", line, labelFloat)
				return
			}
			labelInt := int(math.Round(labelFloat))
			if math.Abs(labelFloat-float64(labelInt)) > 1e-9 {
				datasetRowsErr = fmt.Errorf("label at dataset row %d is not an integer class id: %v", line, labelFloat)
				return
			}
			row.Label = labelInt
			datasetRowsCache = append(datasetRowsCache, row)
		}

		if len(datasetRowsCache) == 0 {
			datasetRowsErr = fmt.Errorf("dataset %s has no rows", path)
		}
	})

	if datasetRowsErr != nil {
		t.Fatalf("dataset load failed: %v", datasetRowsErr)
	}
	return datasetRowsCache
}

func datasetClassCounts(rows []datasetRow) map[int]int {
	counts := make(map[int]int)
	for _, row := range rows {
		counts[row.Label]++
	}
	return counts
}

func sortedKeys(m map[int]int) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func deterministicStratifiedSample(rows []datasetRow, maxPerClass int, seed int64, minPerClass int) ([]datasetRow, error) {
	if maxPerClass < 0 {
		return nil, fmt.Errorf("maxPerClass must be >= 0")
	}
	if minPerClass < 0 {
		return nil, fmt.Errorf("minPerClass must be >= 0")
	}

	byClass := make(map[int][]datasetRow)
	for _, row := range rows {
		byClass[row.Label] = append(byClass[row.Label], row)
	}

	classes := make([]int, 0, len(byClass))
	for cls := range byClass {
		classes = append(classes, cls)
	}
	sort.Ints(classes)

	rng := rand.New(rand.NewSource(seed))
	sampled := make([]datasetRow, 0)

	for _, cls := range classes {
		rowsForClass := append([]datasetRow(nil), byClass[cls]...)
		if len(rowsForClass) < minPerClass {
			return nil, fmt.Errorf("class %d has %d rows, below min_samples_per_class=%d", cls, len(rowsForClass), minPerClass)
		}

		rng.Shuffle(len(rowsForClass), func(i, j int) {
			rowsForClass[i], rowsForClass[j] = rowsForClass[j], rowsForClass[i]
		})

		take := len(rowsForClass)
		if maxPerClass > 0 && take > maxPerClass {
			take = maxPerClass
		}
		sampled = append(sampled, rowsForClass[:take]...)
	}

	rng.Shuffle(len(sampled), func(i, j int) {
		sampled[i], sampled[j] = sampled[j], sampled[i]
	})
	return sampled, nil
}

func classDistributionString(rows []datasetRow) string {
	counts := datasetClassCounts(rows)
	labels := sortedKeys(counts)
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, fmt.Sprintf("%d:%d", label, counts[label]))
	}
	return strings.Join(parts, ", ")
}

func verifyProbabilitySanity(t *testing.T, predictor *ONNXPredictor, predictionLabel int, probs [3]float64) {
	t.Helper()

	if predictionLabel < 0 || predictionLabel > 2 {
		t.Fatalf("predicted label out of allowed range [0,2]: %d", predictionLabel)
	}

	sum := 0.0
	for i := 0; i < predictor.numClasses; i++ {
		p := probs[i]
		if math.IsNaN(p) || math.IsInf(p, 0) {
			t.Fatalf("probability[%d] is non-finite: %v", i, p)
		}
		if p < 0.0 || p > 1.0 {
			t.Fatalf("probability[%d] out of [0,1]: %v", i, p)
		}
		sum += p
	}

	if math.Abs(sum-1.0) > 1e-4 {
		t.Fatalf("probability sum is not normalized: got %.8f, expected 1.0", sum)
	}

	if predictor.numClasses == 2 && probs[2] != 0.0 {
		t.Fatalf("2-class model must keep stealer probability at 0.0, got %.8f", probs[2])
	}
}

func evaluateDatasetRows(t *testing.T, predictor *ONNXPredictor, rows []datasetRow, labels []int) metricResult {
	t.Helper()

	if len(rows) == 0 {
		t.Fatal("evaluation requires at least 1 row")
	}
	if len(labels) == 0 {
		t.Fatal("evaluation requires at least 1 label")
	}

	sortedLabels := append([]int(nil), labels...)
	sort.Ints(sortedLabels)
	labelIndex := make(map[int]int, len(sortedLabels))
	for i, label := range sortedLabels {
		labelIndex[label] = i
	}

	n := len(sortedLabels)
	cm := make([][]int, n)
	for i := range cm {
		cm[i] = make([]int, n)
	}

	correct := 0
	for i, row := range rows {
		prediction, err := predictor.Predict(row.Features)
		if err != nil {
			t.Fatalf("inference failed at eval row %d: %v", i, err)
		}
		verifyProbabilitySanity(t, predictor, prediction.Label, prediction.Probabilities)

		trueIdx, ok := labelIndex[row.Label]
		if !ok {
			t.Fatalf("true label %d (row %d) not in evaluation labels %v", row.Label, i, sortedLabels)
		}
		predIdx, ok := labelIndex[prediction.Label]
		if !ok {
			t.Fatalf("predicted label %d (row %d) not in expected labels %v", prediction.Label, i, sortedLabels)
		}

		cm[trueIdx][predIdx]++
		if prediction.Label == row.Label {
			correct++
		}
	}

	recallByClass := make(map[int]float64, len(sortedLabels))
	macroF1 := 0.0
	for i, label := range sortedLabels {
		tp := float64(cm[i][i])

		rowSum := 0.0
		for _, v := range cm[i] {
			rowSum += float64(v)
		}
		fn := rowSum - tp

		colSum := 0.0
		for r := 0; r < n; r++ {
			colSum += float64(cm[r][i])
		}
		fp := colSum - tp

		recall := 0.0
		if tp+fn > 0 {
			recall = tp / (tp + fn)
		}
		recallByClass[label] = recall

		precision := 0.0
		if tp+fp > 0 {
			precision = tp / (tp + fp)
		}

		f1 := 0.0
		if precision+recall > 0 {
			f1 = 2 * precision * recall / (precision + recall)
		}
		macroF1 += f1
	}
	macroF1 /= float64(len(sortedLabels))

	return metricResult{
		Accuracy:        float64(correct) / float64(len(rows)),
		MacroF1:         macroF1,
		RecallByClass:   recallByClass,
		ConfusionMatrix: cm,
		Labels:          sortedLabels,
		Samples:         len(rows),
	}
}

func assertMetricThresholds(t *testing.T, result metricResult, thresholds evalThresholds, classCount int) {
	t.Helper()

	if result.Accuracy < thresholds.MinAccuracy {
		t.Fatalf("accuracy gate failed: got %.4f < min_accuracy %.4f", result.Accuracy, thresholds.MinAccuracy)
	}
	if result.MacroF1 < thresholds.MinMacroF1 {
		t.Fatalf("macro-F1 gate failed: got %.4f < min_macro_f1 %.4f", result.MacroF1, thresholds.MinMacroF1)
	}

	for labelStr, minRecall := range thresholds.MinRecall {
		label, err := strconv.Atoi(labelStr)
		if err != nil {
			t.Fatalf("invalid min_recall class key %q in threshold config: %v", labelStr, err)
		}
		if label == 2 && classCount < 3 {
			continue
		}
		recall, ok := result.RecallByClass[label]
		if !ok {
			t.Fatalf("recall gate configured for class %d but class not present in evaluation labels %v", label, result.Labels)
		}
		if recall < minRecall {
			t.Fatalf("recall gate failed for class %d: got %.4f < min_recall %.4f", label, recall, minRecall)
		}
	}
}

func labelsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestMLDatasetAvailability(t *testing.T) {
	requireRealDatasetFile(t, realDatasetPath(t))
}

func TestMLDatasetSchema(t *testing.T) {
	rows := loadRealDataset(t)
	if len(rows) == 0 {
		t.Fatal("dataset has zero rows")
	}

	classCounts := datasetClassCounts(rows)
	if len(classCounts) < 2 {
		t.Fatalf("dataset must contain at least 2 classes, got distribution: %s", classDistributionString(rows))
	}
	for label, count := range classCounts {
		if count == 0 {
			t.Fatalf("dataset has empty class %d", label)
		}
	}

	t.Logf("loaded %d rows from %s, distribution=%s", len(rows), realDatasetPath(t), classDistributionString(rows))
}

func TestMLONNXContract(t *testing.T) {
	predictor := getSharedPredictor(t)
	if !predictor.IsReady() {
		t.Fatal("predictor must be ready")
	}

	shape := predictor.inputTensor.GetShape()
	if len(shape) != 2 {
		t.Fatalf("input tensor must be rank-2, got shape %v", shape)
	}
	if shape[1] != int64(len(requiredFeatureColumns)) {
		t.Fatalf("input feature count mismatch: got %d, expected %d", shape[1], len(requiredFeatureColumns))
	}

	modelCfg := modelConfigForCurrentModel(t)
	if predictor.numClasses != modelCfg.ExpectedClassCount {
		t.Fatalf("class mode mismatch for %s: model has %d classes, config expects %d", filepath.Base(resolvedModelPath(t)), predictor.numClasses, modelCfg.ExpectedClassCount)
	}

	seenLabels := []int{0, 1}
	if predictor.numClasses == 3 {
		seenLabels = append(seenLabels, 2)
	}
	if !labelsEqual(seenLabels, modelCfg.ExpectedLabels) {
		t.Fatalf("expected_labels mismatch for %s: inferred=%v config=%v", filepath.Base(resolvedModelPath(t)), seenLabels, modelCfg.ExpectedLabels)
	}
}

func TestMLProbabilitySanity(t *testing.T) {
	rows := loadRealDataset(t)
	predictor := getSharedPredictor(t)
	modelCfg := modelConfigForCurrentModel(t)

	sample, err := deterministicStratifiedSample(rows, 32, modelCfg.Smoke.Seed, 1)
	if err != nil {
		t.Fatalf("sampling failed: %v", err)
	}
	for i, row := range sample {
		prediction, predErr := predictor.Predict(row.Features)
		if predErr != nil {
			t.Fatalf("inference failed at sanity row %d: %v", i, predErr)
		}
		verifyProbabilitySanity(t, predictor, prediction.Label, prediction.Probabilities)
	}
}

func TestMLRealDataSmokeQuality(t *testing.T) {
	rows := loadRealDataset(t)
	predictor := getSharedPredictor(t)
	modelCfg := modelConfigForCurrentModel(t)

	sampledRows, err := deterministicStratifiedSample(
		rows,
		modelCfg.Smoke.MaxSamplesPerClass,
		modelCfg.Smoke.Seed,
		modelCfg.Smoke.MinSamplesPerClass,
	)
	if err != nil {
		t.Fatalf("smoke sampling failed: %v", err)
	}

	result := evaluateDatasetRows(t, predictor, sampledRows, modelCfg.ExpectedLabels)
	assertMetricThresholds(t, result, modelCfg.Smoke, predictor.numClasses)

	t.Logf("smoke metrics: samples=%d accuracy=%.4f macro_f1=%.4f", result.Samples, result.Accuracy, result.MacroF1)
	for _, label := range result.Labels {
		t.Logf("smoke recall class=%d -> %.4f", label, result.RecallByClass[label])
	}
	t.Logf("smoke confusion matrix labels=%v matrix=%v", result.Labels, result.ConfusionMatrix)
}
