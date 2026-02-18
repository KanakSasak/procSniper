package infrastructure

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	ort "github.com/yalue/onnxruntime_go"
	"procSniper/internal/domain"
)

// ONNXPredictor implements domain.MLPredictor using onnxruntime_go.
// Supports both 2-class (benign/ransomware) and 3-class (benign/ransomware/stealer) models.
type ONNXPredictor struct {
	session      *ort.AdvancedSession
	inputTensor  *ort.Tensor[float32]
	labelOutput  *ort.Tensor[int64]
	probOutput   *ort.Tensor[float32]
	numClasses   int // 2 or 3
	mu           sync.Mutex
	ready        bool
}

// initONNXRuntime initializes the ONNX Runtime shared library.
// Must be called once before creating any sessions.
var initOnce sync.Once
var initErr error

func initONNXRuntime(dllDir string) error {
	initOnce.Do(func() {
		// Try to find onnxruntime.dll in several locations
		candidates := []string{
			filepath.Join(dllDir, "onnxruntime.dll"),
			"onnxruntime.dll", // current directory / PATH
		}

		// Also check next to the executable
		if exe, err := os.Executable(); err == nil {
			candidates = append([]string{
				filepath.Join(filepath.Dir(exe), "onnxruntime.dll"),
			}, candidates...)
		}

		found := false
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				ort.SetSharedLibraryPath(candidate)
				found = true
				break
			}
		}

		if !found {
			// Let onnxruntime_go try its default search
			// (will look in system PATH)
		}

		initErr = ort.InitializeEnvironment()
	})
	return initErr
}

// NewONNXPredictor loads an ONNX model and creates an inference session.
// The dllDir parameter specifies where to look for onnxruntime.dll.
// If empty, it defaults to the directory containing the model file.
// Automatically detects whether the model has 2 or 3 output classes.
func NewONNXPredictor(modelPath string, dllDir string) (*ONNXPredictor, error) {
	// Validate model file exists
	if _, err := os.Stat(modelPath); err != nil {
		return nil, fmt.Errorf("model file not found: %w", err)
	}

	// Initialize ONNX Runtime (once globally)
	if dllDir == "" {
		dllDir = filepath.Dir(modelPath)
	}
	if err := initONNXRuntime(dllDir); err != nil {
		return nil, fmt.Errorf("failed to initialize ONNX Runtime: %w", err)
	}

	// Create input tensor: shape [1, 14] (batch=1, 14 features)
	inputTensor, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 14))
	if err != nil {
		return nil, fmt.Errorf("failed to create input tensor: %w", err)
	}

	labelOutput, err := ort.NewEmptyTensor[int64](ort.NewShape(1))
	if err != nil {
		inputTensor.Destroy()
		return nil, fmt.Errorf("failed to create label output tensor: %w", err)
	}

	// Try 3-class first; if probe inference fails (shape mismatch), recreate with 2-class.
	// NewAdvancedSession doesn't validate output shapes — only Run() does.
	numClasses := 3
	probOutput, err := ort.NewEmptyTensor[float32](ort.NewShape(1, int64(numClasses)))
	if err != nil {
		inputTensor.Destroy()
		labelOutput.Destroy()
		return nil, fmt.Errorf("failed to create probability output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"features"},
		[]string{"label", "probabilities"},
		[]ort.ArbitraryTensor{inputTensor},
		[]ort.ArbitraryTensor{labelOutput, probOutput},
		nil,
	)
	if err != nil {
		inputTensor.Destroy()
		labelOutput.Destroy()
		probOutput.Destroy()
		return nil, fmt.Errorf("failed to create ONNX session: %w", err)
	}

	// Probe inference to detect actual output shape
	if probeErr := session.Run(); probeErr != nil {
		// Shape mismatch on probabilities → recreate with 2-class
		log.Printf("[ML] 3-class probe failed, retrying with 2-class: %v", probeErr)
		session.Destroy()
		probOutput.Destroy()
		numClasses = 2

		probOutput, err = ort.NewEmptyTensor[float32](ort.NewShape(1, int64(numClasses)))
		if err != nil {
			inputTensor.Destroy()
			labelOutput.Destroy()
			return nil, fmt.Errorf("failed to create 2-class probability output tensor: %w", err)
		}

		session, err = ort.NewAdvancedSession(
			modelPath,
			[]string{"features"},
			[]string{"label", "probabilities"},
			[]ort.ArbitraryTensor{inputTensor},
			[]ort.ArbitraryTensor{labelOutput, probOutput},
			nil,
		)
		if err != nil {
			inputTensor.Destroy()
			labelOutput.Destroy()
			probOutput.Destroy()
			return nil, fmt.Errorf("failed to create ONNX session (tried 3-class and 2-class): %w", err)
		}
	}

	log.Printf("[ML] ONNX session created: %s (%d classes, 14 features)", filepath.Base(modelPath), numClasses)

	return &ONNXPredictor{
		session:     session,
		inputTensor: inputTensor,
		labelOutput: labelOutput,
		probOutput:  probOutput,
		numClasses:  numClasses,
		ready:       true,
	}, nil
}

// Predict runs inference on a 14-feature vector and returns the prediction.
// Always returns [3]float64 probabilities — for 2-class models, index 2 (stealer) is 0.
func (p *ONNXPredictor) Predict(features [14]float64) (*domain.MLPrediction, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.ready {
		return nil, fmt.Errorf("predictor is not ready (session closed or not initialized)")
	}

	// Copy features into input tensor (float64 → float32)
	inputData := p.inputTensor.GetData()
	for i := 0; i < 14; i++ {
		inputData[i] = float32(features[i])
	}

	// Run inference
	if err := p.session.Run(); err != nil {
		return nil, fmt.Errorf("ONNX inference failed: %w", err)
	}

	// Read outputs
	labelData := p.labelOutput.GetData()
	probData := p.probOutput.GetData()

	label := int(labelData[0])

	// Always produce [3]float64: [benign, ransomware, stealer]
	// For 2-class models, stealer probability is 0.
	var probs [3]float64
	probs[0] = float64(probData[0])
	probs[1] = float64(probData[1])
	if p.numClasses >= 3 {
		probs[2] = float64(probData[2])
	}

	// Find confidence (max probability)
	confidence := probs[0]
	for i := 1; i < p.numClasses; i++ {
		if probs[i] > confidence {
			confidence = probs[i]
		}
	}

	labelName := domain.ClassLabels[label]
	if labelName == "" {
		labelName = fmt.Sprintf("unknown_%d", label)
	}

	return &domain.MLPrediction{
		Label:         label,
		LabelName:     labelName,
		Confidence:    confidence,
		Probabilities: probs,
		Features:      features,
		Timestamp:     time.Now(),
	}, nil
}

// IsReady returns true if the predictor has a loaded model and is ready for inference.
func (p *ONNXPredictor) IsReady() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready
}

// Close destroys the ONNX session and frees resources.
func (p *ONNXPredictor) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.ready {
		return nil
	}

	p.ready = false

	if p.session != nil {
		p.session.Destroy()
	}
	if p.inputTensor != nil {
		p.inputTensor.Destroy()
	}
	if p.labelOutput != nil {
		p.labelOutput.Destroy()
	}
	if p.probOutput != nil {
		p.probOutput.Destroy()
	}

	return nil
}
