package usecase

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"procSniper/internal/domain"
)

// FeatureNames lists the 14 model features in order.
var FeatureNames = [14]string{
	"velocity", "file_count", "txt_file_count", "directory_count",
	"file_delete_count", "is_signed", "extension_match", "extension_entropy",
	"shadow_copy_delete", "browser_credential_access", "browser_history_access",
	"ssh_key_access", "lsass_access", "system_info_queries",
}

// MLTestScenario defines a single test case for the ML model.
type MLTestScenario struct {
	Name          string
	Category      string
	Description   string
	Features      [14]float64
	ExpectedLabel int
	MinConfidence float64
}

// MLTestResult holds the outcome of running one scenario.
type MLTestResult struct {
	Scenario   MLTestScenario
	Prediction *domain.MLPrediction
	Passed     bool
	FailReason string
	Duration   time.Duration
}

// MLTestSummary holds aggregate results.
type MLTestSummary struct {
	Total    int
	Passed   int
	Failed   int
	Skipped  int
	Errors   int
	Duration time.Duration
	Results  []MLTestResult
}

// BuiltinScenarios returns predefined test vectors covering ransomware, stealer, and benign profiles.
func BuiltinScenarios() []MLTestScenario {
	return []MLTestScenario{
		// --- RANSOMWARE ---
		{
			Name:          "Ransomware: Fast Encryptor (LockBit-like)",
			Category:      "ransomware",
			Description:   "High velocity, shadow copy delete, many files with ransomware extensions",
			Features:      [14]float64{8000, 12000, 8, 800, 3000, 0, 0.85, 0.12, 1, 0, 0, 0, 0, 1},
			ExpectedLabel: 1,
			MinConfidence: 0.70,
		},
		{
			Name:          "Ransomware: Slow Encryptor (Maze-like)",
			Category:      "ransomware",
			Description:   "Low velocity, shadow copy delete, LSASS access, extension match",
			Features:      [14]float64{200, 1000, 5, 100, 300, 0, 0.75, 0.30, 1, 0, 0, 0, 1, 1},
			ExpectedLabel: 1,
			MinConfidence: 0.60,
		},
		{
			Name:          "Ransomware: Wiper (HermeticWiper-like)",
			Category:      "ransomware",
			Description:   "High deletes, low extension match, shadow copy delete",
			Features:      [14]float64{500, 2000, 0, 200, 3500, 0, 0.05, 0.80, 1, 0, 0, 0, 0, 1},
			ExpectedLabel: 1,
			MinConfidence: 0.50,
		},

		// --- STEALER (only meaningful for 3-class models) ---
		{
			Name:          "Stealer: Browser (RedLine-like)",
			Category:      "stealer",
			Description:   "Low velocity, browser credential + history access",
			Features:      [14]float64{10, 30, 0, 5, 1, 0, 0, 1.8, 0, 1, 1, 0, 1, 1},
			ExpectedLabel: 2,
			MinConfidence: 0.60,
		},
		{
			Name:          "Stealer: Credential Harvester (Mimikatz-like)",
			Category:      "stealer",
			Description:   "Minimal file IO, LSASS access, SSH key access, system info queries",
			Features:      [14]float64{5, 10, 0, 3, 0, 0, 0, 0.5, 0, 0, 0, 1, 1, 1},
			ExpectedLabel: 2,
			MinConfidence: 0.50,
		},

		// --- BENIGN ---
		{
			Name:          "Benign: Normal User Activity",
			Category:      "benign",
			Description:   "Low velocity, signed, no threat indicators",
			Features:      [14]float64{8, 15, 1, 3, 2, 1, 0, 2.2, 0, 0, 0, 0, 0, 0},
			ExpectedLabel: 0,
			MinConfidence: 0.70,
		},
		{
			Name:          "Benign: IDE Build (Visual Studio)",
			Category:      "benign",
			Description:   "High velocity, diverse extensions, signed, no threat indicators",
			Features:      [14]float64{250, 500, 0, 30, 20, 1, 0, 3.2, 0, 0, 0, 0, 0, 0},
			ExpectedLabel: 0,
			MinConfidence: 0.60,
		},
		{
			Name:          "Benign: Backup Software (Veeam-like)",
			Category:      "benign",
			Description:   "Moderate velocity, many dirs, signed, no threat indicators",
			Features:      [14]float64{150, 800, 0, 60, 3, 1, 0, 2.8, 0, 0, 0, 0, 0, 0},
			ExpectedLabel: 0,
			MinConfidence: 0.60,
		},
	}
}

// RunMLTestScenarios executes all scenarios against the given predictor.
func RunMLTestScenarios(predictor domain.MLPredictor, scenarios []MLTestScenario) *MLTestSummary {
	summary := &MLTestSummary{}
	startAll := time.Now()

	for _, scenario := range scenarios {
		start := time.Now()
		prediction, err := predictor.Predict(scenario.Features)
		elapsed := time.Since(start)

		result := MLTestResult{
			Scenario: scenario,
			Duration: elapsed,
		}

		if err != nil {
			result.FailReason = "INFERENCE ERROR: " + err.Error()
			summary.Errors++
			summary.Results = append(summary.Results, result)
			continue
		}

		result.Prediction = prediction

		// Detect 2-class model: stealer probability is always 0
		is2Class := prediction.Probabilities[2] == 0.0

		// For stealer scenarios against 2-class models, mark as skipped
		if scenario.ExpectedLabel == 2 && is2Class {
			result.FailReason = "SKIPPED (2-class model, no stealer class)"
			result.Passed = true
			summary.Skipped++
			summary.Results = append(summary.Results, result)
			continue
		}

		// Check label match
		if prediction.Label != scenario.ExpectedLabel {
			result.FailReason = fmt.Sprintf("label mismatch: expected %s, got %s",
				domain.ClassLabels[scenario.ExpectedLabel],
				prediction.LabelName)
			summary.Failed++
		} else if scenario.MinConfidence > 0 && prediction.Confidence < scenario.MinConfidence {
			result.FailReason = fmt.Sprintf("confidence too low: expected >= %.2f, got %.4f",
				scenario.MinConfidence, prediction.Confidence)
			summary.Failed++
		} else {
			result.Passed = true
			summary.Passed++
		}

		summary.Results = append(summary.Results, result)
	}

	summary.Total = len(scenarios)
	summary.Duration = time.Since(startAll)
	return summary
}

// LoadScenariosFromCSV reads custom test scenarios from a CSV file.
// Format: name, expected_label, velocity, file_count, ..., system_info_queries (16 columns)
// Lines starting with # are comments. Header row is auto-detected and skipped.
func LoadScenariosFromCSV(path string) ([]MLTestScenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.Comment = '#'
	reader.TrimLeadingSpace = true

	var scenarios []MLTestScenario
	lineNum := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("CSV parse error at line %d: %w", lineNum+1, err)
		}
		lineNum++

		// Skip header row
		if lineNum == 1 && strings.ToLower(strings.TrimSpace(record[0])) == "name" {
			continue
		}

		if len(record) != 16 {
			return nil, fmt.Errorf("line %d: expected 16 columns (name, label, 14 features), got %d", lineNum, len(record))
		}

		name := strings.TrimSpace(record[0])
		expectedLabel, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid expected_label '%s': %w", lineNum, record[1], err)
		}

		var features [14]float64
		for i := 0; i < 14; i++ {
			features[i], err = strconv.ParseFloat(strings.TrimSpace(record[i+2]), 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid feature %s value '%s': %w",
					lineNum, FeatureNames[i], record[i+2], err)
			}
		}

		scenarios = append(scenarios, MLTestScenario{
			Name:          name,
			Category:      domain.ClassLabels[expectedLabel],
			Description:   "custom CSV scenario",
			Features:      features,
			ExpectedLabel: expectedLabel,
			MinConfidence: 0.0,
		})
	}

	if len(scenarios) == 0 {
		return nil, fmt.Errorf("no valid scenarios found in CSV file")
	}

	return scenarios, nil
}

// PrintMLTestResults prints the test results in a formatted table.
func PrintMLTestResults(summary *MLTestSummary, modelPath string, verbose bool) {
	fmt.Println()
	fmt.Println("==========================================================")
	fmt.Println(" ML MODEL TEST RESULTS")
	fmt.Printf(" Model: %s\n", modelPath)
	fmt.Printf(" Scenarios: %d | Duration: %s\n", summary.Total, summary.Duration.Round(time.Millisecond))
	fmt.Println("==========================================================")
	fmt.Println()

	for i, result := range summary.Results {
		status := "PASS"
		if !result.Passed {
			status = "FAIL"
		}
		if result.FailReason != "" && strings.HasPrefix(result.FailReason, "SKIPPED") {
			status = "SKIP"
		}
		if result.FailReason != "" && strings.HasPrefix(result.FailReason, "INFERENCE ERROR") {
			status = "ERR "
		}

		fmt.Printf("[%d/%d] [%s] %s\n", i+1, summary.Total, status, result.Scenario.Name)

		if result.Prediction != nil {
			fmt.Printf("       Predicted: %-12s  Confidence: %.4f  (%s)\n",
				result.Prediction.LabelName,
				result.Prediction.Confidence,
				result.Duration.Round(time.Microsecond))
			fmt.Printf("       Probs: benign=%.4f  ransomware=%.4f  stealer=%.4f\n",
				result.Prediction.Probabilities[0],
				result.Prediction.Probabilities[1],
				result.Prediction.Probabilities[2])
		}

		if result.FailReason != "" {
			fmt.Printf("       Reason: %s\n", result.FailReason)
		}

		if verbose {
			fmt.Printf("       Features: [")
			for j, f := range result.Scenario.Features {
				if j > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s=%.2f", FeatureNames[j], f)
			}
			fmt.Println("]")
		}

		fmt.Println()
	}

	fmt.Println("----------------------------------------------------------")
	fmt.Printf(" SUMMARY: %d passed, %d failed, %d skipped, %d errors out of %d total\n",
		summary.Passed, summary.Failed, summary.Skipped, summary.Errors, summary.Total)
	fmt.Println("----------------------------------------------------------")
	fmt.Println()
}
