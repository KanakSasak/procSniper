package domain

import (
	"testing"
	"time"
)

func TestThreatScorer_AddIndicator(t *testing.T) {
	scorer := NewThreatScorer()
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	indicator := Indicator{
		Type:        IndicatorHighEntropy,
		Severity:    ThreatHigh,
		Points:      IndicatorScores[IndicatorHighEntropy],
		Description: "High entropy file detected",
		Timestamp:   time.Now(),
		Evidence: map[string]string{
			"file":    "C:\\test\\encrypted.txt",
			"entropy": "7.95",
		},
	}

	score := scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)

	if score != IndicatorScores[IndicatorHighEntropy] {
		t.Errorf("Score = %d, expected %d", score, IndicatorScores[IndicatorHighEntropy])
	}

	threatScore := scorer.GetThreatScore(processGuid)
	if threatScore == nil {
		t.Fatal("ThreatScore is nil")
	}

	if len(threatScore.Indicators) != 1 {
		t.Errorf("Indicators count = %d, expected 1", len(threatScore.Indicators))
	}
}

func TestThreatScorer_EvaluateThreat(t *testing.T) {
	tests := []struct {
		name           string
		indicators     []IndicatorType
		expectedLevel  ThreatLevel
		expectedMinScore int
		description    string
	}{
		{
			name:           "Single low indicator",
			indicators:     []IndicatorType{IndicatorRansomExtension},
			expectedLevel:  ThreatLow,
			expectedMinScore: 20,
			description:    "20 points - LOW threat",
		},
		{
			name:           "Medium threat",
			indicators:     []IndicatorType{IndicatorHighEntropy, IndicatorRansomExtension},
			expectedLevel:  ThreatMedium,
			expectedMinScore: 45,
			description:    "45 points - MEDIUM threat",
		},
		{
			name: "High threat",
			indicators: []IndicatorType{
				IndicatorHighEntropy,
				IndicatorIOVelocity,
			},
			expectedLevel:  ThreatMedium,
			expectedMinScore: 55,
			description:    "55 points - MEDIUM threat (61 needed for HIGH)",
		},
		{
			name: "Critical threat",
			indicators: []IndicatorType{
				IndicatorHighEntropy,
				IndicatorIOVelocity,
				IndicatorShadowCopyDeletion,
				IndicatorRansomExtension,
			},
			expectedLevel:  ThreatCritical,
			expectedMinScore: 100,
			description:    "100+ points - CRITICAL threat with auto-response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scorer := NewThreatScorer()
			processGuid := "{12345678-1234-1234-1234-123456789012}"

			// Add indicators
			for _, indType := range tt.indicators {
				indicator := Indicator{
					Type:        indType,
					Severity:    ThreatHigh,
					Points:      IndicatorScores[indType],
					Description: string(indType),
					Timestamp:   time.Now(),
					Evidence:    make(map[string]string),
				}
				scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)
			}

			level, score := scorer.EvaluateThreat(processGuid)

			if level != tt.expectedLevel {
				t.Errorf("Threat level = %s, expected %s (score: %d)",
					level, tt.expectedLevel, score)
			}

			if score < tt.expectedMinScore {
				t.Errorf("Score = %d, expected >= %d", score, tt.expectedMinScore)
			}

			t.Logf("%s - Level: %s, Score: %d", tt.description, level, score)
		})
	}
}

func TestThreatScorer_TemporalCorrelation(t *testing.T) {
	scorer := NewThreatScorer()
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Add 3 indicators within 1 second (should trigger temporal bonus)
	indicators := []IndicatorType{
		IndicatorHighEntropy,
		IndicatorIOVelocity,
		IndicatorRansomExtension,
	}

	for _, indType := range indicators {
		indicator := Indicator{
			Type:        indType,
			Severity:    ThreatHigh,
			Points:      IndicatorScores[indType],
			Description: string(indType),
			Timestamp:   time.Now(),
			Evidence:    make(map[string]string),
		}
		scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)
	}

	level, score := scorer.EvaluateThreat(processGuid)

	baseScore := IndicatorScores[IndicatorHighEntropy] +
		IndicatorScores[IndicatorIOVelocity] +
		IndicatorScores[IndicatorRansomExtension]

	expectedScore := int(float64(baseScore) * 1.5) // 1.5x multiplier

	if score < expectedScore-1 || score > expectedScore+1 {
		t.Errorf("Score with temporal bonus = %d, expected ~%d (base: %d)",
			score, expectedScore, baseScore)
	}

	t.Logf("Temporal correlation: Base=%d, Boosted=%d, Level=%s",
		baseScore, score, level)
}

func TestThreatScorer_CategorizeThreat(t *testing.T) {
	tests := []struct {
		name             string
		indicators       []IndicatorType
		expectedCategory string
		description      string
	}{
		{
			name: "Ransomware",
			indicators: []IndicatorType{
				IndicatorHighEntropy,
				IndicatorIOVelocity,
				IndicatorBulkEncryption,
			},
			expectedCategory: "RANSOMWARE",
			description:      "Encryption indicators",
		},
		{
			name: "Stealer",
			indicators: []IndicatorType{
				IndicatorLSASSAccess,
				IndicatorCredentialTheft,
			},
			expectedCategory: "STEALER",
			description:      "Credential theft indicators",
		},
		{
			name: "Unknown",
			indicators: []IndicatorType{
				IndicatorRecoveryDisable,
			},
			expectedCategory: "UNKNOWN",
			description:      "Ambiguous indicators",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scorer := NewThreatScorer()
			processGuid := "{12345678-1234-1234-1234-123456789012}"

			for _, indType := range tt.indicators {
				indicator := Indicator{
					Type:        indType,
					Severity:    ThreatHigh,
					Points:      IndicatorScores[indType],
					Description: string(indType),
					Timestamp:   time.Now(),
					Evidence:    make(map[string]string),
				}
				scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)
			}

			threatScore := scorer.GetThreatScore(processGuid)
			if threatScore == nil {
				t.Fatal("ThreatScore is nil")
			}

			if threatScore.Category != tt.expectedCategory {
				t.Errorf("Category = %s, expected %s",
					threatScore.Category, tt.expectedCategory)
			}

			t.Logf("%s - Category: %s", tt.description, threatScore.Category)
		})
	}
}

func TestThreatScorer_ShouldAutoRespond(t *testing.T) {
	scorer := NewThreatScorer()
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Add indicators to reach CRITICAL level (86+ points)
	criticalIndicators := []IndicatorType{
		IndicatorHighEntropy,       // 25
		IndicatorIOVelocity,        // 30
		IndicatorShadowCopyDeletion, // 25
		IndicatorRansomExtension,   // 20
	} // Total: 100 points

	for _, indType := range criticalIndicators {
		indicator := Indicator{
			Type:        indType,
			Severity:    ThreatCritical,
			Points:      IndicatorScores[indType],
			Description: string(indType),
			Timestamp:   time.Now(),
			Evidence:    make(map[string]string),
		}
		scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)
	}

	shouldRespond := scorer.ShouldAutoRespond(processGuid)
	if !shouldRespond {
		level, score := scorer.EvaluateThreat(processGuid)
		t.Errorf("ShouldAutoRespond = false, expected true (Level: %s, Score: %d)",
			level, score)
	}

	t.Log("Auto-response correctly triggered for CRITICAL threat")
}

func TestThreatScorer_CleanupOldScores(t *testing.T) {
	scorer := NewThreatScorer()

	// Add old score
	oldGuid := "{OLD-GUID}"
	indicator := Indicator{
		Type:        IndicatorHighEntropy,
		Severity:    ThreatHigh,
		Points:      25,
		Description: "Old indicator",
		Timestamp:   time.Now().Add(-10 * time.Minute),
		Evidence:    make(map[string]string),
	}
	scorer.AddIndicator(oldGuid, "C:\\old.exe", 1234, indicator)

	// Add recent score
	recentGuid := "{RECENT-GUID}"
	indicator2 := Indicator{
		Type:        IndicatorHighEntropy,
		Severity:    ThreatHigh,
		Points:      25,
		Description: "Recent indicator",
		Timestamp:   time.Now(),
		Evidence:    make(map[string]string),
	}
	scorer.AddIndicator(recentGuid, "C:\\recent.exe", 5678, indicator2)

	// Manually set LastSeen to simulate age
	scorer.scores[oldGuid].LastSeen = time.Now().Add(-10 * time.Minute)

	// Cleanup scores older than 5 minutes
	removed := scorer.CleanupOldScores(5 * time.Minute)

	if removed != 1 {
		t.Errorf("Removed = %d, expected 1", removed)
	}

	// Old score should be gone
	if scorer.GetThreatScore(oldGuid) != nil {
		t.Error("Old score not removed")
	}

	// Recent score should remain
	if scorer.GetThreatScore(recentGuid) == nil {
		t.Error("Recent score incorrectly removed")
	}
}

func BenchmarkThreatScorer_AddIndicator(b *testing.B) {
	scorer := NewThreatScorer()
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	indicator := Indicator{
		Type:        IndicatorHighEntropy,
		Severity:    ThreatHigh,
		Points:      25,
		Description: "Test indicator",
		Timestamp:   time.Now(),
		Evidence:    make(map[string]string),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)
	}
}

func BenchmarkThreatScorer_EvaluateThreat(b *testing.B) {
	scorer := NewThreatScorer()
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Pre-populate with indicators
	for i := 0; i < 5; i++ {
		indicator := Indicator{
			Type:        IndicatorHighEntropy,
			Severity:    ThreatHigh,
			Points:      25,
			Description: "Test indicator",
			Timestamp:   time.Now(),
			Evidence:    make(map[string]string),
		}
		scorer.AddIndicator(processGuid, "C:\\malware.exe", 1234, indicator)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		scorer.EvaluateThreat(processGuid)
	}
}
