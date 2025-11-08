package domain

import (
	"sync"
	"time"
)

// ThreatLevel represents severity of detected threat
type ThreatLevel string

const (
	ThreatNone     ThreatLevel = "NONE"
	ThreatLow      ThreatLevel = "LOW"
	ThreatMedium   ThreatLevel = "MEDIUM"
	ThreatHigh     ThreatLevel = "HIGH"
	ThreatCritical ThreatLevel = "CRITICAL"
)

// IndicatorType categorizes threat indicators
type IndicatorType string

const (
	IndicatorHighEntropy         IndicatorType = "HIGH_ENTROPY"
	IndicatorIOVelocity          IndicatorType = "IO_VELOCITY"
	IndicatorShadowCopyDeletion  IndicatorType = "SHADOW_COPY_DELETE"
	IndicatorLSASSAccess         IndicatorType = "LSASS_ACCESS"
	IndicatorCredentialTheft     IndicatorType = "CREDENTIAL_THEFT"
	IndicatorRansomExtension     IndicatorType = "RANSOM_EXTENSION"
	IndicatorRecoveryDisable     IndicatorType = "RECOVERY_DISABLE"
	IndicatorBulkEncryption      IndicatorType = "BULK_ENCRYPTION"
	IndicatorFakeFile            IndicatorType = "FAKE_FILE"             // File extension doesn't match magic bytes (ransomware evasion)
	IndicatorEntropyIncrease     IndicatorType = "ENTROPY_INCREASE"      // Significant entropy increase detected (in-place encryption)
	IndicatorInPlaceEncryption   IndicatorType = "IN_PLACE_ENCRYPTION"   // File modified with detected entropy increase (Event ID 2 detection)
	IndicatorModifyDeletePattern IndicatorType = "MODIFY_DELETE_PATTERN" // File modified with high entropy then deleted (classic ransomware)
	IndicatorRansomNote          IndicatorType = "RANSOM_NOTE"           // Ransom note file created (README.txt, DECRYPT.txt, etc.)
	IndicatorBackupPrivilege     IndicatorType = "BACKUP_PRIVILEGE"      // SeBackupPrivilege/SeRestorePrivilege enabled (BackupWrite evasion)
	IndicatorBackupAPIUsage      IndicatorType = "BACKUP_API_USAGE"      // BackupRead/BackupWrite API calls detected (Sysmon Event ID 11 bypass)
	IndicatorCanaryCompromised   IndicatorType = "CANARY_COMPROMISED"    // Honeypot canary file encrypted/deleted (very high confidence ransomware)
)

// Indicator represents a single threat indicator
type Indicator struct {
	Type        IndicatorType
	Severity    ThreatLevel
	Points      int
	Description string
	Timestamp   time.Time
	Evidence    map[string]string
}

// Scoring weights based on research and MITRE ATT&CK
var IndicatorScores = map[IndicatorType]int{
	IndicatorHighEntropy:         25,
	IndicatorIOVelocity:          30,
	IndicatorShadowCopyDeletion:  25,
	IndicatorLSASSAccess:         35,
	IndicatorCredentialTheft:     40,
	IndicatorRansomExtension:     20,
	IndicatorRecoveryDisable:     25,
	IndicatorBulkEncryption:      30,
	IndicatorFakeFile:            35, // High score - clear evasion attempt
	IndicatorEntropyIncrease:     30, // High score - file was encrypted in-place
	IndicatorInPlaceEncryption:   45, // Very high score - direct detection of in-place encryption via Event ID 2
	IndicatorModifyDeletePattern: 40, // Very high score - classic ransomware behavior, low false positive rate
	IndicatorRansomNote:          50, // CRITICAL - ransom note creation is definitive ransomware indicator
	IndicatorBackupPrivilege:     40, // CRITICAL - enables BackupWrite evasion (bypasses Sysmon Event ID 11)
	IndicatorBackupAPIUsage:      45, // CRITICAL - direct detection of BackupRead/BackupWrite usage (advanced evasion)
	IndicatorCanaryCompromised:   50, // CRITICAL - honeypot canary file compromised (very high confidence ransomware)
}

// ThreatScore tracks accumulated threat indicators for a process
type ThreatScore struct {
	ProcessGuid string
	Image       string
	ProcessID   int
	Score       int
	Indicators  []Indicator
	FirstSeen   time.Time
	LastSeen    time.Time
	Category    string // "RANSOMWARE", "STEALER", "UNKNOWN"
}

// ThreatScorer manages threat scoring for all processes
type ThreatScorer struct {
	scores map[string]*ThreatScore
	mu     sync.RWMutex
}

// NewThreatScorer creates a new threat scorer
func NewThreatScorer() *ThreatScorer {
	return &ThreatScorer{
		scores: make(map[string]*ThreatScore),
	}
}

// AddIndicator adds a threat indicator and returns the new score
// For certain indicator types (like IO_VELOCITY), only the first occurrence is counted
// to prevent score inflation from repeated detections of the same behavior
func (ts *ThreatScorer) AddIndicator(processGuid string, image string, pid int, indicator Indicator) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	score, exists := ts.scores[processGuid]
	if !exists {
		score = &ThreatScore{
			ProcessGuid: processGuid,
			Image:       image,
			ProcessID:   pid,
			FirstSeen:   time.Now(),
			Indicators:  make([]Indicator, 0),
			Category:    "UNKNOWN",
		}
		ts.scores[processGuid] = score
	}

	// Check if this indicator type already exists (for non-repeatable indicators)
	// Some indicators should only be counted once per process to avoid score inflation
	nonRepeatableTypes := []IndicatorType{
		IndicatorIOVelocity,
		IndicatorHighEntropy,     // Count once (threshold-based)
		IndicatorRansomExtension, // Count once (threshold-based)
	}

	for _, nonRepeatableType := range nonRepeatableTypes {
		if indicator.Type == nonRepeatableType {
			for _, existingInd := range score.Indicators {
				if existingInd.Type == nonRepeatableType {
					// Already have this indicator type, update evidence but don't add points again
					existingInd.Evidence = indicator.Evidence
					existingInd.Timestamp = indicator.Timestamp
					score.LastSeen = time.Now()
					return score.Score
				}
			}
		}
	}

	score.Score += indicator.Points
	score.Indicators = append(score.Indicators, indicator)
	score.LastSeen = time.Now()

	// Categorize threat based on indicators
	score.Category = ts.categorizeThreat(score)

	return score.Score
}

// categorizeThreat determines threat category based on indicators
func (ts *ThreatScorer) categorizeThreat(score *ThreatScore) string {
	hasEncryption := false
	hasCredentialTheft := false

	for _, ind := range score.Indicators {
		switch ind.Type {
		case IndicatorHighEntropy, IndicatorIOVelocity, IndicatorBulkEncryption, IndicatorRansomExtension:
			hasEncryption = true
		case IndicatorLSASSAccess, IndicatorCredentialTheft:
			hasCredentialTheft = true
		}
	}

	if hasEncryption {
		return "RANSOMWARE"
	} else if hasCredentialTheft {
		return "STEALER"
	}

	return "UNKNOWN"
}

// EvaluateThreat returns threat level and score for a process
func (ts *ThreatScorer) EvaluateThreat(processGuid string) (ThreatLevel, int) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	score, exists := ts.scores[processGuid]
	if !exists {
		return ThreatNone, 0
	}

	finalScore := score.Score

	// Temporal correlation bonus
	// Multiple indicators within 60 seconds = 1.5x multiplier
	timespan := score.LastSeen.Sub(score.FirstSeen)
	if timespan < 60*time.Second && len(score.Indicators) >= 3 {
		finalScore = int(float64(finalScore) * 1.5)
	}

	// Determine threat level
	switch {
	case finalScore >= 86:
		return ThreatCritical, finalScore
	case finalScore >= 61:
		return ThreatHigh, finalScore
	case finalScore >= 31:
		return ThreatMedium, finalScore
	case finalScore >= 1:
		return ThreatLow, finalScore
	default:
		return ThreatNone, 0
	}
}

// GetThreatScore returns the threat score for a process
func (ts *ThreatScorer) GetThreatScore(processGuid string) *ThreatScore {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	score, exists := ts.scores[processGuid]
	if !exists {
		return nil
	}

	// Return copy to prevent external modification
	scoreCopy := *score
	scoreCopy.Indicators = make([]Indicator, len(score.Indicators))
	copy(scoreCopy.Indicators, score.Indicators)

	return &scoreCopy
}

// GetAllThreats returns all processes with non-zero threat scores
func (ts *ThreatScorer) GetAllThreats() []*ThreatScore {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	threats := make([]*ThreatScore, 0, len(ts.scores))
	for _, score := range ts.scores {
		if score.Score > 0 {
			scoreCopy := *score
			scoreCopy.Indicators = make([]Indicator, len(score.Indicators))
			copy(scoreCopy.Indicators, score.Indicators)
			threats = append(threats, &scoreCopy)
		}
	}

	return threats
}

// CleanupOldScores removes scores for processes inactive for specified duration
func (ts *ThreatScorer) CleanupOldScores(maxAge time.Duration) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for guid, score := range ts.scores {
		if score.LastSeen.Before(cutoff) {
			delete(ts.scores, guid)
			removed++
		}
	}

	return removed
}

// ShouldAutoRespond determines if automated response is warranted
func (ts *ThreatScorer) ShouldAutoRespond(processGuid string) bool {
	level, _ := ts.EvaluateThreat(processGuid)
	return level == ThreatCritical
}
