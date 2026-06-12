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
	IndicatorBackupAPIUsage      IndicatorType = "BACKUP_API_USAGE"      // BackupRead/BackupWrite API calls detected (file creation detection bypass)
	IndicatorCanaryCompromised   IndicatorType = "CANARY_COMPROMISED"    // Honeypot canary file encrypted/deleted (very high confidence ransomware)
	IndicatorMLRansomware        IndicatorType = "ML_RANSOMWARE"         // ML model predicts ransomware behavior
	IndicatorMLStealer           IndicatorType = "ML_STEALER"            // ML model predicts stealer behavior
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
	IndicatorRansomExtension:     50, // CRITICAL - definitive ransomware indicator
	IndicatorRecoveryDisable:     25,
	IndicatorBulkEncryption:      30,
	IndicatorFakeFile:            35, // High score - clear evasion attempt
	IndicatorEntropyIncrease:     30, // High score - file was encrypted in-place
	IndicatorInPlaceEncryption:   45, // Very high score - direct detection of in-place encryption via Event ID 2
	IndicatorModifyDeletePattern: 40, // Very high score - classic ransomware behavior, low false positive rate
	IndicatorRansomNote:          50, // CRITICAL - ransom note creation is definitive ransomware indicator
	IndicatorBackupPrivilege:     40, // CRITICAL - enables BackupWrite evasion (bypasses file creation monitoring)
	IndicatorBackupAPIUsage:      45, // CRITICAL - direct detection of BackupRead/BackupWrite usage (advanced evasion)
	IndicatorCanaryCompromised:   50, // CRITICAL - honeypot canary file compromised (very high confidence ransomware)
	IndicatorMLRansomware:        40, // ML model prediction - ransomware behavior pattern
	IndicatorMLStealer:           30, // ML model prediction - stealer behavior pattern
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

// threatShardCount stripes the score map so per-process scoring contends on different locks.
// Power of two for masking; keyed by FNV-1a(ProcessGuid) — same striping discipline as the
// velocity tracker (Phase 5).
const threatShardCount = 64

type threatShard struct {
	mu     sync.RWMutex
	scores map[string]*ThreatScore
}

// ThreatScorer manages threat scoring for all processes, striped by ProcessGuid (Phase 5) so
// AddIndicator/EvaluateThreat/GetThreatScore for different processes no longer serialize on a
// single map lock. Cross-process methods (GetAllThreats/CleanupOldScores/Reset) fan out across
// shards, locking each in turn — never two at once, preserving a deadlock-free ordering.
type ThreatScorer struct {
	shards [threatShardCount]threatShard
}

// NewThreatScorer creates a new threat scorer
func NewThreatScorer() *ThreatScorer {
	ts := &ThreatScorer{}
	for i := range ts.shards {
		ts.shards[i].scores = make(map[string]*ThreatScore)
	}
	return ts
}

func (ts *ThreatScorer) shardFor(processGuid string) *threatShard {
	return &ts.shards[fnvHash32a(processGuid)&(threatShardCount-1)]
}

// AddIndicator adds a threat indicator and returns the new score
// For certain indicator types (like IO_VELOCITY), only the first occurrence is counted
// to prevent score inflation from repeated detections of the same behavior
func (ts *ThreatScorer) AddIndicator(processGuid string, image string, pid int, indicator Indicator) int {
	sh := ts.shardFor(processGuid)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	score, exists := sh.scores[processGuid]
	if !exists {
		score = &ThreatScore{
			ProcessGuid: processGuid,
			Image:       image,
			ProcessID:   pid,
			FirstSeen:   time.Now(),
			Indicators:  make([]Indicator, 0),
			Category:    "UNKNOWN",
		}
		sh.scores[processGuid] = score
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
	sh := ts.shardFor(processGuid)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	score, exists := sh.scores[processGuid]
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
	sh := ts.shardFor(processGuid)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	score, exists := sh.scores[processGuid]
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
	// Per-shard-consistent snapshot, NOT globally atomic (Phase 5): each shard is RLocked in
	// turn and its scores deep-copied, so a score can change in an unvisited shard mid-scan.
	// Each returned ThreatScore is internally consistent; consumers treat this as advisory stats.
	threats := make([]*ThreatScore, 0)
	for i := range ts.shards {
		sh := &ts.shards[i]
		sh.mu.RLock()
		for _, score := range sh.scores {
			if score.Score > 0 {
				scoreCopy := *score
				scoreCopy.Indicators = make([]Indicator, len(score.Indicators))
				copy(scoreCopy.Indicators, score.Indicators)
				threats = append(threats, &scoreCopy)
			}
		}
		sh.mu.RUnlock()
	}

	return threats
}

// CleanupOldScores removes scores for processes inactive for specified duration
func (ts *ThreatScorer) CleanupOldScores(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for i := range ts.shards {
		sh := &ts.shards[i]
		sh.mu.Lock()
		for guid, score := range sh.scores {
			if score.LastSeen.Before(cutoff) {
				delete(sh.scores, guid)
				removed++
			}
		}
		sh.mu.Unlock()
	}

	return removed
}

// ShouldAutoRespond determines if automated response is warranted
func (ts *ThreatScorer) ShouldAutoRespond(processGuid string) bool {
	level, _ := ts.EvaluateThreat(processGuid)
	return level == ThreatCritical
}

// Reset clears all tracked threat scores.
func (ts *ThreatScorer) Reset() {
	for i := range ts.shards {
		sh := &ts.shards[i]
		sh.mu.Lock()
		sh.scores = make(map[string]*ThreatScore)
		sh.mu.Unlock()
	}
}
