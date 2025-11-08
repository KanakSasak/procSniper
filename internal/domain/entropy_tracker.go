package domain

import (
	"sync"
	"time"
)

// FileEntropyRecord tracks entropy values for files
type FileEntropyRecord struct {
	FilePath        string
	OriginalEntropy float64
	CurrentEntropy  float64
	Delta           float64 // CurrentEntropy - OriginalEntropy
	FirstSeen       time.Time
	LastSeen        time.Time
	ModifiedCount   int // How many times file was modified
}

// EntropyTracker tracks file entropy changes to detect encryption
type EntropyTracker struct {
	records map[string]*FileEntropyRecord // filePath -> record
	mu      sync.RWMutex
	ttl     time.Duration // How long to keep records
}

// NewEntropyTracker creates a new entropy tracker
func NewEntropyTracker(ttl time.Duration) *EntropyTracker {
	return &EntropyTracker{
		records: make(map[string]*FileEntropyRecord),
		ttl:     ttl,
	}
}

// TrackFileEntropy tracks entropy for a file
// Returns:
// - isNew: true if this is the first time seeing this file
// - delta: entropy change from original (0 if new file)
// - record: the entropy record
func (et *EntropyTracker) TrackFileEntropy(filePath string, entropy float64) (isNew bool, delta float64, record *FileEntropyRecord) {
	et.mu.Lock()
	defer et.mu.Unlock()

	existing, exists := et.records[filePath]

	if !exists {
		// First time seeing this file - record baseline entropy
		record = &FileEntropyRecord{
			FilePath:        filePath,
			OriginalEntropy: entropy,
			CurrentEntropy:  entropy,
			Delta:           0,
			FirstSeen:       time.Now(),
			LastSeen:        time.Now(),
			ModifiedCount:   0,
		}
		et.records[filePath] = record
		return true, 0, record
	}

	// File seen before - calculate delta
	existing.CurrentEntropy = entropy
	existing.Delta = entropy - existing.OriginalEntropy
	existing.LastSeen = time.Now()
	existing.ModifiedCount++

	return false, existing.Delta, existing
}

// GetEntropyRecord retrieves the entropy record for a file
func (et *EntropyTracker) GetEntropyRecord(filePath string) (*FileEntropyRecord, bool) {
	et.mu.RLock()
	defer et.mu.RUnlock()

	record, exists := et.records[filePath]
	return record, exists
}

// GetPreviousEntropy returns the last known entropy for a file
// Returns 0 if file has never been tracked
func (et *EntropyTracker) GetPreviousEntropy(filePath string) float64 {
	et.mu.RLock()
	defer et.mu.RUnlock()

	record, exists := et.records[filePath]
	if !exists {
		return 0
	}

	return record.CurrentEntropy
}

// IsSignificantEntropyIncrease checks if entropy increased significantly
// Threshold: +2.0 bits/byte is highly suspicious (encryption)
func IsSignificantEntropyIncrease(delta float64) bool {
	return delta >= 2.0
}

// Cleanup removes stale records older than TTL
func (et *EntropyTracker) Cleanup() int {
	et.mu.Lock()
	defer et.mu.Unlock()

	now := time.Now()
	removed := 0

	for filePath, record := range et.records {
		if now.Sub(record.LastSeen) > et.ttl {
			delete(et.records, filePath)
			removed++
		}
	}

	return removed
}

// GetStats returns tracker statistics
func (et *EntropyTracker) GetStats() map[string]interface{} {
	et.mu.RLock()
	defer et.mu.RUnlock()

	modifiedFiles := 0
	significantIncreases := 0

	for _, record := range et.records {
		if record.ModifiedCount > 0 {
			modifiedFiles++
		}
		if IsSignificantEntropyIncrease(record.Delta) {
			significantIncreases++
		}
	}

	return map[string]interface{}{
		"tracked_files":         len(et.records),
		"modified_files":        modifiedFiles,
		"significant_increases": significantIncreases,
	}
}
