package domain

import (
	"sync"
	"time"
)

// FileOperation represents a single file operation event
type FileOperation struct {
	Timestamp   time.Time
	ProcessGuid string
	ProcessID   int
	Operation   string // "create", "delete", "modify"
	FilePath    string
	Image       string // Process executable path
}

// FileOperationTracker tracks file operations in sliding time windows
// Research shows ransomware encrypts at 38-280 files/second
// Detection threshold: 100 files/minute for high-confidence alerts
type FileOperationTracker struct {
	operations []FileOperation
	windowSize time.Duration
	mu         sync.RWMutex
}

// VelocityTier represents the detection tier based on I/O velocity
type VelocityTier int

const (
	VelocityTierNone     VelocityTier = 0 // < 10 files/min - normal activity
	VelocityTierMonitor  VelocityTier = 1 // 10-29 files/min - start lightweight tracking
	VelocityTierAnalyze  VelocityTier = 2 // 30-99 files/min - deep analysis with entropy
	VelocityTierCritical VelocityTier = 3 // >= 100 files/min - immediate investigation
)

// String returns human-readable tier name
func (vt VelocityTier) String() string {
	switch vt {
	case VelocityTierNone:
		return "NONE"
	case VelocityTierMonitor:
		return "MONITOR"
	case VelocityTierAnalyze:
		return "ANALYZE"
	case VelocityTierCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// VelocityThresholds define detection sensitivity levels
// Based on ransomware research: 38-280 files/second encryption rate
// These tiers provide graduated response to catch both fast and slow-moving ransomware
const (
	TierMonitorThreshold  = 10.0  // Files per minute - start watching (catch slow ransomware)
	TierAnalyzeThreshold  = 30.0  // Files per minute - deep analysis (catch moderate ransomware)
	TierCriticalThreshold = 100.0 // Files per minute - immediate alert (catch fast ransomware)
)

// NewFileOperationTracker creates a new tracker with specified window size
func NewFileOperationTracker(windowSize time.Duration) *FileOperationTracker {
	return &FileOperationTracker{
		operations: make([]FileOperation, 0, 10000),
		windowSize: windowSize,
	}
}

// AddOperation adds a file operation and removes expired ones
func (fot *FileOperationTracker) AddOperation(op FileOperation) {
	fot.mu.Lock()
	defer fot.mu.Unlock()

	// Remove operations outside window
	cutoff := time.Now().Add(-fot.windowSize)
	validOps := make([]FileOperation, 0, len(fot.operations)+1)

	for _, existingOp := range fot.operations {
		if existingOp.Timestamp.After(cutoff) {
			validOps = append(validOps, existingOp)
		}
	}

	fot.operations = append(validOps, op)
}

// GetVelocity calculates files per minute for a specific process
func (fot *FileOperationTracker) GetVelocity(processGuid string) float64 {
	fot.mu.RLock()
	defer fot.mu.RUnlock()

	count := 0
	for _, op := range fot.operations {
		if op.ProcessGuid == processGuid {
			count++
		}
	}

	return float64(count) / fot.windowSize.Minutes()
}

// DetectAnomalousActivity checks if process exhibits ransomware-like I/O velocity
// Returns the velocity tier, actual velocity in files/min, and tier name
func (fot *FileOperationTracker) DetectAnomalousActivity(processGuid string) (VelocityTier, float64, string) {
	velocity := fot.GetVelocity(processGuid)

	if velocity >= TierCriticalThreshold {
		return VelocityTierCritical, velocity, "CRITICAL"
	} else if velocity >= TierAnalyzeThreshold {
		return VelocityTierAnalyze, velocity, "ANALYZE"
	} else if velocity >= TierMonitorThreshold {
		return VelocityTierMonitor, velocity, "MONITOR"
	}

	return VelocityTierNone, velocity, "NONE"
}

// GetVelocityTier returns just the tier classification for a process
func (fot *FileOperationTracker) GetVelocityTier(processGuid string) VelocityTier {
	tier, _, _ := fot.DetectAnomalousActivity(processGuid)
	return tier
}

// GetOperationCount returns total operations in window for a process
func (fot *FileOperationTracker) GetOperationCount(processGuid string) int {
	fot.mu.RLock()
	defer fot.mu.RUnlock()

	count := 0
	for _, op := range fot.operations {
		if op.ProcessGuid == processGuid {
			count++
		}
	}
	return count
}

// GetRecentOperations returns recent operations for a process
func (fot *FileOperationTracker) GetRecentOperations(processGuid string, limit int) []FileOperation {
	fot.mu.RLock()
	defer fot.mu.RUnlock()

	result := make([]FileOperation, 0, limit)
	for i := len(fot.operations) - 1; i >= 0 && len(result) < limit; i-- {
		if fot.operations[i].ProcessGuid == processGuid {
			result = append(result, fot.operations[i])
		}
	}

	return result
}

// GetOperationsByType counts operations by type for a process
func (fot *FileOperationTracker) GetOperationsByType(processGuid string) map[string]int {
	fot.mu.RLock()
	defer fot.mu.RUnlock()

	counts := make(map[string]int)
	for _, op := range fot.operations {
		if op.ProcessGuid == processGuid {
			counts[op.Operation]++
		}
	}
	return counts
}

// Cleanup removes all expired operations
func (fot *FileOperationTracker) Cleanup() int {
	fot.mu.Lock()
	defer fot.mu.Unlock()

	cutoff := time.Now().Add(-fot.windowSize)
	validOps := make([]FileOperation, 0, len(fot.operations))

	for _, op := range fot.operations {
		if op.Timestamp.After(cutoff) {
			validOps = append(validOps, op)
		}
	}

	removed := len(fot.operations) - len(validOps)
	fot.operations = validOps
	return removed
}
