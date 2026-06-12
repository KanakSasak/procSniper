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

// velocityShardCount is the number of striped shards (power of two so we can mask). Operations
// are partitioned by FNV-1a(ProcessGuid) so events from different processes contend on
// different locks and each scan touches only one shard's slice instead of a global one.
const velocityShardCount = 64

// velocityShard holds the windowed operations for the processes whose GUID hashes to it.
type velocityShard struct {
	mu  sync.RWMutex
	ops []FileOperation
}

// FileOperationTracker tracks file operations in sliding time windows.
// Research shows ransomware encrypts at 38-280 files/second; detection threshold is
// 100 files/minute for high-confidence alerts.
//
// The operation store is striped by ProcessGuid across velocityShardCount shards (Phase 5):
// AddOperation/GetVelocity touch only the one shard for a process, so the per-event hot path
// no longer serializes every process through a single global lock + global-slice scan.
type FileOperationTracker struct {
	shards     [velocityShardCount]velocityShard
	windowSize time.Duration

	// Per-minute tier thresholds. Defaulted to the Tier*Threshold consts by the
	// constructor and overridable via SetThresholds (wired from the io_velocity_* config
	// keys). Set once at construction, before the tracker is shared with detection
	// goroutines, so they are read without locking on the hot path.
	monitorThreshold  float64
	analyzeThreshold  float64
	criticalThreshold float64
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

// NewFileOperationTracker creates a new tracker with specified window size.
// Tier thresholds default to the Tier*Threshold consts; override via SetThresholds.
func NewFileOperationTracker(windowSize time.Duration) *FileOperationTracker {
	return &FileOperationTracker{
		windowSize:        windowSize,
		monitorThreshold:  TierMonitorThreshold,
		analyzeThreshold:  TierAnalyzeThreshold,
		criticalThreshold: TierCriticalThreshold,
	}
}

// fnvHash32a is an allocation-free FNV-1a hash used to pick a process's shard.
func fnvHash32a(s string) uint32 {
	const (
		offset = uint32(2166136261)
		prime  = uint32(16777619)
	)
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}

func (fot *FileOperationTracker) shardFor(processGuid string) *velocityShard {
	return &fot.shards[fnvHash32a(processGuid)&(velocityShardCount-1)]
}

// SetThresholds overrides the per-minute tier thresholds. Non-positive values are
// ignored so an unset/zero config key cannot collapse a tier to 0. Call during
// construction, before the tracker is shared with detection goroutines (not safe for
// concurrent use with DetectAnomalousActivity).
func (fot *FileOperationTracker) SetThresholds(monitor, analyze, critical float64) {
	if monitor > 0 {
		fot.monitorThreshold = monitor
	}
	if analyze > 0 {
		fot.analyzeThreshold = analyze
	}
	if critical > 0 {
		fot.criticalThreshold = critical
	}
}

// AddOperation adds a file operation and removes expired ones from its shard.
// The prune predicate is purely per-op-timestamp (no cross-process coupling), so partitioning
// by ProcessGuid yields counts identical to the former global slice.
func (fot *FileOperationTracker) AddOperation(op FileOperation) {
	sh := fot.shardFor(op.ProcessGuid)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	// Remove operations outside window
	cutoff := time.Now().Add(-fot.windowSize)
	validOps := make([]FileOperation, 0, len(sh.ops)+1)

	for _, existingOp := range sh.ops {
		if existingOp.Timestamp.After(cutoff) {
			validOps = append(validOps, existingOp)
		}
	}

	sh.ops = append(validOps, op)
}

// GetVelocity calculates files per minute for a specific process.
// Mirrors the original: counts the process's operations in its (already-pruned) shard and
// divides by the fixed window — no read-time re-filtering.
func (fot *FileOperationTracker) GetVelocity(processGuid string) float64 {
	sh := fot.shardFor(processGuid)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	count := 0
	for _, op := range sh.ops {
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

	if velocity >= fot.criticalThreshold {
		return VelocityTierCritical, velocity, "CRITICAL"
	} else if velocity >= fot.analyzeThreshold {
		return VelocityTierAnalyze, velocity, "ANALYZE"
	} else if velocity >= fot.monitorThreshold {
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
	sh := fot.shardFor(processGuid)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	count := 0
	for _, op := range sh.ops {
		if op.ProcessGuid == processGuid {
			count++
		}
	}
	return count
}

// GetRecentOperations returns recent operations for a process
func (fot *FileOperationTracker) GetRecentOperations(processGuid string, limit int) []FileOperation {
	sh := fot.shardFor(processGuid)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	result := make([]FileOperation, 0, limit)
	for i := len(sh.ops) - 1; i >= 0 && len(result) < limit; i-- {
		if sh.ops[i].ProcessGuid == processGuid {
			result = append(result, sh.ops[i])
		}
	}

	return result
}

// GetOperationsByType counts operations by type for a process
func (fot *FileOperationTracker) GetOperationsByType(processGuid string) map[string]int {
	sh := fot.shardFor(processGuid)
	sh.mu.RLock()
	defer sh.mu.RUnlock()

	counts := make(map[string]int)
	for _, op := range sh.ops {
		if op.ProcessGuid == processGuid {
			counts[op.Operation]++
		}
	}
	return counts
}

// Cleanup removes all expired operations across every shard, returning the total removed.
func (fot *FileOperationTracker) Cleanup() int {
	cutoff := time.Now().Add(-fot.windowSize)
	removed := 0

	for i := range fot.shards {
		sh := &fot.shards[i]
		sh.mu.Lock()
		validOps := make([]FileOperation, 0, len(sh.ops))
		for _, op := range sh.ops {
			if op.Timestamp.After(cutoff) {
				validOps = append(validOps, op)
			}
		}
		removed += len(sh.ops) - len(validOps)
		sh.ops = validOps
		sh.mu.Unlock()
	}

	return removed
}
