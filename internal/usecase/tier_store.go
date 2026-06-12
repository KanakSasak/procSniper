package usecase

import (
	"sync"
	"time"
)

// tierStore tracks which processes have reached each I/O-velocity tier. Within a
// maintenance window the maps are insert-only: a process that ever reaches a tier stays
// recorded until the janitor evicts it. This drives "emit the tier indicator once per
// process" in the velocity switch, plus the high-IO flag queries (IsHighIO/HighIOCount).
//
// Extracted from DetectionService (Phase 6, ProcessState). Behavior-preserving — same
// insert-only semantics as the original monitoredProcesses/analyzedProcesses/
// highIOProcesses maps — and consolidates their three RWMutexes into one.
type tierStore struct {
	mu        sync.RWMutex
	monitored map[string]time.Time // Tier 1 (10-29 files/min)
	analyzed  map[string]time.Time // Tier 2 (30-99 files/min)
	highIO    map[string]time.Time // Tier 3 (>=100 files/min)
}

func newTierStore() *tierStore {
	return &tierStore{
		monitored: make(map[string]time.Time),
		analyzed:  make(map[string]time.Time),
		highIO:    make(map[string]time.Time),
	}
}

// markNew stamps guid in m with the current time if absent, returning true on first insert.
func markNew(m map[string]time.Time, guid string) bool {
	if _, ok := m[guid]; ok {
		return false
	}
	m[guid] = time.Now()
	return true
}

// MarkMonitored/MarkAnalyzed/MarkHighIO record a process at the given tier, returning true
// only on the first observation (so the caller emits the tier indicator once).
func (s *tierStore) MarkMonitored(guid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return markNew(s.monitored, guid)
}

func (s *tierStore) MarkAnalyzed(guid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return markNew(s.analyzed, guid)
}

func (s *tierStore) MarkHighIO(guid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return markNew(s.highIO, guid)
}

// IsHighIO reports whether the process has ever reached the CRITICAL tier (insert-only).
func (s *tierStore) IsHighIO(guid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.highIO[guid]
	return ok
}

// HighIOCount returns the number of processes flagged at the CRITICAL tier.
func (s *tierStore) HighIOCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.highIO)
}

// EvictHighIO removes high-IO flags stamped before cutoff, returning the count removed.
func (s *tierStore) EvictHighIO(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return evictOlder(s.highIO, cutoff)
}

// EvictStale removes monitored + analyzed entries stamped before cutoff (the tiers with
// no other eviction path), returning the total removed.
func (s *tierStore) EvictStale(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return evictOlder(s.monitored, cutoff) + evictOlder(s.analyzed, cutoff)
}

func evictOlder(m map[string]time.Time, cutoff time.Time) int {
	removed := 0
	for guid, ts := range m {
		if ts.Before(cutoff) {
			delete(m, guid)
			removed++
		}
	}
	return removed
}
