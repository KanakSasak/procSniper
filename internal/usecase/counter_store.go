package usecase

import (
	"sync"
	"time"
)

// counterStore owns the per-process ProcessFileCounters map and its mutex. Extracted from
// DetectionService (Phase 6, ProcessState aggregate), mirroring tierStore: a small in-package
// type that consolidates the lock discipline so callers cannot hold a counters pointer outside
// the lock. fileCountersMux previously guarded only this map; that invariant is now structural
// — every access goes through Mutate/MutateMany/Read/Evict, which take s.mu and nothing else.
type counterStore struct {
	mu       sync.RWMutex
	counters map[string]*ProcessFileCounters // ProcessGuid -> counters
}

func newCounterStore() *counterStore {
	return &counterStore{counters: make(map[string]*ProcessFileCounters)}
}

// getOrInitLocked returns the counters for a GUID, initializing it (and backfilling the ML maps
// for pre-existing entries) if needed. PRECONDITION: s.mu is held for writing. This is the
// former DetectionService.getOrInitMLCounters body, unchanged.
func (s *counterStore) getOrInitLocked(processGuid string) *ProcessFileCounters {
	counters, exists := s.counters[processGuid]
	if !exists {
		counters = &ProcessFileCounters{
			TxtFileDirectories: make([]string, 0),
			DirectorySet:       make(map[string]struct{}),
			ExtensionCounts:    make(map[string]int),
			LastUpdated:        time.Now(),
		}
		s.counters[processGuid] = counters
	} else {
		// Ensure ML maps are initialized (for pre-existing counters created before ML)
		if counters.DirectorySet == nil {
			counters.DirectorySet = make(map[string]struct{})
		}
		if counters.ExtensionCounts == nil {
			counters.ExtensionCounts = make(map[string]int)
		}
	}
	return counters
}

// Mutate runs fn against the process's counters under the write lock, initializing the entry if
// absent. The pointer must not escape fn.
func (s *counterStore) Mutate(processGuid string, fn func(*ProcessFileCounters)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.getOrInitLocked(processGuid))
}

// MutateMany applies fn to each guid's counters under a SINGLE write-lock acquisition,
// preserving the original single-acquisition cost of the broadcast path.
func (s *counterStore) MutateMany(guids []string, fn func(*ProcessFileCounters)) {
	if len(guids) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, guid := range guids {
		fn(s.getOrInitLocked(guid))
	}
}

// Read runs fn against the process's counters under the read lock. fn receives (counters, ok)
// where ok reports whether an entry exists (counters is nil when ok is false). The pointer must
// not escape fn — fn copies out whatever it needs.
func (s *counterStore) Read(processGuid string, fn func(counters *ProcessFileCounters, ok bool)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counters, ok := s.counters[processGuid]
	fn(counters, ok)
}

// Evict removes entries whose LastUpdated is before cutoff, returning the count removed.
// Mirrors tierStore.EvictStale / mlEngine.EvictStale.
func (s *counterStore) Evict(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for guid, counters := range s.counters {
		if counters != nil && counters.LastUpdated.Before(cutoff) {
			delete(s.counters, guid)
			removed++
		}
	}
	return removed
}
