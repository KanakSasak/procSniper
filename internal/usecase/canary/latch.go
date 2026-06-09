// Package canary holds the self-contained pieces of procSniper's honeypot (canary)
// detection subsystem, extracted from DetectionService as the first slice of the Phase 6
// decomposition (see docs/PHASE6-DECOMPOSITION-PLAN.md).
//
// It lives in its own package so its logic is unit-testable in isolation — the usecase
// package's test binary is blocked by endpoint AV in some dev environments, whereas this
// package's test binary runs cleanly.
package canary

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// NormalizePath canonicalizes a canary file path for use as a map key (lowercased and
// cleaned). It returns "" for an empty input.
func NormalizePath(path string) string {
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.Clean(path))
}

// CompromiseState tracks latched compromise state to avoid repeated periodic alerts for
// an already-reported canary.
type CompromiseState struct {
	FirstSeen             time.Time
	LastSeen              time.Time
	CompromiseType        string
	RelatedPath           string
	AttributedProcessGuid string
	Latched               bool
}

// LatchSet is the canary alert-dedup state machine: the first compromise of a canary
// latches and emits; later observations update metadata but suppress re-emission until
// the latch is reset (e.g. on canary recreation). Safe for concurrent use.
type LatchSet struct {
	mu     sync.Mutex
	states map[string]CompromiseState
}

// NewLatchSet returns an empty LatchSet.
func NewLatchSet() *LatchSet {
	return &LatchSet{states: make(map[string]CompromiseState)}
}

// ResetAll clears every latch (e.g. on a full canary re-setup).
func (l *LatchSet) ResetAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.states)
}

// Reset clears the latch for one canary path so a fresh compromise can alert again.
func (l *LatchSet) Reset(path string) {
	key := NormalizePath(path)
	if key == "" {
		return
	}
	l.mu.Lock()
	delete(l.states, key)
	l.mu.Unlock()
}

// ShouldEmit reports whether a compromise alert should be emitted for path. The first
// observation latches and returns true; subsequent observations update metadata and
// return false until Reset. A zero observedAt defaults to time.Now().
func (l *LatchSet) ShouldEmit(path, compromiseType, relatedPath, attributedProcessGuid string, observedAt time.Time) bool {
	key := NormalizePath(path)
	if key == "" {
		return true
	}

	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if state, exists := l.states[key]; exists && state.Latched {
		state.LastSeen = observedAt
		if compromiseType != "" {
			state.CompromiseType = compromiseType
		}
		if relatedPath != "" {
			state.RelatedPath = relatedPath
		}
		if attributedProcessGuid != "" && !strings.EqualFold(attributedProcessGuid, "UNKNOWN") {
			state.AttributedProcessGuid = attributedProcessGuid
		}
		l.states[key] = state
		return false
	}

	l.states[key] = CompromiseState{
		FirstSeen:             observedAt,
		LastSeen:              observedAt,
		CompromiseType:        compromiseType,
		RelatedPath:           relatedPath,
		AttributedProcessGuid: attributedProcessGuid,
		Latched:               true,
	}
	return true
}
