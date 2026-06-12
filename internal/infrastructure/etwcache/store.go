// Package etwcache holds the in-process correlation caches the kernel ETW consumer maintains.
// Extracted from KernelETWConsumer (Phase 6) so this pure map+lock state is unit-testable off a
// live kernel feed — the consumer itself is cgo/ETW-bound and only build-verifiable. These are
// behavior-preserving relocations of the consumer's fileObjectCache and writeDebounce.
package etwcache

import (
	"sync"
	"time"
)

// FileObjectEntry stores the file path and opener's PID/GUID for cross-process correlation.
type FileObjectEntry struct {
	Path       string
	OpenerPID  uint32
	OpenerGUID string
}

// FileObjectStore maps FileObject/FileKey -> FileObjectEntry under one RWMutex. It mirrors the
// consumer's fileObjectCache verbatim: keyed by either the FileObject or the FileKey, dual-key
// lookup preferring FileKey, delete on handle close, and a size-capped leaked-handle safety net.
type FileObjectStore struct {
	mu    sync.RWMutex
	cache map[uint64]FileObjectEntry
}

func NewFileObjectStore() *FileObjectStore {
	return &FileObjectStore{cache: make(map[uint64]FileObjectEntry)}
}

// Put stores entry under key (a FileObject or a FileKey).
func (s *FileObjectStore) Put(key uint64, entry FileObjectEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = entry
}

// Path returns the cached path for fileKey (preferred) or fileObject, or "" if neither is cached.
func (s *FileObjectStore) Path(fileKey, fileObject uint64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fileKey != 0 {
		if e, ok := s.cache[fileKey]; ok {
			return e.Path
		}
	}
	if fileObject != 0 {
		if e, ok := s.cache[fileObject]; ok {
			return e.Path
		}
	}
	return ""
}

// Entry returns the full FileObjectEntry for fileKey (preferred) or fileObject.
func (s *FileObjectStore) Entry(fileKey, fileObject uint64) (FileObjectEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if fileKey != 0 {
		if e, ok := s.cache[fileKey]; ok {
			return e, true
		}
	}
	if fileObject != 0 {
		if e, ok := s.cache[fileObject]; ok {
			return e, true
		}
	}
	return FileObjectEntry{}, false
}

// Delete removes the entry for key (called when a file handle is closed).
func (s *FileObjectStore) Delete(key uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, key)
}

// Len returns the current cache size.
func (s *FileObjectStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cache)
}

// Trim is the leaked-handle safety net: if the cache exceeds maxSize it evicts ~half
// (map-iteration order, matching the original). Returns whether it trimmed and the new size.
func (s *FileObjectStore) Trim(maxSize int) (trimmed bool, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) <= maxSize {
		return false, len(s.cache)
	}
	count := 0
	for key := range s.cache {
		if count >= maxSize/2 {
			break
		}
		delete(s.cache, key)
		count++
	}
	return true, len(s.cache)
}

// writeDebounceKey identifies a write stream by (PID, FileKey).
type writeDebounceKey struct {
	PID     uint32
	FileKey uint64
}

// WriteDebouncer suppresses duplicate write events per (PID, FileKey) within a window. It
// mirrors the consumer's writeDebounce verbatim: ShouldEmit is a single atomic check-and-set
// under one lock (NOT a separate get+set), preserving the original critical section exactly.
type WriteDebouncer struct {
	mu     sync.Mutex
	last   map[writeDebounceKey]time.Time
	window time.Duration
}

func NewWriteDebouncer(window time.Duration) *WriteDebouncer {
	return &WriteDebouncer{last: make(map[writeDebounceKey]time.Time), window: window}
}

// ShouldEmit reports whether a write for (pid, fileKey) should be emitted at time now,
// recording now as the last-emit when it returns true. Atomic check-and-set under one lock.
func (d *WriteDebouncer) ShouldEmit(pid uint32, fileKey uint64, now time.Time) bool {
	key := writeDebounceKey{PID: pid, FileKey: fileKey}
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.last[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.last[key] = now
	return true
}

// Sweep removes entries last emitted before now-maxAge.
func (d *WriteDebouncer) Sweep(now time.Time, maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := now.Add(-maxAge)
	for key, ts := range d.last {
		if ts.Before(cutoff) {
			delete(d.last, key)
		}
	}
}
