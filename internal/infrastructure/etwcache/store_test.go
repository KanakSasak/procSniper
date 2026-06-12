package etwcache

import (
	"testing"
	"time"
)

func TestFileObjectStore_DualKeyAndDelete(t *testing.T) {
	s := NewFileObjectStore()
	entry := FileObjectEntry{Path: `C:\victim\doc.txt`, OpenerPID: 42, OpenerGUID: "g-42"}

	// Cached under both FileObject (0xF0) and FileKey (0xABCD), as handleFileOpen does.
	s.Put(0xF0, entry)
	s.Put(0xABCD, entry)

	// Path prefers fileKey, falls back to fileObject.
	if got := s.Path(0xABCD, 0xF0); got != entry.Path {
		t.Errorf("Path(fileKey) = %q, want %q", got, entry.Path)
	}
	if got := s.Path(0, 0xF0); got != entry.Path {
		t.Errorf("Path(fileObject fallback) = %q, want %q", got, entry.Path)
	}
	if got := s.Path(0, 0); got != "" {
		t.Errorf("Path(0,0) = %q, want empty", got)
	}

	// Entry returns the full record + presence.
	if e, ok := s.Entry(0xABCD, 0); !ok || e.OpenerPID != 42 || e.OpenerGUID != "g-42" {
		t.Errorf("Entry = %+v, ok=%v; want full entry", e, ok)
	}
	if _, ok := s.Entry(0x9999, 0x8888); ok {
		t.Error("Entry for absent keys should report ok=false")
	}

	// Delete (on FileClose) removes the entry.
	s.Delete(0xF0)
	if got := s.Path(0, 0xF0); got != "" {
		t.Errorf("after Delete, Path(fileObject) = %q, want empty", got)
	}
	if got := s.Path(0xABCD, 0); got != entry.Path {
		t.Errorf("Delete(0xF0) must not affect the FileKey entry; got %q", got)
	}
}

func TestFileObjectStore_Trim(t *testing.T) {
	s := NewFileObjectStore()
	for i := 0; i < 10; i++ {
		s.Put(uint64(i), FileObjectEntry{Path: "p"})
	}
	if trimmed, _ := s.Trim(100); trimmed {
		t.Error("Trim under cap should be a no-op")
	}
	if got := s.Len(); got != 10 {
		t.Errorf("Len = %d, want 10", got)
	}
	trimmed, size := s.Trim(4) // over cap -> evict ~half (>= maxSize/2 deleted)
	if !trimmed {
		t.Error("Trim over cap should trim")
	}
	if size != s.Len() || size > 10 {
		t.Errorf("Trim returned size %d, Len %d", size, s.Len())
	}
}

func TestWriteDebouncer_ShouldEmit(t *testing.T) {
	d := NewWriteDebouncer(time.Second)
	base := time.Now()

	// First write for (pid,key) emits.
	if !d.ShouldEmit(7, 0xAA, base) {
		t.Error("first write should emit")
	}
	// Within the window -> suppressed.
	if d.ShouldEmit(7, 0xAA, base.Add(500*time.Millisecond)) {
		t.Error("write within 1s window should be suppressed")
	}
	// After the window -> emits again.
	if !d.ShouldEmit(7, 0xAA, base.Add(1500*time.Millisecond)) {
		t.Error("write after window should emit")
	}
	// Different key is independent.
	if !d.ShouldEmit(7, 0xBB, base.Add(500*time.Millisecond)) {
		t.Error("distinct FileKey should emit independently")
	}
	// Different PID is independent.
	if !d.ShouldEmit(8, 0xAA, base.Add(500*time.Millisecond)) {
		t.Error("distinct PID should emit independently")
	}
}

func TestWriteDebouncer_Sweep(t *testing.T) {
	d := NewWriteDebouncer(time.Second)
	base := time.Now()
	d.ShouldEmit(1, 1, base)                      // old
	d.ShouldEmit(2, 2, base.Add(20*time.Second))  // recent

	// Sweep at base+40s, maxAge 30s -> cutoff base+10s: (1,1) [base] removed, (2,2) [base+20s] kept.
	d.Sweep(base.Add(40*time.Second), 30*time.Second)

	// (1,1) was swept from the map -> behaves as new (emits).
	if !d.ShouldEmit(1, 1, base.Add(40*time.Second)) {
		t.Error("swept entry should behave as new (emit)")
	}
	// (2,2) survived the sweep -> a query within its 1s debounce window still suppresses,
	// proving its debounce timestamp persisted.
	if d.ShouldEmit(2, 2, base.Add(20*time.Second).Add(500*time.Millisecond)) {
		t.Error("retained entry within debounce window should still suppress")
	}
}
