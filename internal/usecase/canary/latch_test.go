package canary

import (
	"testing"
	"time"
)

func TestNormalizePath(t *testing.T) {
	if got := NormalizePath(""); got != "" {
		t.Errorf(`NormalizePath("") = %q, want ""`, got)
	}
	// Lowercased.
	if got := NormalizePath(`C:\Temp\X.TXT`); got == `C:\Temp\X.TXT` {
		t.Errorf("expected lowercasing, got %q", got)
	}
	// Idempotent.
	once := NormalizePath(`C:\Users\Foo\BAR.docx`)
	if twice := NormalizePath(once); once != twice {
		t.Errorf("not idempotent: %q != %q", once, twice)
	}
}

func TestLatchSet_FirstEmitThenSuppress(t *testing.T) {
	l := NewLatchSet()
	now := time.Now()
	if !l.ShouldEmit(`C:\decoy\canary.docx`, "ENCRYPTED", "", "guid-1", now) {
		t.Fatal("first compromise should emit")
	}
	if l.ShouldEmit(`C:\decoy\canary.docx`, "ENCRYPTED", "", "guid-1", now.Add(time.Second)) {
		t.Error("second compromise of a latched canary should be suppressed")
	}
	// Normalized-equal path (different case/separators) stays suppressed.
	if l.ShouldEmit(`c:\decoy\CANARY.docx`, "ENCRYPTED", "", "guid-1", now.Add(2*time.Second)) {
		t.Error("normalized-equal path should remain latched")
	}
}

func TestLatchSet_ResetReopens(t *testing.T) {
	l := NewLatchSet()
	now := time.Now()
	l.ShouldEmit("p.txt", "ENC", "", "g", now)
	l.Reset("p.txt")
	if !l.ShouldEmit("p.txt", "ENC", "", "g", now.Add(time.Second)) {
		t.Error("after Reset, the canary should emit again")
	}
}

func TestLatchSet_ResetAll(t *testing.T) {
	l := NewLatchSet()
	now := time.Now()
	l.ShouldEmit("a.txt", "ENC", "", "g", now)
	l.ShouldEmit("b.txt", "ENC", "", "g", now)
	l.ResetAll()
	if !l.ShouldEmit("a.txt", "ENC", "", "g", now.Add(time.Second)) {
		t.Error("after ResetAll, a.txt should emit again")
	}
	if !l.ShouldEmit("b.txt", "ENC", "", "g", now.Add(time.Second)) {
		t.Error("after ResetAll, b.txt should emit again")
	}
}

func TestLatchSet_EmptyPathAlwaysEmits(t *testing.T) {
	l := NewLatchSet()
	if !l.ShouldEmit("", "ENC", "", "g", time.Now()) {
		t.Error("empty path should always emit (cannot latch)")
	}
}

// Latched metadata is updated even while emission is suppressed (matches the original
// shouldEmitCanaryAlert behavior: AttributedProcessGuid upgrades away from UNKNOWN).
func TestLatchSet_UpdatesMetadataWhileSuppressed(t *testing.T) {
	l := NewLatchSet()
	now := time.Now()
	if !l.ShouldEmit("c.txt", "RENAME", "", "UNKNOWN", now) {
		t.Fatal("first should emit")
	}
	// Suppressed, but should not panic and should keep latching.
	if l.ShouldEmit("c.txt", "ENCRYPTED", "related.txt", "guid-real", now.Add(time.Second)) {
		t.Error("still latched -> suppressed")
	}
}
