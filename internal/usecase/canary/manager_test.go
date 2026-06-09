package canary

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"procSniper/internal/domain"
)

// --- fakes for the injected seams ---

type fakeEmitter struct {
	raised    []domain.Indicator
	evaluated int
	sent      []*domain.Alert
	score     int
}

func (f *fakeEmitter) RaiseIndicator(_, _ string, _ int, ind domain.Indicator) int {
	f.raised = append(f.raised, ind)
	return f.score
}
func (f *fakeEmitter) Evaluate(_, _ string, _ int) { f.evaluated++ }
func (f *fakeEmitter) SendAlert(a *domain.Alert)    { f.sent = append(f.sent, a) }

type fakeRelated struct{ ret []domain.RelatedProcess }

func (f fakeRelated) RelatedActors(_, _ string, _ time.Time) []domain.RelatedProcess { return f.ret }

type fakeTxt struct{ count, dirs int }

func (f fakeTxt) TxtActivity(_ string) (int, int) { return f.count, f.dirs }

func newTestManager() (*Manager, *fakeEmitter) {
	em := &fakeEmitter{}
	return NewManager(em, fakeRelated{}, fakeTxt{}), em
}

func TestManager_ResponseAction(t *testing.T) {
	m, _ := newTestManager()
	if got := m.ResponseAction(); got != "terminate" {
		t.Errorf("default ResponseAction = %q, want terminate", got)
	}
	m.SetResponseAction("suspend")
	if got := m.ResponseAction(); got != "suspend" {
		t.Errorf("ResponseAction = %q, want suspend", got)
	}
	m.SetResponseAction("garbage")
	if got := m.ResponseAction(); got != "terminate" {
		t.Errorf("invalid action should fall back to terminate, got %q", got)
	}
}

func TestManager_TrackLookupMatch(t *testing.T) {
	m, _ := newTestManager()
	const p = `C:\decoy\~canary.docx`
	m.Track(p, &domain.CanaryFile{Path: p, Extension: ".docx", OriginalEntropy: 1.0})

	if _, ok := m.IsCanaryFile(p); !ok {
		t.Fatal("tracked canary should be found by IsCanaryFile")
	}
	if m.Count() != 1 {
		t.Errorf("Count = %d, want 1", m.Count())
	}

	// Exact match.
	if cp, kind, ok := m.Match(p); !ok || kind != "exact" || cp != p {
		t.Errorf("exact Match = (%q,%q,%v), want (%q,exact,true)", cp, kind, ok, p)
	}
	// Renamed-prefix match (ransomware appends an extension in the same dir).
	if cp, kind, ok := m.Match(`C:\decoy\~canary.docx.CONTI`); !ok || kind != "renamed_prefix" || cp != p {
		t.Errorf("renamed Match = (%q,%q,%v), want canonical/renamed_prefix/true", cp, kind, ok)
	}
	// Unrelated path: no match.
	if _, _, ok := m.Match(`C:\other\file.txt`); ok {
		t.Error("unrelated path should not match")
	}
}

func TestManager_RecordResolveActor(t *testing.T) {
	m, _ := newTestManager()
	const p = `C:\decoy\~canary.docx`
	m.Track(p, &domain.CanaryFile{Path: p, Extension: ".docx"})

	m.RecordActor(&domain.MonitorEvent{
		TargetFile:  p,
		ProcessID:   1234,
		ProcessGuid: "guid-x",
		Image:       `C:\evil.exe`,
		Timestamp:   time.Now(),
	}, "FILE_MODIFIED")

	actor, ok := m.ResolveActor(p, "")
	if !ok {
		t.Fatal("expected to resolve the recorded actor")
	}
	if actor.ProcessGuid != "guid-x" || actor.ProcessID != 1234 {
		t.Errorf("resolved actor = %+v, want guid-x/1234", actor)
	}

	// An event on a non-canary path records nothing.
	m.RecordActor(&domain.MonitorEvent{TargetFile: `C:\tmp\x.txt`, ProcessGuid: "g2"}, "FILE_MODIFIED")
	if _, ok := m.ResolveActor(`C:\tmp\x.txt`, ""); ok {
		t.Error("non-canary event should not be recorded as an actor")
	}
}

// The txt-correlation branch raises a canary-compromise indicator and evaluates, without
// touching the filesystem (no entropy analysis on this path).
func TestManager_HandleWriteOrRename_TxtCorrelation(t *testing.T) {
	em := &fakeEmitter{}
	m := NewManager(em, fakeRelated{}, fakeTxt{count: 3, dirs: 2})
	const p = `C:\decoy\~canary.docx`
	m.Track(p, &domain.CanaryFile{Path: p, Extension: ".docx", OriginalEntropy: 1.0})

	if !m.HandleWriteOrRename(&domain.MonitorEvent{TargetFile: p, ProcessGuid: "g", Image: "e.exe", ProcessID: 7}) {
		t.Fatal("write on a tracked canary should return true")
	}
	if len(em.raised) != 1 || em.raised[0].Type != domain.IndicatorCanaryCompromised {
		t.Errorf("expected one IndicatorCanaryCompromised raised, got %+v", em.raised)
	}
	if em.evaluated != 1 {
		t.Errorf("expected Evaluate called once, got %d", em.evaluated)
	}
}

func TestManager_HandleWriteOrRename_NotACanary(t *testing.T) {
	m, em := newTestManager()
	if m.HandleWriteOrRename(&domain.MonitorEvent{TargetFile: `C:\tmp\not-a-canary.txt`}) {
		t.Error("non-canary target should return false")
	}
	if len(em.raised) != 0 || em.evaluated != 0 {
		t.Error("non-canary target must not raise/evaluate")
	}
}

// CheckFiles detects a deleted canary, emits one CRITICAL alert, and latches so a repeat
// scan does not re-emit. Uses a real temp file (benign, dummy content).
func TestManager_CheckFiles_DeletedCanaryAlerts(t *testing.T) {
	em := &fakeEmitter{}
	m := NewManager(em, fakeRelated{}, fakeTxt{})

	dir := t.TempDir()
	p := filepath.Join(dir, "decoy.docx")
	if err := os.WriteFile(p, []byte("benign low-entropy canary content............"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.Track(p, &domain.CanaryFile{Path: p, Extension: ".docx", FileSize: 45, OriginalEntropy: 1.0})

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if !m.CheckFiles() {
		t.Fatal("CheckFiles should report compromise after canary deletion")
	}
	if len(em.sent) != 1 || em.sent[0].Severity != domain.ThreatCritical {
		t.Fatalf("expected one CRITICAL alert sent, got %+v", em.sent)
	}

	// Latched: a second scan must not re-emit for the same canary.
	em.sent = nil
	m.CheckFiles()
	if len(em.sent) != 0 {
		t.Errorf("latched canary should suppress the repeat alert, got %d", len(em.sent))
	}
}

// Response action drives the indicator points on the txt-correlation path.
func TestManager_HandleWriteOrRename_AlertOnlyZeroPoints(t *testing.T) {
	em := &fakeEmitter{}
	m := NewManager(em, fakeRelated{}, fakeTxt{count: 5})
	m.SetResponseAction("alert_only")
	const p = `C:\decoy\~canary.docx`
	m.Track(p, &domain.CanaryFile{Path: p, Extension: ".docx"})

	m.HandleWriteOrRename(&domain.MonitorEvent{TargetFile: p, ProcessGuid: "g"})
	if len(em.raised) != 1 || em.raised[0].Points != 0 {
		t.Errorf("alert_only should raise an indicator with 0 points, got %+v", em.raised)
	}
}
