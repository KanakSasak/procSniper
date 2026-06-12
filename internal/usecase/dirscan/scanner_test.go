package dirscan

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"procSniper/internal/domain"
)

type fakeEmitter struct {
	raised    []domain.Indicator
	evaluated int
	score     int
}

func (f *fakeEmitter) RaiseIndicator(_, _ string, _ int, ind domain.Indicator) int {
	f.raised = append(f.raised, ind)
	return f.score
}
func (f *fakeEmitter) Evaluate(_, _ string, _ int) { f.evaluated++ }

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("benign data"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanner_ScanDirectory(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.locked"))
	mustWrite(t, filepath.Join(dir, "b.txt"))
	mustWrite(t, filepath.Join(dir, "c.locked"))

	s := NewScanner(&fakeEmitter{}, []string{".locked"})
	files, total := s.ScanDirectory(dir)
	if total != 3 {
		t.Errorf("total files = %d, want 3", total)
	}
	if len(files) != 2 {
		t.Errorf("ransomware files = %v, want 2 (.locked)", files)
	}
}

// A ransomware-extension file present in a scanned directory raises a single
// IndicatorRansomExtension and triggers evaluation.
func TestScanner_ScanDirectories_DetectsEncrypted(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "victim.docx.locked"))

	em := &fakeEmitter{}
	s := NewScanner(em, []string{".locked"})
	s.ScanDirectoriesForEncryptedFiles("g", `C:\evil.exe`, 1, []string{dir}, time.Now())

	if len(em.raised) != 1 || em.raised[0].Type != domain.IndicatorRansomExtension {
		t.Fatalf("expected one IndicatorRansomExtension, got %+v", em.raised)
	}
	if em.evaluated != 1 {
		t.Errorf("expected Evaluate once, got %d", em.evaluated)
	}
}

// Ransom-note-named .txt files WITHOUT any encrypted file must NOT raise an indicator
// (ransom notes alone are insufficient).
func TestScanner_ScanDirectories_NoteWithoutEncryptedDoesNotAlert(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "HOW_TO_DECRYPT.txt"))

	em := &fakeEmitter{}
	s := NewScanner(em, []string{".locked"})
	s.ScanDirectoriesForEncryptedFiles("g", `C:\evil.exe`, 1, []string{dir}, time.Now())

	if len(em.raised) != 0 || em.evaluated != 0 {
		t.Errorf("ransom note without encrypted files must not alert; raised=%v eval=%d", em.raised, em.evaluated)
	}
}

// The progressive scan dedups per directory: a second call while one is in progress is a
// no-op (returns false) so the caller can preserve its skip-the-rest behavior.
func TestScanner_ScanDeletedFileDir_Dedup(t *testing.T) {
	dir := t.TempDir()
	s := NewScanner(&fakeEmitter{}, []string{".locked"})
	ev := &domain.MonitorEvent{TargetFile: filepath.Join(dir, "x.txt")}

	if !s.ScanDeletedFileDir(ev) {
		t.Fatal("first ScanDeletedFileDir should start a scan (true)")
	}
	if s.ScanDeletedFileDir(ev) {
		t.Error("second ScanDeletedFileDir for the same directory should dedup (false)")
	}
}
