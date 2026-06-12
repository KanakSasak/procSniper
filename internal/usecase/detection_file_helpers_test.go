package usecase

import (
	"fmt"
	"testing"
	"time"

	"procSniper/internal/domain"
)

// TestDetectionService_RecordMLFeatures pins the deduplicated dir/ext/delete counter
// accumulation extracted from the three file-event methods (Phase 6 S2).
func TestDetectionService_RecordMLFeatures(t *testing.T) {
	ds := newMLTestDetectionService()
	ev := func(target string) *domain.MonitorEvent {
		return &domain.MonitorEvent{
			Timestamp: time.Now(), ProcessGuid: "guid-feat", ProcessID: 7,
			Image: `C:\x.exe`, TargetFile: target,
		}
	}
	ds.recordMLFeatures(ev(`C:\a\f.docx.locked`), "create")
	ds.recordMLFeatures(ev(`C:\b\g.pdf`), "modify")
	ds.recordMLFeatures(ev(`C:\a\h.dat`), "delete")

	f := ds.ExtractFeatureVector("guid-feat")
	// feature[3] = directory_count: distinct dirs C:\a and C:\b → 2
	if f[3] != 2 {
		t.Errorf("directory_count = %v, want 2", f[3])
	}
	// feature[4] = file_delete_count: one delete
	if f[4] != 1 {
		t.Errorf("file_delete_count = %v, want 1", f[4])
	}
}

// TestDetectionService_RansomNoteTracking pins the .txt ransom-note accumulation extracted
// into trackRansomNote (Phase 6 S4): TxtFileCount increments per .txt, directories dedupe,
// and both the create path (fullCreatePath=true) and the modify/rename path count.
func TestDetectionService_RansomNoteTracking(t *testing.T) {
	ds := newMLTestDetectionService()
	mk := func(dir string, n int) *domain.MonitorEvent {
		return &domain.MonitorEvent{
			Timestamp: time.Now(), ProcessGuid: "guid-note", ProcessID: 9,
			Image: `C:\x.exe`, TargetFile: fmt.Sprintf(`%s\note%d.txt`, dir, n),
		}
	}
	// 5 .txt files across 3 distinct directories via the create path.
	ds.trackRansomNote(mk(`C:\a`, 1), true)
	ds.trackRansomNote(mk(`C:\a`, 2), true)
	ds.trackRansomNote(mk(`C:\b`, 3), true)
	ds.trackRansomNote(mk(`C:\b`, 4), true)
	ds.trackRansomNote(mk(`C:\c`, 5), true)

	if txt, dirs := ds.TxtActivity("guid-note"); txt != 5 || dirs != 3 {
		t.Errorf("after create path: TxtActivity = (%d, %d), want (5, 3)", txt, dirs)
	}

	// The modify/rename path also counts (no scan trigger, but the counters advance).
	ds.trackRansomNote(mk(`C:\d`, 6), false)
	if txt, dirs := ds.TxtActivity("guid-note"); txt != 6 || dirs != 4 {
		t.Errorf("after rename path: TxtActivity = (%d, %d), want (6, 4)", txt, dirs)
	}
}
