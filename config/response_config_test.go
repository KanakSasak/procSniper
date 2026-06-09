package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A missing/unreadable on-disk file must NOT error — it falls back to the compiled-in
// copy. This is the regression guard for the relative-path fragility (wrong CWD) and the
// former hard-fail on a missing file.
func TestLoadResponseConfig_EmbeddedFallbackOnMissingFile(t *testing.T) {
	rc, err := LoadResponseConfig(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("expected embedded fallback, got error: %v", err)
	}
	if rc == nil {
		t.Fatal("expected non-nil config from embedded fallback")
	}
	if len(rc.RansomwareExtensions) < 50 {
		t.Fatalf("embedded config should carry the full extension list, got %d", len(rc.RansomwareExtensions))
	}
}

// Empty path -> default path; in the test working directory that default does not exist,
// so this also exercises the embedded fallback and asserts normalization.
func TestLoadResponseConfig_NormalizesExtensionsLowercase(t *testing.T) {
	rc, err := LoadResponseConfig("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, ext := range rc.RansomwareExtensions {
		if ext != strings.ToLower(ext) {
			t.Errorf("extension %q is not lowercase-normalized", ext)
		}
	}
}

func TestResponseConfig_IsRansomwareExtension_CaseInsensitive(t *testing.T) {
	rc, err := LoadResponseConfig("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rc.RansomwareExtensions) == 0 {
		t.Fatal("no extensions loaded")
	}
	known := rc.RansomwareExtensions[0]
	if !rc.IsRansomwareExtension(strings.ToUpper(known)) {
		t.Errorf("IsRansomwareExtension(%q) should be true (case-insensitive)", strings.ToUpper(known))
	}
	if rc.IsRansomwareExtension(".definitely-not-a-real-ext-zzz") {
		t.Error("unexpected match for a non-ransomware extension")
	}
}

// An on-disk file must override the embedded default, and extensions must be normalized.
func TestLoadResponseConfig_FromDiskOverridesEmbedded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	dummy := `{
		"version": "test",
		"ransomware_extensions": [".DUMMYEXT"],
		"response_settings": {"critical_score_threshold": 42}
	}`
	if err := os.WriteFile(p, []byte(dummy), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	rc, err := LoadResponseConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rc.RansomwareExtensions) != 1 || rc.RansomwareExtensions[0] != ".dummyext" {
		t.Fatalf("expected on-disk override [.dummyext], got %v", rc.RansomwareExtensions)
	}
	if rc.ResponseSettings.CriticalScoreThreshold != 42 {
		t.Errorf("expected threshold 42 from disk, got %d", rc.ResponseSettings.CriticalScoreThreshold)
	}
}

// A malformed on-disk file must surface as an error, not be silently masked by the
// embedded fallback (fallback is for unreadable files only).
func TestLoadResponseConfig_MalformedDiskFileErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("{ this is not json "), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	if _, err := LoadResponseConfig(p); err == nil {
		t.Error("expected parse error for malformed on-disk config, got nil")
	}
}
