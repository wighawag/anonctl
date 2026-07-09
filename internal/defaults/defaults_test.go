package defaults_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wighawag/anonctl/internal/defaults"
)

// TestReadMissingIsEmptyNotError: no defaults.json is the common case and reads as
// an empty Defaults, not an error.
func TestReadMissingIsEmptyNotError(t *testing.T) {
	s := defaults.Store{BaseDir: t.TempDir()}
	d, err := s.Read()
	if err != nil {
		t.Fatalf("Read on missing file: %v", err)
	}
	if len(d.AllowDirect) != 0 {
		t.Errorf("expected empty AllowDirect, got %v", d.AllowDirect)
	}
}

// TestReadAllowDirect: a defaults.json with allowDirect is parsed.
func TestReadAllowDirect(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "defaults.json"),
		[]byte(`{"allowDirect":["192.168.1.50:11434","10.0.0.0/8"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := defaults.Store{BaseDir: base}
	d, err := s.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(d.AllowDirect) != 2 || d.AllowDirect[0] != "192.168.1.50:11434" {
		t.Errorf("AllowDirect = %v", d.AllowDirect)
	}
}

// TestReadCorruptIsLoud: a malformed defaults.json is an error, never silently
// dropped (which would silently drop a configured exemption).
func TestReadCorruptIsLoud(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "defaults.json"), []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := defaults.Store{BaseDir: base}
	if _, err := s.Read(); err == nil {
		t.Fatalf("expected an error for corrupt defaults.json, got nil")
	}
}

// TestDefaultHomePresent: the directory-exists convention. Absent by default;
// present once the dir exists; a FILE by that name does NOT count.
func TestDefaultHomePresent(t *testing.T) {
	base := t.TempDir()
	s := defaults.Store{BaseDir: base}
	if s.DefaultHomePresent() {
		t.Errorf("default-home should be absent in a fresh base dir")
	}
	if err := os.Mkdir(s.DefaultHomeDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if !s.DefaultHomePresent() {
		t.Errorf("default-home should be present after mkdir")
	}
}

func TestDefaultHomeFileDoesNotCount(t *testing.T) {
	base := t.TempDir()
	s := defaults.Store{BaseDir: base}
	if err := os.WriteFile(s.DefaultHomeDir(), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s.DefaultHomePresent() {
		t.Errorf("a FILE named default-home must not switch seeding on")
	}
}
