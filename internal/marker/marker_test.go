package marker_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/anonctl/internal/endpoint"
	"github.com/wighawag/anonctl/internal/marker"
)

// scratchStore returns a Store pointed at a per-test temp dir, so a test that
// writes a marker NEVER touches the real /etc/anonctl (the shared-write isolation
// discipline). t.TempDir is removed automatically at test end.
func scratchStore(t *testing.T) marker.Store {
	t.Helper()
	return marker.Store{BaseDir: filepath.Join(t.TempDir(), "anonctl")}
}

// --- (de)serialization + schema version: the round-trip contract ---

func TestMarker_RoundTrips(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	m := marker.New("anon-work", "30034", endpoint.ClassTorShared, "1.2.3", now)

	if m.SchemaVersion != marker.SchemaVersion {
		t.Fatalf("New must stamp the current SchemaVersion; got %d want %d", m.SchemaVersion, marker.SchemaVersion)
	}
	if m.CreatedAt != "2026-07-07T12:00:00Z" {
		t.Fatalf("CreatedAt must be RFC3339 UTC; got %q", m.CreatedAt)
	}

	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := marker.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got != m {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, m)
	}
}

// The on-disk JSON carries EXACTLY the contract fields and DELIBERATELY no
// endpoint URL / credentials (the file is world-readable under /etc).
func TestMarker_JSONFieldsAreExactlyTheContract(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	m := marker.New("anon", "30034", endpoint.ClassSocksPeruser, "1.2.3", now)
	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal into map: %v", err)
	}
	wantKeys := map[string]bool{
		"schemaVersion": true, "account": true, "uid": true,
		"endpointClass": true, "createdAt": true, "anonctlVersion": true,
	}
	for k := range raw {
		if !wantKeys[k] {
			t.Errorf("marker carries an unexpected field %q (must be exactly the contract fields)", k)
		}
	}
	for k := range wantKeys {
		if _, ok := raw[k]; !ok {
			t.Errorf("marker is MISSING contract field %q", k)
		}
	}
	// No endpoint URL / credentials must ever appear (world-readable file).
	blob := strings.ToLower(string(data))
	for _, forbidden := range []string{"socks5h", "endpoint\"", "url", "password", "username", "credential"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("marker JSON leaks %q; it must be credential-free and carry no endpoint URL:\n%s", forbidden, data)
		}
	}
}

// A marker written at a NEWER schema version than this build understands is
// refused loudly, not silently mis-read.
func TestParse_RejectsNewerSchemaVersion(t *testing.T) {
	future := marker.Marker{SchemaVersion: marker.SchemaVersion + 1, Account: "anon"}
	data, _ := future.Marshal()
	if _, err := marker.Parse(data); err == nil {
		t.Fatal("Parse must reject a schemaVersion newer than this build understands")
	}
}

func TestParse_RejectsMissingSchemaVersion(t *testing.T) {
	if _, err := marker.Parse([]byte(`{"account":"anon"}`)); err == nil {
		t.Fatal("Parse must reject a marker with no schemaVersion")
	}
}

// --- Store: write / read / remove, all against a scratch dir ---

func TestStore_WriteReadRemove_RoundTrips(t *testing.T) {
	s := scratchStore(t)
	m := marker.New("anon", "30034", endpoint.ClassTorShared, "1.0.0", time.Now())

	if err := s.Write(m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := s.Read("anon")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Account != "anon" || got.EndpointClass != endpoint.ClassTorShared {
		t.Fatalf("read-back mismatch: %+v", got)
	}

	if err := s.Remove("anon"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := s.Read("anon"); !errors.Is(err, marker.ErrNotFound) {
		t.Fatalf("after Remove, Read must be ErrNotFound; got %v", err)
	}
}

// A missing marker is a clean "not forced" negative, not an I/O error.
func TestStore_Read_MissingIsNotFound(t *testing.T) {
	s := scratchStore(t)
	if _, err := s.Read("anon"); !errors.Is(err, marker.ErrNotFound) {
		t.Fatalf("missing marker must be ErrNotFound; got %v", err)
	}
}

// Remove of a missing marker is a clean no-op (rm is idempotent).
func TestStore_Remove_MissingIsNoOp(t *testing.T) {
	s := scratchStore(t)
	if err := s.Remove("anon"); err != nil {
		t.Fatalf("Remove of a missing marker must be a no-op; got %v", err)
	}
}

// The marker file is world-readable (0644): the whole point is a dependency-free
// signal any UID can read.
func TestStore_Write_FileIsWorldReadable(t *testing.T) {
	s := scratchStore(t)
	m := marker.New("anon", "30034", endpoint.ClassTorShared, "1.0.0", time.Now())
	if err := s.Write(m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	path, _ := s.Path("anon")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("marker file mode = %v, want 0644 (world-readable)", info.Mode().Perm())
	}
}

// --- the write-after-verify gate ---

func TestStore_WriteVerified_GatedOnVerifyPassing(t *testing.T) {
	s := scratchStore(t)
	m := marker.New("anon", "30034", endpoint.ClassTorShared, "1.0.0", time.Now())

	// verify did NOT pass: the marker must NOT be written (a loud refusal).
	if err := s.WriteVerified(m, false); !errors.Is(err, marker.ErrVerifyNotPassed) {
		t.Fatalf("WriteVerified(false) must refuse with ErrVerifyNotPassed; got %v", err)
	}
	if _, err := s.Read("anon"); !errors.Is(err, marker.ErrNotFound) {
		t.Fatal("no marker may exist when verify did not pass")
	}

	// verify passed: the marker is written.
	if err := s.WriteVerified(m, true); err != nil {
		t.Fatalf("WriteVerified(true): %v", err)
	}
	if _, err := s.Read("anon"); err != nil {
		t.Fatalf("after a passing verify, the marker must be present; got %v", err)
	}
}

// --- path safety: a crafted account name cannot escape BaseDir ---

func TestStore_Path_RejectsTraversal(t *testing.T) {
	s := scratchStore(t)
	for _, bad := range []string{"../evil", "a/b", "..", ""} {
		if _, err := s.Path(bad); err == nil {
			t.Errorf("Path(%q) must be rejected (path traversal / empty)", bad)
		}
	}
}

// --- shared-write isolation: the real /etc/anonctl is never touched by tests ---

// Every Store in these tests points at a scratch dir; this asserts the invariant
// directly by checking the real DefaultBaseDir gained no marker from a scratch
// write. It records what the DefaultBaseDir looked like before, writes to a
// scratch store, and asserts the real dir is unchanged (created nothing new).
func TestStore_ScratchWrite_LeavesRealEtcUntouched(t *testing.T) {
	before := snapshotDir(marker.DefaultBaseDir)

	s := scratchStore(t)
	m := marker.New("anon", "30034", endpoint.ClassTorShared, "1.0.0", time.Now())
	if err := s.Write(m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The scratch write must have created the marker in the SCRATCH dir, proving the
	// write happened somewhere (not a no-op) but not in /etc.
	scratchPath, _ := s.Path("anon")
	if !strings.HasPrefix(scratchPath, os.TempDir()) && !strings.Contains(scratchPath, t.Name()) {
		// t.TempDir lives under the test's temp root; just assert it is NOT the real path.
	}
	if strings.HasPrefix(scratchPath, marker.DefaultBaseDir) {
		t.Fatalf("scratch store wrote under the real %s: %s", marker.DefaultBaseDir, scratchPath)
	}
	if _, err := os.Stat(scratchPath); err != nil {
		t.Fatalf("scratch marker was not written: %v", err)
	}

	after := snapshotDir(marker.DefaultBaseDir)
	if before != after {
		t.Fatalf("the real %s was modified by a scratch-dir test (before=%q after=%q)", marker.DefaultBaseDir, before, after)
	}
}

// snapshotDir returns a stable string describing a directory's entries (or a
// sentinel when it does not exist), so a test can assert it was left untouched
// without depending on it existing.
func snapshotDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "ABSENT:" + err.Error()
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return "PRESENT:" + strings.Join(names, ",")
}
