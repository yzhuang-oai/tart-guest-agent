//nolint:testpackage // Exercise the file operations without launching an agent.
package command

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGuestFileWriteParentsAndOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "parent", "child", "file")
	count, err := writeGuestFile(path, 0, true, bytes.NewReader([]byte("abcdef")))
	if err != nil || count != 6 {
		t.Fatalf("create: %d %v", count, err)
	}
	if _, err := writeGuestFile(path, 2, false, bytes.NewReader([]byte{0, 'Z'})); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := readGuestFile(path, 1, 3, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), []byte{'b', 0, 'Z'}) {
		t.Fatalf("read offset produced %q", out.Bytes())
	}
	// #nosec G304 -- This path belongs to the test's temporary directory.
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, []byte{'a', 'b', 0, 'Z', 'e', 'f'}) {
		t.Fatalf("write unexpectedly truncated: %q %v", data, err)
	}
	for _, check := range []struct {
		path string
		mode os.FileMode
	}{{path, 0600}, {filepath.Dir(path), 0700}} {
		info, err := os.Stat(check.path)
		if err != nil || info.Mode().Perm() != check.mode {
			t.Fatalf("file permissions differ: %s %v", check.path, err)
		}
	}
}

func TestGuestFileWriteRejectsOversizeBeforeTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeGuestFile(path, 0, true, bytes.NewReader(make([]byte, guestFileChunk+1))); err == nil {
		t.Fatal("accepted oversized stdin")
	}
	// #nosec G304 -- This path belongs to the test's temporary directory.
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("oversized write changed file: %q %v", data, err)
	}
}

func TestGuestFileReadSentinelAndEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	offset, limit, err := fileReadNumbers("1", "1048577")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := readGuestFile(path, offset, limit, &out); err != nil || out.String() != "bc" {
		t.Fatalf("EOF read: %q %v", out.String(), err)
	}
	if _, _, err := fileReadNumbers("0", "1048578"); err == nil {
		t.Fatal("accepted oversized read limit")
	}
	if _, _, err := fileReadNumbers("-1", "1"); err == nil {
		t.Fatal("accepted negative offset")
	}
}
