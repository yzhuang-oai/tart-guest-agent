//go:build darwin && cgo

//nolint:testpackage // Inspect private framing and path validation without root execution.
package guestuser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedExecutableDoesNotRetainMutableSymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "helper")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	resolved, err := protectedExecutable(link)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "/usr/bin/true" {
		t.Fatalf("helper retained mutable startup path: %s", resolved)
	}
	native := &nativeBackend{executable: resolved}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	untrusted := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(untrusted, []byte("not a trusted helper"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(untrusted, link); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedExecutable(link); err == nil {
		t.Fatal("accepted replacement helper in an ordinary-user directory")
	}
	user := User{
		ID: "11111111-1111-4111-8111-111111111111", Username: "tga-test", Home: "/Users/tga-test", UID: 20000, GID: 20,
	}
	cmd, _, err := native.command(t.Context(), user, "unused", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Args[len(cmd.Args)-2] != resolved {
		t.Fatalf("command did not retain the original helper: %q", cmd.Args)
	}
}

func TestExecFramePreservesWorkloadInput(t *testing.T) {
	data := []byte(`{"name":"cat","args":[],"environment":{},"workdir":"/tmp","user":{}}`)
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	input := bytes.NewReader(bytes.Join([][]byte{frame, []byte("workload stdin\x00\n")}, nil))
	request, err := readExec(input)
	if err != nil || request.Name != "cat" {
		t.Fatalf("cannot decode helper request: %v", err)
	}
	rest, err := io.ReadAll(input)
	if err != nil || string(rest) != "workload stdin\x00\n" {
		t.Fatalf("helper consumed workload stdin: %q %v", rest, err)
	}
}

func TestExecFrameRejectsOversizedOrTruncatedInput(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxExecEnvelope+1)
	if _, err := readExec(bytes.NewReader(header[:])); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted oversized request: %v", err)
	}
	binary.BigEndian.PutUint32(header[:], 10)
	if _, err := readExec(bytes.NewReader(append(header[:], '{'))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("accepted incomplete request: %v", err)
	}
}

func TestUserEnvironmentDoesNotInheritController(t *testing.T) {
	t.Setenv("CONTROLLER_SECRET", "must-not-leak")
	t.Setenv("HOME", "/var/root")
	user := User{Username: "tga-example", Home: "/Users/tga-example", TempDirectory: "/private/var/folders/ab/example/T"}
	environment := strings.Join(userEnvironment(user, map[string]string{"HOME": "/var/root", "TEST_VALUE": "value"}), "\n")
	if strings.Contains(environment, "CONTROLLER_SECRET") || strings.Contains(environment, "/var/root") {
		t.Fatalf("controller identity leaked into user environment: %s", environment)
	}
	for _, expected := range []string{
		"HOME=" + user.Home, "USER=" + user.Username, "TMPDIR=" + user.TempDirectory + "/", "TEST_VALUE=value",
	} {
		if !strings.Contains(environment, expected) {
			t.Fatalf("missing user environment value %q", expected)
		}
	}
}
