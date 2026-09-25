//go:build darwin && cgo

package guestuser

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxExecEnvelope = 1024 * 1024
const execHeaderBytes = 4
const standardFileDescriptors = 3

type execRequest struct {
	User        User              `json:"user"`
	Name        string            `json:"name"`
	Args        []string          `json:"args"`
	Environment map[string]string `json:"environment"`
	Workdir     string            `json:"workdir"`
}

// command enters the existing user's Aqua context without selecting its desktop.
// The fixed privileged helper receives command data through the stdin prefix,
// permanently drops privilege, and replaces itself with the workload.
func (n *nativeBackend) command(
	ctx context.Context, user User, name string, args []string, environment map[string]string, workdir string,
) (*exec.Cmd, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := validateCommand(user, name, args, environment); err != nil {
		return nil, nil, err
	}
	if workdir == "" {
		workdir = filepath.Join(user.Home, "workspace")
	}
	if strings.ContainsRune(workdir, 0) {
		return nil, nil, ErrInvalid
	}
	request := execRequest{User: user, Name: name, Args: args, Environment: environment, Workdir: workdir}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	defer clear(data)
	if len(data) > maxExecEnvelope {
		return nil, nil, ErrInvalid
	}
	prefix := make([]byte, execHeaderBytes+len(data))
	binary.BigEndian.PutUint32(prefix[:4], uint32(len(data)))
	copy(prefix[4:], data)
	// #nosec G204 -- The root helper path was resolved and protected when this backend started.
	cmd := exec.CommandContext(ctx, "/bin/launchctl", "asuser", strconv.FormatUint(uint64(user.UID), 10),
		n.executable, "guest-user-exec")
	cmd.Env = []string{"PATH=" + systemPath, nativeLocale}
	return cmd, prefix, nil
}

func validateCommand(user User, name string, args []string, env map[string]string) error {
	if _, err := requestID(user.ID); err != nil {
		return err
	}
	if !strings.HasPrefix(user.Username, UsernamePrefix) || user.Home != filepath.Join("/Users", user.Username) ||
		user.UID < 501 || user.UID >= 65534 || user.GID != 20 {
		return ErrInvalid
	}
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsRune(name, 0) || len(args) > 4096 || len(env) > 256 {
		return ErrInvalid
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return ErrInvalid
		}
	}
	for key, value := range env {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, 0) {
			return ErrInvalid
		}
	}
	return nil
}

func userEnvironment(user User, additions map[string]string) []string {
	values := map[string]string{
		"PATH": "/usr/local/bin:/opt/homebrew/bin:" + systemPath, "LANG": "en_US.UTF-8", "SHELL": "/bin/zsh",
	}
	maps.Copy(values, additions)
	// These identify the selected account and must never inherit daemon values.
	maps.Copy(values, map[string]string{
		"HOME": user.Home, "CFFIXED_USER_HOME": user.Home, "USER": user.Username, "LOGNAME": user.Username,
		"TMPDIR": user.TempDirectory + "/", "XDG_CACHE_HOME": user.Home + "/.cache",
		"XDG_CONFIG_HOME": user.Home + "/.config", "XDG_DATA_HOME": user.Home + "/.local/share",
	})
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(values))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment
}

func readExec(input io.Reader) (execRequest, error) {
	var request execRequest
	var header [4]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return request, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxExecEnvelope {
		return request, ErrInvalid
	}
	data := make([]byte, int(size))
	defer clear(data)
	if _, err := io.ReadFull(input, data); err != nil {
		return request, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return request, ErrInvalid
	}
	return request, nil
}

func RunExec(input io.Reader) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("guest user executor requires root")
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	request, err := readExec(input)
	if err != nil {
		return err
	}
	if err := validateCommand(request.User, request.Name, request.Args, request.Environment); err != nil {
		return err
	}
	if err := accountOperation(request.User, "", "verify"); err != nil {
		return err
	}
	if err := checkTemp(request.User); err != nil {
		return err
	}
	if err := dropCredentials(request.User); err != nil {
		return err
	}
	if err := os.Chdir(request.Workdir); err != nil {
		return err
	}
	environment := userEnvironment(request.User, request.Environment)
	os.Clearenv()
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	name, err := exec.LookPath(request.Name)
	if err != nil {
		return err
	}
	// #nosec G204 -- The workload is selected only after permanently dropping root and supplementary groups.
	return syscall.Exec(name, append([]string{request.Name}, request.Args...), environment)
}

// Darwin credential changes are process-wide. This function is only called in
// a dedicated helper that exits or execs, never in the multithreaded daemon.
func dropCredentials(user User) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || user.UID < 501 || user.UID >= 65534 || user.GID != 20 {
		return ErrInvalid
	}
	// Only stdin/stdout/stderr belong to the eventual workload. Go's runtime
	// owns other close-on-exec descriptors; protect inherited descriptors too.
	dir, err := os.Open("/dev/fd")
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, name := range names {
		descriptor, err := strconv.Atoi(name)
		if err != nil {
			return err
		}
		if descriptor < standardFileDescriptors {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
		if errors.Is(err, syscall.EBADF) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = unix.FcntlInt(uintptr(descriptor), unix.F_SETFD, flags|unix.FD_CLOEXEC)
		if err != nil && !errors.Is(err, syscall.EBADF) {
			return err
		}
	}
	// A singleton group list also opts out of Darwin's external group resolver.
	if err := syscall.Setgroups([]int{int(user.GID)}); err != nil {
		return err
	}
	if err := syscall.Setgid(int(user.GID)); err != nil {
		return err
	}
	if err := syscall.Setuid(int(user.UID)); err != nil {
		return err
	}
	if os.Getuid() != int(user.UID) || os.Geteuid() != int(user.UID) ||
		os.Getgid() != int(user.GID) || os.Getegid() != int(user.GID) {
		return errors.New("guest credential drop failed")
	}
	groups, err := syscall.Getgroups()
	if err != nil {
		return err
	}
	if len(groups) != 1 || groups[0] != int(user.GID) {
		return errors.New("guest supplementary group drop failed")
	}
	if err := syscall.Setuid(0); !errors.Is(err, syscall.EPERM) {
		return errors.New("guest executor retained root identity")
	}
	return nil
}
