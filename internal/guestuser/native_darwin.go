//go:build darwin && cgo

package guestuser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const systemPath = "/usr/bin:/bin:/usr/sbin:/sbin"
const loginwindowPath = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
const nativeLocale = "LANG=C"
const nativeOutputLimit = 4 * 1024 * 1024
const nativeDiagnosticLimit = 64 * 1024
const privateDirectoryMode = 0o700
const privateFileMode = 0o600
const pollInterval = 100 * time.Millisecond
const recoveryInterval = 500 * time.Millisecond
const passwordFileLimit = 514 // Up to 512 password bytes and a CRLF terminator.

type nativeBackend struct {
	controller               User
	passwordFile, executable string
}
type helperRequest struct {
	User        User    `json:"user"`
	Password    string  `json:"password,omitempty"`
	Prepared    []byte  `json:"prepared,omitempty"`
	Loginwindow process `json:"loginwindow"`
	Start       bool    `json:"start,omitempty"`
}

//nolint:ireturn // The manager shares this platform backend contract with test doubles.
func newBackend(config Config) (backend, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("guest user configuration requires a root daemon")
	}
	account, err := osuser.Lookup(config.ControllerUsername)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	if uid < 501 || uid >= 65534 || gid == 0 || gid == 80 {
		return nil, errors.New("controller must have an ordinary primary user and group")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = protectedExecutable(executable)
	if err != nil {
		return nil, err
	}
	passwordFile, err := filepath.EvalSymlinks(config.ControllerPasswordFile)
	if err != nil {
		return nil, err
	}
	if err := protectedPath(passwordFile, true); err != nil {
		return nil, err
	}
	if err := protectedPath("/Users", false); err != nil {
		return nil, err
	}
	if err := capabilities(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	accounts, err := run(ctx, nil, "/usr/bin/dscl", ".", "-list", "/Users")
	if err != nil {
		return nil, err
	}
	for name := range strings.FieldsSeq(string(accounts)) {
		if strings.HasPrefix(name, UsernamePrefix) {
			return nil, fmt.Errorf("%w: a previous daemon left managed accounts", ErrUnavailable)
		}
	}
	return &nativeBackend{
		controller:   User{Username: account.Username, Home: account.HomeDir, UID: uint32(uid), GID: uint32(gid)},
		passwordFile: passwordFile, executable: executable,
	}, nil
}

func protectedPath(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("guest user configuration needs canonical absolute paths")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !ownedBy(info, 0) || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("path is not protected from ordinary users: %s", current)
		}
		if current == path && private && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
			return errors.New("controller password file must be a root-private regular file")
		}
		if current == "/" {
			return nil
		}
	}
}

func protectedExecutable(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if err := protectedPath(resolved, false); err != nil {
		return "", err
	}
	return resolved, nil
}

func (n *nativeBackend) available(uid uint32) (bool, error) {
	if uid == n.controller.UID {
		return false, nil
	}
	_, err := osuser.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err == nil {
		return false, nil
	}
	var absent osuser.UnknownUserIdError
	if !errors.As(err, &absent) {
		return false, err
	}
	all, err := processes(uid)
	return len(all) == 0, err
}

type limitedOutput struct {
	bytes.Buffer

	limit int
}

func (b *limitedOutput) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		return 0, errors.New("native operation output exceeded its limit")
	}
	return b.Buffer.Write(data)
}

// A timed-out native call is never retried. The manager becomes unhealthy and
// the caller replaces the VM, even if macOS completes a queued operation later.
func run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload := bytes.Clone(input)
	// #nosec G204 -- Callers select fixed system commands or the validated root helper.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + systemPath, nativeLocale}
	cmd.Stdin = bytes.NewReader(payload)
	out, diagnostics := &limitedOutput{limit: nativeOutputLimit}, &limitedOutput{limit: nativeDiagnosticLimit}
	cmd.Stdout, cmd.Stderr = out, diagnostics
	if err := cmd.Start(); err != nil {
		clear(payload)
		return nil, err
	}
	done := make(chan error, 1)
	go func() { err := cmd.Wait(); clear(payload); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("native operation %s failed: %w", filepath.Base(name), err)
		}
		return out.Bytes(), ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *nativeBackend) helper(
	ctx context.Context, operation string, request helperRequest, bootstrap *process,
) ([]byte, error) {
	// #nosec G117 -- Credentials travel only over the child helper's stdin and buffers are cleared after use.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	name, args := n.executable, []string{"guest-user-helper", operation}
	if bootstrap != nil {
		name = "/bin/launchctl"
		args = append([]string{"bsexec", strconv.Itoa(int(bootstrap.PID)), n.executable}, args...)
	}
	return run(ctx, data, name, args...)
}

func (n *nativeBackend) create(ctx context.Context, user User, password string) (User, error) {
	if _, err := os.Lstat(user.Home); !errors.Is(err, os.ErrNotExist) {
		return User{}, errors.New("guest home already exists or cannot be checked")
	}
	if _, err := n.helper(ctx, "account-create", helperRequest{User: user, Password: password}, nil); err != nil {
		return User{}, err
	}
	if err := os.Mkdir(user.Home, privateDirectoryMode); err != nil {
		return User{}, err
	}
	if err := os.Chown(user.Home, int(user.UID), int(user.GID)); err != nil {
		return User{}, err
	}
	for _, suffix := range []string{
		"workspace", "tmp", ".cache", ".config", ".local", ".local/share", "Library",
		"Library/Group Containers", "Library/Caches", "Library/WebKit",
	} {
		path := filepath.Join(user.Home, suffix)
		if err := os.Mkdir(path, privateDirectoryMode); err != nil {
			return User{}, err
		}
		if err := os.Chown(path, int(user.UID), int(user.GID)); err != nil {
			return User{}, err
		}
	}
	for _, name := range []string{".skipbuddy", ".AppleSetupDone"} {
		// #nosec G304 -- Fixed marker names are created in this new managed user's home before first login.
		file, err := os.OpenFile(filepath.Join(user.Home, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
		if err != nil {
			return User{}, err
		}
		err = file.Chown(int(user.UID), int(user.GID))
		closeErr := file.Close()
		if err != nil {
			return User{}, err
		}
		if closeErr != nil {
			return User{}, closeErr
		}
	}
	data, err := n.helper(ctx, "temp-directory", helperRequest{User: user}, nil)
	if err != nil {
		return User{}, err
	}
	user.TempDirectory, err = filepath.EvalSymlinks(strings.TrimSpace(string(data)))
	if err != nil {
		return User{}, err
	}
	if err := checkTemp(user); err != nil {
		return User{}, err
	}
	if err := n.selectUser(ctx, user, password, true); err != nil {
		return User{}, err
	}
	if err := n.restore(ctx); err != nil {
		return User{}, err
	}
	return user, nil
}

func ownedDirectory(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedBy(info, uid) {
		return errors.New("guest directory ownership changed")
	}
	return nil
}
func ownedBy(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}
func checkTemp(user User) error {
	path := user.TempDirectory
	if !strings.HasPrefix(path, "/private/var/folders/") || filepath.Clean(path) != path ||
		filepath.Base(path) != "T" || len(strings.Split(strings.TrimPrefix(path, "/private/var/folders/"), "/")) != 3 {
		return errors.New("unexpected Darwin temporary directory")
	}
	if err := ownedDirectory(filepath.Dir(path), user.UID); err != nil {
		return err
	}
	return ownedDirectory(path, user.UID)
}
func matchingProcesses(uid uint32, path string) ([]process, error) {
	all, err := processes(uid)
	if err != nil {
		return nil, err
	}
	var found []process
	for _, observed := range all {
		actual, err := processPath(observed)
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if actual == path {
			found = append(found, observed)
		}
	}
	return found, nil
}
func loginwindow(uid uint32) (*process, error) {
	all, err := matchingProcesses(uid, loginwindowPath)
	if err != nil {
		return nil, err
	}
	if len(all) > 1 {
		return nil, errors.New("multiple loginwindow processes for a user")
	}
	if len(all) == 0 {
		return nil, nil //nolint:nilnil // Absence is distinct from an inventory error during first login.
	}
	return &all[0], nil
}
func consoleUID() (uint32, error) {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("console metadata is unavailable")
	}
	return stat.Uid, nil
}
func consoleReady(ctx context.Context, uid uint32) (bool, error) {
	owner, err := consoleUID()
	if err != nil || owner != uid {
		return false, err
	}
	data, err := run(ctx, nil, "/usr/sbin/ioreg", "-n", "Root", "-d1", "-a")
	if err != nil {
		return false, err
	}
	_, ready, err := consolePlist(data, uid)
	if err != nil || !ready {
		return false, err
	}
	owner, err = consoleUID()
	return owner == uid, err
}
func poll(ctx context.Context) error {
	timer := time.NewTimer(pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (n *nativeBackend) selectUser(ctx context.Context, user User, password string, initial bool) error {
	ready, err := consoleReady(ctx, user.UID)
	if err != nil {
		return err
	}
	if !ready {
		if err := n.activateUser(ctx, user, password); err != nil {
			return err
		}
		if err := n.waitForSelected(ctx, user, password, initial); err != nil {
			return err
		}
	}
	if !initial {
		return nil
	}
	return waitForAquaServices(ctx, user)
}

func (n *nativeBackend) activateUser(ctx context.Context, user User, password string) error {
	uid, err := consoleUID()
	if err != nil {
		return err
	}
	current, err := loginwindow(uid)
	if err != nil {
		return err
	}
	if current == nil {
		return errors.New("console loginwindow is missing")
	}
	target, err := loginwindow(user.UID)
	if err != nil {
		return err
	}
	start := uid == 0 && target == nil
	request := helperRequest{User: user, Password: password, Loginwindow: *current, Start: start}
	prepared, err := n.helper(ctx, "aqua-prepare", request, nil)
	if err != nil {
		return err
	}
	defer clear(prepared)
	request.Prepared = prepared
	var bootstrap *process
	if start {
		bootstrap = current
	}
	_, err = n.helper(ctx, "aqua-activate", request, bootstrap)
	return err
}

func (n *nativeBackend) waitForSelected(ctx context.Context, user User, password string, initial bool) error {
	// Supported images sometimes need their initial login moved to the
	// console explicitly. Keep this bounded within the Create deadline.
	nextRecovery := time.Now()
	attempts := 0
	for {
		ready, err := consoleReady(ctx, user.UID)
		if err != nil || ready {
			return err
		}
		if initial && attempts < 5 && !time.Now().Before(nextRecovery) {
			nextRecovery = time.Now().Add(recoveryInterval)
			recovered, err := n.recoverInitial(ctx, user, password)
			if err != nil {
				return err
			}
			if recovered {
				attempts++
			}
		}
		if err := poll(ctx); err != nil {
			return err
		}
	}
}

func (n *nativeBackend) recoverInitial(ctx context.Context, user User, password string) (bool, error) {
	owner, err := consoleUID()
	if err != nil {
		return false, err
	}
	if owner != 0 && owner != user.UID {
		return false, nil
	}
	target, err := loginwindow(user.UID)
	if err != nil || target == nil {
		return false, err
	}
	request := helperRequest{User: user, Password: password, Loginwindow: *target}
	if _, err := n.helper(ctx, "aqua-recover", request, nil); err != nil {
		return false, err
	}
	// The audited move is asynchronous. Readiness is proved by the caller's
	// console, Dock, Finder, and TCC checks rather than another foreground API.
	return true, nil
}

func waitForAquaServices(ctx context.Context, user User) error {
	services := []struct{ path, label string }{
		{"/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", "com.apple.Dock.agent"},
		{"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "com.apple.Finder"},
	}
	for _, service := range services {
		found, err := matchingProcesses(user.UID, service.path)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			_, err := run(ctx, nil, "/bin/launchctl", "kickstart", fmt.Sprintf("gui/%d/%s", user.UID, service.label))
			if err != nil {
				return err
			}
		}
	}
	for {
		info, err := os.Lstat(filepath.Join(user.Home, "Library/Application Support/com.apple.TCC/TCC.db"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		ready := err == nil && info.Mode().IsRegular() && ownedBy(info, user.UID)
		for _, service := range services {
			found, err := matchingProcesses(user.UID, service.path)
			if err != nil {
				return err
			}
			ready = ready && len(found) > 0
		}
		if ready {
			ready, err = consoleReady(ctx, user.UID)
			if err != nil {
				return err
			}
			if ready {
				return nil
			}
		}
		if err := poll(ctx); err != nil {
			return err
		}
	}
}

func (n *nativeBackend) restore(ctx context.Context) error {
	if err := protectedPath(n.passwordFile, true); err != nil {
		return err
	}
	file, err := os.Open(n.passwordFile)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, passwordFileLimit+1))
	defer clear(data)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(data) > passwordFileLimit {
		return errors.New("invalid controller password file")
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if len(password) == 0 || len(password) > 512 {
		return errors.New("invalid controller password file")
	}
	return n.selectUser(ctx, n.controller, password, false)
}

func (n *nativeBackend) remove(ctx context.Context, user User) error {
	if _, err := n.helper(ctx, "account-verify", helperRequest{User: user}, nil); err != nil {
		return err
	}
	if err := ownedDirectory(user.Home, user.UID); err != nil {
		return err
	}
	if err := checkTemp(user); err != nil {
		return err
	}
	owner, err := consoleUID()
	if err != nil {
		return err
	}
	if owner == user.UID {
		if err := n.restore(ctx); err != nil {
			return err
		}
	}
	if err := stopUser(ctx, user.UID); err != nil {
		return err
	}
	if _, err := n.helper(ctx, "account-delete", helperRequest{User: user}, nil); err != nil {
		return err
	}
	if err := os.RemoveAll(user.Home); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Dir(user.TempDirectory)); err != nil {
		return err
	}
	// Drain any user activity started during account and file cleanup.
	return stopUser(ctx, user.UID)
}

func stopUser(ctx context.Context, uid uint32) error {
	// macOS can recreate a background user domain after logout. Verify login
	// session and process removal rather than requiring domain absence.
	_, _ = run(ctx, nil, "/bin/launchctl", "bootout", fmt.Sprintf("user/%d", uid))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		output, err := run(ctx, nil, "/usr/sbin/ioreg", "-n", "Root", "-d1", "-a")
		if err != nil {
			return err
		}
		present, _, err := consolePlist(output, uid)
		if err != nil {
			return err
		}
		all, err := processes(uid)
		if err != nil {
			return err
		}
		if !present && len(all) == 0 {
			return nil
		}
		for _, p := range all {
			if err := signalProcess(p); err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.ENOENT) {
				return err
			}
		}
		if err := poll(ctx); err != nil {
			return err
		}
	}
}

func RunHelper(operation string, input io.Reader, output io.Writer) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("guest user helper requires root")
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(input, 2*1024*1024+1))
	if err != nil {
		return err
	}
	defer clear(data)
	if len(data) > 2*1024*1024 {
		return ErrInvalid
	}
	var request helperRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	defer clear(request.Prepared)
	user := request.User
	if user.ID == "" && operation != "account-verify" && operation != "aqua-prepare" && operation != "aqua-activate" {
		return ErrInvalid
	}
	switch operation {
	case "account-create", "account-verify", "account-delete":
		return accountOperation(user, request.Password, strings.TrimPrefix(operation, "account-"))
	case "temp-directory":
		if err := accountOperation(user, "", "verify"); err != nil {
			return err
		}
		if err := dropCredentials(user); err != nil {
			return err
		}
		return syscall.Exec("/usr/bin/getconf", []string{"getconf", "DARWIN_USER_TEMP_DIR"},
			[]string{"PATH=" + systemPath, nativeLocale})
	case "aqua-prepare":
		prepared, err := prepareSession(user, request.Password)
		if err != nil {
			return err
		}
		defer clear(prepared)
		_, err = output.Write(prepared)
		return err
	case "aqua-activate":
		return activateSession(user, request.Password, request.Prepared, request.Loginwindow, request.Start)
	case "aqua-recover":
		return recoverSession(user, request.Password, request.Loginwindow)
	default:
		return ErrInvalid
	}
}
