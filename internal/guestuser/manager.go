// Package guestuser creates disposable macOS users and executes commands in their Aqua context.
package guestuser

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const UsernamePrefix = "tga-"
const operationTimeout = 90 * time.Second
const passwordRandomBytes = 36
const ordinaryUserGroup = 20

var (
	ErrInvalid     = errors.New("invalid guest user request")
	ErrNotFound    = errors.New("guest user not found")
	ErrUnavailable = errors.New("guest user manager is unavailable; replace the guest")
)

type Config struct {
	ControllerUsername     string
	ControllerPasswordFile string
	FirstUID               uint32
	LastUID                uint32
}

type User struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Home          string `json:"home"`
	TempDirectory string `json:"temp_directory"` //nolint:tagliatelle // Private helper envelopes use snake_case.
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
}

type backend interface {
	available(uid uint32) (bool, error)
	create(ctx context.Context, user User, password string) (User, error)
	remove(ctx context.Context, user User) error
	command(
		ctx context.Context, user User, name string, args []string, environment map[string]string, workdir string,
	) (*exec.Cmd, []byte, error)
}

type entry struct {
	user                     User
	ready, deleting, deleted bool
	active                   map[uint64]context.CancelFunc
	drained                  chan struct{}
}

// Manager intentionally has no restart recovery. Its owner must replace the VM
// when BootID changes or Health fails. UIDs are never reused during this boot.
type Manager struct {
	mu               sync.Mutex
	operation        chan struct{}
	bootID           string
	nextUID, lastUID uint32
	sequence         uint64
	users            map[string]*entry
	byName           map[string]*entry
	failed           error
	native           backend
}

func New(config Config) (*Manager, error) {
	if config.FirstUID == 0 {
		config.FirstUID = 20000
	}
	if config.LastUID == 0 {
		config.LastUID = 65000
	}
	if config.FirstUID < 501 || config.LastUID >= 65534 || config.FirstUID > config.LastUID {
		return nil, fmt.Errorf("%w: invalid UID range", ErrInvalid)
	}
	native, err := newBackend(config)
	if err != nil {
		return nil, err
	}
	return newManager(config, native), nil
}

func newManager(config Config, native backend) *Manager {
	return &Manager{operation: make(chan struct{}, 1), bootID: uuid.NewString(), nextUID: config.FirstUID,
		lastUID: config.LastUID, users: make(map[string]*entry), byName: make(map[string]*entry), native: native}
}

func (m *Manager) BootID() string { return m.bootID }
func (m *Manager) Health() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failed
}

// Command builds an execution using the helper selected when the manager started.
// Callers must first Acquire the user and release it only after the command exits.
func (m *Manager) Command(
	ctx context.Context, user User, name string, args []string, environment map[string]string, workdir string,
) (*exec.Cmd, []byte, error) {
	return m.native.command(ctx, user, name, args, environment, workdir)
}

func requestID(id string) (string, error) {
	value, err := uuid.Parse(id)
	if err != nil || value == uuid.Nil {
		return "", fmt.Errorf("%w: user ID must be a UUID", ErrInvalid)
	}
	return value.String(), nil
}

func (m *Manager) Create(ctx context.Context, userID string) (User, error) {
	userID, err := requestID(userID)
	if err != nil {
		return User{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := m.lock(ctx); err != nil {
		return User{}, err
	}
	defer func() { <-m.operation }()
	m.mu.Lock()
	if m.failed != nil {
		err := m.failed
		m.mu.Unlock()
		return User{}, err
	}
	if existing := m.users[userID]; existing != nil {
		value, ready := existing.user, existing.ready && !existing.deleting && !existing.deleted
		m.mu.Unlock()
		if !ready {
			return User{}, fmt.Errorf("%w: user ID was already deleted", ErrInvalid)
		}
		return value, nil
	}
	m.mu.Unlock()
	var uid uint32
	for m.nextUID <= m.lastUID {
		candidate := m.nextUID
		m.nextUID++
		available, err := m.native.available(candidate)
		if err != nil {
			return User{}, m.fail(err)
		}
		if available {
			uid = candidate
			break
		}
	}
	if uid == 0 {
		return User{}, fmt.Errorf("%w: UID range exhausted", ErrInvalid)
	}
	secret := make([]byte, passwordRandomBytes)
	if _, err := rand.Read(secret); err != nil {
		return User{}, err
	}
	password := base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	name := UsernamePrefix + m.bootID[:8] + "-" + strings.ReplaceAll(userID, "-", "")
	value := User{ID: userID, Username: name, UID: uid, GID: ordinaryUserGroup, Home: filepath.Join("/Users", name)}
	value, err = m.native.create(ctx, value, password)
	if err != nil {
		return User{}, m.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return User{}, m.fail(err)
	}
	m.mu.Lock()
	selected := &entry{user: value, ready: true, active: make(map[uint64]context.CancelFunc), drained: make(chan struct{})}
	m.users[userID], m.byName[value.Username] = selected, selected
	m.mu.Unlock()
	return value, nil
}

func (m *Manager) Lookup(name string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lookup(name)
}

// Acquire prevents deletion until the caller confirms its command has actually
// exited. Release must follow Wait, or a definite failure to start the command.
func (m *Manager) Acquire(ctx context.Context, name string) (User, context.Context, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, err := m.lookup(name)
	if err != nil {
		return User{}, nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return User{}, nil, nil, err
	}
	execCtx, cancel := context.WithCancel(ctx)
	selected := m.byName[name]
	m.sequence++
	token := m.sequence
	selected.active[token] = cancel
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			m.mu.Lock()
			defer m.mu.Unlock()
			delete(selected.active, token)
			if selected.deleting && len(selected.active) == 0 {
				close(selected.drained)
			}
		})
	}
	return value, execCtx, release, nil
}

func (m *Manager) Delete(ctx context.Context, userID string) error {
	userID, err := requestID(userID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer func() { <-m.operation }()
	m.mu.Lock()
	if m.failed != nil {
		err := m.failed
		m.mu.Unlock()
		return err
	}
	selected := m.users[userID]
	if selected == nil || selected.deleted {
		m.mu.Unlock()
		return nil
	}
	selected.deleting = true
	for _, cancel := range selected.active {
		cancel()
	}
	if len(selected.active) == 0 {
		close(selected.drained)
	}
	m.mu.Unlock()
	select {
	case <-selected.drained:
	case <-ctx.Done():
		return m.fail(ctx.Err())
	}
	if err := m.native.remove(ctx, selected.user); err != nil {
		return m.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return m.fail(err)
	}
	m.mu.Lock()
	selected.deleted, selected.ready = true, false
	m.mu.Unlock()
	return nil
}

func (m *Manager) fail(err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed == nil {
		m.failed = fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for _, value := range m.users {
		for _, cancel := range value.active {
			cancel()
		}
	}
	return m.failed
}

func (m *Manager) lock(ctx context.Context) error {
	select {
	case m.operation <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-m.operation
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) lookup(name string) (User, error) {
	if m.failed != nil {
		return User{}, m.failed
	}
	selected := m.byName[name]
	if selected == nil || selected.deleted {
		return User{}, ErrNotFound
	}
	if !selected.ready || selected.deleting {
		return User{}, fmt.Errorf("%w: user is being deleted", ErrUnavailable)
	}
	return selected.user, nil
}
