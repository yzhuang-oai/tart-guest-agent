//nolint:testpackage // Inject a native backend so these tests never create macOS accounts.
package guestuser

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type fakeBackend struct {
	mu               sync.Mutex
	created, removed int
	createErr        error
	removeCalled     chan struct{}
}

func (*fakeBackend) available(uint32) (bool, error) { return true, nil }
func (*fakeBackend) command(
	context.Context, User, string, []string, map[string]string, string,
) (*exec.Cmd, []byte, error) {
	return nil, nil, ErrUnavailable
}
func (f *fakeBackend) create(_ context.Context, user User, _ string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	user.TempDirectory = "/private/var/folders/ab/example/T"
	return user, f.createErr
}
func (f *fakeBackend) remove(context.Context, User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed++
	if f.removeCalled != nil {
		close(f.removeCalled)
	}
	return nil
}
func fixture() (*Manager, *fakeBackend) {
	native := &fakeBackend{}
	return newManager(Config{FirstUID: 20000, LastUID: 20010}, native), native
}
func create(t *testing.T, manager *Manager) User {
	t.Helper()
	user, err := manager.Create(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestCreateRetryAndUIDReuse(t *testing.T) {
	manager, native := fixture()
	user := create(t, manager)
	retry, err := manager.Create(context.Background(), user.ID)
	if err != nil || retry != user || native.created != 1 {
		t.Fatalf("retry created another account: %#v %v", retry, err)
	}
	if err := manager.Delete(context.Background(), user.ID); err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(context.Background(), user.ID); err != nil {
		t.Fatal(err)
	}
	if native.removed != 1 {
		t.Fatal("delete retried native account removal")
	}
	if _, err := manager.Create(context.Background(), user.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("deleted ID became usable again: %v", err)
	}
	next := create(t, manager)
	if next.UID <= user.UID {
		t.Fatal("deleted UID was reused")
	}
}

func TestDeleteWaitsForCommandExit(t *testing.T) {
	manager, native := fixture()
	native.removeCalled = make(chan struct{})
	user := create(t, manager)
	_, commandCtx, release, err := manager.Acquire(context.Background(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan error, 1)
	go func() { done <- manager.Delete(context.Background(), user.ID) }()
	<-commandCtx.Done()
	if _, _, _, err := manager.Acquire(context.Background(), user.Username); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("accepted another command during deletion: %v", err)
	}
	select {
	case <-native.removeCalled:
		t.Fatal("removed account before the command exited")
	default:
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-native.removeCalled:
	default:
		t.Fatal("account was not removed")
	}
}

func TestNativeFailurePoisonsManagerAndCancelsCommands(t *testing.T) {
	manager, native := fixture()
	user := create(t, manager)
	_, commandCtx, release, err := manager.Acquire(context.Background(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	native.createErr = errors.New("Aqua operation timed out")
	if _, err := manager.Create(context.Background(), uuid.NewString()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("native failure was not terminal: %v", err)
	}
	select {
	case <-commandCtx.Done():
	default:
		t.Fatal("active command was not canceled")
	}
	if !errors.Is(manager.Health(), ErrUnavailable) {
		t.Fatal("failed manager reports healthy")
	}
	if _, err := manager.Lookup(user.Username); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lookup after native failure: %v", err)
	}
	if err := manager.Delete(context.Background(), user.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attempted recovery after native failure: %v", err)
	}
	if _, err := manager.Create(context.Background(), user.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("returned an old account after native failure: %v", err)
	}
	if native.created != 2 || native.removed != 0 {
		t.Fatal("performed native work after failure")
	}
}

func TestCanceledDeleteDoesNotClaimCleanup(t *testing.T) {
	manager, native := fixture()
	user := create(t, manager)
	_, commandCtx, release, err := manager.Acquire(context.Background(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- manager.Delete(ctx, user.ID) }()
	<-commandCtx.Done()
	cancel()
	if err := <-done; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("canceled deletion appeared successful: %v", err)
	}
	if native.removed != 0 {
		t.Fatal("deleted account while its command was still active")
	}
	if !errors.Is(manager.Health(), ErrUnavailable) {
		t.Fatal("incomplete cleanup left manager healthy")
	}
	release()
}

func TestNewBootCannotAcquireOldUsername(t *testing.T) {
	manager, _ := fixture()
	old := create(t, manager)
	restarted, _ := fixture()
	if restarted.BootID() == manager.BootID() {
		t.Fatal("daemon boot ID was reused")
	}
	if _, _, _, err := restarted.Acquire(context.Background(), old.Username); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new daemon adopted an old account: %v", err)
	}
	current, err := restarted.Create(context.Background(), old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Username == old.Username {
		t.Fatal("username did not include daemon boot identity")
	}
}
