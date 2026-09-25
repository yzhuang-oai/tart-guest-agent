//nolint:testpackage
package rpc

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cirruslabs/tart-guest-agent/internal/guestuser"
	"github.com/cirruslabs/tart-guest-agent/pkg/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const testUserRequestID = "request"
const testInputAcknowledgement = "input-ack"
const testStandardOutput = "output"
const testStarted = "started"

type fakeUserManager struct {
	user                       guestuser.User
	health                     error
	creates, deletes, acquires int
	onRelease                  func()
	onAcquire                  func(context.Context) context.Context
}

func (m *fakeUserManager) BootID() string { return "current-boot" }
func (m *fakeUserManager) Health() error  { return m.health }
func (m *fakeUserManager) Create(context.Context, string) (guestuser.User, error) {
	m.creates++
	return m.user, m.health
}
func (m *fakeUserManager) Delete(context.Context, string) error {
	m.deletes++
	return m.health
}
func (m *fakeUserManager) Acquire(ctx context.Context, name string) (guestuser.User, context.Context, func(), error) {
	m.acquires++
	if name != m.user.Username {
		return guestuser.User{}, nil, nil, guestuser.ErrNotFound
	}
	if m.onAcquire != nil {
		ctx = m.onAcquire(ctx)
	}
	return m.user, ctx, func() {
		if m.onRelease != nil {
			m.onRelease()
		}
	}, nil
}

func userTestRPC(t *testing.T) (*RPC, *fakeUserManager) {
	rpc, err := New(nil)
	require.NoError(t, err)
	users := &fakeUserManager{user: guestuser.User{
		ID: testUserRequestID, Username: "tga-test", UID: 20000, GID: 20,
		Home: "/Users/tga-test", TempDirectory: "/tmp/tga-test",
	}}
	rpc.users = users
	return rpc, users
}

func TestUserRPCsRequireCurrentBootBeforeMutation(t *testing.T) {
	rpc, users := userTestRPC(t)
	for _, boot := range []string{"", "old-boot"} {
		_, err := rpc.CreateUser(t.Context(), &v1.CreateUserRequest{BootId: boot, RequestId: testUserRequestID})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		_, err = rpc.DeleteUser(t.Context(), &v1.DeleteUserRequest{BootId: boot, Id: testUserRequestID})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	}
	require.Zero(t, users.creates)
	require.Zero(t, users.deletes)
	info, err := rpc.UserInfo(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)
	require.Equal(t, users.BootID(), info.GetBootId())
	require.True(t, info.GetHealthy())
	created, err := rpc.CreateUser(t.Context(), &v1.CreateUserRequest{
		BootId: info.GetBootId(), RequestId: testUserRequestID,
	})
	require.NoError(t, err)
	require.Equal(t, users.user.Username, created.GetUsername())
	require.Equal(t, users.user.TempDirectory, created.GetTemporaryDirectory())
	_, err = rpc.DeleteUser(t.Context(), &v1.DeleteUserRequest{BootId: info.GetBootId(), Id: created.GetId()})
	require.NoError(t, err)
	require.Equal(t, 1, users.creates)
	require.Equal(t, 1, users.deletes)
	users.health = guestuser.ErrUnavailable
	info, err = rpc.UserInfo(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)
	require.False(t, info.GetHealthy())
}

func TestManagedNamesCannotFallBackToOrdinaryExecution(t *testing.T) {
	for _, mode := range []string{
		"disabled", "unknown", "group-override", "tty", "detached", "empty-user", "ordinary-user", "numeric-user",
	} {
		t.Run(mode, func(t *testing.T) {
			rpc, users := userTestRPC(t)
			rpc.userCommand = func(
				context.Context, guestuser.User, string, []string, map[string]string, string,
			) (*exec.Cmd, []byte, error) {
				t.Error("rejected managed execution reached the command factory")
				return nil, nil, guestuser.ErrUnavailable
			}
			request := &v1.ExecRequest_Command{User: users.user.Username, Name: "/usr/bin/true"}
			expected := codes.InvalidArgument
			switch mode {
			case "disabled":
				rpc.users = nil
				expected = codes.FailedPrecondition
			case "unknown":
				request.User = "tga-stale"
				expected = codes.NotFound
			case "group-override":
				request.User += ":staff"
				expected = codes.NotFound
			case "tty":
				request.Tty = true
			case "detached":
				request.Detach = true
			case "empty-user":
				request.User = ""
				expected = codes.FailedPrecondition
			case "ordinary-user":
				request.User = "controller"
				expected = codes.FailedPrecondition
			case "numeric-user":
				request.User = "0"
				expected = codes.FailedPrecondition
			}
			_, stream, result := startExecTestWithRPC(t, rpc, request)
			require.Equal(t, expected, status.Code(receiveExecResult(t, result)))
			require.Empty(t, stream.responses)
		})
	}
}

func TestManagedInputAcknowledgesWorkloadBytesAndRepeatedEOF(t *testing.T) {
	rpc, users := userTestRPC(t)
	released := false
	var process *exec.Cmd
	users.onRelease = func() { released = true; require.NotNil(t, process.ProcessState) }
	rpc.userCommand = func(
		ctx context.Context, user guestuser.User, name string, args []string, env map[string]string, workdir string,
	) (*exec.Cmd, []byte, error) {
		require.Equal(t, users.user, user)
		require.Equal(t, "tenant-command", name)
		require.Equal(t, []string{"argument"}, args)
		require.Equal(t, map[string]string{"HOME": "tenant-value"}, env)
		require.Equal(t, "/tenant/workspace", workdir)
		// A shell substitutes for the privileged helper, consumes its private
		// launch line, then copies only workload input to stdout.
		process = exec.CommandContext(ctx, execTestShell, "-c", "IFS= read -r private; cat; sleep 0.1")
		return process, []byte("private launch data\n"), nil
	}
	_, stream, result := startExecTestWithRPC(t, rpc, &v1.ExecRequest_Command{
		User: users.user.Username, Name: "tenant-command", Args: []string{"argument"},
		Env: map[string]string{"HOME": "tenant-value"}, Workdir: "/tenant/workspace", Interactive: true,
	})
	require.NotNil(t, receiveExecResponse(t, stream).GetStarted())
	for _, data := range [][]byte{[]byte("hello"), nil, nil} {
		stream.requests <- &v1.ExecRequest{Type: &v1.ExecRequest_StandardInput{StandardInput: &v1.IOChunk{Data: data}}}
	}
	var output strings.Builder
	var acknowledgements []*v1.ExecResponse_InputAck
	for {
		response := receiveExecResponse(t, stream)
		if ack := response.GetInputAck(); ack != nil {
			acknowledgements = append(acknowledgements, ack)
		}
		output.Write(response.GetStandardOutput().GetData())
		if response.GetExit() != nil {
			require.Zero(t, response.GetExit().GetCode())
			break
		}
	}
	require.NoError(t, receiveExecResult(t, result))
	require.True(t, released)
	require.Equal(t, "hello", output.String())
	require.Len(t, acknowledgements, 3)
	for i, ack := range acknowledgements {
		require.EqualValues(t, 5, ack.GetOffset())
		require.Equal(t, i > 0, ack.GetEof())
	}
}

func TestManagedSendFailureReapsBeforeRelease(t *testing.T) {
	for _, point := range []string{testStarted, testStandardOutput, testInputAcknowledgement} {
		t.Run(point, func(t *testing.T) {
			rpc, users := userTestRPC(t)
			var process *exec.Cmd
			released := false
			users.onRelease = func() { released = true; require.NotNil(t, process.ProcessState) }
			rpc.userCommand = func(
				ctx context.Context, _ guestuser.User, _ string, _ []string, _ map[string]string, _ string,
			) (*exec.Cmd, []byte, error) {
				process = exec.CommandContext(ctx, execTestShell, "-c", "printf ready; exec sleep 30")
				return process, nil, nil
			}
			sendErr := errors.New("stream send failed")
			_, stream, result := startExecTestWithRPC(t, rpc, &v1.ExecRequest_Command{
				User: users.user.Username, Name: "unused", Interactive: true,
			}, func(stream *execTestStream) {
				stream.sendHook = func(response *v1.ExecResponse) error {
					if isTestResponse(point, response) {
						return sendErr
					}
					return nil
				}
			})
			if point == testInputAcknowledgement {
				stream.requests <- &v1.ExecRequest{Type: &v1.ExecRequest_StandardInput{
					StandardInput: &v1.IOChunk{Data: []byte("input")},
				}}
			}
			require.ErrorIs(t, receiveExecResult(t, result), sendErr)
			require.True(t, released)
		})
	}
}

func TestManagedCancellationReleasesBlockedResponse(t *testing.T) {
	for _, point := range []string{testStarted, testStandardOutput, testInputAcknowledgement} {
		t.Run(point, func(t *testing.T) {
			rpc, users := userTestRPC(t)
			userCtx, cancelUser := context.WithCancel(t.Context())
			defer cancelUser()
			users.onAcquire = func(context.Context) context.Context { return userCtx }
			var process *exec.Cmd
			released := false
			users.onRelease = func() { released = true; require.NotNil(t, process.ProcessState) }
			rpc.userCommand = func(
				ctx context.Context, _ guestuser.User, _ string, _ []string, _ map[string]string, _ string,
			) (*exec.Cmd, []byte, error) {
				process = exec.CommandContext(ctx, execTestShell, "-c", "printf ready; exec sleep 30")
				return process, nil, nil
			}
			blocked, unblock := make(chan struct{}), make(chan struct{})
			defer close(unblock)
			_, stream, result := startExecTestWithRPC(t, rpc, &v1.ExecRequest_Command{
				User: users.user.Username, Name: "unused", Interactive: true,
			}, func(stream *execTestStream) {
				stream.sendHook = func(response *v1.ExecResponse) error {
					if isTestResponse(point, response) {
						close(blocked)
						<-unblock
						return context.Canceled
					}
					return nil
				}
			})
			if point == testInputAcknowledgement {
				stream.requests <- &v1.ExecRequest{Type: &v1.ExecRequest_StandardInput{
					StandardInput: &v1.IOChunk{Data: []byte("input")},
				}}
			}
			select {
			case <-blocked:
			case <-time.After(execTestTimeout):
				t.Fatal("response did not reach blocked reader")
			}
			cancelUser()
			require.Error(t, receiveExecResult(t, result))
			require.True(t, released)
		})
	}
}

func isTestResponse(point string, response *v1.ExecResponse) bool {
	switch point {
	case testStarted:
		return response.GetStarted() != nil
	case testStandardOutput:
		return response.GetStandardOutput() != nil
	case testInputAcknowledgement:
		return response.GetInputAck() != nil
	default:
		return false
	}
}
