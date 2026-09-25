package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/cirruslabs/tart-guest-agent/internal/execuser"
	"github.com/cirruslabs/tart-guest-agent/internal/guestuser"
	"github.com/cirruslabs/tart-guest-agent/pkg/v1"
	"github.com/creack/pty"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	standardStreamsBufferSize = 4096

	eofChar = 0x04

	// execRuntimeFailureExitCode matches Docker's exit code for runtime failures before a process starts.
	execRuntimeFailureExitCode = 125
	// signalExitCodeOffset is the base for shell-style exit codes of processes terminated by signals.
	signalExitCodeOffset = 128
)

//nolint:gocognit,gocyclo,maintidx // Exec coordinates process startup, bidirectional I/O, and cleanup.
func (rpc *RPC) Exec(stream grpc.BidiStreamingServer[v1.ExecRequest, v1.ExecResponse]) error {
	// Read the first exec request, it should describe a command to execute
	firstExecRequest, err := stream.Recv()
	if err != nil {
		return err
	}
	firstExecRequestCommand, ok := firstExecRequest.GetType().(*v1.ExecRequest_Command_)
	if !ok || firstExecRequestCommand.Command == nil {
		return fmt.Errorf("first exec request should describe a command to execute")
	}

	zap.S().Infof("executing %s", formatCommandAndArgs(firstExecRequestCommand.Command.Name,
		firstExecRequestCommand.Command.Args))

	if firstExecRequestCommand.Command.Detach &&
		(firstExecRequestCommand.Command.Interactive || firstExecRequestCommand.Command.Tty) {
		return fmt.Errorf("detach cannot be used with interactive or tty")
	}

	// Execute the command
	execCtx := stream.Context()
	if firstExecRequestCommand.Command.Detach {
		execCtx = context.Background()
	}

	command := firstExecRequestCommand.Command
	managed := strings.HasPrefix(command.GetUser(), guestuser.UsernamePrefix)
	if rpc.users != nil && !managed {
		return status.Error(codes.FailedPrecondition, "managed-user mode requires a managed user")
	}
	var cmd *exec.Cmd
	var prefix []byte
	var cancelExec context.CancelFunc
	if managed { //nolint:nestif // Reserve the selected user before constructing its privileged helper.
		if rpc.users == nil {
			return status.Error(codes.FailedPrecondition, "managed users are not enabled")
		}
		if command.GetDetach() || command.GetTty() {
			return status.Error(codes.InvalidArgument, "managed users require attached execution without a terminal")
		}
		user, userCtx, release, err := rpc.users.Acquire(execCtx, command.GetUser())
		if err != nil {
			return userRPCError(err)
		}
		defer release()
		execCtx, cancelExec = context.WithCancel(userCtx)
		defer cancelExec()
		cmd, prefix, err = rpc.userCommand(execCtx, user, command.GetName(), command.GetArgs(),
			command.GetEnv(), command.GetWorkdir())
		if err != nil {
			return userRPCError(err)
		}
		defer clear(prefix)
	} else {
		cmd = rpc.execCommand(execCtx, command.GetName(), command.GetArgs())
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	if !managed {
		if err := applyExecOverrides(cmd, command); err != nil {
			zap.S().Warnf("failed to configure %s: %v", formatCommandAndArgs(firstExecRequestCommand.Command.GetName(),
				firstExecRequestCommand.Command.GetArgs()), err)

			return sendStartFailure(stream)
		}
	}

	if firstExecRequestCommand.Command.Detach {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.SysProcAttr.Setsid = true

		if err := cmd.Start(); err != nil {
			zap.S().Warnf("failed to start %s: %v", formatCommandAndArgs(firstExecRequestCommand.Command.GetName(),
				firstExecRequestCommand.Command.GetArgs()), err)

			return sendStartFailure(stream)
		}

		// Release ownership before sending responses so failures do not leak the process handle
		if err := cmd.Process.Release(); err != nil {
			return err
		}

		// Explicitly notify the client that the process was started,
		// but don't provide an exec ID since it's a detached process
		err = sendStartSuccess(stream, "")
		if err != nil {
			return err
		}

		if err := stream.Send(&v1.ExecResponse{
			Type: &v1.ExecResponse_Exit_{
				Exit: &v1.ExecResponse_Exit{
					Code: 0,
				},
			},
		}); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}

		return nil
	}

	// Kill the whole process group when the exec stream is canceled
	cmd.Cancel = func() error {
		return signalProcessGroup(cmd.Process, syscall.SIGKILL)
	}

	var stdin io.WriteCloser
	var stdout, stderr io.ReadCloser
	var ptmx *os.File

	if firstExecRequestCommand.Command.Tty {
		ptmx, err = pty.StartWithSize(cmd, &pty.Winsize{
			Rows: uint16(firstExecRequestCommand.Command.GetTerminalSize().GetRows()),
			Cols: uint16(firstExecRequestCommand.Command.GetTerminalSize().GetCols()),
		})

		if firstExecRequestCommand.Command.Interactive {
			stdin = ptmx
		}
		stdout = ptmx
		stderr = ptmx
	} else {
		// Start the command in its own process group so signals reach all descendants
		cmd.SysProcAttr.Setpgid = true

		if firstExecRequestCommand.Command.GetInteractive() || managed {
			stdin, err = cmd.StdinPipe()
			if err != nil {
				return err
			}
		}

		stdout, err = cmd.StdoutPipe()
		if err != nil {
			return err
		}

		stderr, err = cmd.StderrPipe()
		if err != nil {
			return err
		}

		err = cmd.Start()
	}

	if err != nil {
		zap.S().Warnf("failed to start %s: %v", formatCommandAndArgs(firstExecRequestCommand.Command.GetName(),
			firstExecRequestCommand.Command.GetArgs()), err)

		if managed {
			return sendManagedResponse(execCtx, stream, &v1.ExecResponse{
				Type: &v1.ExecResponse_Exit_{Exit: &v1.ExecResponse_Exit{Code: execRuntimeFailureExitCode}},
			})
		}
		return sendStartFailure(stream)
	}
	waited := false
	if managed { //nolint:nestif // Every post-start failure must cancel and reap before releasing the user.
		stopClosing := context.AfterFunc(execCtx, func() {
			_ = stdin.Close()
			_ = stdout.Close()
			_ = stderr.Close()
		})
		defer stopClosing()
		defer func() {
			if !waited {
				cancelExec()
				_ = cmd.Wait()
			}
		}()
		if n, err := stdin.Write(prefix); err != nil {
			return err
		} else if n != len(prefix) {
			return io.ErrShortWrite
		}
		clear(prefix)
		if !command.GetInteractive() {
			if err := stdin.Close(); err != nil {
				return err
			}
		}
	}

	// Ensure the PTY is closed if sending the Started response fails
	if ptmx != nil {
		defer ptmx.Close()
	}

	execID := uuid.NewString()
	rpc.execs.Store(execID, cmd.Process)
	defer rpc.execs.Delete(execID)

	// Explicitly notify the client that the process was started
	if managed {
		err = sendManagedResponse(execCtx, stream, &v1.ExecResponse{
			Type: &v1.ExecResponse_Started_{Started: &v1.ExecResponse_Started{ExecId: execID}},
		})
	} else {
		err = sendStartSuccess(stream, execID)
	}
	if err != nil {
		// Output readers have not started yet, so cancel and reap directly
		_ = cmd.Cancel()
		_ = cmd.Wait()
		waited = true

		return err
	}

	// Serialize input acknowledgements with command output and the terminal response.
	var sendMutex sync.Mutex
	finished := false
	sendResponse := func(response *v1.ExecResponse) error {
		sendMutex.Lock()
		defer sendMutex.Unlock()
		if managed && finished {
			return context.Canceled
		}
		if managed {
			return sendManagedResponse(execCtx, stream, response)
		}
		return stream.Send(response)
	}

	// Handle standard input and terminal resize events from the client
	var inputMutex sync.Mutex
	inputFinished := false
	fromClientErrCh := make(chan error, 1)
	reportClientError := func(err error) {
		fromClientErrCh <- err
		if managed {
			cancelExec()
		} else {
			_ = cmd.Cancel()
		}
	}

	go func() {
		stdinClosed := managed && !command.GetInteractive()
		var inputOffset uint64
		acceptInput := func(data []byte) error {
			inputMutex.Lock()
			defer inputMutex.Unlock()
			if managed && inputFinished {
				return context.Canceled
			}
			if len(data) == 0 {
				if err := closeStdin(stdin, command.GetTty(), &stdinClosed); err != nil {
					return err
				}
			} else {
				n, err := stdin.Write(data)
				inputOffset += uint64(n)
				if err != nil {
					return err
				}
				if n != len(data) {
					return io.ErrShortWrite
				}
			}
			if !managed || !command.GetInteractive() {
				return nil
			}
			return sendResponse(&v1.ExecResponse{Type: &v1.ExecResponse_InputAck_{
				InputAck: &v1.ExecResponse_InputAck{Offset: inputOffset, Eof: stdinClosed},
			}})
		}

		for {
			request, err := stream.Recv()
			if err != nil {
				// Allow the client to close its sending side while continuing to receive responses
				if errors.Is(err, io.EOF) {
					if err := acceptInput(nil); err != nil {
						reportClientError(err)
					}

					return
				}

				if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
					reportClientError(err)
				}

				return
			}

			switch typedAction := request.Type.(type) {
			case *v1.ExecRequest_StandardInput:
				if !firstExecRequestCommand.Command.Interactive {
					if managed {
						reportClientError(status.Error(codes.InvalidArgument, "standard input requires interactive execution"))
						return
					}
					// Ignore standard input from the client
					// as non-interactive command is running
					continue
				}

				if err := acceptInput(typedAction.StandardInput.GetData()); err != nil {
					reportClientError(err)
					return
				}
			case *v1.ExecRequest_TerminalResize:
				// Ignore terminal resize requests
				// when pseudo terminal is disabled
				if !firstExecRequestCommand.Command.Tty {
					continue
				}

				if err := pty.Setsize(ptmx, &pty.Winsize{
					Rows: uint16(typedAction.TerminalResize.GetRows()),
					Cols: uint16(typedAction.TerminalResize.GetCols()),
				}); err != nil {
					reportClientError(err)

					return
				}
			}
		}
	}()

	group, _ := errgroup.WithContext(stream.Context())
	cancelOutputError := func(err *error) {
		if managed && *err != nil {
			cancelExec()
		}
	}

	// Handle standard output from the command
	group.Go(func() (outputErr error) { //nolint:nonamedreturns // The defer cancels execution on any output failure.
		defer cancelOutputError(&outputErr)
		buf := make([]byte, standardStreamsBufferSize)

		for {
			n, err := stdout.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}

				// PTY way of signalling io.EOF
				if ptmx != nil && strings.Contains(err.Error(), "input/output error") {
					return nil
				}

				return err
			}

			if err := sendResponse(&v1.ExecResponse{
				Type: &v1.ExecResponse_StandardOutput{
					StandardOutput: &v1.IOChunk{
						Data: slices.Clone(buf[:n]),
					},
				},
			}); err != nil {
				return err
			}
		}
	})

	// Handle standard error from the command
	//
	// Note that it makes no sense to handle standard error when TTY is requested
	// because in this case stdout and stderr will point to the same file descriptor
	if !firstExecRequestCommand.Command.Tty {
		group.Go(func() (outputErr error) { //nolint:nonamedreturns // The defer cancels execution on any output failure.
			defer cancelOutputError(&outputErr)
			buf := make([]byte, standardStreamsBufferSize)

			for {
				n, err := stderr.Read(buf)
				if err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}

					return err
				}

				if err := sendResponse(&v1.ExecResponse{
					Type: &v1.ExecResponse_StandardError{
						StandardError: &v1.IOChunk{
							Data: slices.Clone(buf[:n]),
						},
					},
				}); err != nil {
					return err
				}
			}
		})
	}

	outputErr := group.Wait()
	if outputErr != nil {
		zap.S().Warnf("%v", outputErr)
	}

	// Wait for the command to finish
	err = cmd.Wait()
	waited = true
	// Remove the signal target before waiting for any final input acknowledgement.
	rpc.execs.Delete(execID)
	if managed {
		inputMutex.Lock()
		inputFinished = true
		sendMutex.Lock()
		finished = true
		sendMutex.Unlock()
		inputMutex.Unlock()
	}

	// Prefer a client error over the command exit result
	select {
	case err := <-fromClientErrCh:
		return err
	default:
	}
	if managed && outputErr != nil {
		return outputErr
	}

	exitCode := 0

	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			return err
		}

		// ExitCode returns -1 for signals; report the containerd-compatible 128 + signal instead
		exitCode = exitError.ExitCode()

		if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok && waitStatus.Signaled() {
			exitCode = signalExitCodeOffset + int(waitStatus.Signal())
		}
	}

	response := &v1.ExecResponse{
		Type: &v1.ExecResponse_Exit_{
			Exit: &v1.ExecResponse_Exit{
				Code: int32(exitCode),
			},
		},
	}
	if managed {
		return sendManagedResponse(execCtx, stream, response)
	}
	return stream.Send(response)
}

// A slow reader must not prevent user deletion from canceling and reaping a
// command. Returning the RPC closes the transport and unblocks its pending Send.
func sendManagedResponse(
	ctx context.Context,
	stream grpc.BidiStreamingServer[v1.ExecRequest, v1.ExecResponse],
	response *v1.ExecResponse,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() { result <- stream.Send(response) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func signalProcessGroup(process *os.Process, signal syscall.Signal) error {
	if err := syscall.Kill(-process.Pid, signal); err != nil {
		// Translate a missing process group into the process-finished error expected by os/exec
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}

		return err
	}

	return nil
}

func closeStdin(stdin io.WriteCloser, tty bool, closed *bool) error {
	if stdin == nil || *closed {
		return nil
	}

	if tty {
		// When using pseudo-terminal, we can't simply close the
		// standard input, as the file descriptor is shared for
		// standard output and standard error too, so we send
		// an EOF character instead
		if _, err := stdin.Write([]byte{eofChar}); err != nil {
			return err
		}
	} else if err := stdin.Close(); err != nil {
		return err
	}

	*closed = true

	return nil
}

func (rpc *RPC) Signal(_ context.Context, request *v1.SignalRequest) (*emptypb.Empty, error) {
	process, ok := rpc.execs.Load(request.GetExecId())
	if !ok {
		return nil, fmt.Errorf("exec %q is not running", request.GetExecId())
	}

	var signal syscall.Signal

	switch request.GetSignal() {
	case v1.SignalRequest_SIGNAL_SIGTERM:
		signal = syscall.SIGTERM
	case v1.SignalRequest_SIGNAL_SIGKILL:
		signal = syscall.SIGKILL
	default:
		return nil, fmt.Errorf("unsupported exec signal %q", request.GetSignal().String())
	}

	if err := signalProcessGroup(process, signal); err != nil {
		// The process may exit after lookup, so treat the missing process as a no-op
		if errors.Is(err, os.ErrProcessDone) {
			return &emptypb.Empty{}, nil
		}

		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func sendStartSuccess(stream grpc.BidiStreamingServer[v1.ExecRequest, v1.ExecResponse], execID string) error {
	return stream.Send(&v1.ExecResponse{
		Type: &v1.ExecResponse_Started_{
			Started: &v1.ExecResponse_Started{
				ExecId: execID,
			},
		},
	})
}

func sendStartFailure(stream grpc.BidiStreamingServer[v1.ExecRequest, v1.ExecResponse]) error {
	return stream.Send(&v1.ExecResponse{
		Type: &v1.ExecResponse_Exit_{
			Exit: &v1.ExecResponse_Exit{
				Code: execRuntimeFailureExitCode,
			},
		},
	})
}

func applyExecOverrides(cmd *exec.Cmd, command *v1.ExecRequest_Command) error {
	if command.Workdir != "" {
		cmd.Dir = command.Workdir
	}

	if len(command.Env) > 0 {
		cmd.Env = mergeEnv(command.Env)
	}

	if user := command.GetUser(); user != "" {
		credential, err := execuser.Resolve(user)
		if err != nil {
			return fmt.Errorf("failed to apply user override %q: %w", user, err)
		}

		// Avoid changing credentials when the requested user is the guest agent user
		if credential.Uid == uint32(os.Geteuid()) && credential.Gid == uint32(os.Getegid()) {
			return nil
		}

		cmd.SysProcAttr.Credential = credential
	}

	return nil
}

func mergeEnv(overrides map[string]string) []string {
	if len(overrides) == 0 {
		return os.Environ()
	}

	envMap := make(map[string]string, len(overrides))
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		envMap[parts[0]] = parts[1]
	}

	for key, value := range overrides {
		envMap[key] = value
	}

	merged := make([]string, 0, len(envMap))
	for key, value := range envMap {
		merged = append(merged, key+"="+value)
	}

	return merged
}

func formatCommandAndArgs(name string, args []string) string {
	var all []string

	all = append(all, name)
	all = append(all, args...)

	all = lo.Map(all, func(item string, _ int) string {
		return fmt.Sprintf("%q", item)
	})

	return fmt.Sprintf("[%s]", strings.Join(all, ", "))
}
