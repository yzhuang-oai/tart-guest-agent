package rpc

import (
	"context"
	"errors"
	"net"

	"github.com/cirruslabs/tart-guest-agent/internal/guestuser"
	"github.com/cirruslabs/tart-guest-agent/pkg/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type userManager interface {
	BootID() string
	Health() error
	Create(ctx context.Context, requestID string) (guestuser.User, error)
	Delete(ctx context.Context, id string) error
	Acquire(ctx context.Context, username string) (guestuser.User, context.Context, func(), error)
}

// NewWithUsers enables managed users and requires one for every Exec request.
func NewWithUsers(listener net.Listener, users *guestuser.Manager) (*RPC, error) {
	if users == nil {
		return nil, errors.New("managed users require a manager")
	}
	rpc, err := New(listener)
	if err != nil {
		return nil, err
	}
	rpc.users, rpc.userCommand = users, users.Command
	return rpc, nil
}

func (rpc *RPC) UserInfo(_ context.Context, _ *emptypb.Empty) (*v1.UserInfoResponse, error) {
	if rpc.users == nil {
		return nil, status.Error(codes.Unimplemented, "managed users are not enabled")
	}
	return &v1.UserInfoResponse{BootId: rpc.users.BootID(), Healthy: rpc.users.Health() == nil}, nil
}

func (rpc *RPC) requireUserBoot(bootID string) error {
	if rpc.users == nil {
		return status.Error(codes.Unimplemented, "managed users are not enabled")
	}
	if bootID == "" || bootID != rpc.users.BootID() {
		return status.Error(codes.FailedPrecondition, "managed-user daemon changed")
	}
	return nil
}

func (rpc *RPC) CreateUser(ctx context.Context, request *v1.CreateUserRequest) (*v1.ManagedUser, error) {
	if err := rpc.requireUserBoot(request.GetBootId()); err != nil {
		return nil, err
	}
	user, err := rpc.users.Create(ctx, request.GetRequestId())
	if err != nil {
		return nil, userRPCError(err)
	}
	return &v1.ManagedUser{
		Id: user.ID, Username: user.Username, Uid: user.UID, Gid: user.GID,
		Home: user.Home, TemporaryDirectory: user.TempDirectory,
	}, nil
}

func (rpc *RPC) DeleteUser(ctx context.Context, request *v1.DeleteUserRequest) (*emptypb.Empty, error) {
	if err := rpc.requireUserBoot(request.GetBootId()); err != nil {
		return nil, err
	}
	if err := rpc.users.Delete(ctx, request.GetId()); err != nil {
		return nil, userRPCError(err)
	}
	return &emptypb.Empty{}, nil
}

func userRPCError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "managed-user operation canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "managed-user operation timed out")
	case errors.Is(err, guestuser.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid managed-user request")
	case errors.Is(err, guestuser.ErrNotFound):
		return status.Error(codes.NotFound, "managed user is unavailable")
	default:
		return status.Error(codes.Unavailable, "managed-user operation failed")
	}
}
