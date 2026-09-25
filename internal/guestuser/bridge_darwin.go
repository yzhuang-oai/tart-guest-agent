//go:build darwin && cgo

package guestuser

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <stdlib.h>
#include "bridge_darwin.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const processInventoryLimit = 131072
const processPathLimit = 4096

type process struct {
	PID               int32  `json:"pid"`
	UID               uint32 `json:"uid"`
	UniqueID          uint64 `json:"uniqueId"`
	StartSeconds      uint64 `json:"startSeconds"`
	StartMicroseconds uint32 `json:"startMicroseconds"`
}

func (p process) native() C.sn_process {
	return C.sn_process{
		pid: C.int32_t(p.PID), uid: C.uint32_t(p.UID), unique_id: C.uint64_t(p.UniqueID),
		start_seconds: C.uint64_t(p.StartSeconds), start_microseconds: C.uint32_t(p.StartMicroseconds),
	}
}
func bridgeError(operation string, code C.int) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("native %s: %w", operation, syscall.Errno(code))
}
func snapshot(pid int32) (process, error) {
	var p C.sn_process
	err := bridgeError("process snapshot", C.sn_snapshot(C.int32_t(pid), &p))
	return process{
		int32(p.pid), uint32(p.uid), uint64(p.unique_id), uint64(p.start_seconds), uint32(p.start_microseconds),
	}, err
}
func processes(uid uint32) ([]process, error) {
	pids := make([]C.int32_t, processInventoryLimit)
	var count C.size_t
	if err := bridgeError("process list", C.sn_list(C.uint32_t(uid), &pids[0], C.size_t(len(pids)), &count)); err != nil {
		return nil, err
	}
	var result []process
	for _, pid := range pids[:int(count)] {
		observed, err := snapshot(int32(pid))
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if observed.UID == uid {
			result = append(result, observed)
		}
	}
	return result, nil
}
func processPath(p process) (string, error) {
	v := p.native()
	buf := make([]C.char, processPathLimit)
	if err := bridgeError("process path", C.sn_path(&v, &buf[0], C.size_t(len(buf)))); err != nil {
		return "", err
	}
	return C.GoString(&buf[0]), nil
}
func signalProcess(p process) error {
	v := p.native()
	return bridgeError("kill process", C.sn_signal(&v, C.int(syscall.SIGKILL)))
}
func withAccount(user User, password string, operation func(*C.sn_account) error) error {
	for _, value := range []string{user.Username, user.Home, user.ID, password} {
		if strings.ContainsRune(value, 0) {
			return ErrInvalid
		}
	}
	name, home := C.CString(user.Username), C.CString(user.Home)
	generationID, secret := C.CString(user.ID), C.CString(password)
	defer C.free(unsafe.Pointer(name))
	defer C.free(unsafe.Pointer(home))
	defer C.free(unsafe.Pointer(generationID))
	defer func() {
		clear(unsafe.Slice((*byte)(unsafe.Pointer(secret)), len(password)))
		C.free(unsafe.Pointer(secret))
	}()
	account := C.sn_account{
		uid: C.uint32_t(user.UID), gid: C.uint32_t(user.GID), name: name, home: home,
		generation: generationID, password: secret,
	}
	return operation(&account)
}
func accountOperation(user User, password, operation string) error {
	return withAccount(user, password, func(a *C.sn_account) error {
		op := C.CString(operation)
		defer C.free(unsafe.Pointer(op))
		return bridgeError("account "+operation, C.sn_account_op(a, op))
	})
}
func prepareSession(user User, password string) ([]byte, error) {
	var result []byte
	err := withAccount(user, password, func(a *C.sn_account) error {
		var data unsafe.Pointer
		var length C.size_t
		//nolint:gocritic // The generated cgo pointer checks repeat operands deliberately.
		if err := bridgeError("prepare Aqua", C.sn_prepare(a, &data, &length)); err != nil {
			return err
		}
		defer C.free(data)
		if length == 0 || length > 1024*1024 {
			return errors.New("invalid Aqua credential envelope")
		}
		defer clear(unsafe.Slice((*byte)(data), int(length)))
		result = C.GoBytes(data, C.int(length))
		return nil
	})
	return result, err
}
func activateSession(user User, password string, prepared []byte, login process, start bool) error {
	if len(prepared) == 0 || len(prepared) > 1024*1024 {
		return ErrInvalid
	}
	nativeProcess := login.native()
	flag := 0
	if start {
		flag = 1
	}
	return withAccount(user, password, func(a *C.sn_account) error {
		return bridgeError("activate Aqua",
			C.sn_activate(a, unsafe.Pointer(&prepared[0]), C.size_t(len(prepared)), &nativeProcess, C.int(flag)))
	})
}
func recoverSession(user User, password string, login process) error {
	nativeProcess := login.native()
	return withAccount(user, password, func(a *C.sn_account) error {
		return bridgeError("initialize Aqua", C.sn_recover(a, &nativeProcess))
	})
}
func consolePlist(data []byte, uid uint32) (bool, bool, error) {
	if len(data) == 0 {
		return false, false, errors.New("empty console registry")
	}
	var present, ready C.int
	err := bridgeError("console registry",
		C.sn_console(unsafe.Pointer(&data[0]), C.size_t(len(data)), C.uint32_t(uid), &present, &ready))
	return present != 0, ready != 0, err
}
func capabilities() error { return bridgeError("required macOS APIs", C.sn_capabilities()) }
