//go:build !darwin || !cgo

package guestuser

import (
	"errors"
	"io"
)

var errUnsupported = errors.New("guest users require macOS, cgo, and a root daemon")

func newBackend(Config) (backend, error)           { return nil, errUnsupported }
func RunHelper(string, io.Reader, io.Writer) error { return errUnsupported }
func RunExec(io.Reader) error                      { return errUnsupported }
