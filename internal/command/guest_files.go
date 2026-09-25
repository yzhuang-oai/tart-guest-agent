package command

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
)

const (
	guestFileChunk         = 1024 * 1024
	guestFileArgumentCount = 3
	guestDirectoryMode     = 0o700
	guestFileMode          = 0o600
)

// These commands use the caller's ordinary file permissions. Managed Exec has
// already selected the guest user's identity before starting this binary.
func newGuestFileReadCommand() *cobra.Command {
	return &cobra.Command{
		Use: "guest-file-read path offset limit", Hidden: true, DisableFlagParsing: true,
		Args: cobra.ExactArgs(guestFileArgumentCount),
		RunE: func(cmd *cobra.Command, args []string) error {
			offset, limit, err := fileReadNumbers(args[1], args[2])
			if err != nil {
				return err
			}
			return readGuestFile(args[0], offset, limit, cmd.OutOrStdout())
		},
	}
}

func fileReadNumbers(offsetText, limitText string) (int64, int64, error) {
	offset, err := strconv.ParseInt(offsetText, 10, 64)
	if err != nil || offset < 0 {
		return 0, 0, errors.New("file offset must be nonnegative")
	}
	limit, err := strconv.ParseInt(limitText, 10, 64)
	if err != nil || limit < 0 || limit > guestFileChunk+1 {
		return 0, 0, errors.New("file read limit exceeds one chunk plus EOF sentinel")
	}
	return offset, limit, nil
}

func readGuestFile(path string, offset, limit int64, output io.Writer) error {
	// #nosec G304 -- The requested path uses the caller's existing user permissions.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	_, err = io.CopyN(output, file, limit)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func newGuestFileWriteCommand() *cobra.Command {
	return &cobra.Command{
		Use: "guest-file-write path offset truncate", Hidden: true, DisableFlagParsing: true,
		Args: cobra.ExactArgs(guestFileArgumentCount),
		RunE: func(cmd *cobra.Command, args []string) error {
			offset, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil || offset < 0 {
				return errors.New("file offset must be nonnegative")
			}
			if args[2] != "0" && args[2] != "1" {
				return errors.New("truncate must be 0 or 1")
			}
			count, err := writeGuestFile(args[0], offset, args[2] == "1", cmd.InOrStdin())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), count)
			return err
		},
	}
}

func writeGuestFile(path string, offset int64, truncate bool, input io.Reader) (int, error) {
	data, err := io.ReadAll(io.LimitReader(input, guestFileChunk+1))
	if err != nil {
		return 0, err
	}
	if len(data) > guestFileChunk {
		return 0, errors.New("file write exceeds one chunk")
	}
	if err := os.MkdirAll(filepath.Dir(path), guestDirectoryMode); err != nil {
		return 0, err
	}
	flags := os.O_WRONLY | os.O_CREATE
	if truncate {
		flags |= os.O_TRUNC
	}
	// #nosec G304 -- The requested path uses the caller's existing user permissions.
	file, err := os.OpenFile(path, flags, guestFileMode)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}
	count, err := file.Write(data)
	if err != nil {
		return count, err
	}
	return count, file.Close()
}
