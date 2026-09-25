# Disposable macOS users

Managed-user mode lets a trusted host create several ordinary macOS accounts in
one VM. Each account has its own UID, home directory and initialized Aqua session.
Commands run in that user's existing Aqua context after dropping root privileges.
Creating another user briefly selects its desktop and then restores the controller;
background commands in other users can continue. This does not provide exclusive
foreground automation or screen capture. Coordinate those operations in the caller.

## Setup

Prepare a disposable macOS Tart image with a controller administrator account.
Install the binary at a canonical path protected from ordinary users and place
the controller password in a root-owned, root-private regular file. Its directory
chain must also be protected from ordinary writes. Do not put the password in
command-line arguments.

Run a root LaunchDaemon with arguments equivalent to:

```sh
/usr/local/bin/tart-guest-agent --run-rpc --manage-users \
  --controller-user=admin \
  --controller-password-file=/var/root/tart-controller-password
```

Run the controller's LaunchAgent with `--run-vdagent` only. Do not use
`--run-agent` there: it also starts RPC and would contend for VSOCK port 8080.
The existing disk-resize daemon may remain separate. Managed mode cannot combine
with `--run-agent`, `--run-vdagent`, or `--exec-wrapper`.

The default managed UID range is 20000 through 65000; `--user-uid-start` and
`--user-uid-end` can narrow it. Existing accounts and active UIDs are skipped.
UIDs are never reused during a daemon boot. On startup, existing managed accounts
cause refusal rather than account adoption. Use a fresh VM after agent restart.

Managed mode rejects ordinary, numeric and empty usernames in Exec. Callers must
select a returned managed username. The agent without `--manage-users` retains
its existing ordinary execution behavior. Only one RPC listener may own port 8080.

## API

| Method | Contract |
| --- | --- |
| `UserInfo` | Returns a random daemon boot UUID and health status. |
| `CreateUser` | Takes the expected boot UUID and a caller request UUID; returns ID, username, UID, GID, home and temporary directory. |
| `DeleteUser` | Takes the expected boot UUID and user ID; stops that user's work and removes its account and private files. |
| `Exec` | Uses the existing command `user` field to select the returned username. Managed execution is attached and non-TTY. |

Creation is serialized around native account setup and Aqua login. Repeating a
request UUID returns its existing account within the same daemon. Deletion is
idempotent; a deleted creation ID cannot be reused. The caller must keep the full
returned identity and original boot UUID. Check `UserInfo` on the same connection
before Exec. A missing managed user never falls back to ordinary execution.

Managed Exec sends `InputAck` after bytes are written or its stdin pipe is closed.
The cumulative byte offset excludes the private helper frame. Treat an exit
response as successful only after the RPC ends successfully. A lost connection
cannot prove cleanup of detached descendants; delete that user after interrupted
execution. Successful deletion stops execution before returning.

Deletion waits for the user's processes and Aqua session to end, then removes
the account, home and temporary directory. macOS services such as Spotlight can
recreate a background launchd domain for a deleted UID. That domain does not
restore the account or Aqua session, so its presence is not a deletion failure.

There is no guest lease timer, allocation-group API, persistent operation journal,
log service or desktop lease. The caller handles idle expiry and capacity. A native
mutation failure or timeout makes the manager unhealthy, cancels its managed work,
and requires VM replacement. A new boot UUID also requires replacement. The agent
does not retry an uncertain native mutation or restore prior users.

## File helpers

`guest-file-read path offset limit` writes raw bytes to stdout.
`guest-file-write path offset truncate` reads stdin through EOF and prints the
number of bytes written. The truncate argument is `0` or `1`. These commands use
the executing user's ordinary filesystem permissions; they have no privileged
file access. Writes accept at most 1 MiB. Reads allow 1 MiB plus one byte so a caller
can determine EOF. Parent directories are created with mode 0700; new files use
0600. Existing modes and normal symlink behavior are preserved. Successful writes
include file close but promise neither fsync durability nor an upload transaction.

Validate account creation, concurrent Aqua commands and deletion on the exact
macOS image before using this mode. Unit tests and cross-platform builds do not
establish installed GUI behavior.
