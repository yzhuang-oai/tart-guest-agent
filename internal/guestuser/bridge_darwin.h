#ifndef TART_SESSION_NATIVE_BRIDGE_H
#define TART_SESSION_NATIVE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

// All functions return zero on success and an errno value otherwise. They never
// log credentials or fall back from a checked operation to a broader one.
typedef struct sn_process {
    int32_t pid;
    uint32_t uid;
    uint64_t unique_id;
    uint64_t start_seconds;
    uint32_t start_microseconds;
    uint32_t pid_version;
    uint32_t status;
} sn_process;

typedef struct sn_account {
    uint32_t uid;
    uint32_t gid;
    const char *name;
    const char *home;
    const char *generation;
    const char *password;
} sn_account;

// Symbol checks only; this does not create accounts or select an Aqua session.
int sn_capabilities(void);
int sn_snapshot(int32_t pid, sn_process *out);
// Inventory is bounded and may race process exit. Snapshot every returned PID
// and compare its UID before using it. A full buffer is an error, never success.
int sn_list(uint32_t uid, int32_t *pids, size_t capacity, size_t *count);
int sn_path(const sn_process *expected, char *path, size_t capacity);
int sn_signal(const sn_process *expected, int signal);
// Accepts only the exact system loginwindow executable and its verified audit ID.
int sn_audit(const sn_process *loginwindow, int32_t *asid);

// The following operations belong in a dedicated root helper process. In
// particular, sn_activate joins an audit session and must not run in the daemon.
// account_op accepts absent/create/verify/auth/delete. Empty generation is
// permitted only for verify/auth of an existing controller account.
int sn_account_op(const sn_account *account, const char *operation);
// The caller owns *bytes and must clear the credential envelope before free().
int sn_prepare(const sn_account *account, void **bytes, size_t *length);
int sn_activate(const sn_account *account, const void *bytes, size_t length,
                const sn_process *loginwindow, int start);
int sn_recover(const sn_account *account, const sn_process *loginwindow);

// Presence includes background and locked sessions; readiness requires an
// unlocked foreground session. Exactly one IOConsoleUsers array is required;
// both outputs remain false on a parsing error.
int sn_console(const void *plist, size_t length, uint32_t uid, int *present, int *ready);

#endif
