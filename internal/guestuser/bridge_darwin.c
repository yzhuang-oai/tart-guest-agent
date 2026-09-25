//go:build darwin && cgo

#include "bridge_darwin.h"

#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <membership.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define SN_LOGIN "/System/Library/PrivateFrameworks/login.framework/Versions/Current/login"
#define SN_SKYLIGHT "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight"
#define SN_LOGINWINDOW "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
#define SN_PREPARED_LIMIT (1024U * 1024U)
#define SN_PROCESS_LIMIT 131072U

// PROC_PIDUNIQIDENTIFIERINFO is private. Verify the complete result size before
// admitting its identity, including before/after checks around the BSD snapshot.
struct sn_unique_info {
    unsigned char executable_uuid[16];
    uint64_t unique_id;
    uint64_t parent_unique_id;
    int32_t pid_version;
    int32_t original_parent_version;
    uint64_t reserved[2];
};
_Static_assert(sizeof(struct sn_unique_info) == 56, "unexpected process identity ABI");
_Static_assert(sizeof(auditpinfo_addr_t) == 56, "unexpected audit process ABI");
_Static_assert(sizeof(audit_token_t) == 32, "unexpected audit token ABI");

static int system_error(void) { return errno ? errno : EIO; }

static int process_valid(const sn_process *p) {
    return p && p->pid > 1 && p->unique_id && p->start_seconds &&
           p->start_microseconds < 1000000;
}

static int process_equal(const sn_process *a, const sn_process *b) {
    return a->pid == b->pid && a->uid == b->uid && a->unique_id == b->unique_id &&
           a->start_seconds == b->start_seconds &&
           a->start_microseconds == b->start_microseconds;
}

static int process_info(int32_t pid, int flavor, void *out, size_t size) {
    errno = 0;
    int result = proc_pidinfo(pid, flavor, 1, out, (int)size);
    if (result <= 0) return system_error();
    return (size_t)result == size ? 0 : EPROTO;
}

int sn_snapshot(int32_t pid, sn_process *out) {
    if (pid <= 1 || !out) return EINVAL;
    memset(out, 0, sizeof(*out));
    struct sn_unique_info before = {0}, after = {0};
    struct proc_bsdinfo bsd = {0};
    int err = process_info(pid, 17, &before, sizeof(before));
    if (!err) err = process_info(pid, PROC_PIDTBSDINFO, &bsd, sizeof(bsd));
    if (!err) err = process_info(pid, 17, &after, sizeof(after));
    if (err) return err;
    if (memcmp(&before, &after, sizeof(before)) || bsd.pbi_pid != (uint32_t)pid ||
        bsd.pbi_start_tvusec >= 1000000) return EPROTO;
    sn_process value = {
        .pid = pid, .uid = bsd.pbi_uid, .unique_id = after.unique_id,
        .start_seconds = bsd.pbi_start_tvsec,
        .start_microseconds = (uint32_t)bsd.pbi_start_tvusec,
        .pid_version = (uint32_t)after.pid_version, .status = bsd.pbi_status,
    };
    if (!process_valid(&value)) return EPROTO;
    *out = value;
    return 0;
}

int sn_list(uint32_t uid, int32_t *pids, size_t capacity, size_t *count) {
    if (!pids || !count || !capacity || capacity > SN_PROCESS_LIMIT ||
        (uid != 0 && (uid < 501 || uid >= 65534))) return EINVAL;
    *count = 0;
    errno = 0;
    int result = proc_listpids(PROC_UID_ONLY, uid, pids, (int)(capacity * sizeof(*pids)));
    if (result < 0 || (result == 0 && errno)) return system_error();
    if ((size_t)result % sizeof(*pids) || (size_t)result >= capacity * sizeof(*pids)) return EOVERFLOW;
    size_t used = (size_t)result / sizeof(*pids);
    for (size_t i = 0; i < used; ++i) {
        if (pids[i] > 1) pids[(*count)++] = pids[i];
    }
    return 0;
}

int sn_path(const sn_process *expected, char *path, size_t capacity) {
    if (!process_valid(expected) || !path || capacity < PROC_PIDPATHINFO_MAXSIZE ||
        capacity > UINT32_MAX) return EINVAL;
    memset(path, 0, capacity);
    errno = 0;
    int result = proc_pidpath(expected->pid, path, (uint32_t)capacity);
    if (result <= 0) return system_error();
    if ((size_t)result >= capacity || !memchr(path, '\0', capacity)) return EPROTO;
    sn_process current;
    int err = sn_snapshot(expected->pid, &current);
    if (err) return err;
    return process_equal(expected, &current) ? 0 : ESTALE;
}

int sn_signal(const sn_process *expected, int signal_number) {
    if (!process_valid(expected) || (signal_number != SIGTERM && signal_number != SIGKILL &&
        signal_number != SIGSTOP && signal_number != SIGCONT)) return EINVAL;
    sn_process current;
    int err = sn_snapshot(expected->pid, &current);
    if (err) return err;
    if (!process_equal(expected, &current)) return ESTALE;
    void *library = dlopen("/usr/lib/libproc.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) return ENOTSUP;
    int (*deliver)(audit_token_t *, int) = dlsym(library, "proc_signal_with_audittoken");
    if (!deliver) {
        dlclose(library);
        return ENOTSUP;
    }
    audit_token_t token = {{0, 0, 0, 0, 0, (uint32_t)expected->pid, 0, current.pid_version}};
    err = deliver(&token, signal_number);
    dlclose(library);
    return err > 0 ? err : err == 0 ? 0 : EIO;
}

static void cf_release(CFTypeRef value) { if (value) CFRelease(value); }

static CFStringRef cf_string(const char *value) {
    return CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
}

static int cf_string_equals(CFTypeRef value, const char *expected) {
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
    CFStringRef text = cf_string(expected);
    if (!text) return 0;
    int same = CFEqual(value, text);
    CFRelease(text);
    return same;
}

static int cf_uuid_equals(CFTypeRef value, const char *expected) {
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
    char text[37];
    uuid_t left, right;
    return CFStringGetCString(value, text, sizeof(text), kCFStringEncodingUTF8) &&
           strlen(text) == 36 && uuid_parse(text, left) == 0 && uuid_parse(expected, right) == 0 &&
           uuid_compare(left, right) == 0;
}

static CFTypeRef single_attribute(CFDictionaryRef details, CFStringRef key) {
    CFTypeRef value = CFDictionaryGetValue(details, key);
    if (!value || CFGetTypeID(value) != CFArrayGetTypeID() || CFArrayGetCount(value) != 1) return NULL;
    return CFArrayGetValueAtIndex(value, 0);
}

static int dictionary_string(CFMutableDictionaryRef dictionary, CFStringRef key, const char *text, int array) {
    CFStringRef value = cf_string(text);
    if (!value) return EINVAL;
    CFArrayRef values = NULL;
    if (array) {
        const void *element = value;
        values = CFArrayCreate(NULL, &element, 1, &kCFTypeArrayCallBacks);
        if (!values) { CFRelease(value); return ENOMEM; }
    }
    CFDictionarySetValue(dictionary, key, array ? (CFTypeRef)values : value);
    cf_release(values);
    CFRelease(value);
    return 0;
}

static CFMutableDictionaryRef dictionary(void) {
    return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

static int plist_parse(const void *bytes, size_t length, size_t maximum, CFPropertyListRef *out) {
    *out = NULL;
    if (!bytes || !length || length > maximum || length > LONG_MAX) return EINVAL;
    CFDataRef data = CFDataCreate(NULL, bytes, (CFIndex)length);
    if (!data) return ENOMEM;
    *out = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(data);
    return *out ? 0 : EPROTO;
}

struct directory_api {
    void *library;
    ODNodeRef (*node)(CFAllocatorRef, ODSessionRef, ODNodeType, CFErrorRef *);
    ODRecordRef (*create)(ODNodeRef, ODRecordType, CFStringRef, CFDictionaryRef, CFErrorRef *);
    ODRecordRef (*copy)(ODNodeRef, ODRecordType, CFStringRef, CFTypeRef, CFErrorRef *);
    bool (*password)(ODRecordRef, CFStringRef, CFStringRef, CFErrorRef *);
    bool (*auth)(ODRecordRef, CFStringRef, CFErrorRef *);
    bool (*sync)(ODRecordRef, CFErrorRef *);
    bool (*remove)(ODRecordRef, CFErrorRef *);
    CFDictionaryRef (*details)(ODRecordRef, CFArrayRef, CFErrorRef *);
    ODQueryRef (*query)(CFAllocatorRef, ODNodeRef, CFTypeRef, ODAttributeType, ODMatchType, CFTypeRef, CFTypeRef, CFIndex, CFErrorRef *);
    CFArrayRef (*results)(ODQueryRef, bool, CFErrorRef *);
    int valid;
};

static struct directory_api directory_api;
static pthread_once_t directory_once = PTHREAD_ONCE_INIT;

static void directory_load(void) {
    struct directory_api *api = &directory_api;
    api->library = dlopen("/System/Library/Frameworks/OpenDirectory.framework/OpenDirectory", RTLD_NOW | RTLD_LOCAL);
    if (!api->library) return;
#define OD_SYMBOL(field, name) do { api->field = dlsym(api->library, name); if (!api->field) return; } while (0)
    OD_SYMBOL(node, "ODNodeCreateWithNodeType");
    OD_SYMBOL(create, "ODNodeCreateRecord");
    OD_SYMBOL(copy, "ODNodeCopyRecord");
    OD_SYMBOL(password, "ODRecordChangePassword");
    OD_SYMBOL(auth, "ODRecordVerifyPassword");
    OD_SYMBOL(sync, "ODRecordSynchronize");
    OD_SYMBOL(remove, "ODRecordDelete");
    OD_SYMBOL(details, "ODRecordCopyDetails");
    OD_SYMBOL(query, "ODQueryCreateWithNode");
    OD_SYMBOL(results, "ODQueryCopyResults");
#undef OD_SYMBOL
    // Retain the framework for process lifetime, including any CF record caches.
    api->valid = 1;
}

static int directory_ready(void) {
    int err = pthread_once(&directory_once, directory_load);
    return err ? err : directory_api.valid ? 0 : ENOTSUP;
}

static int library_symbols(const char *path, const char *const *symbols, size_t count) {
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) return ENOTSUP;
    int err = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!dlsym(library, symbols[i])) { err = ENOTSUP; break; }
    }
    dlclose(library);
    return err;
}

int sn_capabilities(void) {
    int err = directory_ready();
    const char *const login[] = {
        "SACStartSessionForUser", "SACSwitchToUser", "LFSMMoveSessionToConsoleTemporaryBridge",
    };
    const char *const sky[] = {"SLSSessionSwitchToAuditSessionID"};
    const char *const audit[] = {"audit_get_pinfo_addr", "audit_session_port", "audit_session_join"};
    const char *const process[] = {"proc_signal_with_audittoken"};
    if (!err) err = library_symbols(SN_LOGIN, login, sizeof(login) / sizeof(login[0]));
    if (!err) err = library_symbols(SN_SKYLIGHT, sky, sizeof(sky) / sizeof(sky[0]));
    if (!err) err = library_symbols("/usr/lib/libbsm.dylib", audit, sizeof(audit) / sizeof(audit[0]));
    if (!err) err = library_symbols("/usr/lib/libproc.dylib", process, sizeof(process) / sizeof(process[0]));
    return err;
}

static int account_valid(const sn_account *account, int require_generation) {
    if (!account || account->uid < 501 || account->uid >= 65534 ||
        account->gid == 0 || account->gid == 80 || !account->name || !account->home ||
        !account->generation) return EINVAL;
    size_t name_length = strnlen(account->name, 64);
    if (!name_length || name_length >= 64 ||
        !((account->name[0] >= 'A' && account->name[0] <= 'Z') ||
          (account->name[0] >= 'a' && account->name[0] <= 'z'))) return EINVAL;
    for (size_t i = 0; i < name_length; ++i) {
        char c = account->name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-')) return EINVAL;
    }
    size_t home_length = strnlen(account->home, PATH_MAX);
    if (!home_length || home_length >= PATH_MAX || account->home[0] != '/' ||
        account->home[home_length - 1] == '/' || strstr(account->home, "//") ||
        strstr(account->home, "/../") || strstr(account->home, "/./")) return EINVAL;
    const char *base = strrchr(account->home, '/');
    if (!base || strcmp(base + 1, account->name)) return EINVAL;
    for (size_t i = 0; i < home_length; ++i) {
        if ((unsigned char)account->home[i] < 32 || (unsigned char)account->home[i] == 127) return EINVAL;
    }
    if (*account->generation) {
        uuid_t value;
        if (strnlen(account->generation, 37) != 36 || uuid_parse(account->generation, value) || uuid_is_null(value)) return EINVAL;
    } else if (require_generation) {
        return EINVAL;
    }
    return 0;
}

static int require_root(void) { return getuid() == 0 && geteuid() == 0 ? 0 : EPERM; }

static int account_details(CFDictionaryRef details, const sn_account *account) {
    if (!details || CFGetTypeID(details) != CFDictionaryGetTypeID()) return EPROTO;
    char uid[16], gid[16];
    snprintf(uid, sizeof(uid), "%u", account->uid);
    snprintf(gid, sizeof(gid), "%u", account->gid);
    if (!cf_string_equals(single_attribute(details, CFSTR("dsAttrTypeStandard:RecordName")), account->name) ||
        !cf_string_equals(single_attribute(details, CFSTR("dsAttrTypeStandard:UniqueID")), uid) ||
        !cf_string_equals(single_attribute(details, CFSTR("dsAttrTypeStandard:PrimaryGroupID")), gid) ||
        !cf_string_equals(single_attribute(details, CFSTR("dsAttrTypeStandard:NFSHomeDirectory")), account->home)) return ESTALE;
    if (*account->generation && !cf_uuid_equals(single_attribute(details, CFSTR("dsAttrTypeStandard:GeneratedUID")), account->generation)) return ESTALE;
    return 0;
}

static int password_value(const char *value, int creating, CFStringRef *out) {
    *out = NULL;
    if (!value) return EINVAL;
    size_t length = strnlen(value, 513);
    if (length < (creating ? 24U : 1U) || length > 512) return EINVAL;
    CFStringRef string = cf_string(value);
    if (!string) return EINVAL;
    if (CFStringFindCharacterFromSet(string, CFCharacterSetGetPredefined(kCFCharacterSetControl),
                                    CFRangeMake(0, CFStringGetLength(string)), 0, NULL)) {
        CFRelease(string);
        return EINVAL;
    }
    *out = string;
    return 0;
}

static int passwd_matches(const struct passwd *found, const sn_account *account) {
    return found && found->pw_name && found->pw_dir && found->pw_uid == account->uid &&
           found->pw_gid == account->gid && !strcmp(found->pw_name, account->name) &&
           !strcmp(found->pw_dir, account->home);
}

static int account_nss(const sn_account *account, int absent) {
    char *buffer = malloc(65536);
    if (!buffer) return ENOMEM;
    struct passwd value, *found = NULL;
    int err = getpwnam_r(account->name, &value, buffer, 65536, &found);
    if (err == ENOENT && !found) err = 0;
    if (!err && (absent ? found != NULL : !passwd_matches(found, account))) err = absent ? EEXIST : ESTALE;
    if (!err) {
        found = NULL;
        err = getpwuid_r(account->uid, &value, buffer, 65536, &found);
        if (err == ENOENT && !found) err = 0;
        if (!err && (absent ? found != NULL : !passwd_matches(found, account))) err = absent ? EEXIST : ESTALE;
    }
    free(buffer);
    return err;
}

static int account_nonadmin(const sn_account *account) {
    if (!*account->generation) return 0; // The existing controller is never modified.
    uuid_t user, group, expected;
    int member = 0;
    int err = mbr_uid_to_uuid(account->uid, user);
    if (!err && (uuid_parse(account->generation, expected) || uuid_compare(user, expected))) err = ESTALE;
    if (!err) err = mbr_gid_to_uuid(80, group);
    if (!err) err = mbr_check_membership(user, group, &member);
    return err ? err : member ? EACCES : 0;
}

static int record_verify(ODRecordRef record, const sn_account *account, int native_lookup) {
    CFDictionaryRef details = directory_api.details(record, NULL, NULL);
    int err = account_details(details, account);
    cf_release(details);
    if (!err && native_lookup) err = account_nss(account, 0);
    if (!err && native_lookup) err = account_nonadmin(account);
    return err;
}

static int query_absent(ODNodeRef node, CFStringRef attribute, const char *value) {
    CFStringRef text = cf_string(value);
    if (!text) return EINVAL;
    ODQueryRef query = directory_api.query(NULL, node, CFSTR("dsRecTypeStandard:Users"),
                                         attribute, kODMatchEqualTo, text, NULL, 2, NULL);
    CFRelease(text);
    if (!query) return EIO;
    CFArrayRef results = directory_api.results(query, false, NULL);
    CFRelease(query);
    if (!results) return EIO;
    int err = CFGetTypeID(results) != CFArrayGetTypeID() ? EPROTO :
              CFArrayGetCount(results) != 0 ? EEXIST : 0;
    CFRelease(results);
    return err;
}

static int record_absent(ODNodeRef node, const sn_account *account) {
    int err = query_absent(node, CFSTR("dsAttrTypeStandard:RecordName"), account->name);
    char uid[16];
    snprintf(uid, sizeof(uid), "%u", account->uid);
    if (!err) err = query_absent(node, CFSTR("dsAttrTypeStandard:UniqueID"), uid);
    return err;
}

static int account_absent(ODNodeRef node, const sn_account *account) {
    int err = account_nss(account, 1);
    return err ? err : record_absent(node, account);
}

static int record_copy(ODNodeRef node, const sn_account *account, ODRecordRef *record) {
    *record = NULL;
    CFStringRef name = cf_string(account->name);
    if (!name) return EINVAL;
    CFErrorRef error = NULL;
    *record = directory_api.copy(node, CFSTR("dsRecTypeStandard:Users"), name, NULL, &error);
    CFRelease(name);
    int err = *record ? 0 : error && CFErrorGetCode(error) == kODErrorRecordNoLongerExists ? ENOENT : EIO;
    cf_release(error);
    return err;
}

static int record_create(ODNodeRef node, const sn_account *account, CFStringRef secret) {
    int err = account_absent(node, account);
    if (err) return err;
    CFMutableDictionaryRef attributes = dictionary();
    CFStringRef name = cf_string(account->name);
    if (!attributes || !name) { cf_release(attributes); cf_release(name); return ENOMEM; }
    char uid[16], gid[16];
    snprintf(uid, sizeof(uid), "%u", account->uid);
    snprintf(gid, sizeof(gid), "%u", account->gid);
    err = dictionary_string(attributes, CFSTR("dsAttrTypeStandard:UniqueID"), uid, 1);
    if (!err) err = dictionary_string(attributes, CFSTR("dsAttrTypeStandard:PrimaryGroupID"), gid, 1);
    if (!err) err = dictionary_string(attributes, CFSTR("dsAttrTypeStandard:NFSHomeDirectory"), account->home, 1);
    if (!err) err = dictionary_string(attributes, CFSTR("dsAttrTypeStandard:GeneratedUID"), account->generation, 1);
    if (!err) err = dictionary_string(attributes, CFSTR("dsAttrTypeStandard:UserShell"), "/bin/zsh", 1);
    if (!err) err = dictionary_string(attributes, CFSTR("dsAttrTypeStandard:RealName"), "Disposable guest user", 1);
    ODRecordRef record = NULL;
    if (!err) {
        // The generation marker is part of the initial create, before any
        // password side effect. Partial failures remain attributable to it.
        record = directory_api.create(node, CFSTR("dsRecTypeStandard:Users"), name, attributes, NULL);
        if (!record) err = EIO;
    }
    if (!err) err = record_verify(record, account, 0);
    if (!err && !directory_api.password(record, NULL, secret, NULL)) err = EACCES;
    if (!err && !directory_api.auth(record, secret, NULL)) err = EACCES;
    if (!err && !directory_api.sync(record, NULL)) err = EIO;
    if (!err) err = record_verify(record, account, 1);
    cf_release(record);
    CFRelease(attributes);
    CFRelease(name);
    return err;
}

int sn_account_op(const sn_account *account, const char *operation) {
    if (!operation) return EINVAL;
    int create = !strcmp(operation, "create"), absent = !strcmp(operation, "absent");
    int verify = !strcmp(operation, "verify"), auth = !strcmp(operation, "auth");
    int remove = !strcmp(operation, "delete");
    if (!create && !absent && !verify && !auth && !remove) return EINVAL;
    int err = require_root();
    if (!err) err = account_valid(account, create || absent || remove);
    if (!err) err = directory_ready();
    if (err) return err;
    CFStringRef secret = NULL;
    if (create || auth) err = password_value(account->password, create, &secret);
    if (err) return err;
    ODNodeRef node = directory_api.node(NULL, NULL, kODNodeTypeLocalNodes, NULL);
    if (!node) { cf_release(secret); return EIO; }
    ODRecordRef record = NULL;
    if (create) {
        err = record_create(node, account, secret);
    } else if (absent) {
        err = account_absent(node, account);
    } else {
        err = record_copy(node, account, &record);
        if (!err) err = record_verify(record, account, 1);
        if (!err && auth && !directory_api.auth(record, secret, NULL)) err = EACCES;
        if (!err && remove && !directory_api.remove(record, NULL)) err = EIO;
        // NSS can retain the deleted identity after the local record is gone.
        if (!err && remove) err = record_absent(node, account);
    }
    cf_release(record);
    CFRelease(node);
    cf_release(secret);
    return err;
}

int sn_prepare(const sn_account *account, void **bytes, size_t *length) {
    if (!bytes || !length) return EINVAL;
    *bytes = NULL;
    *length = 0;
    int err = sn_account_op(account, "auth");
    if (err) return err;
    ODNodeRef node = directory_api.node(NULL, NULL, kODNodeTypeLocalNodes, NULL);
    if (!node) return EIO;
    ODRecordRef record = NULL;
    CFDictionaryRef original = NULL;
    CFMutableDictionaryRef details = NULL;
    CFDataRef data = NULL;
    err = record_copy(node, account, &record);
    if (!err) {
        original = directory_api.details(record, NULL, NULL);
        err = account_details(original, account);
    }
    if (!err) {
        details = CFDictionaryCreateMutableCopy(NULL, 0, original);
        if (!details) err = ENOMEM;
    }
    if (!err) err = dictionary_string(details, CFSTR("UserName"), account->name, 0);
    if (!err) err = dictionary_string(details, CFSTR("UserPasswordKey"), account->password, 0);
    if (!err) {
        data = CFPropertyListCreateData(NULL, details, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
        if (!data) err = EPROTO;
    }
    if (!err) {
        CFIndex count = CFDataGetLength(data);
        if (count <= 0 || count > SN_PREPARED_LIMIT) err = EOVERFLOW;
        else {
            *bytes = malloc((size_t)count);
            if (!*bytes) err = ENOMEM;
            else {
                memcpy(*bytes, CFDataGetBytePtr(data), (size_t)count);
                *length = (size_t)count;
            }
        }
    }
    cf_release(data);
    cf_release(details);
    cf_release(original);
    cf_release(record);
    CFRelease(node);
    return err;
}

static int console_uid(uint32_t *uid) {
    struct stat information;
    if (stat("/dev/console", &information) < 0) return system_error();
    if (!S_ISCHR(information.st_mode)) return EPROTO;
    *uid = information.st_uid;
    return 0;
}

int sn_audit(const sn_process *loginwindow, int32_t *asid) {
    if (!process_valid(loginwindow) || !asid ||
        (loginwindow->uid != 0 && (loginwindow->uid < 501 || loginwindow->uid >= 65534))) return EINVAL;
    *asid = 0;
    int err = require_root();
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (!err) err = sn_path(loginwindow, path, sizeof(path));
    if (!err && strcmp(path, SN_LOGINWINDOW)) err = EACCES;
    if (err) return err;
    void *library = dlopen("/usr/lib/libbsm.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) return ENOTSUP;
    int (*get)(auditpinfo_addr_t *, size_t) = dlsym(library, "audit_get_pinfo_addr");
    if (!get) { dlclose(library); return ENOTSUP; }
    auditpinfo_addr_t information = {.ap_pid = loginwindow->pid};
    errno = 0;
    if (get(&information, sizeof(information)) < 0) err = system_error();
    uint32_t expected_uid = loginwindow->uid == 0 ? (uint32_t)AU_DEFAUDITID : loginwindow->uid;
    if (!err && (information.ap_pid != loginwindow->pid || information.ap_auid != expected_uid ||
        information.ap_asid == 0 || information.ap_asid == (au_asid_t)-1)) err = ESTALE;
    if (!err && loginwindow->uid == 0) {
        uint32_t uid;
        err = console_uid(&uid);
        if (!err && uid != 0) err = ESTALE;
    }
    sn_process current;
    if (!err) err = sn_snapshot(loginwindow->pid, &current);
    if (!err && !process_equal(loginwindow, &current)) err = ESTALE;
    if (!err) *asid = (int32_t)information.ap_asid;
    dlclose(library);
    return err;
}

static int join_loginwindow(const sn_process *loginwindow) {
    int32_t expected_session;
    int err = sn_audit(loginwindow, &expected_session);
    if (err) return err;
    void *library = dlopen("/usr/lib/libbsm.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) return ENOTSUP;
    int (*port)(au_asid_t, mach_port_name_t *) = dlsym(library, "audit_session_port");
    au_asid_t (*join)(mach_port_name_t) = dlsym(library, "audit_session_join");
    if (!port || !join) { dlclose(library); return ENOTSUP; }
    mach_port_name_t name = MACH_PORT_NULL;
    errno = 0;
    if (port((au_asid_t)expected_session, &name) < 0) err = system_error();
    if (!err && name == MACH_PORT_NULL) err = EPROTO;
    if (!err && join(name) != (au_asid_t)expected_session) err = EIO;
    if (name != MACH_PORT_NULL && mach_port_deallocate(mach_task_self(), name) != KERN_SUCCESS && !err) err = EIO;
    if (!err) {
        int32_t current_session;
        err = sn_audit(loginwindow, &current_session);
        if (!err && current_session != expected_session) err = ESTALE;
    }
    dlclose(library);
    return err;
}

int sn_activate(const sn_account *account, const void *bytes, size_t length,
                const sn_process *loginwindow, int start) {
    if (start != 0 && start != 1) return EINVAL;
    int err = require_root();
    if (!err) err = account_valid(account, 0);
    CFStringRef secret = NULL;
    if (!err) err = password_value(account->password, 0, &secret);
    CFPropertyListRef details = NULL;
    if (!err) err = plist_parse(bytes, length, SN_PREPARED_LIMIT, &details);
    if (!err) err = account_details(details, account);
    if (!err && (!cf_string_equals(CFDictionaryGetValue(details, CFSTR("UserName")), account->name) ||
                 !cf_string_equals(CFDictionaryGetValue(details, CFSTR("UserPasswordKey")), account->password))) err = ESTALE;
    void *library = NULL;
    if (!err) {
        library = dlopen(SN_LOGIN, RTLD_NOW | RTLD_LOCAL);
        if (!library) err = ENOTSUP;
    }
    int (*activate)(CFDictionaryRef) = NULL;
    if (!err) {
        activate = dlsym(library, start ? "SACStartSessionForUser" : "SACSwitchToUser");
        if (!activate) err = ENOTSUP;
    }
    // First login enters this loginwindow's bootstrap with bsexec. Switching an
    // existing session keeps the system bootstrap. Both join the selected audit
    // session here, which is a process-wide operation in the dedicated helper.
    if (!err) err = join_loginwindow(loginwindow);
    if (!err && activate(details) != 0) err = EIO;
    if (library) dlclose(library);
    cf_release(details);
    cf_release(secret);
    return err;
}

static int dictionary_integer(CFMutableDictionaryRef details, CFStringRef key, int64_t integer) {
    CFNumberRef value = CFNumberCreate(NULL, kCFNumberSInt64Type, &integer);
    if (!value) return ENOMEM;
    CFDictionarySetValue(details, key, value);
    CFRelease(value);
    return 0;
}

static int recover_background(void *login, const sn_account *account,
                              const sn_process *loginwindow, int32_t session_id) {
    void *sky = dlopen(SN_SKYLIGHT, RTLD_NOW | RTLD_LOCAL);
    if (!sky) return ENOTSUP;
    int (*select_session)(int32_t) = dlsym(sky, "SLSSessionSwitchToAuditSessionID");
    void (*bridge)(CFDictionaryRef) = dlsym(login, "LFSMMoveSessionToConsoleTemporaryBridge");
    if (!select_session || !bridge) { dlclose(sky); return ENOTSUP; }
    CFMutableDictionaryRef details = dictionary();
    if (!details) { dlclose(sky); return ENOMEM; }
    int err = dictionary_integer(details, CFSTR("kCGSSessionAuditIDKey"), session_id);
    if (!err) err = dictionary_integer(details, CFSTR("kCGSSessionUserIDKey"), account->uid);
    if (!err) err = dictionary_integer(details, CFSTR("kCGSSessionGroupIDKey"), account->gid);
    if (!err) err = dictionary_integer(details, CFSTR("AuditSessionID"), session_id);
    if (!err) err = dictionary_integer(details, CFSTR("UserID"), account->uid);
    if (!err) err = dictionary_integer(details, CFSTR("GroupID"), account->gid);
    int32_t observed;
    if (!err) err = sn_audit(loginwindow, &observed);
    if (!err && observed != session_id) err = ESTALE;
    if (!err && select_session(session_id) != 0) err = EIO;
    if (!err) err = sn_audit(loginwindow, &observed);
    if (!err && observed != session_id) err = ESTALE;
    if (!err) bridge(details);
    CFRelease(details);
    dlclose(sky);
    return err;
}

int sn_recover(const sn_account *account, const sn_process *loginwindow) {
    if (!process_valid(loginwindow)) return EINVAL;
    int err = require_root();
    if (!err) err = account_valid(account, 0);
    if (!err && loginwindow->uid != account->uid) err = ESTALE;
    if (!err) err = sn_account_op(account, "auth");
    int32_t session_id;
    if (!err) err = sn_audit(loginwindow, &session_id);
    uint32_t owner;
    if (!err) err = console_uid(&owner);
    if (!err && owner != 0 && owner != account->uid) err = EBUSY;
    if (err) return err;
    void *login = dlopen(SN_LOGIN, RTLD_NOW | RTLD_LOCAL);
    if (!login) return ENOTSUP;
    err = recover_background(login, account, loginwindow, session_id);
    dlclose(login);
    return err;
}

static int console_rows(CFTypeRef root, uint32_t uid, size_t *row_sets, size_t *found, int *ready) {
    if (CFGetTypeID(root) != CFDictionaryGetTypeID()) return EPROTO;
    CFTypeRef rows = CFDictionaryGetValue(root, CFSTR("IOConsoleUsers"));
    if (!rows) return 0;
    if (CFGetTypeID(rows) != CFArrayGetTypeID()) return EPROTO;
    if (++*row_sets > 1) return EPROTO;
    CFIndex count = CFArrayGetCount(rows);
    if (count < 0 || count > 4096) return EOVERFLOW;
    for (CFIndex i = 0; i < count; ++i) {
        CFTypeRef row = CFArrayGetValueAtIndex(rows, i);
        if (!row || CFGetTypeID(row) != CFDictionaryGetTypeID()) return EPROTO;
        CFTypeRef owner = CFDictionaryGetValue(row, CFSTR("kCGSSessionUserIDKey"));
        int64_t value;
        if (!owner || CFGetTypeID(owner) != CFNumberGetTypeID() ||
            !CFNumberGetValue(owner, kCFNumberSInt64Type, &value) || value < 0 || value > UINT32_MAX) return EPROTO;
        if ((uint32_t)value != uid) continue;
        if (++*found > 1) return EPROTO;
        CFTypeRef console = CFDictionaryGetValue(row, CFSTR("kCGSSessionOnConsoleKey"));
        CFTypeRef locked = CFDictionaryGetValue(row, CFSTR("CGSSessionScreenIsLocked"));
        if (!console || CFGetTypeID(console) != CFBooleanGetTypeID() ||
            (locked && CFGetTypeID(locked) != CFBooleanGetTypeID())) return EPROTO;
        // The registry omits ScreenIsLocked when unlocked on supported images.
        *ready = CFBooleanGetValue(console) && (!locked || !CFBooleanGetValue(locked));
    }
    return 0;
}

int sn_console(const void *plist, size_t length, uint32_t uid, int *present, int *ready) {
    if (!present || !ready || (uid != 0 && (uid < 501 || uid >= 65534))) return EINVAL;
    *present = 0;
    *ready = 0;
    CFPropertyListRef root = NULL;
    int err = plist_parse(plist, length, 4U * 1024U * 1024U, &root);
    if (err) return err;
    size_t found = 0;
    size_t row_sets = 0;
    int selected = 0;
    if (CFGetTypeID(root) == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(root);
        if (count < 0 || count > 4096) err = EOVERFLOW;
        for (CFIndex i = 0; !err && i < count; ++i) err = console_rows(CFArrayGetValueAtIndex(root, i), uid, &row_sets, &found, &selected);
    } else {
        err = console_rows(root, uid, &row_sets, &found, &selected);
    }
    if (!err && row_sets != 1) err = EPROTO;
    if (!err) {
        *present = found == 1;
        *ready = found == 1 && selected;
    }
    CFRelease(root);
    return err;
}
