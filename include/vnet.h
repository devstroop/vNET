#ifndef VNET_H
#define VNET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VNET_ABI_VERSION 3u

/*
 * The native library uses the host's POSIX threads. Android bionic provides
 * them; Linux consumers of an older libc should link with -pthread.
 */

typedef void *vnet_t;

enum {
    VNET_OK = 0,
    VNET_ERR_INVALID_ARGUMENT = -1,
    VNET_ERR_INVALID_CONFIG = -2,
    VNET_ERR_OUT_OF_MEMORY = -3,
    VNET_ERR_BUSY = -4,
    VNET_ERR_UNSUPPORTED = -5,
    VNET_ERR_PERMISSION = -6,
    VNET_ERR_IO = -7,
    VNET_ERR_NOT_FOUND = -8,
    VNET_ERR_INTERNAL = -9
};

enum {
    VNET_EVENT_STARTED = 1,
    VNET_EVENT_STOPPED = 2,
    VNET_EVENT_ERROR = 3
};

typedef struct vnet_status {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t running;
    uint32_t port_count;
    uint64_t uptime_ms;
} vnet_status_t;

typedef void (*vnet_event_cb)(void *user, int event, const char *message);

/*
 * Create an instance from a complete JSON config. Returns NULL when the JSON
 * is malformed or fails validation. The input buffer is not retained.
 *
 * Hosts may configure an existing L3 port (kind "l3" without "create") and
 * inject its descriptor with vnet_set_port_fd before vnet_start.
 */
vnet_t vnet_create(const char *config_json);

/* Starts the data plane. Blocks until startup succeeds or fails. */
int vnet_start(vnet_t handle);

/* Stops the data plane and joins the data-plane thread. Idempotent. */
int vnet_stop(vnet_t handle);

/* Stops if needed and releases all native resources. */
void vnet_destroy(vnet_t handle);

/*
 * Bind a host-owned descriptor to a configured L3 port.
 *
 * The descriptor is borrowed: vNET duplicates it during vnet_start, so
 * the caller keeps ownership and may close it after vnet_start returns.
 * It must remain valid for every vnet_start call. A stopped handle reuses
 * the same bindings when restarted. Call before vnet_start.
 *
 * vNET sets O_NONBLOCK on the duplicate. Since dup() shares the open file
 * description, the original descriptor also becomes non-blocking.
 */
int vnet_set_port_fd(vnet_t handle, const char *name, int fd);

/*
 * Install a lifecycle callback. Events run on the data-plane thread. STARTED
 * is delivered before vnet_start returns. Do not call vnet_* functions
 * other than vnet_get_status from inside the callback; vnet_stop and
 * vnet_destroy would deadlock. Keep callbacks short. `message` may be NULL
 * and is valid only for the duration of the callback.
 */
int vnet_set_event_cb(vnet_t handle, vnet_event_cb callback, void *user);

/* Fill a caller-owned status snapshot. */
int vnet_get_status(vnet_t handle, vnet_status_t *status);

/* Returns a static NUL-terminated version string. */
const char *vnet_version(void);

#ifdef __cplusplus
}
#endif

#endif
