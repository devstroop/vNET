//! vnet-port: port vtable, buffer pools and platform port implementations.

const builtin = @import("builtin");

pub const port = @import("port/port.zig");
pub const memory = @import("port/memory.zig");
pub const pool = @import("port/pool.zig");
pub const fd = if (builtin.os.tag == .linux)
    @import("port/fd.zig")
else
    struct {};
pub const manager = if (builtin.os.tag == .linux)
    @import("port/manager.zig")
else
    struct {};
pub const linux = if (builtin.os.tag == .linux)
    @import("port/linux/root.zig")
else
    struct {};

test {
    _ = port;
    _ = memory;
    _ = pool;
    if (builtin.os.tag == .linux) {
        _ = fd;
        _ = manager;
        _ = linux;
    }
}
