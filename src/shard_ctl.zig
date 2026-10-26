//! vnet-ctl: control protocol, transactions, journal and host mutations.

const builtin = @import("builtin");

pub const journal = @import("control/journal.zig");
pub const firewall_counters = @import("control/firewall_counters.zig");
pub const state = @import("control/state.zig");
pub const protocol = @import("control/protocol.zig");
pub const config_apply = @import("control/config_apply.zig");
pub const transaction = @import("control/transaction.zig");
pub const read_model = @import("control/read_model.zig");
pub const client = if (builtin.os.tag == .linux)
    @import("control/client.zig")
else
    struct {};
pub const server = if (builtin.os.tag == .linux)
    @import("control/server.zig")
else
    struct {};
pub const offload = if (builtin.os.tag == .linux)
    @import("control/offload.zig")
else
    struct {};
pub const host = if (builtin.os.tag == .linux)
    @import("control/host.zig")
else
    struct {};

test {
    _ = journal;
    _ = firewall_counters;
    _ = state;
    _ = protocol;
    _ = config_apply;
    _ = transaction;
    _ = read_model;
    if (builtin.os.tag == .linux) {
        _ = client;
        _ = server;
        _ = offload;
        _ = host;
    }
}
