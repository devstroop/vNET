//! vnet-l2: Ethernet parsing and link-layer protocols.

pub const ethernet = @import("l2/ethernet.zig");
pub const stp = @import("l2/stp.zig");
pub const fdb = @import("l2/fdb.zig");

test {
    _ = ethernet;
    _ = stp;
    _ = fdb;
}
