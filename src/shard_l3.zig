//! vnet-l3: packet parsing, routing tables, neighbor discovery and ICMP.
//! The forwarding engine remains in the composition layer until phase 2.

pub const ipv4 = @import("l3/ipv4.zig");
pub const ipv6 = @import("l3/ipv6.zig");
pub const arp = @import("l3/arp.zig");
pub const ndp = @import("l3/ndp.zig");
pub const fib = @import("l3/fib.zig");
pub const fib6 = @import("l3/fib6.zig");
pub const rate = @import("l3/rate.zig");
pub const icmp = @import("l3/icmp.zig");
pub const icmpv6 = @import("l3/icmpv6.zig");

test {
    _ = ipv4;
    _ = ipv6;
    _ = arp;
    _ = ndp;
    _ = fib;
    _ = fib6;
    _ = rate;
    _ = icmp;
    _ = icmpv6;
}
