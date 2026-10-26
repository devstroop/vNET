//! vnet-dns: DNS wire format, cache, diagnostics and forwarder.

pub const message = @import("services/dns/message.zig");
pub const probe = @import("services/dns/probe.zig");
pub const cache = @import("services/dns/cache.zig");
pub const service = @import("services/dns/service.zig");

test {
    _ = message;
    _ = probe;
    _ = cache;
    _ = service;
}
