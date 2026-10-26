//! IPv6 forwarding table with longest-prefix match. Kept separate from the
//! IPv4 FIB so the mature v4 datapath is not disturbed by dual-stack changes.

const std = @import("std");
const types = @import("vnet-core").types;

pub const Kind = enum {
    connected,
    static,
};

pub const Route = struct {
    prefix: types.Prefix6,
    next_hop: ?types.Ipv6 = null,
    port: types.PortId,
    /// Set when `port` is the first member of a userspace bridge.
    bridge: ?u32 = null,
    /// Canonical egress VLAN; 0 for untagged/non-VLAN routes.
    vlan: u16 = 0,
    metric: u32 = 0,
    kind: Kind = .static,
};

pub const Fib = struct {
    routes: std.ArrayListUnmanaged(Route) = .empty,

    pub fn deinit(self: *Fib, gpa: std.mem.Allocator) void {
        self.routes.deinit(gpa);
    }

    pub fn add(self: *Fib, gpa: std.mem.Allocator, route: Route) !void {
        for (self.routes.items) |*existing| {
            if (existing.prefix.eql(route.prefix) and existing.port.eql(route.port)) {
                existing.* = route;
                return;
            }
        }
        try self.routes.append(gpa, route);
    }

    pub fn remove(self: *Fib, prefix: types.Prefix6, port: types.PortId) bool {
        for (self.routes.items, 0..) |route, i| {
            if (route.prefix.eql(prefix) and route.port.eql(port)) {
                _ = self.routes.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn lookup(self: *const Fib, dst: types.Ipv6) ?Route {
        var best: ?Route = null;
        for (self.routes.items) |route| {
            if (!route.prefix.contains(dst)) continue;
            if (best == null) {
                best = route;
                continue;
            }
            const current = best.?;
            if (route.prefix.len > current.prefix.len) {
                best = route;
            } else if (route.prefix.len == current.prefix.len and route.metric < current.metric) {
                best = route;
            }
        }
        return best;
    }

    pub fn count(self: *const Fib) usize {
        return self.routes.items.len;
    }
};

const testing = std.testing;

fn testPrefix(comptime s: []const u8) types.Prefix6 {
    return types.Prefix6.parse(s) catch unreachable;
}

fn testIp(comptime s: []const u8) types.Ipv6 {
    return types.Ipv6.parse(s) catch unreachable;
}

const port_a: types.PortId = .{ .value = 1 };
const port_b: types.PortId = .{ .value = 2 };

test "fib6 longest prefix match" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8:1::/48"), .port = port_a, .kind = .connected });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8:2::/48"), .port = port_b, .kind = .connected });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("::/0"), .next_hop = testIp("2001:db8:1::1"), .port = port_a });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8:2:8000::/49"), .port = port_b, .kind = .connected });

    try testing.expectEqual(@as(u8, 49), fib.lookup(testIp("2001:db8:2:8000::1")).?.prefix.len);
    try testing.expectEqual(@as(u8, 48), fib.lookup(testIp("2001:db8:2:1::1")).?.prefix.len);
    try testing.expectEqual(@as(u8, 0), fib.lookup(testIp("2001:db9::1")).?.prefix.len);
    try testing.expect(fib.lookup(testIp("2001:db9::1")).?.next_hop.?.eql(testIp("2001:db8:1::1")));
}

test "fib6 metric breaks equal prefixes" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8:9::/48"), .port = port_a, .metric = 100 });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8:9::/48"), .port = port_b, .metric = 10 });

    try testing.expect(fib.lookup(testIp("2001:db8:9::1")).?.port.eql(port_b));
}

test "fib6 replace, remove and miss" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8::/32"), .port = port_a, .metric = 50 });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("2001:db8::/32"), .port = port_a, .metric = 5 });
    try testing.expectEqual(@as(usize, 1), fib.count());
    try testing.expectEqual(@as(u32, 5), fib.lookup(testIp("2001:db8::1")).?.metric);

    try testing.expect(fib.remove(testPrefix("2001:db8::/32"), port_a));
    try testing.expect(fib.lookup(testIp("2001:db8::1")) == null);
    try testing.expect(!fib.remove(testPrefix("2001:db8::/32"), port_a));
}
