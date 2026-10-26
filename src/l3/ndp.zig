//! IPv6 Neighbor Discovery (RFC 4861) messages and neighbor cache. This
//! milestone implements Neighbor Solicitation/Advertisement only; router
//! discovery and address autoconfiguration are intentionally absent. The
//! router does not initiate DAD but answers probes for its own addresses.

const std = @import("std");
const types = @import("vnet-core").types;
const ipv6 = @import("ipv6.zig");

pub const Error = error{
    Truncated,
    Unsupported,
    BadOption,
    NoSpace,
};

pub const Type = struct {
    pub const neighbor_solicitation: u8 = 135;
    pub const neighbor_advertisement: u8 = 136;
};

pub const OptionType = struct {
    pub const source_link_layer: u8 = 1;
    pub const target_link_layer: u8 = 2;
};

pub const Flag = struct {
    pub const router: u32 = 0x80000000;
    pub const solicited: u32 = 0x40000000;
    pub const override: u32 = 0x20000000;
};

pub const Message = struct {
    typ: u8,
    target: types.Ipv6,
    /// NA flags; zero for NS.
    flags: u32 = 0,
    source_mac: ?types.Mac = null,
    target_mac: ?types.Mac = null,
};

pub fn parse(payload: []const u8) Error!Message {
    if (payload.len < 24) return error.Truncated;
    const typ = payload[0];
    if (typ != Type.neighbor_solicitation and typ != Type.neighbor_advertisement) {
        return error.Unsupported;
    }

    var message = Message{
        .typ = typ,
        .target = types.Ipv6.fromBytes(payload[8..24].*),
        .flags = if (typ == Type.neighbor_advertisement) readU32(payload, 4) else 0,
    };

    var off: usize = 24;
    while (off < payload.len) {
        if (off + 2 > payload.len) return error.Truncated;
        const opt_type = payload[off];
        const units = payload[off + 1];
        if (units == 0) return error.BadOption;
        const opt_len = @as(usize, units) * 8;
        if (off + opt_len > payload.len) return error.Truncated;
        if (opt_type == OptionType.source_link_layer or
            opt_type == OptionType.target_link_layer)
        {
            if (opt_len < 8) return error.BadOption;
            const mac = types.Mac{ .bytes = payload[off + 2 ..][0..6].* };
            if (opt_type == OptionType.source_link_layer) {
                message.source_mac = mac;
            } else {
                message.target_mac = mac;
            }
        }
        off += opt_len;
    }
    return message;
}

pub fn writeNeighborSolicitation(
    buf: []u8,
    src: types.Ipv6,
    dst: types.Ipv6,
    target: types.Ipv6,
    source_mac: ?types.Mac,
) Error!usize {
    const total: usize = if (source_mac == null) 24 else 32;
    if (buf.len < total) return error.NoSpace;

    buf[0] = Type.neighbor_solicitation;
    buf[1] = 0;
    writeU16(buf, 2, 0);
    writeU32(buf, 4, 0);
    const target_bytes = target.toBytes();
    @memcpy(buf[8..24], &target_bytes);
    if (source_mac) |mac| writeOption(buf, 24, OptionType.source_link_layer, mac);

    writeU16(buf, 2, ipv6.checksum(src, dst, ipv6.Protocol.icmpv6, buf[0..total]));
    return total;
}

pub fn writeNeighborAdvertisement(
    buf: []u8,
    src: types.Ipv6,
    dst: types.Ipv6,
    target: types.Ipv6,
    flags: u32,
    target_mac: ?types.Mac,
) Error!usize {
    const total: usize = if (target_mac == null) 24 else 32;
    if (buf.len < total) return error.NoSpace;

    buf[0] = Type.neighbor_advertisement;
    buf[1] = 0;
    writeU16(buf, 2, 0);
    writeU32(buf, 4, flags);
    const target_bytes = target.toBytes();
    @memcpy(buf[8..24], &target_bytes);
    if (target_mac) |mac| writeOption(buf, 24, OptionType.target_link_layer, mac);

    writeU16(buf, 2, ipv6.checksum(src, dst, ipv6.Protocol.icmpv6, buf[0..total]));
    return total;
}

/// RFC 4291 §2.7.1: the all-nodes multicast address and its Ethernet mapping.
pub fn allNodesMulticast() types.Ipv6 {
    return .{ .value = (@as(u128, 0xff02) << 112) | 1 };
}

pub fn allNodesMac() types.Mac {
    return .{ .bytes = .{ 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 } };
}

/// RFC 4291 §2.7.1: ff02::1:ff00:0/104 plus the low 24 bits of the target.
pub fn solicitedNodeMulticast(target: types.Ipv6) types.Ipv6 {
    const low24: u128 = target.value & 0x00ff_ffff;
    return .{ .value = (@as(u128, 0xff02) << 112) | (@as(u128, 1) << 32) |
        (@as(u128, 0xff) << 24) | low24 };
}

pub const State = enum {
    incomplete,
    reachable,
    stale,
};

pub const Key = struct {
    vlan: u16 = 0,
    ip: types.Ipv6,
};

pub const Entry = struct {
    mac: types.Mac,
    port: types.PortId,
    updated_ms: i64,
    state: State = .reachable,
};

pub const Cache = struct {
    pub const max_entries: usize = 1024;

    map: std.AutoHashMapUnmanaged(Key, Entry) = .empty,

    pub fn deinit(self: *Cache, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
    }

    pub fn reserve(self: *Cache, gpa: std.mem.Allocator, capacity: u32) !void {
        const limit: u32 = @intCast(max_entries);
        try self.map.ensureTotalCapacity(gpa, @min(capacity, limit));
    }

    pub fn getVlan(self: *const Cache, ip: types.Ipv6, vlan: u16) ?Entry {
        return self.map.get(.{ .vlan = vlan, .ip = ip });
    }

    pub fn getFreshVlan(
        self: *const Cache,
        ip: types.Ipv6,
        vlan: u16,
        port: types.PortId,
        now_ms: i64,
        ttl_ms: i64,
    ) ?Entry {
        const entry = self.getVlan(ip, vlan) orelse return null;
        if (!entry.port.eql(port)) return null;
        if (now_ms - entry.updated_ms > ttl_ms) return null;
        return entry;
    }

    pub fn getFreshAnyVlan(
        self: *const Cache,
        ip: types.Ipv6,
        vlan: u16,
        now_ms: i64,
        ttl_ms: i64,
    ) ?Entry {
        const entry = self.getVlan(ip, vlan) orelse return null;
        if (now_ms - entry.updated_ms > ttl_ms) return null;
        return entry;
    }

    pub fn putVlan(
        self: *Cache,
        gpa: std.mem.Allocator,
        ip: types.Ipv6,
        vlan: u16,
        entry: Entry,
    ) !void {
        const key = Key{ .vlan = vlan, .ip = ip };
        if (self.map.getPtr(key)) |slot| {
            slot.* = entry;
            return;
        }
        if (self.map.count() >= max_entries and !self.evictOldest()) {
            return error.NoSpace;
        }
        try self.map.put(gpa, key, entry);
    }

    pub fn prune(self: *Cache, now_ms: i64, ttl_ms: i64) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const age = now_ms - entry.value_ptr.updated_ms;
            if (age > ttl_ms) self.map.removeByPtr(entry.key_ptr);
        }
    }

    pub fn removeVlan(self: *Cache, ip: types.Ipv6, vlan: u16) bool {
        return self.map.remove(.{ .vlan = vlan, .ip = ip });
    }

    pub fn count(self: *const Cache) usize {
        return self.map.count();
    }

    fn evictOldest(self: *Cache) bool {
        var oldest_key: ?Key = null;
        var oldest_ms: i64 = std.math.maxInt(i64);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.updated_ms < oldest_ms) {
                oldest_ms = entry.value_ptr.updated_ms;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |key| return self.map.remove(key);
        return false;
    }
};

fn writeOption(buf: []u8, off: usize, typ: u8, mac: types.Mac) void {
    buf[off] = typ;
    buf[off + 1] = 1;
    @memcpy(buf[off + 2 ..][0..6], &mac.bytes);
}

fn readU32(buf: []const u8, off: usize) u32 {
    return (@as(u32, buf[off]) << 24) |
        (@as(u32, buf[off + 1]) << 16) |
        (@as(u32, buf[off + 2]) << 8) |
        buf[off + 3];
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @truncate(value >> 8);
    buf[off + 1] = @truncate(value);
}

fn writeU32(buf: []u8, off: usize, value: u32) void {
    buf[off] = @truncate(value >> 24);
    buf[off + 1] = @truncate(value >> 16);
    buf[off + 2] = @truncate(value >> 8);
    buf[off + 3] = @truncate(value);
}

const testing = std.testing;

fn testIp(comptime text: []const u8) types.Ipv6 {
    return types.Ipv6.parse(text) catch unreachable;
}

const mac_a: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0a } };
const mac_b: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0b } };

test "ndp solicitation round trip" {
    const target = testIp("2001:db8::2");
    const dst = solicitedNodeMulticast(target);
    var buf: [64]u8 = undefined;
    const n = try writeNeighborSolicitation(&buf, testIp("2001:db8::1"), dst, target, mac_a);
    const msg = try parse(buf[0..n]);

    try testing.expectEqual(Type.neighbor_solicitation, msg.typ);
    try testing.expect(msg.target.eql(target));
    try testing.expect(msg.source_mac.?.eql(mac_a));
}

test "ndp advertisement round trip" {
    const target = testIp("2001:db8::2");
    var buf: [64]u8 = undefined;
    const n = try writeNeighborAdvertisement(
        &buf,
        target,
        testIp("2001:db8::1"),
        target,
        Flag.solicited | Flag.override,
        mac_b,
    );
    const msg = try parse(buf[0..n]);

    try testing.expectEqual(Type.neighbor_advertisement, msg.typ);
    try testing.expect(msg.target.eql(target));
    try testing.expectEqual(Flag.solicited | Flag.override, msg.flags);
    try testing.expect(msg.target_mac.?.eql(mac_b));
}

test "ndp rejects malformed messages" {
    var buf: [64]u8 = @splat(0);
    try testing.expectError(error.Truncated, parse(buf[0..23]));

    buf[0] = Type.neighbor_solicitation;
    buf[24] = OptionType.source_link_layer;
    buf[25] = 0;
    try testing.expectError(error.BadOption, parse(buf[0..32]));

    buf[25] = 1;
    try testing.expectError(error.Truncated, parse(buf[0..31]));
}

test "ndp solicited-node multicast" {
    const got = solicitedNodeMulticast(testIp("2001:db8::1:2:3"));
    try testing.expect(got.eql(testIp("ff02::1:ff02:3")));
}

test "ndp cache freshness and eviction" {
    var cache: Cache = .{};
    defer cache.deinit(testing.allocator);

    const ip = testIp("2001:db8::2");
    try cache.putVlan(testing.allocator, ip, 7, .{
        .mac = mac_a,
        .port = .{ .value = 1 },
        .updated_ms = 100,
    });
    try testing.expect(cache.getFreshAnyVlan(ip, 7, 150, 100) != null);
    try testing.expect(cache.getFreshAnyVlan(ip, 7, 250, 100) == null);
    try testing.expect(cache.getVlan(ip, 0) == null);
    try testing.expect(cache.removeVlan(ip, 7));
    try testing.expectEqual(@as(usize, 0), cache.count());
}
