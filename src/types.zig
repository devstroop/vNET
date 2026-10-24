//! Core value types shared by the datapath and the control plane.
//!
//! All addresses are stored in host byte order as integers; conversion to and
//! from wire format is explicit via `toBytes`/`fromBytes`.

const std = @import("std");

/// Largest IP MTU the current userspace frame buffers can carry end to end.
pub const max_supported_mtu: u16 = 1600;

pub const Mac = struct {
    bytes: [6]u8 = @splat(0),

    pub const zero: Mac = .{};
    pub const broadcast: Mac = .{ .bytes = @splat(0xff) };

    pub fn isZero(self: Mac) bool {
        for (self.bytes) |b| {
            if (b != 0) return false;
        }
        return true;
    }

    pub fn eql(a: Mac, b: Mac) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn isBroadcast(self: Mac) bool {
        return self.eql(broadcast);
    }

    pub fn isMulticast(self: Mac) bool {
        return self.bytes[0] & 1 != 0;
    }

    pub fn parse(s: []const u8) !Mac {
        var out: [6]u8 = undefined;
        var it = std.mem.splitAny(u8, s, ":-");
        var i: usize = 0;
        while (it.next()) |part| {
            if (i == 6 or part.len != 2) return error.InvalidMac;
            out[i] = std.fmt.parseInt(u8, part, 16) catch return error.InvalidMac;
            i += 1;
        }
        if (i != 6) return error.InvalidMac;
        return .{ .bytes = out };
    }

    pub fn format(self: Mac, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            self.bytes[0], self.bytes[1], self.bytes[2],
            self.bytes[3], self.bytes[4], self.bytes[5],
        });
    }
};

pub const Ipv4 = struct {
    /// Host-order integer. Network byte order is produced by `toBytes`.
    value: u32 = 0,

    pub const unspecified: Ipv4 = .{ .value = 0 };
    pub const limited_broadcast: Ipv4 = .{ .value = 0xffffffff };

    pub fn fromBytes(b: [4]u8) Ipv4 {
        return .{ .value = std.mem.readInt(u32, &b, .big) };
    }

    pub fn toBytes(self: Ipv4) [4]u8 {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, self.value, .big);
        return b;
    }

    pub fn parse(s: []const u8) !Ipv4 {
        var octets: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, s, '.');
        var i: usize = 0;
        while (it.next()) |part| {
            if (i == 4 or part.len == 0 or part.len > 3) return error.InvalidIpv4;
            octets[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4;
            i += 1;
        }
        if (i != 4) return error.InvalidIpv4;
        return fromBytes(octets);
    }

    pub fn eql(a: Ipv4, b: Ipv4) bool {
        return a.value == b.value;
    }

    pub fn isUnspecified(self: Ipv4) bool {
        return self.value == 0;
    }

    pub fn isMulticast(self: Ipv4) bool {
        return self.value & 0xf0000000 == 0xe0000000;
    }

    pub fn format(self: Ipv4, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const b = self.toBytes();
        try w.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
    }
};

pub const Ipv6 = struct {
    /// Host-order integer. Network byte order is produced by `toBytes`.
    value: u128 = 0,

    pub const unspecified: Ipv6 = .{ .value = 0 };
    pub const loopback: Ipv6 = .{ .value = 1 };

    pub fn fromBytes(b: [16]u8) Ipv6 {
        return .{ .value = std.mem.readInt(u128, &b, .big) };
    }

    pub fn toBytes(self: Ipv6) [16]u8 {
        var b: [16]u8 = undefined;
        std.mem.writeInt(u128, &b, self.value, .big);
        return b;
    }

    /// RFC 4291 text representation, including `::` compression and an
    /// embedded IPv4 tail for IPv4-mapped addresses (RFC 5952 §5).
    pub fn parse(s: []const u8) !Ipv6 {
        if (s.len == 0 or std.mem.indexOfScalar(u8, s, '%') != null) {
            return error.InvalidIpv6;
        }

        var left: [8]u16 = undefined;
        var right: [8]u16 = undefined;
        var left_len: usize = 0;
        var right_len: usize = 0;

        if (std.mem.indexOf(u8, s, "::")) |dc| {
            if (std.mem.indexOf(u8, s[dc + 2 ..], "::") != null) return error.InvalidIpv6;
            // An embedded IPv4 tail must be the final part of the address.
            if (std.mem.indexOfScalar(u8, s[0..dc], '.') != null) return error.InvalidIpv6;
            if (dc > 0) left_len = try parseIpv6Side(s[0..dc], &left);
            if (dc + 2 < s.len) right_len = try parseIpv6Side(s[dc + 2 ..], &right);
            if (left_len + right_len >= 8) return error.InvalidIpv6;
        } else {
            left_len = try parseIpv6Side(s, &left);
            if (left_len != 8) return error.InvalidIpv6;
        }

        var groups: [8]u16 = @splat(0);
        @memcpy(groups[0..left_len], left[0..left_len]);
        if (right_len > 0) @memcpy(groups[8 - right_len ..], right[0..right_len]);

        var value: u128 = 0;
        for (groups) |group| value = (value << 16) | group;
        return .{ .value = value };
    }

    pub fn eql(a: Ipv6, b: Ipv6) bool {
        return a.value == b.value;
    }

    pub fn isUnspecified(self: Ipv6) bool {
        return self.value == 0;
    }

    pub fn isLoopback(self: Ipv6) bool {
        return self.value == 1;
    }

    pub fn isMulticast(self: Ipv6) bool {
        return self.value >> 120 == 0xff;
    }

    pub fn isLinkLocal(self: Ipv6) bool {
        return self.value >> 118 == 0x3fa;
    }

    pub fn isUniqueLocal(self: Ipv6) bool {
        return self.value >> 121 == 0x7e;
    }

    pub fn isIpv4Mapped(self: Ipv6) bool {
        return self.value >> 32 == 0xffff;
    }

    pub fn format(self: Ipv6, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.isIpv4Mapped()) {
            const mapped = Ipv4{ .value = @truncate(self.value) };
            try w.print("::ffff:{f}", .{mapped});
            return;
        }

        const groups = ipv6Groups(self);
        var best_start: usize = 8;
        var best_len: usize = 0;
        var i: usize = 0;
        while (i < 8) {
            if (groups[i] != 0) {
                i += 1;
                continue;
            }
            const start = i;
            while (i < 8 and groups[i] == 0) i += 1;
            const run = i - start;
            if (run >= 2 and run > best_len) {
                best_start = start;
                best_len = run;
            }
        }

        i = 0;
        while (i < 8) {
            if (best_len != 0 and i == best_start) {
                try w.writeAll("::");
                i += best_len;
                continue;
            }
            if (i != 0 and !(best_len != 0 and i == best_start + best_len)) {
                try w.writeByte(':');
            }
            try w.print("{x}", .{groups[i]});
            i += 1;
        }
    }
};

fn parseIpv6Side(s: []const u8, out: *[8]u16) !usize {
    if (s.len == 0) return 0;

    var count: usize = 0;
    var it = std.mem.splitScalar(u8, s, ':');
    while (it.next()) |part| {
        if (part.len == 0) return error.InvalidIpv6;
        if (count == out.len) return error.InvalidIpv6;

        if (std.mem.indexOfScalar(u8, part, '.') != null) {
            if (it.next() != null) return error.InvalidIpv6;
            const v4 = Ipv4.parse(part) catch return error.InvalidIpv6;
            if (count + 2 > out.len) return error.InvalidIpv6;
            const b = v4.toBytes();
            out[count] = (@as(u16, b[0]) << 8) | b[1];
            out[count + 1] = (@as(u16, b[2]) << 8) | b[3];
            return count + 2;
        }

        if (part.len > 4) return error.InvalidIpv6;
        for (part) |c| {
            if (!std.ascii.isHex(c)) return error.InvalidIpv6;
        }
        out[count] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6;
        count += 1;
    }
    return count;
}

fn ipv6Groups(ip: Ipv6) [8]u16 {
    const b = ip.toBytes();
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*group, i| {
        group.* = (@as(u16, b[i * 2]) << 8) | b[i * 2 + 1];
    }
    return groups;
}

pub const Prefix6 = struct {
    addr: Ipv6,
    len: u8,

    pub fn parse(s: []const u8) !Prefix6 {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidPrefix;
        const addr = try Ipv6.parse(s[0..slash]);
        const len = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return error.InvalidPrefix;
        if (len > 128) return error.InvalidPrefix;
        return .{ .addr = addr, .len = len };
    }

    pub fn mask(self: Prefix6) u128 {
        if (self.len == 0) return 0;
        const shift: u7 = @intCast(128 - self.len);
        const all: u128 = std.math.maxInt(u128);
        return all << shift;
    }

    pub fn network(self: Prefix6) Ipv6 {
        return .{ .value = self.addr.value & self.mask() };
    }

    pub fn contains(self: Prefix6, ip: Ipv6) bool {
        return (ip.value & self.mask()) == self.network().value;
    }

    pub fn eql(a: Prefix6, b: Prefix6) bool {
        return a.len == b.len and a.network().value == b.network().value;
    }

    pub fn format(self: Prefix6, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{f}/{}", .{ self.addr, self.len });
    }
};

pub const IpFamily = enum { ipv4, ipv6 };

pub const IpAddr = union(IpFamily) {
    ipv4: Ipv4,
    ipv6: Ipv6,

    pub fn parse(s: []const u8) !IpAddr {
        if (std.mem.indexOfScalar(u8, s, ':') != null) {
            return .{ .ipv6 = try Ipv6.parse(s) };
        }
        return .{ .ipv4 = try Ipv4.parse(s) };
    }

    pub fn eql(a: IpAddr, b: IpAddr) bool {
        return switch (a) {
            .ipv4 => |a4| switch (b) {
                .ipv4 => |b4| a4.eql(b4),
                .ipv6 => false,
            },
            .ipv6 => |a6| switch (b) {
                .ipv4 => false,
                .ipv6 => |b6| a6.eql(b6),
            },
        };
    }

    pub fn family(self: IpAddr) IpFamily {
        return switch (self) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        };
    }

    pub fn format(self: IpAddr, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ipv4 => |ip| try w.print("{f}", .{ip}),
            .ipv6 => |ip| try w.print("{f}", .{ip}),
        }
    }
};

pub const IpPrefix = union(IpFamily) {
    ipv4: Prefix4,
    ipv6: Prefix6,

    pub fn parse(s: []const u8) !IpPrefix {
        if (std.mem.indexOfScalar(u8, s, ':') != null) {
            return .{ .ipv6 = try Prefix6.parse(s) };
        }
        return .{ .ipv4 = try Prefix4.parse(s) };
    }

    pub fn family(self: IpPrefix) IpFamily {
        return switch (self) {
            .ipv4 => .ipv4,
            .ipv6 => .ipv6,
        };
    }

    pub fn network(self: IpPrefix) IpAddr {
        return switch (self) {
            .ipv4 => |p| .{ .ipv4 = p.network() },
            .ipv6 => |p| .{ .ipv6 = p.network() },
        };
    }

    pub fn contains(self: IpPrefix, ip: IpAddr) bool {
        return switch (self) {
            .ipv4 => |p| switch (ip) {
                .ipv4 => |addr| p.contains(addr),
                .ipv6 => false,
            },
            .ipv6 => |p| switch (ip) {
                .ipv4 => false,
                .ipv6 => |addr| p.contains(addr),
            },
        };
    }

    pub fn eql(a: IpPrefix, b: IpPrefix) bool {
        return switch (a) {
            .ipv4 => |a4| switch (b) {
                .ipv4 => |b4| a4.eql(b4),
                .ipv6 => false,
            },
            .ipv6 => |a6| switch (b) {
                .ipv4 => false,
                .ipv6 => |b6| a6.eql(b6),
            },
        };
    }

    pub fn format(self: IpPrefix, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ipv4 => |p| try w.print("{f}", .{p}),
            .ipv6 => |p| try w.print("{f}", .{p}),
        }
    }
};

pub const Prefix4 = struct {
    addr: Ipv4,
    len: u8,

    pub fn parse(s: []const u8) !Prefix4 {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidPrefix;
        const addr = try Ipv4.parse(s[0..slash]);
        const len = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return error.InvalidPrefix;
        if (len > 32) return error.InvalidPrefix;
        return .{ .addr = addr, .len = len };
    }

    pub fn mask(self: Prefix4) u32 {
        if (self.len == 0) return 0;
        const shift: u5 = @intCast(32 - self.len);
        return @as(u32, 0xffffffff) << shift;
    }

    pub fn network(self: Prefix4) Ipv4 {
        return .{ .value = self.addr.value & self.mask() };
    }

    pub fn contains(self: Prefix4, ip: Ipv4) bool {
        return (ip.value & self.mask()) == self.network().value;
    }

    pub fn eql(a: Prefix4, b: Prefix4) bool {
        return a.len == b.len and a.network().value == b.network().value;
    }

    pub fn format(self: Prefix4, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{f}/{}", .{ self.addr, self.len });
    }
};

pub const IpPort = struct {
    ip: Ipv4,
    port: u16,
};

pub fn parseIpPort(s: []const u8) !IpPort {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidIpPort;
    if (colon == 0 or colon + 1 == s.len) return error.InvalidIpPort;
    const ip = try Ipv4.parse(s[0..colon]);
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.InvalidIpPort;
    if (port == 0) return error.InvalidIpPort;
    return .{ .ip = ip, .port = port };
}

pub const IpRange = struct {
    first: Ipv4,
    last: Ipv4,
};

pub fn parseIpRange(s: []const u8) !IpRange {
    const dash = std.mem.indexOfScalar(u8, s, '-') orelse return error.InvalidRange;
    const first = try Ipv4.parse(std.mem.trim(u8, s[0..dash], " \t"));
    const last = try Ipv4.parse(std.mem.trim(u8, s[dash + 1 ..], " \t"));
    if (first.value > last.value) return error.InvalidRange;
    return .{ .first = first, .last = last };
}

/// Parses `90`, `90s`, `30m`, `12h`, `7d` into seconds.
pub fn parseDurationSeconds(s: []const u8) !u32 {
    if (s.len == 0) return error.InvalidDuration;

    var n: u64 = 0;
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
        n = n * 10 + (s[i] - '0');
        if (n > std.math.maxInt(u32)) return error.InvalidDuration;
    }
    if (i == 0) return error.InvalidDuration;

    var mult: u64 = 1;
    if (i != s.len) {
        if (i + 1 != s.len) return error.InvalidDuration;
        mult = switch (s[i]) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            else => return error.InvalidDuration,
        };
    }

    const total = n * mult;
    if (total == 0 or total > std.math.maxInt(u32)) return error.InvalidDuration;
    return @intCast(total);
}

pub const PortId = struct {
    value: u32,

    pub const invalid: PortId = .{ .value = 0 };

    pub fn eql(a: PortId, b: PortId) bool {
        return a.value == b.value;
    }
};

pub const VlanId = struct {
    value: u12,

    pub const max: VlanId = .{ .value = 4094 };
};

test "ipv6 parse and RFC 5952 format" {
    const cases = [_]struct { input: []const u8, output: []const u8 }{
        .{ .input = "::", .output = "::" },
        .{ .input = "::1", .output = "::1" },
        .{ .input = "2001:0db8:0000:0000:0000:ff00:0042:8329", .output = "2001:db8::ff00:42:8329" },
        .{ .input = "2001:db8:0:0:1:0:0:1", .output = "2001:db8::1:0:0:1" },
        .{ .input = "fe80::1", .output = "fe80::1" },
        .{ .input = "::ffff:192.0.2.128", .output = "::ffff:192.0.2.128" },
    };
    for (cases) |case| {
        const ip = try Ipv6.parse(case.input);
        var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer out.deinit();
        try out.writer.print("{f}", .{ip});
        try std.testing.expectEqualStrings(case.output, out.written());
        try std.testing.expect(ip.eql(try Ipv6.parse(case.output)));
    }
}

test "ipv6 rejects malformed addresses" {
    const invalid = [_][]const u8{
        "",
        "1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:9",
        "1::2::3",
        "1:2:3:4:5:6:7:8::",
        "12345::",
        "fe80::1%eth0",
        ":1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:",
        "::ffff:192.0.2",
        "192.0.2.1::",
        "192.0.2.1::1",
    };
    for (invalid) |text| {
        try std.testing.expectError(error.InvalidIpv6, Ipv6.parse(text));
    }
}

test "ipv6 prefix containment" {
    const p = try Prefix6.parse("2001:db8:1::/48");
    try std.testing.expect(p.contains(try Ipv6.parse("2001:db8:1:2::1")));
    try std.testing.expect(!p.contains(try Ipv6.parse("2001:db8:2::1")));
    try std.testing.expect(p.eql(try Prefix6.parse("2001:db8:1:ffff::/48")));
    try std.testing.expectError(error.InvalidPrefix, Prefix6.parse("2001:db8::/129"));
}

test "dual-stack address and prefix parsing" {
    const v4 = try IpAddr.parse("10.0.0.1");
    const v6 = try IpAddr.parse("2001:db8::1");
    try std.testing.expectEqual(IpFamily.ipv4, v4.family());
    try std.testing.expectEqual(IpFamily.ipv6, v6.family());
    try std.testing.expect(!v4.eql(v6));

    const p4 = try IpPrefix.parse("10.0.0.0/8");
    const p6 = try IpPrefix.parse("2001:db8::/32");
    try std.testing.expect(p4.contains(v4));
    try std.testing.expect(!p4.contains(v6));
    try std.testing.expect(p6.contains(v6));
    try std.testing.expect(!p6.contains(v4));
}

test "mac parse and format" {
    const mac = try Mac.parse("aa:bb:cc:dd:ee:ff");
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &mac.bytes);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try out.writer.print("{f}", .{mac});
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", out.written());
}

test "ipv4 parse and format" {
    const ip = try Ipv4.parse("10.26.0.2");
    try std.testing.expectEqualSlices(u8, &.{ 10, 26, 0, 2 }, &ip.toBytes());

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try out.writer.print("{f}", .{ip});
    try std.testing.expectEqualStrings("10.26.0.2", out.written());
}

test "prefix network and containment" {
    const p = try Prefix4.parse("10.26.0.5/24");
    try std.testing.expectEqual(@as(u32, 0x0a1a0000), p.network().value);
    try std.testing.expect(p.contains(try Ipv4.parse("10.26.0.200")));
    try std.testing.expect(!p.contains(try Ipv4.parse("10.27.0.1")));
}

test "ip:port and ranges" {
    const hp = try parseIpPort("192.168.1.10:8080");
    try std.testing.expectEqual(@as(u16, 8080), hp.port);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &hp.ip.toBytes());

    const r = try parseIpRange("10.0.0.100-10.0.0.200");
    try std.testing.expect(r.first.value < r.last.value);
    try std.testing.expectError(error.InvalidRange, parseIpRange("10.0.0.200-10.0.0.100"));
}

test "duration parser" {
    try std.testing.expectEqual(@as(u32, 90), try parseDurationSeconds("90"));
    try std.testing.expectEqual(@as(u32, 30 * 60), try parseDurationSeconds("30m"));
    try std.testing.expectEqual(@as(u32, 12 * 3600), try parseDurationSeconds("12h"));
    try std.testing.expectEqual(@as(u32, 86400), try parseDurationSeconds("1d"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds("0"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds("12x"));
}
