//! IPv6 header and extension-header parsing (RFC 8200). The datapath only
//! needs the upper-layer protocol and payload; extension headers are walked
//! with strict bounds checks so malformed chains cannot loop or over-read.

const std = @import("std");
const types = @import("vnet-core").types;

pub const Protocol = struct {
    pub const hop_by_hop: u8 = 0;
    pub const tcp: u8 = 6;
    pub const udp: u8 = 17;
    pub const routing: u8 = 43;
    pub const fragment: u8 = 44;
    pub const esp: u8 = 50;
    pub const ah: u8 = 51;
    pub const icmpv6: u8 = 58;
    pub const no_next: u8 = 59;
    pub const destination_options: u8 = 60;
};

pub const Error = error{
    Truncated,
    NotIpv6,
    BadPayloadLength,
    BadExtension,
    TooManyExtensions,
    HopLimitExpired,
    TooLarge,
    NoSpace,
};

pub const Header = struct {
    /// Offset from the start of the IPv6 packet to the upper-layer payload.
    header_len: u16,
    total_len: u16,
    hop_limit: u8,
    /// Final next-header value after walking extension headers.
    protocol: u8,
    src: types.Ipv6,
    dst: types.Ipv6,
    payload: []const u8,
    packet: []const u8,
    fragment_offset: u16 = 0,
    more_fragments: bool = false,
    extension_count: u8 = 0,

    pub fn isFragment(self: Header) bool {
        return self.more_fragments or self.fragment_offset != 0;
    }
};

pub fn isExtensionHeader(protocol: u8) bool {
    return protocol == Protocol.hop_by_hop or
        protocol == Protocol.routing or
        protocol == Protocol.fragment or
        protocol == Protocol.destination_options;
}

pub fn parse(packet: []const u8) Error!Header {
    if (packet.len < 40) return error.Truncated;
    if (packet[0] >> 4 != 6) return error.NotIpv6;

    const payload_len = readU16(packet, 4);
    const total_len: usize = 40 + @as(usize, payload_len);
    if (total_len > packet.len) return error.Truncated;
    // Frames are capped at 2048 bytes; reject the theoretical 65575-byte
    // packet so the Header's u16 lengths cannot overflow.
    if (total_len > std.math.maxInt(u16)) return error.TooLarge;

    var protocol = packet[6];
    var off: usize = 40;
    var fragment_offset: u16 = 0;
    var more_fragments = false;
    var extension_count: u8 = 0;

    while (isExtensionHeader(protocol)) {
        if (extension_count >= 16) return error.TooManyExtensions;
        if (off + 2 > total_len) return error.Truncated;

        const next = packet[off];
        const len: usize = switch (protocol) {
            Protocol.fragment => 8,
            else => (@as(usize, packet[off + 1]) + 1) * 8,
        };
        if (len < 8 or off + len > total_len) return error.BadExtension;

        if (protocol == Protocol.fragment) {
            const off_flags = readU16(packet, off + 2);
            fragment_offset = (off_flags >> 3) & 0x1fff;
            more_fragments = off_flags & 0x0001 != 0;
        }

        protocol = next;
        off += len;
        extension_count += 1;
    }

    return .{
        .header_len = @intCast(off),
        .total_len = @intCast(total_len),
        .hop_limit = packet[7],
        .protocol = protocol,
        .src = types.Ipv6.fromBytes(packet[8..24].*),
        .dst = types.Ipv6.fromBytes(packet[24..40].*),
        .payload = packet[off..total_len],
        .packet = packet[0..total_len],
        .fragment_offset = fragment_offset,
        .more_fragments = more_fragments,
        .extension_count = extension_count,
    };
}

pub fn write(
    buf: []u8,
    src: types.Ipv6,
    dst: types.Ipv6,
    protocol: u8,
    hop_limit: u8,
    payload: []const u8,
) Error!usize {
    const total = 40 + payload.len;
    if (total > 65535) return error.TooLarge;
    if (buf.len < total) return error.NoSpace;

    @memset(buf[0..40], 0);
    buf[0] = 0x60;
    writeU16(buf, 4, @intCast(payload.len));
    buf[6] = protocol;
    buf[7] = hop_limit;
    const src_bytes = src.toBytes();
    const dst_bytes = dst.toBytes();
    @memcpy(buf[8..24], &src_bytes);
    @memcpy(buf[24..40], &dst_bytes);
    @memcpy(buf[40..total], payload);
    return total;
}

/// Decrements the hop limit in place and returns the expired error at zero.
pub fn decrementHopLimit(packet: []u8) Error!void {
    const header = try parse(packet);
    if (header.hop_limit <= 1) return error.HopLimitExpired;
    packet[7] -= 1;
}

/// Ones-complement checksum over the IPv6 pseudo-header and upper-layer data.
pub fn checksum(src: types.Ipv6, dst: types.Ipv6, protocol: u8, data: []const u8) u16 {
    var sum: u32 = 0;
    const src_bytes = src.toBytes();
    const dst_bytes = dst.toBytes();
    var i: usize = 0;
    while (i + 1 < src_bytes.len) : (i += 2) {
        sum += readU16(&src_bytes, i);
    }
    i = 0;
    while (i + 1 < dst_bytes.len) : (i += 2) {
        sum += readU16(&dst_bytes, i);
    }
    sum += @intCast((data.len >> 16) & 0xffff);
    sum += @intCast(data.len & 0xffff);
    sum += protocol;

    i = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += readU16(data, i);
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return @truncate(~sum);
}

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @truncate(value >> 8);
    buf[off + 1] = @truncate(value);
}

const testing = std.testing;

fn testSrc() types.Ipv6 {
    return types.Ipv6.parse("2001:db8:1::1") catch unreachable;
}

fn testDst() types.Ipv6 {
    return types.Ipv6.parse("2001:db8:2::1") catch unreachable;
}

test "ipv6 build and parse" {
    var packet: [128]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.udp, 64, "hello");
    const h = try parse(packet[0..n]);

    try testing.expectEqual(@as(u16, 40), h.header_len);
    try testing.expectEqual(@as(u16, 45), h.total_len);
    try testing.expectEqual(@as(u8, 64), h.hop_limit);
    try testing.expectEqual(Protocol.udp, h.protocol);
    try testing.expect(h.src.eql(testSrc()));
    try testing.expect(h.dst.eql(testDst()));
    try testing.expectEqualSlices(u8, "hello", h.payload);
    try testing.expect(!h.isFragment());
}

test "ipv6 rejects payload lengths that overflow header fields" {
    const packet = try testing.allocator.alloc(u8, 40 + 65535);
    defer testing.allocator.free(packet);
    @memset(packet, 0);
    packet[0] = 0x60;
    packet[4] = 0xff;
    packet[5] = 0xff;
    try testing.expectError(error.TooLarge, parse(packet));
}

test "ipv6 walks hop-by-hop and destination options" {
    var packet: [128]u8 = undefined;
    var options: [24]u8 = undefined;
    @memset(&options, 0);
    _ = try write(&packet, testSrc(), testDst(), Protocol.hop_by_hop, 64, &options);
    packet[40] = Protocol.destination_options;
    packet[41] = 0;
    packet[48] = Protocol.tcp;
    packet[49] = 0;

    const h = try parse(packet[0..64]);
    try testing.expectEqual(@as(u16, 56), h.header_len);
    try testing.expectEqual(Protocol.tcp, h.protocol);
    try testing.expectEqual(@as(u8, 2), h.extension_count);
    try testing.expectEqual(@as(usize, 8), h.payload.len);
}

test "ipv6 parses fragment metadata" {
    var packet: [80]u8 = undefined;
    @memset(&packet, 0);
    packet[0] = 0x60;
    writeU16(&packet, 4, 16);
    packet[6] = Protocol.fragment;
    packet[7] = 64;
    const s = testSrc().toBytes();
    const d = testDst().toBytes();
    @memcpy(packet[8..24], &s);
    @memcpy(packet[24..40], &d);
    packet[40] = Protocol.udp;
    writeU16(&packet, 42, (3 << 3) | 1);
    packet[48] = 9;

    const h = try parse(packet[0..56]);
    try testing.expectEqual(@as(u16, 3), h.fragment_offset);
    try testing.expect(h.more_fragments);
    try testing.expect(h.isFragment());
    try testing.expectEqual(Protocol.udp, h.protocol);
}

test "ipv6 rejects malformed packets" {
    var packet: [64]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.udp, 64, "x");

    var bad = packet;
    bad[0] = 0x40;
    try testing.expectError(error.NotIpv6, parse(&bad));

    bad = packet;
    writeU16(&bad, 4, 100);
    try testing.expectError(error.Truncated, parse(bad[0..n]));

    bad = packet;
    bad[6] = Protocol.hop_by_hop;
    writeU16(&bad, 4, 24);
    bad[40] = Protocol.udp;
    bad[41] = 255;
    try testing.expectError(error.BadExtension, parse(bad[0..64]));

    try testing.expectError(error.Truncated, parse(packet[0..39]));
}

test "ipv6 hop limit decrement" {
    var packet: [64]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.udp, 64, "x");
    try decrementHopLimit(packet[0..n]);
    const h = try parse(packet[0..n]);
    try testing.expectEqual(@as(u8, 63), h.hop_limit);
}

test "ipv6 hop limit expiry" {
    var packet: [64]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.udp, 1, "x");
    try testing.expectError(error.HopLimitExpired, decrementHopLimit(packet[0..n]));
}

test "ipv6 pseudo-header checksum" {
    const sum = checksum(testSrc(), testDst(), Protocol.icmpv6, "abc");
    try testing.expect(sum != 0);
}
