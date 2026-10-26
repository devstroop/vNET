//! Bounds-checked parser fuzz targets.
//!
//! Every target accepts arbitrary bytes, asserts the parser's structural
//! invariants when it succeeds, and returns cleanly on typed errors. Run the
//! smoke pass with `zig build test`; run a campaign with `zig build fuzz
//! --fuzz=<iterations-per-target>`.

const std = @import("std");
const vnet = @import("../src/lib.zig");

fn input(smith: *std.testing.Smith, buf: []u8) []const u8 {
    if (smith.in) |bytes| return bytes;
    const len = smith.slice(buf);
    return buf[0..len];
}

fn fuzzEthernet(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    const header = vnet.ethernet.parse(bytes) catch return;

    try std.testing.expect(header.header_len >= 14);
    try std.testing.expect(header.header_len <= bytes.len);
    try std.testing.expectEqual(bytes.len - header.header_len, header.payload.len);

    var out: [18]u8 = undefined;
    const n = try vnet.ethernet.write(
        &out,
        header.dst,
        header.src,
        header.ethertype,
        header.vlan,
    );
    try std.testing.expectEqual(@as(usize, header.header_len), n);
    if (header.vlan) |vid| {
        // The vlan field is the VID; 802.1Q PCP/DEI are not modeled in
        // 0.2.0, so write() intentionally normalizes those bits to zero.
        try std.testing.expectEqualSlices(u8, bytes[0..12], out[0..12]);
        try std.testing.expectEqual(@as(u16, 0x8100), std.mem.readInt(u16, out[12..14], .big));
        try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[14..16], .big) & 0xf000);
        try std.testing.expectEqual(vid, std.mem.readInt(u16, out[14..16], .big) & 0x0fff);
        try std.testing.expectEqualSlices(u8, bytes[16..n], out[16..n]);
    } else {
        try std.testing.expectEqualSlices(u8, bytes[0..n], out[0..n]);
    }
}

fn fuzzIpv4(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    const header = vnet.ipv4.parse(bytes) catch return;

    try std.testing.expect(header.header_len >= 20);
    try std.testing.expect(header.header_len <= header.total_len);
    try std.testing.expect(header.total_len <= bytes.len);
    try std.testing.expectEqual(
        @as(usize, header.total_len) - header.header_len,
        header.payload.len,
    );
    try std.testing.expectEqual(@as(u16, 0), vnet.ipv4.checksum(bytes[0..header.header_len]));

    if (header.ttl > 1) {
        var copy: [2048]u8 = undefined;
        @memcpy(copy[0..header.total_len], bytes[0..header.total_len]);
        try vnet.ipv4.decrementTtl(copy[0..header.total_len]);
    }
}

fn fuzzIpv6(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    const header = vnet.ipv6.parse(bytes) catch return;

    try std.testing.expect(header.header_len >= 40);
    try std.testing.expect(header.header_len <= header.total_len);
    try std.testing.expect(header.total_len <= bytes.len);
    try std.testing.expectEqual(
        @as(usize, header.total_len) - header.header_len,
        header.payload.len,
    );
    try std.testing.expect(header.extension_count <= 16);

    if (header.hop_limit > 1) {
        var copy: [2048]u8 = undefined;
        @memcpy(copy[0..header.total_len], bytes[0..header.total_len]);
        try vnet.ipv6.decrementHopLimit(copy[0..header.total_len]);
    }
}

fn fuzzArp(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    const packet = vnet.arp.parse(bytes) catch return;

    var out: [28]u8 = undefined;
    const n = try vnet.arp.write(
        &out,
        packet.operation,
        packet.sender_mac,
        packet.sender_ip,
        packet.target_mac,
        packet.target_ip,
    );
    try std.testing.expectEqual(@as(usize, 28), n);
    try std.testing.expectEqualSlices(u8, bytes[0..28], out[0..28]);
}

fn fuzzIcmp(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [1024]u8 = undefined;
    const bytes = input(smith, &in_buf);
    if (bytes.len < 8) return;

    var request: [1024]u8 = undefined;
    @memcpy(request[0..bytes.len], bytes);
    request[0] = vnet.icmp.Type.echo_request;

    var reply: [1024]u8 = undefined;
    const n = try vnet.icmp.writeEchoReply(&reply, request[0..bytes.len]);
    try std.testing.expectEqual(bytes.len, n);
    try std.testing.expectEqual(@as(u16, 0), vnet.ipv4.checksum(reply[0..n]));

    var error_msg: [1032]u8 = undefined;
    if (vnet.icmp.writeError(
        &error_msg,
        vnet.icmp.Type.destination_unreachable,
        vnet.icmp.Code.host_unreachable,
        bytes,
        0,
    )) |len| {
        try std.testing.expectEqual(@as(u16, 0), vnet.ipv4.checksum(error_msg[0..len]));
    } else |_| {}
}

fn fuzzNdp(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    _ = vnet.icmpv6.parse(bytes) catch return;
    _ = vnet.ndp.parse(bytes) catch return;
}

fn fuzzStp(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    const bpdu = vnet.stp.parse(bytes) catch return;

    var out: [vnet.stp.payload_len]u8 = undefined;
    const n = try vnet.stp.write(&out, bpdu);
    try std.testing.expectEqual(vnet.stp.payload_len, n);
}

fn fuzzDhcp(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    const message = vnet.dhcp_message.Message.parse(bytes) catch return;

    try message.options.validate();
    _ = message.messageType();
    _ = message.clientMac();
    _ = message.clientId();
    _ = message.options.requestedIp();
    _ = message.options.serverId();
    _ = message.options.maxMessageSize();
    _ = message.options.parameterRequestList();
    _ = message.options.hostname();
}

fn fuzzDns(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);

    _ = vnet.dns_message.parseHeader(bytes) catch return;
    _ = vnet.dns_message.isStandardQuery(bytes);
    _ = vnet.dns_message.questionEnd(bytes) catch return;
    _ = vnet.dns_message.questionKey(bytes) catch return;
    _ = vnet.dns_message.rcode(bytes);
    _ = vnet.dns_message.truncated(bytes);
    _ = vnet.dns_message.minTtl(bytes);
    _ = vnet.dns_message.cacheTtl(bytes);
    _ = vnet.dns_message.negativeTtl(bytes);
    _ = vnet.dns_message.questionType(bytes);

    var copy: [2048]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    vnet.dns_message.ageTtls(copy[0..bytes.len], 7);

    var out: [2048]u8 = undefined;
    _ = vnet.dns_message.buildError(&out, bytes, 2) catch {};

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = vnet.dns_probe.parseResponse(arena.allocator(), bytes) catch return;
}

fn fuzzConfig(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [4096]u8 = undefined;
    const bytes = input(smith, &in_buf);
    var parsed = vnet.config_parse.parse(std.testing.allocator, bytes) catch return;
    defer parsed.deinit();
    _ = vnet.config_validate.validate(&parsed.config) catch {};
}

fn fuzzControl(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [4096]u8 = undefined;
    const bytes = input(smith, &in_buf);
    var parsed = vnet.control_protocol.parseRequest(std.testing.allocator, bytes) catch return;
    defer parsed.deinit();
    _ = parsed.value.id;
    _ = parsed.value.op;
    _ = parsed.value.nat;
}

fn fuzzJournal(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [4096]u8 = undefined;
    const bytes = input(smith, &in_buf);
    var parsed = vnet.journal.parseLine(std.testing.allocator, bytes) catch return;
    defer parsed.deinit();

    const op = vnet.journal.toOp(parsed.value) catch return;
    var out: [4096]u8 = undefined;
    _ = vnet.journal.writeLine(&out, op) catch return;
}

fn fuzzNat(_: void, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [1024]u8 = undefined;
    const bytes = input(smith, &in_buf);

    const kind: u8 = if (bytes.len != 0) bytes[0] % 3 else 0;
    const body = if (bytes.len > 1) bytes[1..@min(bytes.len, 901)] else &.{};

    var l4: [1024]u8 = @splat(0);
    var l4_len: usize = 0;
    const protocol: u8 = switch (kind) {
        0 => blk: {
            l4_len = 8 + body.len;
            std.mem.writeInt(u16, l4[0..2], 40000, .big);
            std.mem.writeInt(u16, l4[2..4], 443, .big);
            std.mem.writeInt(u16, l4[4..6], @intCast(l4_len), .big);
            @memcpy(l4[8..l4_len], body);
            break :blk vnet.ipv4.Protocol.udp;
        },
        1 => blk: {
            l4_len = 20 + body.len;
            std.mem.writeInt(u16, l4[0..2], 40001, .big);
            std.mem.writeInt(u16, l4[2..4], 80, .big);
            l4[12] = 5 << 4;
            @memcpy(l4[20..l4_len], body);
            break :blk vnet.ipv4.Protocol.tcp;
        },
        else => blk: {
            l4_len = 8 + body.len;
            l4[0] = vnet.icmp.Type.echo_request;
            std.mem.writeInt(u16, l4[4..6], 7, .big);
            @memcpy(l4[8..l4_len], body);
            break :blk vnet.ipv4.Protocol.icmp;
        },
    };

    var packet: [2048]u8 = undefined;
    const n = try vnet.ipv4.write(
        &packet,
        .{ .value = 0x0a000102 },
        .{ .value = 0xc0a80101 },
        protocol,
        64,
        1,
        l4[0..l4_len],
    );
    try std.testing.expect(vnet.nat.rewriteSource(packet[0..n], .{ .value = 0xc0a80102 }, 12345));
    try std.testing.expect(vnet.nat.rewriteDestination(packet[0..n], .{ .value = 0x0a000103 }, 8080));
    _ = vnet.ipv4.parse(packet[0..n]) catch return error.TestUnexpectedResult;

    _ = vnet.nat.adjustL4Checksum(
        std.mem.readInt(u16, l4[0..2], .big),
        .{ .value = 0x0a000102 },
        .{ .value = 0xc0a80102 },
        .{ .value = 0xc0a80101 },
        .{ .value = 0x0a000103 },
        40000,
        12345,
        443,
        8080,
    );
    _ = vnet.nat.adjustWordChecksum(
        std.mem.readInt(u16, l4[2..4], .big),
        std.mem.readInt(u16, l4[4..6], .big),
        std.mem.readInt(u16, l4[6..8], .big),
    );
}

const ForwarderContext = struct {
    fwd: *vnet.forward.Forwarder,
    ingress: vnet.types.PortId,
};

fn fuzzForwarder(ctx: ForwarderContext, smith: *std.testing.Smith) anyerror!void {
    var in_buf: [2048]u8 = undefined;
    const bytes = input(smith, &in_buf);
    ctx.fwd.handle(std.testing.io, bytes, ctx.ingress) catch {};
}

test "fuzz ethernet framing" {
    var seed_buf: [64]u8 = undefined;
    const seed = try vnet.ethernet.write(
        &seed_buf,
        vnet.types.Mac.broadcast,
        .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } },
        vnet.ethernet.EtherType.ipv4,
        null,
    );
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzEthernet, .{ .corpus = &corpus });
}

test "fuzz ipv4 headers" {
    var seed_buf: [128]u8 = undefined;
    const seed = try vnet.ipv4.write(
        &seed_buf,
        .{ .value = 0x0a000001 },
        .{ .value = 0x0a000002 },
        vnet.ipv4.Protocol.udp,
        64,
        1,
        "payload",
    );
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzIpv4, .{ .corpus = &corpus });
}

test "fuzz ipv6 extension headers" {
    var seed_buf: [160]u8 = undefined;
    const seed = try vnet.ipv6.write(
        &seed_buf,
        vnet.types.Ipv6.parse("2001:db8::1") catch unreachable,
        vnet.types.Ipv6.parse("2001:db8::2") catch unreachable,
        vnet.ipv6.Protocol.udp,
        64,
        "payload",
    );
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzIpv6, .{ .corpus = &corpus });
}

test "fuzz arp" {
    var seed_buf: [28]u8 = undefined;
    const seed = try vnet.arp.write(
        &seed_buf,
        .request,
        .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } },
        .{ .value = 0x0a000001 },
        .{},
        .{ .value = 0x0a000002 },
    );
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzArp, .{ .corpus = &corpus });
}

test "fuzz icmp builders" {
    var seed_buf: [64]u8 = undefined;
    const seed = try vnet.icmp.writeEchoRequest(&seed_buf, 1, 2, "payload");
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzIcmp, .{ .corpus = &corpus });
}

test "fuzz ndp and icmpv6" {
    var seed_buf: [64]u8 = undefined;
    const target = vnet.types.Ipv6.parse("2001:db8::2") catch unreachable;
    const seed = try vnet.ndp.writeNeighborSolicitation(
        &seed_buf,
        vnet.types.Ipv6.parse("2001:db8::1") catch unreachable,
        vnet.ndp.solicitedNodeMulticast(target),
        target,
        .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } },
    );
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzNdp, .{ .corpus = &corpus });
}

test "fuzz stp" {
    var seed_buf: [vnet.stp.payload_len]u8 = undefined;
    const seed = try vnet.stp.write(&seed_buf, .{ .root_id = 1, .bridge_id = 2 });
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzStp, .{ .corpus = &corpus });
}

test "fuzz dhcp" {
    var seed_buf: [512]u8 = undefined;
    var builder = try vnet.dhcp_message.Builder.init(
        &seed_buf,
        vnet.dhcp_message.op_request,
        .discover,
        7,
        .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } },
        0,
    );
    const seed = try builder.finish();
    const corpus = [_][]const u8{seed};
    try std.testing.fuzz({}, fuzzDhcp, .{ .corpus = &corpus });
}

test "fuzz dns" {
    var seed_buf: [64]u8 = undefined;
    @memset(seed_buf[0..12], 0);
    std.mem.writeInt(u16, seed_buf[4..6], 1, .big);
    seed_buf[12] = 7;
    @memcpy(seed_buf[13..20], "example");
    seed_buf[20] = 3;
    @memcpy(seed_buf[21..24], "com");
    seed_buf[24] = 0;
    std.mem.writeInt(u16, seed_buf[25..27], 1, .big);
    std.mem.writeInt(u16, seed_buf[27..29], 1, .big);
    const corpus = [_][]const u8{seed_buf[0..29]};
    try std.testing.fuzz({}, fuzzDns, .{ .corpus = &corpus });
}

test "fuzz config" {
    const corpus = [_][]const u8{
        \\{"version":1,"instance":"fuzz"}
        ,
        \\{"version":1,"instance":"fuzz","ports":{"lan":{"kind":"l2","device":"eth0"}},"interfaces":{"lan":{"port":"lan","address":"10.0.0.1/24"}}}
        ,
    };
    try std.testing.fuzz({}, fuzzConfig, .{ .corpus = &corpus });
}

test "fuzz control protocol" {
    const corpus = [_][]const u8{
        \\{"id":1,"op":"status"}
        ,
        \\{"id":2,"op":"nat.apply","nat":{"instance":"x","masquerade":[{"out":"wan"}]}}
        ,
    };
    try std.testing.fuzz({}, fuzzControl, .{ .corpus = &corpus });
}

test "fuzz journal" {
    const corpus = [_][]const u8{
        \\{"op":"addr_add","dev":"lan","cidr":"10.0.0.1/24"}
        ,
        \\{"op":"route_add","dst":"0.0.0.0/0","via":"10.0.0.1","dev":"wan"}
        ,
    };
    try std.testing.fuzz({}, fuzzJournal, .{ .corpus = &corpus });
}

test "fuzz nat rewrite" {
    var seed_buf: [64]u8 = undefined;
    const seed = try vnet.ipv4.write(
        &seed_buf,
        .{ .value = 0x0a000001 },
        .{ .value = 0xc0a80101 },
        vnet.ipv4.Protocol.udp,
        64,
        1,
        &.{ 0, 1, 0, 2, 0, 8, 0, 0 },
    );
    const corpus = [_][]const u8{seed_buf[0..seed]};
    try std.testing.fuzz({}, fuzzNat, .{ .corpus = &corpus });
}

test "fuzz forwarder ingress" {
    const allocator = std.heap.page_allocator;
    const port_a: vnet.types.PortId = .{ .value = 1 };
    const port_b: vnet.types.PortId = .{ .value = 2 };
    var a = vnet.MemoryPort.init(allocator, port_a, "a", 1500);
    defer a.deinit();
    var b = vnet.MemoryPort.init(allocator, port_b, "b", 1500);
    defer b.deinit();
    const entries = [2]vnet.forward.PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    var fwd = try vnet.forward.Forwarder.init(allocator, &entries);
    defer fwd.deinit();

    var frame: [128]u8 = undefined;
    var payload: [64]u8 = undefined;
    const ip = try vnet.ipv4.write(
        &payload,
        .{ .value = 0x0a000001 },
        .{ .value = 0x0a000002 },
        vnet.ipv4.Protocol.udp,
        64,
        1,
        "x",
    );
    const hlen = try vnet.ethernet.write(
        &frame,
        vnet.types.Mac.broadcast,
        .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } },
        vnet.ethernet.EtherType.ipv4,
        null,
    );
    @memcpy(frame[hlen..][0..ip], payload[0..ip]);
    const corpus = [_][]const u8{frame[0 .. hlen + ip]};

    const ctx = ForwarderContext{ .fwd = &fwd, .ingress = port_a };
    try std.testing.fuzz(ctx, fuzzForwarder, .{ .corpus = &corpus });
}
