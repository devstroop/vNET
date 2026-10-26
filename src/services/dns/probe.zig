const std = @import("std");
const types = @import("vnet-core").types;
const message = @import("message.zig");

pub const Error = error{
    InvalidName,
    InvalidType,
    NameTooLong,
    QueryTooLarge,
    BindFailed,
    SendFailed,
    Timeout,
    ReceiveFailed,
    Truncated,
    BadResponse,
    TooManyRecords,
    OutOfMemory,
};

pub const Answer = struct {
    owner: []const u8 = "",
    qtype: []const u8 = "",
    value: []const u8 = "",
    ttl: u32 = 0,
};

pub const Result = struct {
    server: []const u8 = "",
    name: []const u8 = "",
    qtype: []const u8 = "",
    rcode: u8 = 0,
    rcode_text: []const u8 = "NOERROR",
    truncated: bool = false,
    answers: []const Answer = &.{},
};

const query_id: u16 = 0x5652;
const max_answers = 64;

pub fn query(
    arena: std.mem.Allocator,
    io: std.Io,
    server: types.Ipv4,
    name: []const u8,
    qtype: []const u8,
    timeout_ms: i64,
) Error!Result {
    const qtype_code = parseType(qtype) orelse return error.InvalidType;
    var query_buf: [512]u8 = undefined;
    const query_packet = try buildQuery(&query_buf, query_id, name, qtype_code);

    var socket = (std.Io.net.IpAddress{ .ip4 = .unspecified(0) })
        .bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return error.BindFailed;
    defer socket.close(io);

    const dest = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = server.toBytes(),
        .port = 53,
    } };
    socket.send(io, &dest, query_packet) catch return error.SendFailed;

    var response_buf: [4096]u8 = undefined;
    const incoming = socket.receiveTimeout(io, &response_buf, .{
        .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(timeout_ms),
            .clock = .awake,
        },
    }) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return error.ReceiveFailed,
    };
    if (!incoming.from.eql(&dest)) return error.BadResponse;
    if (incoming.data.len < 12) return error.Truncated;

    const header = message.parseHeader(incoming.data) catch return error.BadResponse;
    if (header.id != query_id or header.flags & 0x8000 == 0) return error.BadResponse;
    const expected_key = message.questionKey(query_packet) catch return error.BadResponse;
    const actual_key = message.questionKey(incoming.data) catch return error.BadResponse;
    if (!asciiEql(expected_key, actual_key)) return error.BadResponse;

    var result = try parseResponse(arena, incoming.data);
    result.server = try std.fmt.allocPrint(arena, "{f}", .{server});
    result.name = try arena.dupe(u8, name);
    result.qtype = try arena.dupe(u8, qtype);
    return result;
}

pub fn buildQuery(out: []u8, id: u16, name: []const u8, qtype: u16) Error![]u8 {
    if (name.len == 0 or name.len > 253) return error.NameTooLong;
    if (out.len < 12) return error.QueryTooLarge;
    @memset(out[0..12], 0);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x0100, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);

    const trimmed = if (name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    if (trimmed.len == 0) return error.InvalidName;
    var pos: usize = 12;
    var it = std.mem.splitScalar(u8, trimmed, '.');
    var labels: usize = 0;
    while (it.next()) |label| {
        try writeLabel(out, &pos, label);
        labels += 1;
    }
    if (labels == 0) return error.InvalidName;
    if (pos + 5 > out.len) return error.QueryTooLarge;
    out[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, out[pos..][0..2], qtype, .big);
    std.mem.writeInt(u16, out[pos + 2 ..][0..2], 1, .big);
    return out[0 .. pos + 4];
}

pub fn parseResponse(arena: std.mem.Allocator, packet: []const u8) Error!Result {
    const header = message.parseHeader(packet) catch return error.BadResponse;
    if (header.flags & 0x8000 == 0) return error.BadResponse;
    var pos = message.questionEnd(packet) catch return error.BadResponse;
    if (header.ancount > max_answers) return error.TooManyRecords;

    var answers: std.ArrayListUnmanaged(Answer) = .empty;
    var index: usize = 0;
    while (index < header.ancount) : (index += 1) {
        const owner = try readName(packet, pos, arena);
        pos = owner.next;
        if (pos + 10 > packet.len) return error.Truncated;
        const record_type = std.mem.readInt(u16, packet[pos..][0..2], .big);
        const ttl = std.mem.readInt(u32, packet[pos + 4 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, packet[pos + 8 ..][0..2], .big);
        const rdata = pos + 10;
        if (rdata + rdlen > packet.len) return error.Truncated;

        switch (record_type) {
            1 => if (rdlen == 4) {
                const raw: [4]u8 = packet[rdata..][0..4].*;
                try answers.append(arena, .{
                    .owner = owner.name,
                    .qtype = "A",
                    .value = try std.fmt.allocPrint(arena, "{f}", .{types.Ipv4.fromBytes(raw)}),
                    .ttl = ttl,
                });
            },
            28 => if (rdlen == 16) {
                const raw: [16]u8 = packet[rdata..][0..16].*;
                try answers.append(arena, .{
                    .owner = owner.name,
                    .qtype = "AAAA",
                    .value = try std.fmt.allocPrint(arena, "{f}", .{types.Ipv6.fromBytes(raw)}),
                    .ttl = ttl,
                });
            },
            5, 12 => {
                const target = readName(packet, rdata, arena) catch return error.BadResponse;
                if (target.next > rdata + rdlen) return error.BadResponse;
                try answers.append(arena, .{
                    .owner = owner.name,
                    .qtype = if (record_type == 5) "CNAME" else "PTR",
                    .value = target.name,
                    .ttl = ttl,
                });
            },
            else => {},
        }
        pos = rdata + rdlen;
    }

    return .{
        .rcode = @intCast(header.flags & 0xf),
        .rcode_text = rcodeText(@intCast(header.flags & 0xf)),
        .truncated = header.flags & 0x0200 != 0,
        .answers = try answers.toOwnedSlice(arena),
    };
}

fn writeLabel(out: []u8, pos: *usize, label: []const u8) Error!void {
    if (label.len == 0 or label.len > 63) return error.InvalidName;
    for (label) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidName;
    }
    if (pos.* + 1 + label.len > out.len) return error.QueryTooLarge;
    out[pos.*] = @intCast(label.len);
    pos.* += 1;
    @memcpy(out[pos.*..][0..label.len], label);
    pos.* += label.len;
}

const NameResult = struct {
    name: []const u8,
    next: usize,
};

fn readName(packet: []const u8, start: usize, arena: std.mem.Allocator) Error!NameResult {
    if (start >= packet.len) return error.Truncated;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    var pos = start;
    var next: ?usize = null;
    var jumps: usize = 0;
    while (true) {
        if (pos >= packet.len) return error.Truncated;
        const len = packet[pos];
        if (len == 0) {
            pos += 1;
            if (next == null) next = pos;
            break;
        }
        if (len & 0xc0 == 0xc0) {
            if (pos + 1 >= packet.len) return error.Truncated;
            if (next == null) next = pos + 2;
            jumps += 1;
            if (jumps > 16) return error.BadResponse;
            pos = @as(usize, len & 0x3f) << 8 | packet[pos + 1];
            continue;
        }
        if (len & 0xc0 != 0 or len > 63) return error.BadResponse;
        if (pos + 1 + len > packet.len) return error.Truncated;
        if (out.items.len != 0) try out.append(arena, '.');
        try out.appendSlice(arena, packet[pos + 1 ..][0..len]);
        if (out.items.len > 253) return error.BadResponse;
        pos += 1 + len;
    }
    if (next == null) return error.Truncated;
    return .{ .name = try out.toOwnedSlice(arena), .next = next.? };
}

fn parseType(value: []const u8) ?u16 {
    if (std.ascii.eqlIgnoreCase(value, "A")) return 1;
    if (std.ascii.eqlIgnoreCase(value, "AAAA")) return 28;
    if (std.ascii.eqlIgnoreCase(value, "CNAME")) return 5;
    const number = std.fmt.parseInt(u16, value, 10) catch return null;
    if (number == 0 or number == 41) return null;
    return number;
}

fn rcodeText(code: u4) []const u8 {
    return switch (code) {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        else => "RCODE",
    };
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (std.ascii.toLower(left) != std.ascii.toLower(right)) return false;
    }
    return true;
}

const testing = std.testing;

test "builds a query and parses compressed A answers" {
    var query_buf: [512]u8 = undefined;
    const query_packet = try buildQuery(&query_buf, 7, "example.com", 1);

    var response: [512]u8 = undefined;
    @memcpy(response[0..query_packet.len], query_packet);
    std.mem.writeInt(u16, response[2..4], 0x8180, .big);
    std.mem.writeInt(u16, response[6..8], 1, .big);
    var pos = query_packet.len;
    response[pos] = 0xc0;
    response[pos + 1] = 0x0c;
    pos += 2;
    std.mem.writeInt(u16, response[pos..][0..2], 1, .big);
    std.mem.writeInt(u16, response[pos + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, response[pos + 4 ..][0..4], 60, .big);
    std.mem.writeInt(u16, response[pos + 8 ..][0..2], 4, .big);
    pos += 10;
    response[pos] = 192;
    response[pos + 1] = 0;
    response[pos + 2] = 2;
    response[pos + 3] = 1;
    pos += 4;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const result = try parseResponse(arena_state.allocator(), response[0..pos]);
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqualStrings("example.com", result.answers[0].owner);
    try testing.expectEqualStrings("A", result.answers[0].qtype);
    try testing.expectEqualStrings("192.0.2.1", result.answers[0].value);
    try testing.expectEqual(@as(u32, 60), result.answers[0].ttl);
    try testing.expectEqualStrings("NOERROR", result.rcode_text);
}

test "rejects compressed name loops and malformed records" {
    var query_buf: [512]u8 = undefined;
    const query_packet = try buildQuery(&query_buf, 9, "example.com", 28);
    var response: [512]u8 = undefined;
    @memcpy(response[0..query_packet.len], query_packet);
    std.mem.writeInt(u16, response[2..4], 0x8180, .big);
    std.mem.writeInt(u16, response[6..8], 1, .big);
    var pos = query_packet.len;
    response[pos] = 0xc0;
    response[pos + 1] = @intCast(pos);
    pos += 2;
    std.mem.writeInt(u16, response[pos..][0..2], 28, .big);
    std.mem.writeInt(u16, response[pos + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, response[pos + 4 ..][0..4], 60, .big);
    std.mem.writeInt(u16, response[pos + 8 ..][0..2], 16, .big);
    pos += 10;
    @memset(response[pos..][0..16], 0);
    pos += 16;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.BadResponse, parseResponse(arena_state.allocator(), response[0..pos]));
}
