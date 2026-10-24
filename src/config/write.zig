const std = @import("std");
const schema = @import("schema.zig");
const parse = @import("parse.zig");
const validate = @import("validate.zig");

pub fn renderNat(
    gpa: std.mem.Allocator,
    source: []const u8,
    nat: schema.NatConfig,
) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var root = std.json.parseFromSliceLeaky(
        std.json.Value,
        a,
        source,
        .{ .allocate = .alloc_always },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    const object = switch (root) {
        .object => |*value| value,
        else => return error.NotAnObject,
    };

    if (nat.masquerade.len == 0 and nat.port_forward.len == 0) {
        _ = object.orderedRemove("nat");
    } else {
        var nat_object: std.json.ObjectMap = .empty;
        if (nat.masquerade.len != 0) {
            var items = std.json.Array.init(a);
            for (nat.masquerade) |rule| {
                var item: std.json.ObjectMap = .empty;
                try item.put(a, "out", .{ .string = rule.out });
                try items.append(.{ .object = item });
            }
            try nat_object.put(a, "masquerade", .{ .array = items });
        }
        if (nat.port_forward.len != 0) {
            var items = std.json.Array.init(a);
            for (nat.port_forward) |rule| {
                var item: std.json.ObjectMap = .empty;
                try item.put(a, "proto", .{ .string = @tagName(rule.proto) });
                try item.put(a, "ext_port", .{ .integer = rule.ext_port });
                try item.put(a, "to", .{ .string = rule.to });
                if (rule.in_iface) |name| {
                    try item.put(a, "in", .{ .string = name });
                }
                try items.append(.{ .object = item });
            }
            try nat_object.put(a, "port_forward", .{ .array = items });
        }
        try object.put(a, "nat", .{ .object = nat_object });
    }

    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try std.json.Stringify.value(root, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeByte('\n');
    return out.toOwnedSlice();
}

pub fn saveNat(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    source: []const u8,
    nat: schema.NatConfig,
) !void {
    const lock_path = try std.mem.concat(gpa, u8, &.{ path, ".lock" });
    defer gpa.free(lock_path);
    var lock = try std.Io.Dir.cwd().createFile(io, lock_path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    defer lock.close(io);

    const rendered = try renderNat(gpa, source, nat);
    defer gpa.free(rendered);

    var parsed = try parse.parse(gpa, rendered);
    defer parsed.deinit();
    try validate.validate(&parsed.config);

    try replace(io, path, rendered);
}

pub fn replace(io: std.Io, path: []const u8, contents: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (stat) |value| {
        if (value.kind == .sym_link) return error.InvalidArgument;
    }
    const permissions = if (stat) |value|
        value.permissions
    else
        std.Io.File.Permissions.fromMode(0o600);

    var atomic = try cwd.createFileAtomic(io, path, .{
        .replace = true,
        .permissions = permissions,
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, contents);
    try atomic.file.sync(io);
    try atomic.replace(io);
}

test "renderNat preserves unrelated config and removes empty nat" {
    const source =
        \\{
        \\  "version": 1,
        \\  "instance": "test",
        \\  "ports": { "wan": { "kind": "l2", "device": "eth0" } },
        \\  "nat": {
        \\    "masquerade": [{ "out": "wan" }],
        \\    "port_forward": [{ "proto": "tcp", "ext_port": 80, "to": "10.0.0.2:80" }]
        \\  }
        \\}
    ;
    const rendered = try renderNat(std.testing.allocator, source, .{});
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"nat\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "\"ports\"") != null);

    var parsed = try parse.parse(std.testing.allocator, rendered);
    defer parsed.deinit();
    try validate.validate(&parsed.config);
    try std.testing.expectEqual(@as(usize, 0), parsed.config.nat.masquerade.len);
}

test "renderNat round-trips masquerade and port forwards" {
    const source =
        \\{"version":1,"instance":"test","ports":{"wan":{"kind":"l2","device":"eth0"}},"interfaces":{"wanif":{"port":"wan","address":"10.0.0.1/24"}}}
    ;
    const nat: schema.NatConfig = .{
        .masquerade = &.{.{ .out = "wanif" }},
        .port_forward = &.{.{
            .proto = .tcp,
            .ext_port = 8080,
            .to = "10.0.0.2:80",
            .in_iface = "wanif",
        }},
    };
    const rendered = try renderNat(std.testing.allocator, source, nat);
    defer std.testing.allocator.free(rendered);

    var parsed = try parse.parse(std.testing.allocator, rendered);
    defer parsed.deinit();
    try validate.validate(&parsed.config);
    try std.testing.expectEqual(@as(usize, 1), parsed.config.nat.masquerade.len);
    try std.testing.expectEqualStrings("wanif", parsed.config.nat.masquerade[0].out);
    try std.testing.expectEqual(@as(usize, 1), parsed.config.nat.port_forward.len);
    try std.testing.expectEqual(@as(u16, 8080), parsed.config.nat.port_forward[0].ext_port);
    try std.testing.expectEqualStrings("wanif", parsed.config.nat.port_forward[0].in_iface.?);
}

test "saveNat rotates an existing file atomically" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const source = "{\"version\":1,\"instance\":\"test\",\"ports\":{\"wan\":{\"kind\":\"l2\",\"device\":\"eth0\"}},\"interfaces\":{\"wanif\":{\"port\":\"wan\",\"address\":\"10.0.0.1/24\"}}}\n";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "vrouter.json", .data = source });
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/vrouter.json", .{path_buf[0..dir]});
    defer std.testing.allocator.free(path);

    try saveNat(std.testing.io, std.testing.allocator, path, source, .{
        .masquerade = &.{.{ .out = "wanif" }},
    });

    const saved = try tmp.dir.readFileAlloc(std.testing.io, "vrouter.json", std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(saved);
    try std.testing.expect(std.mem.indexOf(u8, saved, "\"masquerade\"") != null);
}
