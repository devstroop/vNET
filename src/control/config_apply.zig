//! Config proposal validation, canonical serialization, diffing and the
//! one-time confirmation/idempotency state used by the v3 write path.

const std = @import("std");
const config_parse = @import("../config/parse.zig");
const config_validate = @import("../config/validate.zig");
const config_store = @import("../config/store.zig");

pub const max_diff_bytes: usize = 8 * 1024 * 1024;
pub const token_hex_len = 64;
pub const confirm_ttl_ms: i64 = 5 * 60 * 1000;
pub const max_idempotency_key = 128;

pub const Result = enum {
    applied,
    restart_required,
    rolled_back,
    noop,
};

pub const Field = enum(u4) {
    version,
    instance,
    log,
    ports,
    bridges,
    interfaces,
    routes,
    nat,
    dhcp,
    dns,
    firewall,
    lease_db,
};

pub const Affected = struct {
    bits: u16 = 0,

    pub fn add(self: *Affected, field: Field) void {
        self.bits |= @as(u16, 1) << @intFromEnum(field);
    }

    pub fn contains(self: Affected, field: Field) bool {
        return self.bits & (@as(u16, 1) << @intFromEnum(field)) != 0;
    }

    pub fn restartRequired(self: Affected) bool {
        return self.bits & ~(@as(u16, 1) << @intFromEnum(Field.nat)) != 0;
    }

    pub fn count(self: Affected) usize {
        return @popCount(self.bits);
    }

    pub fn labelAt(self: Affected, index: usize) ?[]const u8 {
        var seen: usize = 0;
        inline for (std.meta.fields(Field)) |field| {
            if (self.contains(@enumFromInt(field.value))) {
                if (seen == index) return field.name;
                seen += 1;
            }
        }
        return null;
    }
};

pub const Proposal = struct {
    bytes: []u8,
    parsed: config_parse.Parsed,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Proposal) void {
        self.parsed.deinit();
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const Change = struct {
    proposal: Proposal,
    diff: []u8,
    affected: Affected,
    restart_required: bool,
    diff_hash: [32]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Change) void {
        self.proposal.deinit();
        self.allocator.free(self.diff);
        self.* = undefined;
    }
};

pub fn validateProposal(
    gpa: std.mem.Allocator,
    value: std.json.Value,
) !Proposal {
    const bytes = try canonicalize(gpa, value);
    errdefer gpa.free(bytes);
    var parsed = config_parse.parse(gpa, bytes) catch |err| return err;
    errdefer parsed.deinit();
    config_validate.validate(&parsed.config) catch |err| return err;
    return .{ .bytes = bytes, .parsed = parsed, .allocator = gpa };
}

pub fn analyze(
    gpa: std.mem.Allocator,
    current_bytes: []const u8,
    proposal_value: std.json.Value,
) !Change {
    var proposal = try validateProposal(gpa, proposal_value);
    errdefer proposal.deinit();

    var current = std.json.parseFromSlice(std.json.Value, gpa, current_bytes, .{
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidCurrentConfig,
    };
    defer current.deinit();
    var proposed = std.json.parseFromSlice(std.json.Value, gpa, proposal.bytes, .{
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    defer proposed.deinit();

    const affected = try compare(gpa, current.value, proposed.value);
    const current_canonical = try canonicalize(gpa, current.value);
    defer gpa.free(current_canonical);
    const diff = try unifiedDiff(gpa, current_canonical, proposal.bytes);
    errdefer gpa.free(diff);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(diff, &hash, .{});
    return .{
        .proposal = proposal,
        .diff = diff,
        .affected = affected,
        .restart_required = affected.restartRequired(),
        .diff_hash = hash,
        .allocator = gpa,
    };
}

pub fn canonicalize(gpa: std.mem.Allocator, value: std.json.Value) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const normalized = try normalizeValue(arena.allocator(), value);
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try std.json.Stringify.value(normalized, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeByte('\n');
    return out.toOwnedSlice();
}

fn normalizeValue(arena: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    return switch (value) {
        .object => |object| {
            const keys = try arena.alloc([]const u8, object.keys().len);
            var count: usize = 0;
            for (object.keys()) |key| {
                const field_value = object.get(key) orelse continue;
                if (isNull(field_value)) continue;
                keys[count] = key;
                count += 1;
            }
            std.mem.sort([]const u8, keys[0..count], {}, lessThanKey);
            var map: std.json.ObjectMap = .{};
            for (keys[0..count]) |key| {
                try map.put(arena, key, try normalizeValue(arena, object.get(key).?));
            }
            return .{ .object = map };
        },
        .array => |array| {
            var list = std.json.Array.init(arena);
            try list.ensureTotalCapacity(array.items.len);
            for (array.items) |item| {
                try list.append(try normalizeValue(arena, item));
            }
            return .{ .array = list };
        },
        else => value,
    };
}

fn isNull(value: std.json.Value) bool {
    return switch (value) {
        .null => true,
        else => false,
    };
}

fn lessThanKey(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn compare(
    gpa: std.mem.Allocator,
    before: std.json.Value,
    after: std.json.Value,
) !Affected {
    var affected: Affected = .{};
    inline for (std.meta.fields(Field)) |field| {
        const same = try jsonFieldEqual(gpa, before, after, field.name);
        if (!same) affected.add(@enumFromInt(field.value));
    }
    return affected;
}

fn jsonFieldEqual(
    gpa: std.mem.Allocator,
    before: std.json.Value,
    after: std.json.Value,
    name: []const u8,
) !bool {
    const a = objectField(before, name);
    const b = objectField(after, name);
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    const a_bytes = try canonicalize(gpa, a.?);
    defer gpa.free(a_bytes);
    const b_bytes = try canonicalize(gpa, b.?);
    defer gpa.free(b_bytes);
    return std.mem.eql(u8, a_bytes, b_bytes);
}

fn objectField(value: std.json.Value, name: []const u8) ?std.json.Value {
    return switch (value) {
        .object => |object| object.get(name),
        else => null,
    };
}

pub fn unifiedDiff(
    gpa: std.mem.Allocator,
    before: []const u8,
    after: []const u8,
) ![]u8 {
    var before_lines: std.ArrayListUnmanaged([]const u8) = .empty;
    defer before_lines.deinit(gpa);
    var after_lines: std.ArrayListUnmanaged([]const u8) = .empty;
    defer after_lines.deinit(gpa);

    var it = std.mem.splitScalar(u8, before, '\n');
    while (it.next()) |line| try before_lines.append(gpa, line);
    it = std.mem.splitScalar(u8, after, '\n');
    while (it.next()) |line| try after_lines.append(gpa, line);

    var prefix: usize = 0;
    while (prefix < before_lines.items.len and
        prefix < after_lines.items.len and
        std.mem.eql(u8, before_lines.items[prefix], after_lines.items[prefix]))
    {
        prefix += 1;
    }

    var suffix: usize = 0;
    while (suffix + prefix < before_lines.items.len and
        suffix + prefix < after_lines.items.len and
        std.mem.eql(
            u8,
            before_lines.items[before_lines.items.len - 1 - suffix],
            after_lines.items[after_lines.items.len - 1 - suffix],
        ))
    {
        suffix += 1;
    }

    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    if (prefix == before_lines.items.len and prefix == after_lines.items.len) {
        return out.toOwnedSlice();
    }

    try out.writer.writeAll("--- current\n+++ proposed\n");
    const old_start = prefix + 1;
    const new_start = prefix + 1;
    const old_count = before_lines.items.len - prefix - suffix;
    const new_count = after_lines.items.len - prefix - suffix;
    try out.writer.print("@@ -{d},{d} +{d},{d} @@\n", .{
        old_start,
        old_count,
        new_start,
        new_count,
    });
    for (before_lines.items[prefix .. before_lines.items.len - suffix]) |line| {
        try out.writer.writeByte('-');
        try out.writer.writeAll(line);
        try out.writer.writeByte('\n');
        if (out.writer.buffered().len > max_diff_bytes) return error.DiffTooLarge;
    }
    for (after_lines.items[prefix .. after_lines.items.len - suffix]) |line| {
        try out.writer.writeByte('+');
        try out.writer.writeAll(line);
        try out.writer.writeByte('\n');
        if (out.writer.buffered().len > max_diff_bytes) return error.DiffTooLarge;
    }
    return out.toOwnedSlice();
}

pub const Confirm = struct {
    active: bool = false,
    token: [token_hex_len]u8 = undefined,
    revision: config_store.Revision = undefined,
    diff_hash: [32]u8 = undefined,
    expires_ms: i64 = 0,

    pub fn issue(
        self: *Confirm,
        io: std.Io,
        revision: config_store.Revision,
        diff_hash: [32]u8,
        now_ms: i64,
    ) ![]const u8 {
        var raw: [32]u8 = undefined;
        try io.randomSecure(&raw);
        self.token = std.fmt.bytesToHex(raw, .lower);
        self.revision = revision;
        self.diff_hash = diff_hash;
        self.expires_ms = now_ms + confirm_ttl_ms;
        self.active = true;
        return self.token[0..];
    }

    pub fn consume(
        self: *Confirm,
        token: []const u8,
        revision: config_store.Revision,
        diff_hash: [32]u8,
        now_ms: i64,
    ) bool {
        if (!self.active or now_ms > self.expires_ms) {
            self.active = false;
            return false;
        }
        if (token.len != token_hex_len) return false;
        if (!std.mem.eql(u8, self.token[0..], token)) return false;
        if (!std.mem.eql(u8, self.revision.slice(), revision.slice())) return false;
        if (!std.mem.eql(u8, self.diff_hash[0..], diff_hash[0..])) return false;
        self.active = false;
        return true;
    }
};

pub const Idempotency = struct {
    active: bool = false,
    key: [max_idempotency_key]u8 = undefined,
    key_len: usize = 0,
    proposal_hash: [32]u8 = undefined,
    revision: config_store.Revision = undefined,
    transaction: [64]u8 = undefined,
    result: Result = .applied,
    restart_required: bool = false,
    affected: Affected = .{},
    expires_ms: i64 = 0,

    pub fn lookup(
        self: *const Idempotency,
        key: []const u8,
        proposal_hash: [32]u8,
        now_ms: i64,
    ) ?Lookup {
        if (!self.active or now_ms > self.expires_ms) return null;
        if (key.len != self.key_len or !std.mem.eql(u8, self.key[0..self.key_len], key)) return null;
        if (!std.mem.eql(u8, self.proposal_hash[0..], proposal_hash[0..])) return .conflict;
        return .{ .hit = .{
            .revision = self.revision,
            .transaction = self.transaction,
            .result = self.result,
            .restart_required = self.restart_required,
            .affected = self.affected,
        } };
    }

    pub fn record(
        self: *Idempotency,
        key: []const u8,
        proposal_hash: [32]u8,
        revision: config_store.Revision,
        transaction: [64]u8,
        result: Result,
        restart_required: bool,
        affected: Affected,
        now_ms: i64,
    ) void {
        if (key.len == 0 or key.len > self.key.len) return;
        @memcpy(self.key[0..key.len], key);
        self.key_len = key.len;
        self.proposal_hash = proposal_hash;
        self.revision = revision;
        self.transaction = transaction;
        self.result = result;
        self.restart_required = restart_required;
        self.affected = affected;
        self.expires_ms = now_ms + 10 * 60 * 1000;
        self.active = true;
    }

    pub const Snapshot = struct {
        revision: config_store.Revision,
        transaction: [64]u8,
        result: Result,
        restart_required: bool,
        affected: Affected,
    };

    pub const Lookup = union(enum) {
        hit: Snapshot,
        conflict,
    };
};

test "canonicalize ignores object order and null optionals" {
    const before =
        \\{"version":1,"instance":"test","ports":{"wan":{"kind":"l2","device":"eth0"}},"dns":{"upstreams":["1.1.1.1"],"listen":null}}
    ;
    const after =
        \\{"instance":"test","dns":{"upstreams":["1.1.1.1"]},"ports":{"wan":{"device":"eth0","kind":"l2"}},"version":1}
    ;
    var before_value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, before, .{ .allocate = .alloc_always });
    defer before_value.deinit();
    var after_value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, after, .{ .allocate = .alloc_always });
    defer after_value.deinit();
    const before_canonical = try canonicalize(std.testing.allocator, before_value.value);
    defer std.testing.allocator.free(before_canonical);
    const after_canonical = try canonicalize(std.testing.allocator, after_value.value);
    defer std.testing.allocator.free(after_canonical);
    try std.testing.expectEqualStrings(before_canonical, after_canonical);
}

test "analyze ignores object order and null optionals" {
    const before =
        \\{"version":1,"instance":"test","ports":{"wan":{"kind":"l2","device":"eth0"}},"nat":{"masquerade":[{"out":"wan"}]}}
    ;
    const after =
        \\{"nat":{"masquerade":[{"out":"wan"}]},"ports":{"wan":{"device":"eth0","kind":"l2"}},"instance":"test","version":1}
    ;
    var value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, after, .{ .allocate = .alloc_always });
    defer value.deinit();
    var change = try analyze(std.testing.allocator, before, value.value);
    defer change.deinit();
    try std.testing.expectEqual(@as(usize, 0), change.affected.count());
    try std.testing.expectEqualStrings("", change.diff);
    try std.testing.expect(!change.restart_required);
}

test "canonicalize and diff preserve unrelated fields" {
    const before =
        \\{"version":1,"instance":"test","ports":{"wan":{"kind":"l2","device":"eth0"}},"nat":{"masquerade":[{"out":"wan"}]}}
    ;
    var value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, before, .{ .allocate = .alloc_always });
    defer value.deinit();
    var change = try analyze(std.testing.allocator, before, value.value);
    defer change.deinit();
    try std.testing.expectEqual(@as(usize, 0), change.affected.count());
    try std.testing.expectEqualStrings("", change.diff);
    try std.testing.expect(!change.restart_required);
}

test "analyze reports NAT as live and structural as restart-required" {
    const before =
        \\{"version":1,"instance":"test","ports":{"wan":{"kind":"l2","device":"eth0"}},"nat":{"masquerade":[{"out":"wan"}]}}
    ;
    const after_nat =
        \\{"version":1,"instance":"test","ports":{"wan":{"kind":"l2","device":"eth0"}},"nat":{"masquerade":[]}}
    ;
    var nat_value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, after_nat, .{ .allocate = .alloc_always });
    defer nat_value.deinit();
    var nat_change = try analyze(std.testing.allocator, before, nat_value.value);
    defer nat_change.deinit();
    try std.testing.expect(nat_change.affected.contains(.nat));
    try std.testing.expect(!nat_change.restart_required);

    const after_ports =
        \\{"version":1,"instance":"test","ports":{"lan":{"kind":"l2","device":"eth1"}},"nat":{"masquerade":[{"out":"lan"}]}}
    ;
    var ports_value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, after_ports, .{ .allocate = .alloc_always });
    defer ports_value.deinit();
    var ports_change = try analyze(std.testing.allocator, before, ports_value.value);
    defer ports_change.deinit();
    try std.testing.expect(ports_change.affected.contains(.ports));
    try std.testing.expect(ports_change.restart_required);
}

test "confirm is revision and diff bound and one-shot" {
    var confirm: Confirm = .{};
    const revision = config_store.Revision.compute("{}");
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("diff", &hash, .{});
    const token = try confirm.issue(std.testing.io, revision, hash, 1000);
    var copy: [token_hex_len]u8 = undefined;
    @memcpy(&copy, token);
    try std.testing.expect(confirm.consume(&copy, revision, hash, 1001));
    try std.testing.expect(!confirm.consume(&copy, revision, hash, 1002));
}
