//! Durable write intent and audit trail for config.apply. The pending file is
//! written before the config replace and resolved after a crash by comparing
//! its recorded revisions with the config store's current revision.

const std = @import("std");
const config_apply = @import("config_apply.zig");
const config_store = @import("vnet-core").config_store;

pub const pending_file = "transaction.pending";
pub const audit_file = "audit.jsonl";
pub const restart_file = "restart.pending";
pub const transaction_hex_len = 64;
pub const max_pending_bytes: usize = 64 * 1024;
pub const max_audit_bytes: usize = 16 * 1024 * 1024;

pub const Error = error{
    CorruptPending,
    RevisionMismatch,
    AuditTooLarge,
};

pub const Actor = struct {
    uid: u32,
    pid: i32,
};

pub const Entry = struct {
    transaction: []const u8,
    audit_id: []const u8,
    op: []const u8,
    instance: []const u8,
    revision_before: []const u8,
    revision_after: []const u8,
    affected: config_apply.Affected,
    restart_required: bool,
    actor: Actor,
    ts_ms: i64,
};

pub const Resolution = enum {
    committed,
    rolled_back,
};

pub fn generateId(io: std.Io) ![transaction_hex_len]u8 {
    var raw: [transaction_hex_len / 2]u8 = undefined;
    try io.randomSecure(&raw);
    return std.fmt.bytesToHex(raw, .lower);
}

pub fn writePending(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8, entry: Entry) !void {
    const line = try encode(io, gpa, entry);
    defer gpa.free(line);
    try ensureStateDir(io, state_dir);
    const path = try std.fs.path.join(gpa, &.{ state_dir, pending_file });
    defer gpa.free(path);
    var atomic = try std.Io.Dir.cwd().createFileAtomic(io, path, .{
        .replace = true,
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, line);
    try atomic.file.sync(io);
    try atomic.replace(io);
    try syncParent(io, path);
}

pub fn appendAudit(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8, entry: Entry) !void {
    const line = try encode(io, gpa, entry);
    defer gpa.free(line);
    try ensureStateDir(io, state_dir);
    const path = try std.fs.path.join(gpa, &.{ state_dir, audit_file });
    defer gpa.free(path);
    const cwd = std.Io.Dir.cwd();
    var file = try cwd.createFile(io, path, .{
        .read = true,
        .truncate = false,
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    defer file.close(io);
    const stat = try file.stat(io);
    try file.writePositionalAll(io, line, stat.size);
    try file.sync(io);
}

pub fn appendOperationAudit(
    io: std.Io,
    gpa: std.mem.Allocator,
    state_dir: []const u8,
    op: []const u8,
    instance: []const u8,
    transaction_id: []const u8,
    audit_id: []const u8,
    actor: Actor,
    ts_ms: i64,
) !void {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var json: std.json.Stringify = .{ .writer = &out.writer };
    try json.beginObject();
    try json.objectField("ts_ms");
    try json.write(ts_ms);
    try json.objectField("transaction");
    try json.write(transaction_id);
    try json.objectField("audit_id");
    try json.write(audit_id);
    try json.objectField("kind");
    try json.write("operational");
    try json.objectField("op");
    try json.write(op);
    try json.objectField("instance");
    try json.write(instance);
    try json.objectField("actor_uid");
    try json.write(actor.uid);
    try json.objectField("actor_pid");
    try json.write(actor.pid);
    try json.objectField("result");
    try json.write("accepted");
    try json.endObject();
    try out.writer.writeByte('\n');

    try ensureStateDir(io, state_dir);
    const path = try std.fs.path.join(gpa, &.{ state_dir, audit_file });
    defer gpa.free(path);
    const cwd = std.Io.Dir.cwd();
    var file = try cwd.createFile(io, path, .{
        .read = true,
        .truncate = false,
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    defer file.close(io);
    const stat = try file.stat(io);
    try file.writePositionalAll(io, out.writer.buffered(), stat.size);
    try file.sync(io);
}

pub fn auditContains(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8, transaction: []const u8) !bool {
    const path = try std.fs.path.join(gpa, &.{ state_dir, audit_file });
    defer gpa.free(path);
    const cwd = std.Io.Dir.cwd();
    var file = cwd.openFile(io, path, .{ .allow_directory = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const data = reader.interface.allocRemaining(gpa, .limited(max_audit_bytes)) catch |err| switch (err) {
        error.StreamTooLong => return error.AuditTooLarge,
        else => return err,
    };
    defer gpa.free(data);
    const needle = try std.fmt.allocPrint(gpa, "\"transaction\":\"{s}\"", .{transaction});
    defer gpa.free(needle);
    return std.mem.indexOf(u8, data, needle) != null;
}

pub const Pending = struct {
    entry: Entry,
    parsed: std.json.Parsed(std.json.Value),

    pub fn deinit(self: *Pending) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn loadPending(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8) !?Pending {
    const path = try std.fs.path.join(gpa, &.{ state_dir, pending_file });
    defer gpa.free(path);
    const cwd = std.Io.Dir.cwd();
    var file = cwd.openFile(io, path, .{ .allow_directory = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    const data = reader.interface.allocRemaining(gpa, .limited(max_pending_bytes)) catch |err| switch (err) {
        error.StreamTooLong => return error.CorruptPending,
        else => return err,
    };
    defer gpa.free(data);
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, data, .{
        .allocate = .alloc_always,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CorruptPending,
    };
    errdefer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |object| object,
        else => return error.CorruptPending,
    };
    const transaction = try stringField(object, "transaction");
    const audit_id = try stringField(object, "audit_id");
    const op = try stringField(object, "op");
    const instance = try stringField(object, "instance");
    const revision_before = try stringField(object, "revision_before");
    const revision_after = try stringField(object, "revision_after");
    if (transaction.len != transaction_hex_len or audit_id.len != transaction_hex_len) {
        return error.CorruptPending;
    }
    const restart_required = boolField(object, "restart_required") orelse return error.CorruptPending;
    const uid = intField(object, "actor_uid") orelse return error.CorruptPending;
    const pid = intField(object, "actor_pid") orelse return error.CorruptPending;
    const ts_ms = intField(object, "ts_ms") orelse return error.CorruptPending;
    const affected_value = object.get("affected") orelse return error.CorruptPending;
    var affected: config_apply.Affected = .{};
    switch (affected_value) {
        .array => |array| for (array.items) |item| {
            const label = switch (item) {
                .string => |string| string,
                else => return error.CorruptPending,
            };
            affected.add(fieldByName(label) orelse return error.CorruptPending);
        },
        else => return error.CorruptPending,
    }
    return .{
        .entry = .{
            .transaction = transaction,
            .audit_id = audit_id,
            .op = op,
            .instance = instance,
            .revision_before = revision_before,
            .revision_after = revision_after,
            .affected = affected,
            .restart_required = restart_required,
            .actor = .{ .uid = @intCast(uid), .pid = @intCast(pid) },
            .ts_ms = ts_ms,
        },
        .parsed = parsed,
    };
}

pub fn resolvePending(
    io: std.Io,
    gpa: std.mem.Allocator,
    state_dir: []const u8,
    current: config_store.Revision,
    pending: *const Pending,
) !Resolution {
    const entry = pending.entry;
    if (std.mem.eql(u8, entry.revision_after, current.slice())) {
        if (!try auditContains(io, gpa, state_dir, entry.transaction)) {
            try appendAudit(io, gpa, state_dir, entry);
        }
        if (entry.restart_required) try writeRestartPending(io, gpa, state_dir, entry);
        try clearPending(io, gpa, state_dir);
        return .committed;
    }
    if (std.mem.eql(u8, entry.revision_before, current.slice())) {
        if (!try auditContains(io, gpa, state_dir, entry.transaction)) {
            var rolled_back = entry;
            rolled_back.restart_required = false;
            try appendAudit(io, gpa, state_dir, rolled_back);
        }
        try clearPending(io, gpa, state_dir);
        return .rolled_back;
    }
    return error.RevisionMismatch;
}

pub fn clearPending(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8) !void {
    try clearFile(io, gpa, state_dir, pending_file);
}

pub fn writeRestartPending(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8, entry: Entry) !void {
    const line = try encode(io, gpa, entry);
    defer gpa.free(line);
    try ensureStateDir(io, state_dir);
    const path = try std.fs.path.join(gpa, &.{ state_dir, restart_file });
    defer gpa.free(path);
    var atomic = try std.Io.Dir.cwd().createFileAtomic(io, path, .{
        .replace = true,
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, line);
    try atomic.file.sync(io);
    try atomic.replace(io);
    try syncParent(io, path);
}

pub fn restartPending(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8) !bool {
    const path = try std.fs.path.join(gpa, &.{ state_dir, restart_file });
    defer gpa.free(path);
    _ = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

pub fn clearRestartPending(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8) !void {
    try clearFile(io, gpa, state_dir, restart_file);
}

fn clearFile(io: std.Io, gpa: std.mem.Allocator, state_dir: []const u8, name: []const u8) !void {
    const path = try std.fs.path.join(gpa, &.{ state_dir, name });
    defer gpa.free(path);
    std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

fn encode(io: std.Io, gpa: std.mem.Allocator, entry: Entry) ![]u8 {
    _ = io;
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var json: std.json.Stringify = .{ .writer = &out.writer };
    try json.beginObject();
    try json.objectField("transaction");
    try json.write(entry.transaction);
    try json.objectField("audit_id");
    try json.write(entry.audit_id);
    try json.objectField("op");
    try json.write(entry.op);
    try json.objectField("instance");
    try json.write(entry.instance);
    try json.objectField("revision_before");
    try json.write(entry.revision_before);
    try json.objectField("revision_after");
    try json.write(entry.revision_after);
    try json.objectField("affected");
    try json.beginArray();
    var index: usize = 0;
    while (entry.affected.labelAt(index)) |label| : (index += 1) {
        try json.write(label);
    }
    try json.endArray();
    try json.objectField("restart_required");
    try json.write(entry.restart_required);
    try json.objectField("actor_uid");
    try json.write(entry.actor.uid);
    try json.objectField("actor_pid");
    try json.write(entry.actor.pid);
    try json.objectField("ts_ms");
    try json.write(entry.ts_ms);
    try json.endObject();
    try out.writer.writeByte('\n');
    return out.toOwnedSlice();
}

fn fieldByName(name: []const u8) ?config_apply.Field {
    inline for (std.meta.fields(config_apply.Field)) |field| {
        if (std.mem.eql(u8, field.name, name)) return @enumFromInt(field.value);
    }
    return null;
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.CorruptPending;
    return switch (value) {
        .string => |string| string,
        else => error.CorruptPending,
    };
}

fn boolField(object: std.json.ObjectMap, name: []const u8) ?bool {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .bool => |boolean| boolean,
        else => null,
    };
}

fn intField(object: std.json.ObjectMap, name: []const u8) ?i64 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .integer => |integer| integer,
        else => null,
    };
}

fn ensureStateDir(io: std.Io, state_dir: []const u8) !void {
    _ = try std.Io.Dir.cwd().createDirPathStatus(io, state_dir, std.Io.File.Permissions.fromMode(0o700));
}

fn syncParent(io: std.Io, path: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse ".";
    var dir = try std.Io.Dir.cwd().openFile(io, dir_path, .{ .allow_directory = true });
    defer dir.close(io);
    try dir.sync(io);
}

test "operation audit records accepted daemon actions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(std.testing.io, &path_buf);
    const state_dir = path_buf[0..dir];
    try appendOperationAudit(
        std.testing.io,
        std.testing.allocator,
        state_dir,
        "daemon.restart",
        "test",
        "a" ** 64,
        "b" ** 64,
        .{ .uid = 0, .pid = 42 },
        1000,
    );
    const audit = try tmp.dir.readFileAlloc(std.testing.io, audit_file, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(audit);
    try std.testing.expect(std.mem.indexOf(u8, audit, "\"op\":\"daemon.restart\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit, "\"result\":\"accepted\"") != null);
}

test "resolvePending commits, audits once, and records restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(std.testing.io, &path_buf);
    const state_dir = path_buf[0..dir];

    const before = config_store.Revision.compute("before");
    const after = config_store.Revision.compute("after");
    const tx: [transaction_hex_len]u8 = @splat('a');
    const audit_id: [transaction_hex_len]u8 = @splat('b');
    var affected: config_apply.Affected = .{};
    affected.add(.ports);

    const entry: Entry = .{
        .transaction = tx[0..],
        .audit_id = audit_id[0..],
        .op = "config.apply",
        .instance = "test",
        .revision_before = before.slice(),
        .revision_after = after.slice(),
        .affected = affected,
        .restart_required = true,
        .actor = .{ .uid = 1000, .pid = 42 },
        .ts_ms = 1234,
    };
    try writePending(std.testing.io, std.testing.allocator, state_dir, entry);

    var pending = (try loadPending(std.testing.io, std.testing.allocator, state_dir)).?;
    defer pending.deinit();
    try std.testing.expectEqual(Resolution.committed, try resolvePending(
        std.testing.io,
        std.testing.allocator,
        state_dir,
        after,
        &pending,
    ));
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(std.testing.io, pending_file, .{}),
    );
    try std.testing.expect(try restartPending(std.testing.io, std.testing.allocator, state_dir));

    const audit = try tmp.dir.readFileAlloc(std.testing.io, audit_file, std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(audit);
    try std.testing.expect(std.mem.indexOf(u8, audit, "\"transaction\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit, "\"restart_required\":true") != null);

    try std.testing.expectEqual(Resolution.committed, try resolvePending(
        std.testing.io,
        std.testing.allocator,
        state_dir,
        after,
        &pending,
    ));
    const audit_again = try tmp.dir.readFileAlloc(std.testing.io, audit_file, std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(audit_again);
    try std.testing.expectEqualStrings(audit, audit_again);

    try clearRestartPending(std.testing.io, std.testing.allocator, state_dir);
    try std.testing.expect(!try restartPending(std.testing.io, std.testing.allocator, state_dir));
}

test "resolvePending marks an uncommitted transaction as rolled back" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(std.testing.io, &path_buf);
    const state_dir = path_buf[0..dir];

    const before = config_store.Revision.compute("before");
    const after = config_store.Revision.compute("after");
    const tx: [transaction_hex_len]u8 = @splat('c');
    const audit_id: [transaction_hex_len]u8 = @splat('d');
    var affected: config_apply.Affected = .{};
    affected.add(.nat);

    const entry: Entry = .{
        .transaction = tx[0..],
        .audit_id = audit_id[0..],
        .op = "config.apply",
        .instance = "test",
        .revision_before = before.slice(),
        .revision_after = after.slice(),
        .affected = affected,
        .restart_required = true,
        .actor = .{ .uid = 1000, .pid = 43 },
        .ts_ms = 1235,
    };
    try writePending(std.testing.io, std.testing.allocator, state_dir, entry);

    var pending = (try loadPending(std.testing.io, std.testing.allocator, state_dir)).?;
    defer pending.deinit();
    try std.testing.expectEqual(Resolution.rolled_back, try resolvePending(
        std.testing.io,
        std.testing.allocator,
        state_dir,
        before,
        &pending,
    ));
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(std.testing.io, pending_file, .{}),
    );
    try std.testing.expect(!try restartPending(std.testing.io, std.testing.allocator, state_dir));

    const audit = try tmp.dir.readFileAlloc(std.testing.io, audit_file, std.testing.allocator, .limited(8192));
    defer std.testing.allocator.free(audit);
    try std.testing.expect(std.mem.indexOf(u8, audit, "\"restart_required\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit, "\"affected\":[\"nat\"]") != null);
}

test "resolvePending rejects a revision that matches neither side" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(std.testing.io, &path_buf);
    const state_dir = path_buf[0..dir];

    const before = config_store.Revision.compute("before");
    const after = config_store.Revision.compute("after");
    const other = config_store.Revision.compute("other");
    const tx: [transaction_hex_len]u8 = @splat('e');
    const audit_id: [transaction_hex_len]u8 = @splat('f');

    const entry: Entry = .{
        .transaction = tx[0..],
        .audit_id = audit_id[0..],
        .op = "config.apply",
        .instance = "test",
        .revision_before = before.slice(),
        .revision_after = after.slice(),
        .affected = .{},
        .restart_required = true,
        .actor = .{ .uid = 1000, .pid = 44 },
        .ts_ms = 1236,
    };
    try writePending(std.testing.io, std.testing.allocator, state_dir, entry);

    var pending = (try loadPending(std.testing.io, std.testing.allocator, state_dir)).?;
    defer pending.deinit();
    try std.testing.expectError(error.RevisionMismatch, resolvePending(
        std.testing.io,
        std.testing.allocator,
        state_dir,
        other,
        &pending,
    ));
    _ = try tmp.dir.statFile(std.testing.io, pending_file, .{});
}

test "loadPending rejects corrupt transaction records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(std.testing.io, &path_buf);
    const state_dir = path_buf[0..dir];

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = pending_file, .data = "{not json" });
    try std.testing.expectError(
        error.CorruptPending,
        loadPending(std.testing.io, std.testing.allocator, state_dir),
    );
}
