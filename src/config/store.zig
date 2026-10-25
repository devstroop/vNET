//! Daemon-owned config store: exact on-disk bytes, content revision, shared
//! writer lock and durable atomic replacement. The web never opens the config
//! path directly; it goes through the control socket.

const std = @import("std");

pub const max_bytes = 4 * 1024 * 1024;
pub const revision_prefix = "sha256:";
pub const revision_len = revision_prefix.len + 64;

pub const Error = error{
    InvalidArgument,
    ConfigTooLarge,
    FileNotFound,
    RevisionMismatch,
};

pub const Revision = struct {
    bytes: [revision_len]u8,

    pub fn compute(contents: []const u8) Revision {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(contents, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        var out: Revision = undefined;
        @memcpy(out.bytes[0..revision_prefix.len], revision_prefix);
        @memcpy(out.bytes[revision_prefix.len..], &hex);
        return out;
    }

    pub fn slice(self: *const Revision) []const u8 {
        return self.bytes[0..];
    }
};

pub const Lock = struct {
    io: std.Io,
    file: std.Io.File,

    pub fn deinit(self: *Lock) void {
        self.file.close(self.io);
        self.* = undefined;
    }
};

pub const Store = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []u8,
    lock_path: []u8,
    mutex: std.Io.Mutex = .init,
    bytes: []u8,
    revision: Revision,

    pub fn open(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !Store {
        if (path.len == 0) return error.InvalidArgument;
        const bytes = try readFile(io, gpa, path);
        errdefer gpa.free(bytes);
        const lock_path = try std.mem.concat(gpa, u8, &.{ path, ".lock" });
        errdefer gpa.free(lock_path);
        return .{
            .io = io,
            .gpa = gpa,
            .path = try gpa.dupe(u8, path),
            .lock_path = lock_path,
            .bytes = bytes,
            .revision = Revision.compute(bytes),
        };
    }

    pub fn deinit(self: *Store) void {
        self.gpa.free(self.path);
        self.gpa.free(self.lock_path);
        self.gpa.free(self.bytes);
        self.* = undefined;
    }

    pub fn pathSlice(self: *const Store) []const u8 {
        return self.path;
    }

    pub fn lock(self: *Store) !Lock {
        var file = try std.Io.Dir.cwd().createFile(self.io, self.lock_path, .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        });
        errdefer file.close(self.io);
        return .{ .io = self.io, .file = file };
    }

    pub fn readInto(self: *Store, out: []u8) ?[]const u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (out.len < self.bytes.len) return null;
        @memcpy(out[0..self.bytes.len], self.bytes);
        return out[0..self.bytes.len];
    }

    pub fn revisionCopy(self: *Store) Revision {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.revision;
    }

    /// Replace the config after taking the shared writer lock. Callers that
    /// already hold `lock()` must use `replaceLocked`.
    pub fn replace(self: *Store, contents: []const u8) !Revision {
        var held = try self.lock();
        defer held.deinit();
        return self.replaceLocked(contents);
    }

    /// Replace the config while the caller holds the shared writer lock.
    pub fn replaceLocked(self: *Store, contents: []const u8) !Revision {
        if (contents.len > max_bytes) return error.ConfigTooLarge;
        const next_bytes = try self.gpa.dupe(u8, contents);
        errdefer self.gpa.free(next_bytes);
        const next_revision = Revision.compute(contents);

        try replaceFile(self.io, self.path, contents);
        self.mutex.lockUncancelable(self.io);
        const previous = self.bytes;
        self.bytes = next_bytes;
        self.revision = next_revision;
        self.mutex.unlock(self.io);
        self.gpa.free(previous);
        return next_revision;
    }

    pub fn reload(self: *Store) !Revision {
        var held = try self.lock();
        defer held.deinit();
        const next_bytes = try readFile(self.io, self.gpa, self.path);
        errdefer self.gpa.free(next_bytes);
        const next_revision = Revision.compute(next_bytes);
        self.mutex.lockUncancelable(self.io);
        const previous = self.bytes;
        self.bytes = next_bytes;
        self.revision = next_revision;
        self.mutex.unlock(self.io);
        self.gpa.free(previous);
        return next_revision;
    }
};

fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    const cwd = std.Io.Dir.cwd();
    var file = cwd.openFile(io, path, .{
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.SymLinkLoop => return error.InvalidArgument,
        error.IsDir => return error.InvalidArgument,
        else => return err,
    };
    defer file.close(io);

    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);
    return reader.interface.allocRemaining(gpa, .limited(max_bytes)) catch |err| switch (err) {
        error.StreamTooLong => return error.ConfigTooLarge,
        else => return err,
    };
}

fn replaceFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidArgument;

    var atomic = try cwd.createFileAtomic(io, path, .{
        .replace = true,
        .permissions = stat.permissions,
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, contents);
    try atomic.file.sync(io);
    try atomic.replace(io);
    try syncParent(io, path);
}

fn syncParent(io: std.Io, path: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse ".";
    var dir = try std.Io.Dir.cwd().openFile(io, dir_path, .{ .allow_directory = true });
    defer dir.close(io);
    try dir.sync(io);
}

test "store computes a revision, reads and replaces durably" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "vrouter.json",
        .data = "{\"version\":1,\"instance\":\"test\"}\n",
    });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/vrouter.json", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    var store = try Store.open(testing.io, testing.allocator, path);
    defer store.deinit();

    const first = store.revisionCopy();
    try testing.expectEqualStrings(revision_prefix, first.slice()[0..revision_prefix.len]);
    try testing.expectEqual(@as(usize, revision_len), first.slice().len);

    var config_buf: [1024]u8 = undefined;
    try testing.expectEqualStrings(
        "{\"version\":1,\"instance\":\"test\"}\n",
        store.readInto(&config_buf).?,
    );

    const next = try store.replace("{\"version\":1,\"instance\":\"next\"}\n");
    try testing.expect(!std.mem.eql(u8, first.slice(), next.slice()));
    try testing.expectEqualStrings(
        "{\"version\":1,\"instance\":\"next\"}\n",
        store.readInto(&config_buf).?,
    );

    const reloaded = try store.reload();
    try testing.expectEqualStrings(next.slice(), reloaded.slice());

    var too_small: [1]u8 = undefined;
    try testing.expect(store.readInto(&too_small) == null);
}

test "store rejects symlinks and directories" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "vrouter.json",
        .data = "{}\n",
    });
    try tmp.dir.symLink(testing.io, "vrouter.json", "link.json", .{});

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const link_path = try std.fmt.allocPrint(testing.allocator, "{s}/link.json", .{path_buf[0..dir]});
    defer testing.allocator.free(link_path);
    const dir_path = try std.fmt.allocPrint(testing.allocator, "{s}/subdir", .{path_buf[0..dir]});
    defer testing.allocator.free(dir_path);
    try tmp.dir.makeDir(testing.io, "subdir", .{});

    try testing.expectError(error.InvalidArgument, Store.open(testing.io, testing.allocator, link_path));
    try testing.expectError(error.InvalidArgument, Store.open(testing.io, testing.allocator, dir_path));
}
