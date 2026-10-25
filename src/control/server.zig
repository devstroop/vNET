//! Unix-socket control server. One worker thread accepts short-lived clients;
//! the datapath publishes immutable snapshots under a mutex.

const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");
const config_parse = @import("../config/parse.zig");
const config_store = @import("../config/store.zig");
const config_apply = @import("config_apply.zig");
const transaction = @import("transaction.zig");
const journal = @import("journal.zig");
const protocol = @import("protocol.zig");
const read_model = @import("read_model.zig");
const state = @import("state.zig");
const types = @import("../types.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");
const thread = @import("../thread.zig");

pub const max_request_bytes = 64 * 1024;
pub const max_config_request_bytes = 16 * 1024 * 1024;
const max_response_bytes = 128 * 1024;
const client_timeout_ms = 2_000;
const default_conntrack_limit = 100;
const max_apply_error = 256;
const config_queue_capacity = 4;
const audit_tail_bytes = 512 * 1024;
const journal_tail_bytes = 512 * 1024;
const audit_default_limit = 100;
const journal_default_limit = 100;
const audit_max_limit = 500;
const journal_max_limit = 500;

pub const Options = struct {
    mode: u32 = 0o660,
    allow_uid: ?u32 = null,
    kernel_backlog: u31 = 16,
    config_store: ?*config_store.Store = null,
    state_dir: []const u8 = "",
    restart_pending: bool = false,
    restart_supported: bool = false,
};

pub const Error = error{
    AlreadyRunning,
    PathOccupied,
    Unauthorized,
    PeerCredentials,
};

const ConfigJob = struct {
    stream: std.Io.net.Stream,
    line: []u8,
    uid: u32,
    pid: i32,
};

pub const Server = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []u8,
    listener: std.Io.net.Server,
    lock_file: std.Io.File,
    socket_inode: std.Io.File.INode,
    allowed_uid: u32,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?thread.Thread = null,
    config_thread: ?thread.Thread = null,
    config_mutex: std.Io.Mutex = .init,
    config_cond: std.Io.Condition = .init,
    config_jobs: []ConfigJob,
    config_head: usize = 0,
    config_tail: usize = 0,
    config_count: usize = 0,
    mutex: std.Io.Mutex = .init,
    snapshot: state.Snapshot = .{},
    apply_mutex: std.Io.Mutex = .init,
    apply_pending: bool = false,
    apply_claimed: bool = false,
    apply_done: bool = false,
    apply_ok: bool = false,
    apply_line_len: usize = 0,
    apply_line: [max_request_bytes]u8 = undefined,
    apply_error_code: [max_apply_error]u8 = undefined,
    apply_error_code_len: usize = 0,
    apply_error_message: [max_apply_error]u8 = undefined,
    apply_error_message_len: usize = 0,
    config_store: ?*config_store.Store = null,
    state_dir: []u8,
    restart_pending: bool = false,
    restart_supported: bool = false,
    restart_token: config_apply.RestartToken = .{},
    boot_id: [config_apply.boot_id_len]u8 = undefined,
    restart_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    confirm: config_apply.Confirm = .{},
    idempotency: config_apply.Idempotency = .{},

    pub fn init(
        io: std.Io,
        gpa: std.mem.Allocator,
        path: []const u8,
        options: Options,
    ) !Server {
        if (path.len == 0 or path.len > std.Io.net.UnixAddress.max_len) {
            return error.InvalidArgument;
        }
        const config_jobs = try gpa.alloc(ConfigJob, config_queue_capacity);
        errdefer gpa.free(config_jobs);
        const state_dir = try gpa.dupe(u8, options.state_dir);
        errdefer gpa.free(state_dir);
        var boot_id: [config_apply.boot_id_len]u8 = undefined;
        try io.randomSecure(&boot_id);
        const persisted_restart = if (options.state_dir.len != 0)
            transaction.restartPending(io, gpa, options.state_dir) catch false
        else
            false;
        if (std.fs.path.dirname(path)) |dir| {
            _ = std.Io.Dir.cwd().createDirPathStatus(
                io,
                dir,
                std.Io.File.Permissions.fromMode(0o750),
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        const cwd = std.Io.Dir.cwd();
        const lock_path = try std.mem.concat(gpa, u8, &.{ path, ".lock" });
        defer gpa.free(lock_path);
        var lock_file = cwd.createFile(io, lock_path, .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        }) catch |err| switch (err) {
            error.WouldBlock => return error.AlreadyRunning,
            else => return err,
        };
        errdefer lock_file.close(io);

        const address = try std.Io.net.UnixAddress.init(path);
        var listener = try listenWithStaleRecovery(io, address, path, options.kernel_backlog);
        errdefer {
            listener.deinit(io);
            cwd.deleteFile(io, path) catch {};
        }

        const permissions: std.Io.File.Permissions = @enumFromInt(
            @as(std.posix.mode_t, @intCast(options.mode)),
        );
        try cwd.setFilePermissions(io, path, permissions, .{});
        const stat = try cwd.statFile(io, path, .{ .follow_symlinks = false });
        if (stat.kind != .unix_domain_socket) return error.PathOccupied;

        return .{
            .io = io,
            .gpa = gpa,
            .path = try gpa.dupe(u8, path),
            .listener = listener,
            .lock_file = lock_file,
            .socket_inode = stat.inode,
            .config_jobs = config_jobs,
            .allowed_uid = options.allow_uid orelse linux.geteuid(),
            .config_store = options.config_store,
            .state_dir = state_dir,
            .restart_pending = options.restart_pending or persisted_restart,
            .restart_supported = options.restart_supported,
            .boot_id = boot_id,
        };
    }

    pub fn start(self: *Server) !void {
        self.stop.store(false, .release);
        self.thread = try thread.spawn(run, .{self});
        self.config_thread = thread.spawn(configWorker, .{self}) catch |err| {
            self.stop.store(true, .release);
            const stream: std.Io.net.Stream = .{ .socket = self.listener.socket };
            stream.shutdown(self.io, .both) catch {};
            if (self.thread) |worker| {
                worker.join();
                self.thread = null;
            }
            return err;
        };
    }

    pub fn takeNatApply(self: *Server, out: []u8) ?[]const u8 {
        self.apply_mutex.lockUncancelable(self.io);
        defer self.apply_mutex.unlock(self.io);
        if (!self.apply_pending or self.apply_claimed) return null;
        if (out.len < self.apply_line_len) return null;
        @memcpy(out[0..self.apply_line_len], self.apply_line[0..self.apply_line_len]);
        self.apply_claimed = true;
        return out[0..self.apply_line_len];
    }

    pub fn finishNatApply(
        self: *Server,
        ok: bool,
        code: []const u8,
        message: []const u8,
    ) void {
        self.apply_mutex.lockUncancelable(self.io);
        defer self.apply_mutex.unlock(self.io);
        self.apply_ok = ok;
        self.apply_error_code_len = @min(code.len, self.apply_error_code.len);
        @memcpy(self.apply_error_code[0..self.apply_error_code_len], code[0..self.apply_error_code_len]);
        self.apply_error_message_len = @min(message.len, self.apply_error_message.len);
        @memcpy(
            self.apply_error_message[0..self.apply_error_message_len],
            message[0..self.apply_error_message_len],
        );
        self.apply_done = true;
    }

    pub fn deinit(self: *Server) void {
        self.stop.store(true, .release);
        self.config_mutex.lockUncancelable(self.io);
        self.config_cond.broadcast(self.io);
        self.config_mutex.unlock(self.io);
        self.apply_mutex.lockUncancelable(self.io);
        self.apply_ok = false;
        self.apply_error_code_len = 14;
        @memcpy(self.apply_error_code[0..14], "server_stopped");
        self.apply_error_message_len = 14;
        @memcpy(self.apply_error_message[0..14], "server stopped");
        self.apply_done = true;
        self.apply_mutex.unlock(self.io);
        if (self.thread) |worker| {
            const stream: std.Io.net.Stream = .{ .socket = self.listener.socket };
            stream.shutdown(self.io, .both) catch {};
            worker.join();
            self.thread = null;
        }
        if (self.config_thread) |worker| {
            worker.join();
            self.config_thread = null;
        }
        self.listener.deinit(self.io);
        self.removeOwnedSocket();
        self.lock_file.close(self.io);
        while (self.config_count > 0) {
            self.gpa.free(self.config_jobs[self.config_head].line);
            self.config_head = (self.config_head + 1) % self.config_jobs.len;
            self.config_count -= 1;
        }
        self.gpa.free(self.config_jobs);
        self.gpa.free(self.state_dir);
        self.gpa.free(self.path);
        self.* = undefined;
    }

    pub fn markStarted(self: *Server) void {
        self.restart_pending = false;
        self.restart_token.clear();
        self.restart_requested.store(false, .release);
        self.stop_requested.store(false, .release);
    }

    pub fn restartRequested(self: *const Server) bool {
        return self.restart_requested.load(.acquire);
    }

    pub fn stopRequested(self: *const Server) bool {
        return self.stop_requested.load(.acquire);
    }

    pub fn publish(self: *Server, snapshot: *const state.Snapshot) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.snapshot = snapshot.*;
    }

    fn removeOwnedSocket(self: *Server) void {
        const stat = std.Io.Dir.cwd().statFile(self.io, self.path, .{ .follow_symlinks = false }) catch return;
        if (stat.kind != .unix_domain_socket or stat.inode != self.socket_inode) return;
        std.Io.Dir.cwd().deleteFile(self.io, self.path) catch {};
    }

    fn run(self: *Server) void {
        while (!self.stop.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                else => {
                    if (self.stop.load(.acquire)) return;
                    std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
                    continue;
                },
            };
            self.handleClient(stream);
        }
    }

    fn handleClient(self: *Server, stream: std.Io.net.Stream) void {
        var close_stream = true;
        defer if (close_stream) stream.close(self.io);

        const credentials = peerCredentials(stream.socket.handle) catch {
            self.sendError(stream, null, null, "unauthorized", "peer credentials unavailable");
            return;
        };
        if (credentials.uid != 0 and credentials.uid != self.allowed_uid) {
            self.sendError(stream, null, null, "unauthorized", "peer uid is not allowed");
            return;
        }

        const line = transport.readLineAlloc(
            self.io,
            stream.socket.handle,
            self.gpa,
            max_config_request_bytes,
            client_timeout_ms,
        ) catch |err| {
            self.sendError(stream, null, null, "invalid_request", @errorName(err));
            return;
        } orelse return;
        defer self.gpa.free(line);

        var parsed = protocol.parseRequest(std.heap.page_allocator, line) catch {
            self.sendError(stream, null, null, "invalid_request", "malformed JSON request");
            return;
        };
        defer parsed.deinit();

        if (line.len > max_request_bytes and !protocol.isConfigSized(parsed.value.op)) {
            self.sendError(stream, parsed.value.id, parsed.value.op, "too_large", "request too large");
            return;
        }

        const request_version = parsed.value.version orelse protocol.v2_version;
        if (request_version < protocol.v2_version or request_version > protocol.version) {
            self.sendError(
                stream,
                parsed.value.id,
                parsed.value.op,
                "version_unsupported",
                "unsupported protocol version",
            );
            return;
        }
        const v3 = request_version == protocol.version;

        if (protocol.isV3Only(parsed.value.op) and !v3) {
            self.sendError(
                stream,
                parsed.value.id,
                parsed.value.op,
                "version_unsupported",
                "operation requires protocol version 3",
            );
            return;
        }

        if (!isSupported(parsed.value.op)) {
            self.sendError(stream, parsed.value.id, parsed.value.op, "unknown_op", "unknown operation");
            return;
        }

        if (protocol.isConfigSized(parsed.value.op) or read_model.isListOp(parsed.value.op)) {
            if (self.submitConfig(stream, line, credentials.uid, credentials.pid)) {
                close_stream = false;
            } else {
                self.sendError(stream, parsed.value.id, parsed.value.op, "busy", "config worker is busy");
            }
            return;
        }

        if (std.mem.eql(u8, parsed.value.op, "nat.apply")) {
            self.handleNatApply(stream, parsed.value, line);
            return;
        }
        if (std.mem.eql(u8, parsed.value.op, "daemon.restart")) {
            self.handleDaemonRestart(stream, parsed.value, credentials.uid, credentials.pid);
            return;
        }
        if (std.mem.eql(u8, parsed.value.op, "daemon.stop")) {
            self.handleDaemonStop(stream, parsed.value, credentials.uid, credentials.pid);
            return;
        }
        if (std.mem.eql(u8, parsed.value.op, "audit.list")) {
            self.handleAuditList(stream, parsed.value);
            return;
        }
        if (std.mem.eql(u8, parsed.value.op, "journal.list")) {
            self.handleJournalList(stream, parsed.value);
            return;
        }

        var config_revision: ?config_store.Revision = null;
        var config_writable = false;
        if (v3 and std.mem.eql(u8, parsed.value.op, "status")) {
            if (self.config_store) |store| {
                _ = store.refreshIfChanged() catch false;
                config_revision = store.revisionCopy();
                config_writable = store.isWritable();
            }
        }

        var response_buf: [max_response_bytes]u8 = undefined;
        var response: std.Io.Writer = .fixed(&response_buf);
        self.mutex.lockUncancelable(self.io);
        const written = self.writeResponse(
            &response,
            parsed.value,
            v3,
            config_revision,
            config_writable,
        );
        self.mutex.unlock(self.io);
        if (!written) {
            self.sendError(stream, parsed.value.id, parsed.value.op, "internal", "response too large");
            return;
        }

        var socket_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &socket_buf);
        writer.interface.writeAll(response.buffered()) catch return;
        writer.interface.flush() catch {};
    }

    fn writeResponse(
        self: *Server,
        writer: *std.Io.Writer,
        request: protocol.Request,
        v3: bool,
        config_revision: ?config_store.Revision,
        config_writable: bool,
    ) bool {
        const snapshot = &self.snapshot;
        var json: std.json.Stringify = .{ .writer = writer };
        json.beginObject() catch return false;
        writeField(&json, "ok", true) catch return false;
        writeOptionalId(&json, request.id) catch return false;
        writeField(&json, "op", request.op) catch return false;

        if (std.mem.eql(u8, request.op, "ping")) {
            writeField(&json, "version", if (v3) protocol.version else protocol.v2_version) catch return false;
        } else if (std.mem.eql(u8, request.op, "status")) {
            json.objectField("status") catch return false;
            writeStatus(
                &json,
                snapshot,
                v3,
                config_revision,
                config_writable,
                self.restart_pending,
                self.restart_supported,
            ) catch return false;
        } else if (std.mem.eql(u8, request.op, "nat.list")) {
            json.objectField("nat") catch return false;
            writeNat(&json, snapshot, v3) catch return false;
        } else if (std.mem.eql(u8, request.op, "conntrack.list")) {
            json.objectField("conntrack") catch return false;
            writeConntrack(&json, snapshot, request.state, request.limit) catch return false;
        } else {
            return false;
        }

        json.endObject() catch return false;
        writer.writeByte('\n') catch return false;
        return true;
    }

    fn submitConfig(
        self: *Server,
        stream: std.Io.net.Stream,
        line: []const u8,
        uid: u32,
        pid: i32,
    ) bool {
        self.config_mutex.lockUncancelable(self.io);
        defer self.config_mutex.unlock(self.io);
        if (self.stop.load(.acquire) or self.config_count == self.config_jobs.len) return false;
        const copy = self.gpa.dupe(u8, line) catch return false;
        const job = &self.config_jobs[self.config_tail];
        job.* = .{ .stream = stream, .line = copy, .uid = uid, .pid = pid };
        self.config_tail = (self.config_tail + 1) % self.config_jobs.len;
        self.config_count += 1;
        self.config_cond.signal(self.io);
        return true;
    }

    fn configWorker(self: *Server) void {
        while (true) {
            self.config_mutex.lockUncancelable(self.io);
            while (self.config_count == 0 and !self.stop.load(.acquire)) {
                self.config_cond.waitUncancelable(self.io, &self.config_mutex);
            }
            if (self.config_count == 0) {
                self.config_mutex.unlock(self.io);
                return;
            }
            var job = self.config_jobs[self.config_head];
            self.config_head = (self.config_head + 1) % self.config_jobs.len;
            self.config_count -= 1;
            const stopping = self.stop.load(.acquire);
            self.config_mutex.unlock(self.io);

            if (stopping) {
                self.sendError(job.stream, null, null, "server_stopped", "server stopped");
                job.stream.close(self.io);
                self.gpa.free(job.line);
                continue;
            }

            var parsed = protocol.parseRequest(std.heap.page_allocator, job.line) catch {
                self.sendError(job.stream, null, null, "invalid_request", "malformed JSON request");
                job.stream.close(self.io);
                self.gpa.free(job.line);
                continue;
            };
            defer parsed.deinit();
            if (std.mem.eql(u8, parsed.value.op, "config.get")) {
                self.handleConfigGet(job.stream, parsed.value);
            } else if (std.mem.eql(u8, parsed.value.op, "config.validate")) {
                self.handleConfigValidate(job.stream, parsed.value);
            } else if (std.mem.eql(u8, parsed.value.op, "config.diff")) {
                self.handleConfigDiff(job.stream, parsed.value);
            } else if (std.mem.eql(u8, parsed.value.op, "config.apply")) {
                self.handleConfigApply(job.stream, parsed.value, job.uid, job.pid);
            } else {
                self.handleConfigList(job.stream, parsed.value);
            }
            job.stream.close(self.io);
            self.gpa.free(job.line);
        }
    }

    fn handleConfigGet(self: *Server, stream: std.Io.net.Stream, request: protocol.Request) void {
        const store = self.config_store orelse {
            self.sendError(
                stream,
                request.id,
                request.op,
                "unsupported",
                "config store is unavailable",
            );
            return;
        };
        const requested_instance = request.instance orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing instance");
            return;
        };

        self.mutex.lockUncancelable(self.io);
        const instance_matches = std.mem.eql(u8, requested_instance, self.snapshot.instance);
        self.mutex.unlock(self.io);
        if (!instance_matches) {
            self.sendError(stream, request.id, request.op, "instance_mismatch", "instance does not match");
            return;
        }

        _ = store.refresh() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        var config = store.snapshot() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer config.deinit();
        // The wire format is line-delimited, so re-encode the document without
        // newlines. The revision still covers the exact on-disk bytes.
        var parsed_config = std.json.parseFromSlice(std.json.Value, self.gpa, config.bytes, .{
            .allocate = .alloc_always,
        }) catch {
            self.sendError(stream, request.id, request.op, "internal", "config is not valid JSON");
            return;
        };
        defer parsed_config.deinit();
        const revision = config.revision;
        const source_path = store.pathSlice();
        const writable = store.isWritable();
        var allocating = std.Io.Writer.Allocating.initCapacity(
            self.gpa,
            config.bytes.len + source_path.len + config_store.revision_len + 1024,
        ) catch {
            self.sendError(stream, request.id, request.op, "internal", "response allocation failed");
            return;
        };
        defer allocating.deinit();

        var json: std.json.Stringify = .{ .writer = &allocating.writer };
        const written = blk: {
            json.beginObject() catch break :blk false;
            writeField(&json, "ok", true) catch break :blk false;
            writeOptionalId(&json, request.id) catch break :blk false;
            writeField(&json, "op", request.op) catch break :blk false;
            writeField(&json, "protocol_version", protocol.version) catch break :blk false;
            writeField(&json, "revision", revision.slice()) catch break :blk false;
            writeField(&json, "source_path", source_path) catch break :blk false;
            writeField(&json, "writable", writable) catch break :blk false;
            json.objectField("config") catch break :blk false;
            json.write(parsed_config.value) catch break :blk false;
            json.endObject() catch break :blk false;
            allocating.writer.writeByte('\n') catch break :blk false;
            break :blk true;
        };
        if (!written) {
            self.sendError(stream, request.id, request.op, "internal", "response too large");
            return;
        }

        var socket_buf: [4096]u8 = undefined;
        var stream_writer = stream.writer(self.io, &socket_buf);
        stream_writer.interface.writeAll(allocating.writer.buffered()) catch return;
        stream_writer.interface.flush() catch {};
    }

    fn handleConfigList(self: *Server, stream: std.Io.net.Stream, request: protocol.Request) void {
        const store = self.config_store orelse {
            self.sendError(
                stream,
                request.id,
                request.op,
                "unsupported",
                "config store is unavailable",
            );
            return;
        };
        _ = store.refresh() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        var config = store.snapshot() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer config.deinit();
        var parsed = config_parse.parse(self.gpa, config.bytes) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer parsed.deinit();

        var response_buf: [max_response_bytes]u8 = undefined;
        var response: std.Io.Writer = .fixed(&response_buf);
        var json: std.json.Stringify = .{ .writer = &response };
        const written = blk: {
            json.beginObject() catch break :blk false;
            writeField(&json, "ok", true) catch break :blk false;
            writeOptionalId(&json, request.id) catch break :blk false;
            writeField(&json, "op", request.op) catch break :blk false;
            const known = read_model.writeSection(&json, request.op, &parsed.config) catch break :blk false;
            if (!known) break :blk false;
            json.endObject() catch break :blk false;
            response.writeByte('\n') catch break :blk false;
            break :blk true;
        };
        if (!written) {
            self.sendError(stream, request.id, request.op, "too_large", "response too large");
            return;
        }

        var socket_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &socket_buf);
        writer.interface.writeAll(response.buffered()) catch return;
        writer.interface.flush() catch {};
    }

    fn handleConfigValidate(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
    ) void {
        const store = self.config_store orelse {
            self.sendError(stream, request.id, request.op, "unsupported", "config store is unavailable");
            return;
        };
        const requested_instance = request.instance orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing instance");
            return;
        };
        if (!self.instanceMatches(requested_instance)) {
            self.sendError(stream, request.id, request.op, "instance_mismatch", "instance does not match");
            return;
        }
        const proposal = request.config orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing config");
            return;
        };
        _ = store.refresh() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        var config = store.snapshot() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer config.deinit();
        var change = config_apply.analyze(self.gpa, config.bytes, proposal) catch |err| {
            self.sendConfigAnalyzeError(stream, request, err);
            return;
        };
        defer change.deinit();

        var allocating = std.Io.Writer.Allocating.initCapacity(self.gpa, 4096) catch {
            self.sendError(stream, request.id, request.op, "internal", "response allocation failed");
            return;
        };
        defer allocating.deinit();
        var json: std.json.Stringify = .{ .writer = &allocating.writer };
        const written = blk: {
            json.beginObject() catch break :blk false;
            writeField(&json, "ok", true) catch break :blk false;
            writeOptionalId(&json, request.id) catch break :blk false;
            writeField(&json, "op", request.op) catch break :blk false;
            writeField(&json, "protocol_version", protocol.version) catch break :blk false;
            writeField(&json, "revision", config.revision.slice()) catch break :blk false;
            writeAffected(&json, change.affected) catch break :blk false;
            writeField(&json, "restart_required", change.restart_required) catch break :blk false;
            writeWarnings(&json) catch break :blk false;
            json.endObject() catch break :blk false;
            allocating.writer.writeByte('\n') catch break :blk false;
            break :blk true;
        };
        if (!written) {
            self.sendError(stream, request.id, request.op, "internal", "response too large");
            return;
        }
        self.sendBuffer(stream, allocating.writer.buffered());
    }

    fn handleConfigDiff(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
    ) void {
        const store = self.config_store orelse {
            self.sendError(stream, request.id, request.op, "unsupported", "config store is unavailable");
            return;
        };
        const requested_instance = request.instance orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing instance");
            return;
        };
        if (!self.instanceMatches(requested_instance)) {
            self.sendError(stream, request.id, request.op, "instance_mismatch", "instance does not match");
            return;
        }
        const proposal = request.config orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing config");
            return;
        };
        const expected = request.revision orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing revision");
            return;
        };
        _ = store.refresh() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        var config = store.snapshot() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer config.deinit();
        if (!std.mem.eql(u8, expected, config.revision.slice())) {
            self.sendError(stream, request.id, request.op, "stale_revision", "config revision changed");
            return;
        }
        var change = config_apply.analyze(self.gpa, config.bytes, proposal) catch |err| {
            self.sendConfigAnalyzeError(stream, request, err);
            return;
        };
        defer change.deinit();
        const now = transport.nowMs(self.io);
        const token = self.confirm.issue(self.io, config.revision, change.diff_hash, now) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };

        var allocating = std.Io.Writer.Allocating.initCapacity(
            self.gpa,
            change.diff.len + 4096,
        ) catch {
            self.sendError(stream, request.id, request.op, "internal", "response allocation failed");
            return;
        };
        defer allocating.deinit();
        var json: std.json.Stringify = .{ .writer = &allocating.writer };
        const written = blk: {
            json.beginObject() catch break :blk false;
            writeField(&json, "ok", true) catch break :blk false;
            writeOptionalId(&json, request.id) catch break :blk false;
            writeField(&json, "op", request.op) catch break :blk false;
            writeField(&json, "protocol_version", protocol.version) catch break :blk false;
            writeField(&json, "revision", config.revision.slice()) catch break :blk false;
            writeField(&json, "diff", change.diff) catch break :blk false;
            writeAffected(&json, change.affected) catch break :blk false;
            writeField(&json, "restart_required", change.restart_required) catch break :blk false;
            writeField(&json, "confirm", token) catch break :blk false;
            writeWarnings(&json) catch break :blk false;
            json.endObject() catch break :blk false;
            allocating.writer.writeByte('\n') catch break :blk false;
            break :blk true;
        };
        if (!written) {
            self.sendError(stream, request.id, request.op, "internal", "response too large");
            return;
        }
        self.sendBuffer(stream, allocating.writer.buffered());
    }

    fn handleConfigApply(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        uid: u32,
        pid: i32,
    ) void {
        const store = self.config_store orelse {
            self.sendError(stream, request.id, request.op, "unsupported", "config store is unavailable");
            return;
        };
        if (self.state_dir.len == 0) {
            self.sendError(stream, request.id, request.op, "unsupported", "state directory is unavailable");
            return;
        }
        const requested_instance = request.instance orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing instance");
            return;
        };
        if (!self.instanceMatches(requested_instance)) {
            self.sendError(stream, request.id, request.op, "instance_mismatch", "instance does not match");
            return;
        }
        const proposal = request.config orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing config");
            return;
        };
        const expected = request.revision orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing revision");
            return;
        };
        const idempotency_key = request.idempotency_key orelse "";
        if (idempotency_key.len > config_apply.max_idempotency_key) {
            self.sendError(stream, request.id, request.op, "invalid_request", "idempotency key too long");
            return;
        }
        const now = transport.nowMs(self.io);
        if (idempotency_key.len != 0) {
            var early = config_apply.validateProposal(self.gpa, proposal) catch |err| {
                self.sendConfigAnalyzeError(stream, request, err);
                return;
            };
            defer early.deinit();
            var proposal_hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(early.bytes, &proposal_hash, .{});
            if (self.idempotency.lookup(idempotency_key, proposal_hash, now)) |lookup| {
                switch (lookup) {
                    .hit => |snapshot| {
                        self.sendConfigApplied(
                            stream,
                            request,
                            snapshot.transaction[0..],
                            snapshot.result,
                            snapshot.affected,
                            snapshot.restart_required,
                            snapshot.revision,
                            "",
                            self.restartSupported(),
                            self.currentRestartToken(snapshot.transaction[0..]),
                        );
                        return;
                    },
                    .conflict => {
                        self.sendError(
                            stream,
                            request.id,
                            request.op,
                            "idempotency_conflict",
                            "idempotency key was used for a different change",
                        );
                        return;
                    },
                }
            }
        }
        _ = store.refresh() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        var config = store.snapshot() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer config.deinit();
        if (!std.mem.eql(u8, expected, config.revision.slice())) {
            self.sendError(stream, request.id, request.op, "stale_revision", "config revision changed");
            return;
        }
        var change = config_apply.analyze(self.gpa, config.bytes, proposal) catch |err| {
            self.sendConfigAnalyzeError(stream, request, err);
            return;
        };
        defer change.deinit();
        var proposal_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(change.proposal.bytes, &proposal_hash, .{});

        if (change.affected.count() == 0) {
            self.sendConfigApplied(
                stream,
                request,
                null,
                .noop,
                change.affected,
                false,
                config.revision,
                "",
                false,
                null,
            );
            return;
        }

        const token = request.confirm orelse {
            self.sendError(stream, request.id, request.op, "confirm_required", "config diff confirmation required");
            return;
        };
        if (!self.confirm.consume(token, config.revision, change.diff_hash, now)) {
            self.sendError(stream, request.id, request.op, "confirm_required", "confirmation is invalid or expired");
            return;
        }
        // A newer config write supersedes any outstanding restart authority.
        self.restart_token.clear();

        var held = store.lock() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        defer held.deinit();
        _ = store.refresh() catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        const locked_revision = store.revisionCopy();
        if (!std.mem.eql(u8, expected, locked_revision.slice())) {
            self.sendError(stream, request.id, request.op, "stale_revision", "config revision changed");
            return;
        }

        const transaction_id = transaction.generateId(self.io) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        const audit_id = transaction.generateId(self.io) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        const next_revision = config_store.Revision.compute(change.proposal.bytes);
        const entry: transaction.Entry = .{
            .transaction = transaction_id[0..],
            .audit_id = audit_id[0..],
            .op = request.op,
            .instance = requested_instance,
            .revision_before = locked_revision.slice(),
            .revision_after = next_revision.slice(),
            .affected = change.affected,
            .restart_required = change.restart_required,
            .actor = .{ .uid = uid, .pid = pid },
            .ts_ms = now,
        };
        transaction.writePending(self.io, self.gpa, self.state_dir, entry) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        _ = store.replaceLocked(change.proposal.bytes) catch |err| {
            transaction.clearPending(self.io, self.gpa, self.state_dir) catch {};
            self.sendError(stream, request.id, request.op, configStoreErrorCode(err), @errorName(err));
            return;
        };

        var audit_ok = true;
        transaction.appendAudit(self.io, self.gpa, self.state_dir, entry) catch {
            audit_ok = false;
        };
        if (audit_ok) {
            transaction.clearPending(self.io, self.gpa, self.state_dir) catch {};
        }
        if (change.restart_required) {
            self.restart_pending = true;
            transaction.writeRestartPending(self.io, self.gpa, self.state_dir, entry) catch {};
        }
        var restart_token_buf: [config_apply.token_hex_len]u8 = undefined;
        var restart_token_value: ?[]const u8 = null;
        if (change.restart_required and self.restart_supported) {
            if (self.restart_token.issue(
                self.io,
                transaction_id,
                next_revision,
                self.boot_id,
                now,
            )) |issued| {
                @memcpy(&restart_token_buf, issued);
                restart_token_value = restart_token_buf[0..];
            } else |_| {}
        }
        const result: config_apply.Result = if (change.restart_required) .restart_required else .applied;
        self.idempotency.record(
            idempotency_key,
            proposal_hash,
            next_revision,
            transaction_id,
            result,
            change.restart_required,
            change.affected,
            now,
        );
        self.sendConfigApplied(
            stream,
            request,
            transaction_id[0..],
            result,
            change.affected,
            change.restart_required,
            next_revision,
            "",
            self.restart_supported,
            restart_token_value,
        );
    }

    const Tail = struct {
        data: []u8,
        truncated: bool,
    };

    fn readFileTail(self: *Server, path: []const u8, max_bytes: usize) !?Tail {
        var file = std.Io.Dir.cwd().openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        const offset: u64 = if (stat.size > max_bytes) stat.size - max_bytes else 0;
        const length: usize = @intCast(stat.size - offset);
        if (length == 0) return .{ .data = try self.gpa.alloc(u8, 0), .truncated = offset != 0 };
        const data = try self.gpa.alloc(u8, length);
        errdefer self.gpa.free(data);
        const got = try file.readPositionalAll(self.io, data, offset);
        var result = data[0..got];
        if (offset != 0) {
            const newline = std.mem.indexOfScalar(u8, result, '\n') orelse {
                self.gpa.free(data);
                return .{ .data = try self.gpa.alloc(u8, 0), .truncated = true };
            };
            result = result[newline + 1 ..];
        }
        if (result.len == data.len) return .{ .data = data, .truncated = offset != 0 };
        const copy = try self.gpa.dupe(u8, result);
        self.gpa.free(data);
        return .{ .data = copy, .truncated = offset != 0 };
    }

    fn handleAuditList(self: *Server, stream: std.Io.net.Stream, request: protocol.Request) void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        self.writeAuditResponse(&out.writer, request) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        self.sendBuffer(stream, out.written());
    }

    fn writeAuditResponse(self: *Server, writer: *std.Io.Writer, request: protocol.Request) !void {
        const limit = @min(request.limit orelse audit_default_limit, audit_max_limit);
        const path = try std.fs.path.join(self.gpa, &.{ self.state_dir, transaction.audit_file });
        defer self.gpa.free(path);
        const tail = try self.readFileTail(path, audit_tail_bytes);
        defer if (tail) |value| self.gpa.free(value.data);

        var entries: std.ArrayListUnmanaged(std.json.Parsed(protocol.AuditEntry)) = .empty;
        defer {
            for (entries.items) |*entry| entry.deinit();
            entries.deinit(self.gpa);
        }
        var total: u32 = 0;
        var malformed: u32 = 0;
        if (tail) |value| {
            var lines = std.mem.splitScalar(u8, value.data, '\n');
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                total += 1;
                const parsed = std.json.parseFromSlice(protocol.AuditEntry, self.gpa, line, .{
                    .ignore_unknown_fields = true,
                }) catch {
                    malformed += 1;
                    continue;
                };
                entries.append(self.gpa, parsed) catch {
                    var failed = parsed;
                    failed.deinit();
                    return error.OutOfMemory;
                };
            }
        }
        const first = if (entries.items.len > limit) entries.items.len - limit else 0;
        const returned: u32 = @intCast(entries.items.len - first);

        var json: std.json.Stringify = .{ .writer = writer };
        try json.beginObject();
        try writeField(&json, "ok", true);
        try writeOptionalId(&json, request.id);
        try writeField(&json, "op", request.op);
        try writeField(&json, "protocol_version", protocol.version);
        try json.objectField("audit");
        try json.beginObject();
        try writeField(&json, "instance", self.snapshot.instance);
        try writeField(&json, "path", path);
        try writeField(&json, "total", total);
        try writeField(&json, "returned", returned);
        try writeField(&json, "malformed", malformed);
        try writeField(&json, "truncated", if (tail) |value| value.truncated else false);
        try json.objectField("entries");
        try json.beginArray();
        for (entries.items[first..]) |entry| try json.write(entry.value);
        try json.endArray();
        try json.endObject();
        try json.endObject();
        try writer.writeByte('\n');
    }

    fn handleJournalList(self: *Server, stream: std.Io.net.Stream, request: protocol.Request) void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        self.writeJournalResponse(&out.writer, request) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        self.sendBuffer(stream, out.written());
    }

    const StoredJournalLine = struct {
        index: u64,
        raw: []const u8,
        parsed: ?std.json.Parsed(journal.Wire),
        valid: bool,

        fn deinit(self: *StoredJournalLine) void {
            if (self.parsed) |*value| value.deinit();
        }
    };

    fn writeJournalResponse(self: *Server, writer: *std.Io.Writer, request: protocol.Request) !void {
        const limit = @min(request.limit orelse journal_default_limit, journal_max_limit);
        const name = try std.fmt.allocPrint(self.gpa, "{s}.journal", .{self.snapshot.instance});
        defer self.gpa.free(name);
        const path = try std.fs.path.join(self.gpa, &.{ self.state_dir, name });
        defer self.gpa.free(path);
        const tail = try self.readFileTail(path, journal_tail_bytes);
        defer if (tail) |value| self.gpa.free(value.data);

        var entries: std.ArrayListUnmanaged(StoredJournalLine) = .empty;
        defer {
            for (entries.items) |*entry| entry.deinit();
            entries.deinit(self.gpa);
        }
        var total: u32 = 0;
        var valid: u32 = 0;
        var malformed: u32 = 0;
        var last_valid = true;
        if (tail) |value| {
            var lines = std.mem.splitScalar(u8, value.data, '\n');
            while (lines.next()) |line| {
                if (line.len == 0) continue;
                total += 1;
                var parsed = journal.parseLine(self.gpa, line) catch {
                    malformed += 1;
                    last_valid = false;
                    try appendJournalLine(self.gpa, &entries, limit, .{
                        .index = total,
                        .raw = line,
                        .parsed = null,
                        .valid = false,
                    });
                    continue;
                };
                _ = journal.toOp(parsed.value) catch {
                    parsed.deinit();
                    malformed += 1;
                    last_valid = false;
                    try appendJournalLine(self.gpa, &entries, limit, .{
                        .index = total,
                        .raw = line,
                        .parsed = null,
                        .valid = false,
                    });
                    continue;
                };
                valid += 1;
                last_valid = true;
                try appendJournalLine(self.gpa, &entries, limit, .{
                    .index = total,
                    .raw = line,
                    .parsed = parsed,
                    .valid = true,
                });
            }
        }

        var json: std.json.Stringify = .{ .writer = writer };
        try json.beginObject();
        try writeField(&json, "ok", true);
        try writeOptionalId(&json, request.id);
        try writeField(&json, "op", request.op);
        try writeField(&json, "protocol_version", protocol.version);
        try json.objectField("journal");
        try json.beginObject();
        try writeField(&json, "instance", self.snapshot.instance);
        try writeField(&json, "path", path);
        try writeField(&json, "entries", total);
        try writeField(&json, "valid", valid);
        try writeField(&json, "malformed", malformed);
        try writeField(&json, "malformed_tail", total != 0 and !last_valid);
        try writeField(&json, "returned", @as(u32, @intCast(entries.items.len)));
        try writeField(&json, "truncated", if (tail) |value| value.truncated else false);
        try json.objectField("lines");
        try json.beginArray();
        for (entries.items) |entry| {
            try json.beginObject();
            try writeField(&json, "line", entry.index);
            try writeField(&json, "valid", entry.valid);
            try writeField(&json, "raw", entry.raw);
            if (entry.parsed) |parsed| {
                const wire = parsed.value;
                try writeField(&json, "op", wire.op);
                try writeOptionalField(&json, "dev", wire.dev);
                try writeOptionalField(&json, "cidr", wire.cidr);
                try writeOptionalField(&json, "up", wire.up);
                try writeOptionalField(&json, "dst", wire.dst);
                try writeOptionalField(&json, "via", wire.via);
                try writeOptionalField(&json, "metric", wire.metric);
                try writeOptionalField(&json, "table", wire.table);
                try writeOptionalField(&json, "kind", wire.kind);
                try writeOptionalField(&json, "peer", wire.peer);
                try writeOptionalField(&json, "stp", wire.stp);
                try writeOptionalField(&json, "vlan_filtering", wire.vlan_filtering);
                try writeOptionalField(&json, "master", wire.master);
                try writeOptionalField(&json, "vid", wire.vid);
                try writeOptionalField(&json, "pvid", wire.pvid);
                try writeOptionalField(&json, "untagged", wire.untagged);
            }
            try json.endObject();
        }
        try json.endArray();
        try json.endObject();
        try json.endObject();
        try writer.writeByte('\n');
    }

    fn sendConfigApplied(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        transaction_id: ?[]const u8,
        result: config_apply.Result,
        affected: config_apply.Affected,
        restart_required: bool,
        revision: config_store.Revision,
        diff: []const u8,
        restart_supported: bool,
        restart_token: ?[]const u8,
    ) void {
        var allocating = std.Io.Writer.Allocating.initCapacity(self.gpa, 4096 + diff.len) catch {
            return;
        };
        defer allocating.deinit();
        var json: std.json.Stringify = .{ .writer = &allocating.writer };
        const written = blk: {
            json.beginObject() catch break :blk false;
            writeField(&json, "ok", true) catch break :blk false;
            writeOptionalId(&json, request.id) catch break :blk false;
            writeField(&json, "op", request.op) catch break :blk false;
            writeField(&json, "protocol_version", protocol.version) catch break :blk false;
            writeField(&json, "revision", revision.slice()) catch break :blk false;
            if (transaction_id) |id| {
                writeField(&json, "transaction", id) catch break :blk false;
            }
            writeField(&json, "result", @tagName(result)) catch break :blk false;
            writeAffected(&json, affected) catch break :blk false;
            writeField(&json, "restart_required", restart_required) catch break :blk false;
            if (restart_required) {
                writeField(&json, "restart_supported", restart_supported) catch break :blk false;
                if (restart_token) |value| {
                    writeField(&json, "restart_token", value) catch break :blk false;
                }
            }
            if (diff.len != 0) {
                writeField(&json, "diff", diff) catch break :blk false;
            }
            writeWarnings(&json) catch break :blk false;
            json.endObject() catch break :blk false;
            allocating.writer.writeByte('\n') catch break :blk false;
            break :blk true;
        };
        if (written) self.sendBuffer(stream, allocating.writer.buffered());
    }

    fn sendConfigAnalyzeError(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        err: anyerror,
    ) void {
        const code = switch (err) {
            error.DiffTooLarge, error.ConfigTooLarge => "too_large",
            error.OutOfMemory => "internal",
            error.InvalidCurrentConfig => "internal",
            else => "invalid_config",
        };
        self.sendError(stream, request.id, request.op, code, @errorName(err));
    }

    fn instanceMatches(self: *Server, requested: []const u8) bool {
        self.mutex.lockUncancelable(self.io);
        const matches = std.mem.eql(u8, requested, self.snapshot.instance);
        self.mutex.unlock(self.io);
        return matches;
    }

    fn sendBuffer(self: *Server, stream: std.Io.net.Stream, bytes: []const u8) void {
        var socket_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &socket_buf);
        writer.interface.writeAll(bytes) catch return;
        writer.interface.flush() catch {};
    }

    fn restartSupported(self: *const Server) bool {
        return self.restart_supported;
    }

    fn currentRestartToken(self: *const Server, transaction_id: []const u8) ?[]const u8 {
        if (!self.restart_token.active) return null;
        if (!std.mem.eql(u8, self.restart_token.transaction[0..], transaction_id)) return null;
        return self.restart_token.token[0..];
    }

    fn handleDaemonRestart(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        uid: u32,
        pid: i32,
    ) void {
        if (!self.restart_supported) {
            self.sendError(
                stream,
                request.id,
                request.op,
                "restart_unavailable",
                "no supervisor is configured; restart vrouterd with the service manager",
            );
            return;
        }
        const supplied = request.restart_token orelse {
            self.sendError(stream, request.id, request.op, "confirm_required", "restart token required");
            return;
        };
        const now = transport.nowMs(self.io);
        switch (self.restart_token.validate(supplied, self.boot_id, now)) {
            .ok => {},
            .expired => {
                self.sendError(stream, request.id, request.op, "confirm_expired", "restart token expired");
                return;
            },
            .missing => {
                if (self.restart_pending) {
                    self.sendError(
                        stream,
                        request.id,
                        request.op,
                        "restart_pending",
                        "restart token was already used or superseded",
                    );
                } else {
                    self.sendError(stream, request.id, request.op, "confirm_required", "restart token required");
                }
                return;
            },
        }

        const transaction_id = transaction.generateId(self.io) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        const audit_id = transaction.generateId(self.io) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        transaction.appendOperationAudit(
            self.io,
            self.gpa,
            self.state_dir,
            request.op,
            self.snapshot.instance,
            transaction_id[0..],
            audit_id[0..],
            .{ .uid = uid, .pid = pid },
            now,
        ) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        self.restart_token.clear();
        self.sendDaemonAccepted(stream, request, transaction_id[0..]);
        self.restart_requested.store(true, .release);
    }

    fn handleDaemonStop(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        uid: u32,
        pid: i32,
    ) void {
        if (!self.restart_supported) {
            self.sendError(
                stream,
                request.id,
                request.op,
                "restart_unavailable",
                "no supervisor is configured; stop vrouterd with the service manager",
            );
            return;
        }
        if (request.confirm == null or !std.mem.eql(u8, request.confirm.?, "stop")) {
            self.sendError(stream, request.id, request.op, "confirm_required", "type stop to confirm");
            return;
        }
        const now = transport.nowMs(self.io);
        const transaction_id = transaction.generateId(self.io) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        const audit_id = transaction.generateId(self.io) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        transaction.appendOperationAudit(
            self.io,
            self.gpa,
            self.state_dir,
            request.op,
            self.snapshot.instance,
            transaction_id[0..],
            audit_id[0..],
            .{ .uid = uid, .pid = pid },
            now,
        ) catch |err| {
            self.sendError(stream, request.id, request.op, "internal", @errorName(err));
            return;
        };
        self.sendDaemonAccepted(stream, request, transaction_id[0..]);
        self.stop_requested.store(true, .release);
    }

    fn sendDaemonAccepted(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        transaction_id: []const u8,
    ) void {
        var buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        var json: std.json.Stringify = .{ .writer = &writer };
        const written = blk: {
            json.beginObject() catch break :blk false;
            writeField(&json, "ok", true) catch break :blk false;
            writeOptionalId(&json, request.id) catch break :blk false;
            writeField(&json, "op", request.op) catch break :blk false;
            writeField(&json, "protocol_version", protocol.version) catch break :blk false;
            writeField(&json, "result", "accepted") catch break :blk false;
            writeField(&json, "transaction", transaction_id) catch break :blk false;
            json.endObject() catch break :blk false;
            writer.writeByte('\n') catch break :blk false;
            break :blk true;
        };
        if (written) self.sendBuffer(stream, writer.buffered());
    }

    fn handleNatApply(
        self: *Server,
        stream: std.Io.net.Stream,
        request: protocol.Request,
        line: []const u8,
    ) void {
        const apply = request.nat orelse {
            self.sendError(stream, request.id, request.op, "invalid_request", "missing nat payload");
            return;
        };
        self.mutex.lockUncancelable(self.io);
        const instance = self.snapshot.instance;
        const instance_matches = std.mem.eql(u8, apply.instance, instance);
        self.mutex.unlock(self.io);
        if (!instance_matches) {
            self.sendError(stream, request.id, request.op, "instance_mismatch", "instance does not match");
            return;
        }

        self.apply_mutex.lockUncancelable(self.io);
        if (self.apply_pending and self.apply_done) {
            self.apply_pending = false;
            self.apply_claimed = false;
        }
        if (self.apply_pending) {
            self.apply_mutex.unlock(self.io);
            self.sendError(stream, request.id, request.op, "busy", "another NAT update is pending");
            return;
        }
        if (line.len > self.apply_line.len) {
            self.apply_mutex.unlock(self.io);
            self.sendError(stream, request.id, request.op, "invalid_request", "request too large");
            return;
        }
        @memcpy(self.apply_line[0..line.len], line);
        self.apply_line_len = line.len;
        self.apply_pending = true;
        self.apply_claimed = false;
        self.apply_done = false;
        self.apply_ok = false;
        self.apply_error_code_len = 0;
        self.apply_error_message_len = 0;
        self.apply_mutex.unlock(self.io);

        var elapsed_ms: u64 = 0;
        while (true) : (elapsed_ms += 1) {
            self.apply_mutex.lockUncancelable(self.io);
            if (self.apply_done) {
                const ok = self.apply_ok;
                var code_buf: [max_apply_error]u8 = undefined;
                var message_buf: [max_apply_error]u8 = undefined;
                const code_len = self.apply_error_code_len;
                const message_len = self.apply_error_message_len;
                @memcpy(code_buf[0..code_len], self.apply_error_code[0..code_len]);
                @memcpy(message_buf[0..message_len], self.apply_error_message[0..message_len]);
                self.apply_pending = false;
                self.apply_claimed = false;
                self.apply_mutex.unlock(self.io);
                if (ok) {
                    self.sendApplyOk(stream, request.id, request.op);
                } else {
                    self.sendError(
                        stream,
                        request.id,
                        request.op,
                        code_buf[0..code_len],
                        message_buf[0..message_len],
                    );
                }
                return;
            }
            if (elapsed_ms >= client_timeout_ms and !self.apply_claimed) {
                // The datapath has not picked the job up, so cancel it before
                // replying. Once claimed, the swap will finish; wait for the
                // acknowledgement instead of returning an uncertain timeout.
                self.apply_pending = false;
                self.apply_claimed = false;
                self.apply_mutex.unlock(self.io);
                self.sendError(stream, request.id, request.op, "timeout", "NAT update timed out");
                return;
            }
            self.apply_mutex.unlock(self.io);
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
    }

    fn sendApplyOk(self: *Server, stream: std.Io.net.Stream, id: ?u64, op: []const u8) void {
        var buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        var json: std.json.Stringify = .{ .writer = &writer };
        json.beginObject() catch return;
        writeField(&json, "ok", true) catch return;
        writeOptionalId(&json, id) catch return;
        writeField(&json, "op", op) catch return;
        json.endObject() catch return;
        writer.writeByte('\n') catch return;

        var socket_buf: [1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &socket_buf);
        stream_writer.interface.writeAll(writer.buffered()) catch return;
        stream_writer.interface.flush() catch {};
    }

    fn sendError(
        self: *Server,
        stream: std.Io.net.Stream,
        id: ?u64,
        op: ?[]const u8,
        code: []const u8,
        message: []const u8,
    ) void {
        var buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        var json: std.json.Stringify = .{ .writer = &writer };
        json.beginObject() catch return;
        writeField(&json, "ok", false) catch return;
        writeOptionalId(&json, id) catch return;
        if (op) |value| {
            writeField(&json, "op", value) catch return;
        } else {
            json.objectField("op") catch return;
            json.write(null) catch return;
        }
        writeField(&json, "error_code", code) catch return;
        writeField(&json, "message", message) catch return;
        json.endObject() catch return;
        writer.writeByte('\n') catch return;

        var socket_buf: [1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &socket_buf);
        stream_writer.interface.writeAll(writer.buffered()) catch return;
        stream_writer.interface.flush() catch {};
    }
};

fn isSupported(op: []const u8) bool {
    return std.mem.eql(u8, op, "ping") or
        std.mem.eql(u8, op, "status") or
        std.mem.eql(u8, op, "nat.list") or
        std.mem.eql(u8, op, "nat.apply") or
        std.mem.eql(u8, op, "conntrack.list") or
        std.mem.eql(u8, op, "config.get") or
        std.mem.eql(u8, op, "config.validate") or
        std.mem.eql(u8, op, "config.diff") or
        std.mem.eql(u8, op, "config.apply") or
        std.mem.eql(u8, op, "daemon.stop") or
        std.mem.eql(u8, op, "daemon.restart") or
        std.mem.eql(u8, op, "audit.list") or
        std.mem.eql(u8, op, "journal.list") or
        read_model.isListOp(op);
}

fn configStoreErrorCode(err: anyerror) []const u8 {
    return switch (err) {
        error.ConfigTooLarge => "too_large",
        error.FileNotFound => "config_not_found",
        error.InvalidArgument => "invalid_config",
        error.RevisionMismatch => "stale_revision",
        else => "internal",
    };
}

fn writeAffected(json: *std.json.Stringify, affected: config_apply.Affected) !void {
    try json.objectField("affected");
    try json.beginArray();
    var index: usize = 0;
    while (affected.labelAt(index)) |label| : (index += 1) {
        try json.write(label);
    }
    try json.endArray();
}

fn writeWarnings(json: *std.json.Stringify) !void {
    try json.objectField("warnings");
    try json.beginArray();
    try json.endArray();
}

fn writeField(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
}

fn writeOptionalField(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
}

fn appendJournalLine(
    gpa: std.mem.Allocator,
    entries: *std.ArrayListUnmanaged(Server.StoredJournalLine),
    limit: u32,
    entry: Server.StoredJournalLine,
) !void {
    if (limit == 0) {
        var dropped = entry;
        dropped.deinit();
        return;
    }
    while (entries.items.len >= limit) {
        var removed = entries.orderedRemove(0);
        removed.deinit();
    }
    try entries.append(gpa, entry);
}

fn writeOptionalId(json: *std.json.Stringify, id: ?u64) !void {
    try json.objectField("id");
    try json.write(id);
}

fn writeStatus(
    json: *std.json.Stringify,
    snapshot: *const state.Snapshot,
    v3: bool,
    config_revision: ?config_store.Revision,
    config_writable: bool,
    restart_pending: bool,
    restart_supported: bool,
) !void {
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try writeField(json, "version", build_options.version);
    try json.objectField("pid");
    try json.write(linux.getpid());
    try writeField(json, "started_ms", snapshot.started_ms);
    try writeField(json, "updated_ms", snapshot.updated_ms);
    try json.objectField("uptime_ms");
    try json.write(@max(snapshot.updated_ms - snapshot.started_ms, 0));
    try writeField(json, "state_dir", snapshot.state_dir);
    try writeField(json, "control_path", snapshot.control_path);
    try writeField(json, "ports", snapshot.ports);
    try json.objectField("counters");
    try json.write(snapshot.counters);
    if (v3) {
        try writeField(json, "protocol_version", protocol.version);
        if (config_revision) |revision| {
            try writeField(json, "config_revision", revision.slice());
        } else {
            try json.objectField("config_revision");
            try json.write(null);
        }
        try writeField(json, "restart_pending", restart_pending);
        try writeField(json, "config_writable", config_writable);
        try writeField(json, "restart_supported", restart_supported);
    }
    try json.endObject();
}

fn writeNat(json: *std.json.Stringify, snapshot: *const state.Snapshot, v3: bool) !void {
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try json.objectField("snat");
    try json.beginArray();
    for (snapshot.snatSlice()) |rule| {
        try json.beginObject();
        try writeField(json, "out", rule.out);
        try json.objectField("addr");
        try json.print("\"{f}\"", .{rule.addr});
        if (v3) {
            try json.objectField("src");
            if (rule.src) |src| {
                try json.print("\"{f}\"", .{src});
            } else {
                try json.write(null);
            }
            try writeField(json, "explicit", rule.explicit);
        }
        try json.endObject();
    }
    try json.endArray();

    try json.objectField("port_forward");
    try json.beginArray();
    for (snapshot.portForwardSlice()) |rule| {
        try json.beginObject();
        try writeField(json, "proto", state.protoName(rule.proto));
        try writeField(json, "ext_port", rule.ext_port);
        try json.objectField("to_addr");
        try json.print("\"{f}\"", .{rule.to_addr});
        try writeField(json, "to_port", rule.to_port);
        try json.objectField("ingress");
        if (rule.ingress.len == 0) {
            try json.write(null);
        } else {
            try json.write(rule.ingress);
        }
        if (v3) {
            try json.objectField("description");
            if (rule.description_len == 0) {
                try json.write(null);
            } else {
                try json.write(rule.description[0..rule.description_len]);
            }
            try writeField(json, "enabled", rule.enabled);
        }
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
}

fn writeConntrack(
    json: *std.json.Stringify,
    snapshot: *const state.Snapshot,
    state_filter: ?[]const u8,
    requested_limit: ?u32,
) !void {
    const limit: usize = @min(
        requested_limit orelse default_conntrack_limit,
        state.max_conntrack,
    );
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try writeField(json, "total", snapshot.conntrack_total);

    var returned: u32 = 0;
    try json.objectField("entries");
    try json.beginArray();
    for (snapshot.conntrackSlice()) |entry| {
        if (state_filter) |wanted| {
            if (!std.mem.eql(u8, wanted, entry.state)) continue;
        }
        if (returned >= limit) break;
        returned += 1;

        try json.beginObject();
        try writeField(json, "proto", state.protoName(entry.proto));
        try writeField(json, "state", entry.state);
        try json.objectField("src");
        try json.print("\"{f}\"", .{entry.src});
        try writeField(json, "sport", entry.sport);
        try json.objectField("dst");
        try json.print("\"{f}\"", .{entry.dst});
        try writeField(json, "dport", entry.dport);

        try json.objectField("translated_src");
        if (entry.translated_src) |addr| {
            try json.print("\"{f}\"", .{addr});
        } else {
            try json.write(null);
        }
        try writeField(json, "translated_sport", entry.translated_sport);
        try json.objectField("translated_dst");
        if (entry.translated_dst) |addr| {
            try json.print("\"{f}\"", .{addr});
        } else {
            try json.write(null);
        }
        try writeField(json, "translated_dport", entry.translated_dport);
        try writeField(json, "packets", entry.packets);
        try writeField(json, "bytes", entry.bytes);
        try writeField(json, "reply_packets", entry.reply_packets);
        try writeField(json, "reply_bytes", entry.reply_bytes);
        try writeField(json, "created_ms", entry.created_ms);
        try writeField(json, "last_seen_ms", entry.last_seen_ms);
        try writeField(json, "timeout_ms", entry.timeout_ms);
        try json.endObject();
    }
    try json.endArray();
    try writeField(json, "returned", returned);
    try json.endObject();
}

fn listenWithStaleRecovery(
    io: std.Io,
    address: std.Io.net.UnixAddress,
    path: []const u8,
    kernel_backlog: u31,
) !std.Io.net.Server {
    var recovered = false;
    while (true) {
        return address.listen(io, .{ .kernel_backlog = kernel_backlog }) catch |err| switch (err) {
            error.AddressInUse => {
                if (recovered) return error.PathOccupied;
                try removeStaleSocket(io, path);
                recovered = true;
                continue;
            },
            else => return err,
        };
    }
}

fn removeStaleSocket(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const maybe_stream = unix.connect(path) catch |err| switch (err) {
        error.ConnectionRefused, error.FileNotFound => null,
        else => return error.PathOccupied,
    };
    if (maybe_stream) |stream| {
        var live = stream;
        live.close(io);
        return error.PathOccupied;
    }

    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .unix_domain_socket) return error.PathOccupied;
    try cwd.deleteFile(io, path);
}

const Credentials = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

fn peerCredentials(fd: std.posix.fd_t) Error!Credentials {
    var credentials: Credentials = undefined;
    var len: linux.socklen_t = @sizeOf(Credentials);
    const rc = linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &len,
    );
    if (std.posix.errno(rc) != .SUCCESS) return error.PeerCredentials;
    if (len < @sizeOf(Credentials)) return error.PeerCredentials;
    return credentials;
}

fn sendRequest(
    io: std.Io,
    path: []const u8,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    const address = try std.Io.net.UnixAddress.init(path);
    var stream = try address.connect(io);
    defer stream.close(io);
    var out_buf: [256]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    try writer.interface.writeAll(payload);
    try writer.interface.flush();
    return (try transport.readLine(io, stream.socket.handle, out, 1000)).?;
}

test "server starts, answers status, and removes its socket" {
    const testing = std.testing;
    const client_mod = @import("client.zig");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    var snapshot: state.Snapshot = .{
        .instance = "test",
        .state_dir = path_buf[0..dir],
        .control_path = path,
        .started_ms = 1,
        .updated_ms = 2,
        .ports = 1,
    };
    snapshot.snat[0] = .{
        .out = "wan",
        .addr = try types.Ipv4.parse("203.0.113.1"),
        .src = try types.Prefix4.parse("10.0.0.0/24"),
        .explicit = true,
    };
    snapshot.snat_len = 1;
    snapshot.port_forward[0] = .{
        .proto = 6,
        .ext_port = 8080,
        .to_addr = try types.Ipv4.parse("10.0.0.5"),
        .to_port = 80,
        .ingress = "wan",
        .description_len = 6,
        .enabled = false,
    };
    @memcpy(snapshot.port_forward[0].description[0..6], "web ui");
    snapshot.port_forward_len = 1;
    snapshot.conntrack[0] = .{
        .proto = 6,
        .state = "established",
        .src = try types.Ipv4.parse("10.0.0.2"),
        .sport = 40000,
        .dst = try types.Ipv4.parse("198.51.100.10"),
        .dport = 443,
        .translated_src = try types.Ipv4.parse("203.0.113.1"),
        .translated_sport = 40001,
        .translated_dst = try types.Ipv4.parse("198.51.100.10"),
        .translated_dport = 443,
        .packets = 3,
        .bytes = 300,
        .reply_packets = 2,
        .reply_bytes = 200,
        .created_ms = 10,
        .last_seen_ms = 20,
        .timeout_ms = 30,
    };
    snapshot.conntrack_len = 1;
    snapshot.conntrack_total = 1;

    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "vrouter.json",
        .data = "{\n  \"version\": 1,\n  \"instance\": \"test\",\n  \"ports\": {\"lan\": {\"kind\": \"l2\", \"device\": \"eth0\"}}\n}\n",
    });
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/vrouter.json", .{path_buf[0..dir]});
    defer testing.allocator.free(config_path);
    var store = try config_store.Store.open(testing.io, testing.allocator, config_path);
    defer store.deinit();

    var server = try Server.init(testing.io, testing.allocator, path, .{ .config_store = &store });
    var server_active = true;
    defer if (server_active) server.deinit();
    server.publish(&snapshot);
    try server.start();

    var input: [4096]u8 = undefined;
    const line = try sendRequest(testing.io, path, "{\"id\":1,\"op\":\"status\"}\n", &input);
    var response = try std.json.parseFromSlice(protocol.Response, testing.allocator, line, .{});
    defer response.deinit();
    try testing.expect(response.value.ok);
    try testing.expectEqualStrings("test", response.value.status.?.instance);
    try testing.expectEqual(@as(u32, 1), response.value.status.?.ports);
    try testing.expect(response.value.status.?.protocol_version == null);
    try testing.expect(response.value.status.?.config_revision == null);
    try testing.expect(response.value.status.?.restart_pending == null);
    try testing.expect(response.value.status.?.config_writable == null);
    try testing.expect(response.value.status.?.restart_supported == null);

    const v3_status_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":11,\"op\":\"status\"}\n",
        &input,
    );
    var v3_status = try std.json.parseFromSlice(protocol.Response, testing.allocator, v3_status_line, .{});
    defer v3_status.deinit();
    try testing.expect(v3_status.value.ok);
    try testing.expectEqual(@as(?u32, 3), v3_status.value.status.?.protocol_version);
    try testing.expectEqualStrings("sha256:", v3_status.value.status.?.config_revision.?[0..7]);
    try testing.expect(v3_status.value.status.?.restart_pending == false);
    try testing.expect(v3_status.value.status.?.config_writable == true);
    try testing.expect(v3_status.value.status.?.restart_supported == false);

    var status_client = try client_mod.Client.connect(testing.io, testing.allocator, path);
    defer status_client.deinit();
    var client_status = try status_client.call(.{
        .version = 3,
        .id = 19,
        .op = "status",
    });
    defer client_status.deinit();
    try testing.expect(client_status.value.ok);
    try testing.expectEqual(@as(?u32, 3), client_status.value.status.?.protocol_version);

    var config_client = try client_mod.Client.connect(testing.io, testing.allocator, path);
    defer config_client.deinit();
    var client_config = try config_client.call(.{
        .version = 3,
        .id = 20,
        .op = "config.get",
        .instance = "test",
    });
    defer client_config.deinit();
    try testing.expect(client_config.value.ok);
    try testing.expectEqualStrings("test", client_config.value.config.?.object.get("instance").?.string);

    const ports_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":21,\"op\":\"ports.list\"}\n",
        &input,
    );
    var ports = try std.json.parseFromSlice(protocol.Response, testing.allocator, ports_line, .{});
    defer ports.deinit();
    try testing.expect(ports.value.ok);
    try testing.expectEqualStrings("lan", ports.value.ports.?.array.items[0].object.get("name").?.string);
    try testing.expectEqualStrings("eth0", ports.value.ports.?.array.items[0].object.get("device").?.string);

    const v2_restart_line = try sendRequest(
        testing.io,
        path,
        "{\"id\":13,\"op\":\"daemon.restart\",\"restart_token\":\"abc\"}\n",
        &input,
    );
    try testing.expect(std.mem.indexOf(u8, v2_restart_line, "\"version_unsupported\"") != null);

    const unavailable_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":14,\"op\":\"daemon.restart\",\"restart_token\":\"abc\"}\n",
        &input,
    );
    try testing.expect(std.mem.indexOf(u8, unavailable_line, "\"restart_unavailable\"") != null);

    const v2_ping_line = try sendRequest(testing.io, path, "{\"id\":12,\"op\":\"ping\"}\n", &input);
    var v2_ping = try std.json.parseFromSlice(protocol.Response, testing.allocator, v2_ping_line, .{});
    defer v2_ping.deinit();
    try testing.expectEqual(@as(?u32, 2), v2_ping.value.version);

    const nat_line = try sendRequest(testing.io, path, "{\"id\":2,\"op\":\"nat.list\"}\n", &input);
    try testing.expect(std.mem.indexOf(u8, nat_line, "\"src\"") == null);
    try testing.expect(std.mem.indexOf(u8, nat_line, "\"explicit\"") == null);
    try testing.expect(std.mem.indexOf(u8, nat_line, "\"description\"") == null);
    try testing.expect(std.mem.indexOf(u8, nat_line, "\"enabled\"") == null);
    var nat = try std.json.parseFromSlice(protocol.Response, testing.allocator, nat_line, .{});
    defer nat.deinit();
    try testing.expect(nat.value.ok);
    try testing.expectEqualStrings("test", nat.value.nat.?.instance);
    try testing.expectEqualStrings("wan", nat.value.nat.?.snat[0].out);
    try testing.expectEqualStrings("203.0.113.1", nat.value.nat.?.snat[0].addr);
    try testing.expect(nat.value.nat.?.snat[0].src == null);
    try testing.expect(!nat.value.nat.?.snat[0].explicit);
    try testing.expectEqual(@as(u16, 8080), nat.value.nat.?.port_forward[0].ext_port);
    try testing.expectEqualStrings("10.0.0.5", nat.value.nat.?.port_forward[0].to_addr);
    try testing.expect(nat.value.nat.?.port_forward[0].description == null);
    try testing.expect(nat.value.nat.?.port_forward[0].enabled);

    const v3_nat_line = try sendRequest(testing.io, path, "{\"version\":3,\"id\":22,\"op\":\"nat.list\"}\n", &input);
    try testing.expect(std.mem.indexOf(u8, v3_nat_line, "\"src\"") != null);
    try testing.expect(std.mem.indexOf(u8, v3_nat_line, "\"explicit\"") != null);
    try testing.expect(std.mem.indexOf(u8, v3_nat_line, "\"description\"") != null);
    try testing.expect(std.mem.indexOf(u8, v3_nat_line, "\"enabled\"") != null);
    var v3_nat = try std.json.parseFromSlice(protocol.Response, testing.allocator, v3_nat_line, .{});
    defer v3_nat.deinit();
    try testing.expect(v3_nat.value.ok);
    try testing.expectEqualStrings("10.0.0.0/24", v3_nat.value.nat.?.snat[0].src.?);
    try testing.expect(v3_nat.value.nat.?.snat[0].explicit);
    try testing.expectEqualStrings("web ui", v3_nat.value.nat.?.port_forward[0].description.?);
    try testing.expect(!v3_nat.value.nat.?.port_forward[0].enabled);

    const ct_line = try sendRequest(
        testing.io,
        path,
        "{\"id\":3,\"op\":\"conntrack.list\",\"state\":\"established\",\"limit\":5}\n",
        &input,
    );
    var ct = try std.json.parseFromSlice(protocol.Response, testing.allocator, ct_line, .{});
    defer ct.deinit();
    try testing.expect(ct.value.ok);
    try testing.expectEqualStrings("test", ct.value.conntrack.?.instance);
    try testing.expectEqual(@as(u32, 1), ct.value.conntrack.?.returned);
    try testing.expectEqualStrings("203.0.113.1", ct.value.conntrack.?.entries[0].translated_src.?);
    try testing.expectEqual(@as(u16, 40001), ct.value.conntrack.?.entries[0].translated_sport);

    const config_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":13,\"op\":\"config.get\",\"instance\":\"test\"}\n",
        &input,
    );
    var config_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, config_line, .{});
    defer config_response.deinit();
    try testing.expect(config_response.value.ok);
    try testing.expectEqualStrings("sha256:", config_response.value.revision.?[0..7]);
    try testing.expectEqualStrings(config_path, config_response.value.source_path.?);
    try testing.expect(config_response.value.writable.?);
    try testing.expectEqualStrings("test", config_response.value.config.?.object.get("instance").?.string);
    const first_revision = try testing.allocator.dupe(u8, config_response.value.revision.?);
    defer testing.allocator.free(first_revision);

    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "vrouter.json",
        .data = "{\"version\":1,\"instance\":\"test\",\"changed\":true}\n",
    });
    const refreshed_status_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":17,\"op\":\"status\"}\n",
        &input,
    );
    var refreshed_status = try std.json.parseFromSlice(protocol.Response, testing.allocator, refreshed_status_line, .{});
    defer refreshed_status.deinit();
    try testing.expect(!std.mem.eql(u8, first_revision, refreshed_status.value.status.?.config_revision.?));

    const refreshed_config_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":18,\"op\":\"config.get\",\"instance\":\"test\"}\n",
        &input,
    );
    var refreshed_config = try std.json.parseFromSlice(protocol.Response, testing.allocator, refreshed_config_line, .{});
    defer refreshed_config.deinit();
    try testing.expect(refreshed_config.value.config.?.object.get("changed").?.bool);

    const config_no_version_line = try sendRequest(
        testing.io,
        path,
        "{\"id\":14,\"op\":\"config.get\",\"instance\":\"test\"}\n",
        &input,
    );
    var config_no_version = try std.json.parseFromSlice(protocol.Response, testing.allocator, config_no_version_line, .{});
    defer config_no_version.deinit();
    try testing.expect(!config_no_version.value.ok);
    try testing.expectEqualStrings("version_unsupported", config_no_version.value.error_code.?);

    const config_bad_instance_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":15,\"op\":\"config.get\",\"instance\":\"other\"}\n",
        &input,
    );
    var config_bad_instance = try std.json.parseFromSlice(protocol.Response, testing.allocator, config_bad_instance_line, .{});
    defer config_bad_instance.deinit();
    try testing.expect(!config_bad_instance.value.ok);
    try testing.expectEqualStrings("instance_mismatch", config_bad_instance.value.error_code.?);

    const future_line = try sendRequest(testing.io, path, "{\"version\":4,\"id\":16,\"op\":\"status\"}\n", &input);
    var future = try std.json.parseFromSlice(protocol.Response, testing.allocator, future_line, .{});
    defer future.deinit();
    try testing.expect(!future.value.ok);
    try testing.expectEqualStrings("version_unsupported", future.value.error_code.?);

    const bad_line = try sendRequest(testing.io, path, "{bad json}\n", &input);
    var bad = try std.json.parseFromSlice(protocol.Response, testing.allocator, bad_line, .{});
    defer bad.deinit();
    try testing.expect(!bad.value.ok);
    try testing.expectEqualStrings("invalid_request", bad.value.error_code.?);

    const unknown_line = try sendRequest(testing.io, path, "{\"id\":2,\"op\":\"bogus\"}\n", &input);
    var unknown = try std.json.parseFromSlice(protocol.Response, testing.allocator, unknown_line, .{});
    defer unknown.deinit();
    try testing.expect(!unknown.value.ok);
    try testing.expectEqualStrings("unknown_op", unknown.value.error_code.?);

    server.deinit();
    server_active = false;
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "control.sock", .{}));
}

test "server diffs, applies and audits a config proposal" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);
    const state_dir = path_buf[0..dir];

    const current_json =
        \\{"version":1,"instance":"test","ports":{"lan":{"kind":"l2","device":"eth0"}}}
    ;
    const proposed_json =
        \\{"version":1,"instance":"test","ports":{"lan":{"kind":"l2","device":"eth0"}},"log":{"level":"debug"}}
    ;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "vrouter.json", .data = current_json });
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/vrouter.json", .{state_dir});
    defer testing.allocator.free(config_path);
    var store = try config_store.Store.open(testing.io, testing.allocator, config_path);
    defer store.deinit();

    var snapshot: state.Snapshot = .{
        .instance = "test",
        .state_dir = state_dir,
        .control_path = path,
        .started_ms = 1,
        .updated_ms = 2,
    };
    var server = try Server.init(testing.io, testing.allocator, path, .{
        .config_store = &store,
        .state_dir = state_dir,
        .restart_supported = true,
    });
    defer server.deinit();
    server.publish(&snapshot);
    try server.start();

    var input: [8192]u8 = undefined;
    const get_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":30,\"op\":\"config.get\",\"instance\":\"test\"}\n",
        &input,
    );
    var get_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, get_line, .{});
    defer get_response.deinit();
    try testing.expect(get_response.value.ok);
    const revision = try testing.allocator.dupe(u8, get_response.value.revision.?);
    defer testing.allocator.free(revision);

    const diff_payload = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"version\":3,\"id\":31,\"op\":\"config.diff\",\"instance\":\"test\",\"revision\":\"{s}\",\"config\":{s}}}\n",
        .{ revision, proposed_json },
    );
    defer testing.allocator.free(diff_payload);
    const diff_line = try sendRequest(testing.io, path, diff_payload, &input);
    var diff_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, diff_line, .{});
    defer diff_response.deinit();
    try testing.expect(diff_response.value.ok);
    try testing.expect(diff_response.value.confirm != null);
    try testing.expect(diff_response.value.diff != null);
    try testing.expect(diff_response.value.restart_required.?);
    const confirm = try testing.allocator.dupe(u8, diff_response.value.confirm.?);
    defer testing.allocator.free(confirm);

    const apply_payload = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"version\":3,\"id\":32,\"op\":\"config.apply\",\"instance\":\"test\",\"revision\":\"{s}\",\"confirm\":\"{s}\",\"idempotency_key\":\"k1\",\"config\":{s}}}\n",
        .{ revision, confirm, proposed_json },
    );
    defer testing.allocator.free(apply_payload);
    const apply_line = try sendRequest(testing.io, path, apply_payload, &input);
    var apply_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, apply_line, .{});
    defer apply_response.deinit();
    try testing.expect(apply_response.value.ok);
    try testing.expectEqualStrings("restart_required", apply_response.value.result.?);
    try testing.expect(apply_response.value.transaction != null);
    try testing.expect(apply_response.value.restart_required.?);
    try testing.expect(apply_response.value.restart_supported.?);
    try testing.expect(apply_response.value.restart_token != null);
    const restart_token = try testing.allocator.dupe(u8, apply_response.value.restart_token.?);
    defer testing.allocator.free(restart_token);
    const transaction_id = try testing.allocator.dupe(u8, apply_response.value.transaction.?);
    defer testing.allocator.free(transaction_id);

    var applied_config = try store.snapshot();
    defer applied_config.deinit();
    try testing.expect(std.mem.indexOf(u8, applied_config.bytes, "\"level\": \"debug\"") != null);
    const audit = try tmp.dir.readFileAlloc(testing.io, "audit.jsonl", testing.allocator, .limited(8192));
    defer testing.allocator.free(audit);
    try testing.expect(std.mem.indexOf(u8, audit, transaction_id) != null);
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, transaction.pending_file, .{}));

    const replay_line = try sendRequest(testing.io, path, apply_payload, &input);
    var replay_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, replay_line, .{});
    defer replay_response.deinit();
    try testing.expect(replay_response.value.ok);
    try testing.expectEqualStrings(transaction_id, replay_response.value.transaction.?);

    const noop_payload = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"version\":3,\"id\":33,\"op\":\"config.apply\",\"instance\":\"test\",\"revision\":\"{s}\",\"config\":{s}}}\n",
        .{ replay_response.value.revision.?, proposed_json },
    );
    defer testing.allocator.free(noop_payload);
    const noop_line = try sendRequest(testing.io, path, noop_payload, &input);
    var noop_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, noop_line, .{});
    defer noop_response.deinit();
    try testing.expect(noop_response.value.ok);
    try testing.expectEqualStrings("noop", noop_response.value.result.?);
    try testing.expect(noop_response.value.restart_required.? == false);
    try testing.expect(noop_response.value.restart_token == null);
    try testing.expect(!server.restartRequested());
}

test "server accepts restart once and audits the operation" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);
    const state_dir = path_buf[0..dir];

    const current_json =
        \\{"version":1,"instance":"test","ports":{"lan":{"kind":"l2","device":"eth0"}}}
    ;
    const proposed_json =
        \\{"version":1,"instance":"test","ports":{"lan":{"kind":"l2","device":"eth0"}},"log":{"level":"debug"}}
    ;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "vrouter.json", .data = current_json });
    const config_path = try std.fmt.allocPrint(testing.allocator, "{s}/vrouter.json", .{state_dir});
    defer testing.allocator.free(config_path);
    var store = try config_store.Store.open(testing.io, testing.allocator, config_path);
    defer store.deinit();

    var server = try Server.init(testing.io, testing.allocator, path, .{
        .config_store = &store,
        .state_dir = state_dir,
        .restart_supported = true,
    });
    defer server.deinit();
    var snapshot: state.Snapshot = .{
        .instance = "test",
        .state_dir = state_dir,
        .control_path = path,
    };
    server.publish(&snapshot);
    try server.start();

    var input: [8192]u8 = undefined;
    const get_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":40,\"op\":\"config.get\",\"instance\":\"test\"}\n",
        &input,
    );
    var get_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, get_line, .{});
    defer get_response.deinit();
    const revision = try testing.allocator.dupe(u8, get_response.value.revision.?);
    defer testing.allocator.free(revision);

    const diff_payload = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"version\":3,\"id\":41,\"op\":\"config.diff\",\"instance\":\"test\",\"revision\":\"{s}\",\"config\":{s}}}\n",
        .{ revision, proposed_json },
    );
    defer testing.allocator.free(diff_payload);
    const diff_line = try sendRequest(testing.io, path, diff_payload, &input);
    var diff_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, diff_line, .{});
    defer diff_response.deinit();
    try testing.expect(diff_response.value.confirm != null);
    const confirm = try testing.allocator.dupe(u8, diff_response.value.confirm.?);
    defer testing.allocator.free(confirm);

    const apply_payload = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"version\":3,\"id\":42,\"op\":\"config.apply\",\"instance\":\"test\",\"revision\":\"{s}\",\"confirm\":\"{s}\",\"idempotency_key\":\"restart-1\",\"config\":{s}}}\n",
        .{ revision, confirm, proposed_json },
    );
    defer testing.allocator.free(apply_payload);
    const apply_line = try sendRequest(testing.io, path, apply_payload, &input);
    var apply_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, apply_line, .{});
    defer apply_response.deinit();
    try testing.expect(apply_response.value.ok);
    try testing.expect(apply_response.value.restart_token != null);
    const restart_token = try testing.allocator.dupe(u8, apply_response.value.restart_token.?);
    defer testing.allocator.free(restart_token);

    const missing_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":43,\"op\":\"daemon.restart\"}\n",
        &input,
    );
    var missing = try std.json.parseFromSlice(protocol.Response, testing.allocator, missing_line, .{});
    defer missing.deinit();
    try testing.expect(!missing.value.ok);
    try testing.expectEqualStrings("confirm_required", missing.value.error_code.?);

    const restart_payload = try std.fmt.allocPrint(
        testing.allocator,
        "{{\"version\":3,\"id\":44,\"op\":\"daemon.restart\",\"restart_token\":\"{s}\"}}\n",
        .{restart_token},
    );
    defer testing.allocator.free(restart_payload);
    const restart_line = try sendRequest(testing.io, path, restart_payload, &input);
    var restart = try std.json.parseFromSlice(protocol.Response, testing.allocator, restart_line, .{});
    defer restart.deinit();
    try testing.expect(restart.value.ok);
    try testing.expectEqualStrings("accepted", restart.value.result.?);
    try testing.expect(restart.value.transaction != null);
    try testing.expect(server.restartRequested());

    const replay_line = try sendRequest(testing.io, path, restart_payload, &input);
    var replay = try std.json.parseFromSlice(protocol.Response, testing.allocator, replay_line, .{});
    defer replay.deinit();
    try testing.expect(!replay.value.ok);
    try testing.expectEqualStrings("restart_pending", replay.value.error_code.?);

    const audit = try tmp.dir.readFileAlloc(testing.io, "audit.jsonl", testing.allocator, .limited(8192));
    defer testing.allocator.free(audit);
    try testing.expect(std.mem.indexOf(u8, audit, "\"kind\":\"operational\"") != null);
    try testing.expect(std.mem.indexOf(u8, audit, "\"op\":\"daemon.restart\"") != null);
    try testing.expect(std.mem.indexOf(u8, audit, "\"result\":\"accepted\"") != null);
}

test "server refuses a regular file at the socket path" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "control.sock", .data = "x" });
    try testing.expectError(
        error.PathOccupied,
        Server.init(testing.io, testing.allocator, path, .{}),
    );
    const stat = try tmp.dir.statFile(testing.io, "control.sock", .{});
    try testing.expectEqual(std.Io.File.Kind.file, stat.kind);
}

test "server refuses a second instance while the first is live" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    var first = try Server.init(testing.io, testing.allocator, path, .{});
    defer first.deinit();
    try testing.expectError(
        error.AlreadyRunning,
        Server.init(testing.io, testing.allocator, path, .{}),
    );
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try tmp.dir.statFile(testing.io, "control.sock", .{})).kind,
    );
}

test "server does not remove a socket it no longer owns" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    const cwd = std.Io.Dir.cwd();
    var server = try Server.init(testing.io, testing.allocator, path, .{});
    var server_active = true;
    defer if (server_active) server.deinit();

    try cwd.deleteFile(testing.io, path);
    const address = try std.Io.net.UnixAddress.init(path);
    var replacement = try address.listen(testing.io, .{});
    defer {
        replacement.deinit(testing.io);
        cwd.deleteFile(testing.io, path) catch {};
    }

    server.deinit();
    server_active = false;
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try cwd.statFile(testing.io, path, .{ .follow_symlinks = false })).kind,
    );
}

test "server replaces a stale socket" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    const address = try std.Io.net.UnixAddress.init(path);
    var stale = try address.listen(testing.io, .{});
    stale.deinit(testing.io);
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try tmp.dir.statFile(testing.io, "control.sock", .{})).kind,
    );

    var server = try Server.init(testing.io, testing.allocator, path, .{});
    defer server.deinit();
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try tmp.dir.statFile(testing.io, "control.sock", .{})).kind,
    );
}

test "server lists bounded audit and journal tails" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const state_dir = path_buf[0..dir];
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{state_dir});
    defer testing.allocator.free(path);

    const audit_data =
        \\{"ts_ms":1000,"transaction":"t1","audit_id":"a1","kind":"operational","op":"config.apply","instance":"test","actor_uid":1000,"actor_pid":10,"result":"applied"}
        \\not-json
        \\{"ts_ms":2000,"transaction":"t2","audit_id":"a2","kind":"operational","op":"daemon.restart","instance":"test","actor_uid":1000,"actor_pid":11,"result":"accepted"}
        \\{"ts_ms":3000,"transaction":"t3","audit_id":"a3","kind":"operational","op":"daemon.stop","instance":"test","actor_uid":1000,"actor_pid":12,"result":"accepted"}
        \\
    ;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = transaction.audit_file, .data = audit_data });

    const journal_data =
        \\{"op":"addr_add","dev":"lan","cidr":"192.0.2.1/24"}
        \\{"op":"bogus"}
        \\{"op":"link","dev":"lan","up":true}
        \\{"op":"route_add","dst":"not-a-prefix","dev":"lan"}
        \\
    ;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "test.journal", .data = journal_data });

    var server = try Server.init(testing.io, testing.allocator, path, .{
        .state_dir = state_dir,
    });
    defer server.deinit();
    var snapshot: state.Snapshot = .{
        .instance = "test",
        .state_dir = state_dir,
        .control_path = path,
    };
    server.publish(&snapshot);
    try server.start();

    var input: [16384]u8 = undefined;
    const audit_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":60,\"op\":\"audit.list\",\"limit\":2}\n",
        &input,
    );
    var audit_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, audit_line, .{});
    defer audit_response.deinit();
    try testing.expect(audit_response.value.ok);
    const audit_snapshot = audit_response.value.audit.?;
    try testing.expectEqual(@as(u32, 4), audit_snapshot.total);
    try testing.expectEqual(@as(u32, 1), audit_snapshot.malformed);
    try testing.expectEqual(@as(u32, 2), audit_snapshot.returned);
    try testing.expectEqualStrings("daemon.restart", audit_snapshot.entries[0].op);
    try testing.expectEqualStrings("daemon.stop", audit_snapshot.entries[1].op);
    try testing.expectEqual(@as(i64, 3000), audit_snapshot.entries[1].ts_ms);

    const journal_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":3,\"id\":61,\"op\":\"journal.list\",\"limit\":2}\n",
        &input,
    );
    var journal_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, journal_line, .{});
    defer journal_response.deinit();
    try testing.expect(journal_response.value.ok);
    const journal_snapshot = journal_response.value.journal.?;
    try testing.expectEqual(@as(u32, 4), journal_snapshot.entries);
    try testing.expectEqual(@as(u32, 2), journal_snapshot.valid);
    try testing.expectEqual(@as(u32, 2), journal_snapshot.malformed);
    try testing.expect(journal_snapshot.malformed_tail);
    try testing.expectEqual(@as(usize, 2), journal_snapshot.lines.len);
    try testing.expect(journal_snapshot.lines[0].valid);
    try testing.expectEqualStrings("link", journal_snapshot.lines[0].op);
    try testing.expect(!journal_snapshot.lines[1].valid);

    const v2_line = try sendRequest(
        testing.io,
        path,
        "{\"version\":2,\"id\":62,\"op\":\"audit.list\"}\n",
        &input,
    );
    var v2_response = try std.json.parseFromSlice(protocol.Response, testing.allocator, v2_line, .{});
    defer v2_response.deinit();
    try testing.expect(!v2_response.value.ok);
    try testing.expectEqualStrings("version_unsupported", v2_response.value.error_code.?);
}
