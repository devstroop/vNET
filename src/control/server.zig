//! Unix-socket control server. One worker thread accepts short-lived clients;
//! the datapath publishes immutable snapshots under a mutex.

const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");
const config_parse = @import("../config/parse.zig");
const config_store = @import("../config/store.zig");
const protocol = @import("protocol.zig");
const read_model = @import("read_model.zig");
const state = @import("state.zig");
const types = @import("../types.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");
const thread = @import("../thread.zig");

pub const max_request_bytes = 64 * 1024;
const max_response_bytes = 128 * 1024;
const client_timeout_ms = 2_000;
const default_conntrack_limit = 100;
const max_apply_error = 256;
const config_queue_capacity = 4;

pub const Options = struct {
    mode: u32 = 0o660,
    allow_uid: ?u32 = null,
    kernel_backlog: u31 = 16,
    config_store: ?*config_store.Store = null,
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
    line: [max_request_bytes]u8 = undefined,
    line_len: usize = 0,
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
    restart_pending: bool = false,
    restart_supported: bool = false,

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
            .restart_pending = options.restart_pending,
            .restart_supported = options.restart_supported,
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
        self.gpa.free(self.config_jobs);
        self.gpa.free(self.path);
        self.* = undefined;
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

        var request_buf: [max_request_bytes]u8 = undefined;
        const line = transport.readLine(
            self.io,
            stream.socket.handle,
            &request_buf,
            client_timeout_ms,
        ) catch |err| {
            self.sendError(stream, null, null, "invalid_request", @errorName(err));
            return;
        } orelse return;

        var parsed = protocol.parseRequest(std.heap.page_allocator, line) catch {
            self.sendError(stream, null, null, "invalid_request", "malformed JSON request");
            return;
        };
        defer parsed.deinit();

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

        if (isV3Only(parsed.value.op) and !v3) {
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

        if (std.mem.eql(u8, parsed.value.op, "config.get") or read_model.isListOp(parsed.value.op)) {
            if (self.submitConfig(stream, line)) {
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
            writeNat(&json, snapshot) catch return false;
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

    fn submitConfig(self: *Server, stream: std.Io.net.Stream, line: []const u8) bool {
        self.config_mutex.lockUncancelable(self.io);
        defer self.config_mutex.unlock(self.io);
        if (self.stop.load(.acquire) or self.config_count == self.config_jobs.len) return false;
        const job = &self.config_jobs[self.config_tail];
        job.stream = stream;
        job.line_len = line.len;
        @memcpy(job.line[0..line.len], line);
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
                continue;
            }

            var parsed = protocol.parseRequest(std.heap.page_allocator, job.line[0..job.line_len]) catch {
                self.sendError(job.stream, null, null, "invalid_request", "malformed JSON request");
                job.stream.close(self.io);
                continue;
            };
            defer parsed.deinit();
            if (std.mem.eql(u8, parsed.value.op, "config.get")) {
                self.handleConfigGet(job.stream, parsed.value);
            } else {
                self.handleConfigList(job.stream, parsed.value);
            }
            job.stream.close(self.io);
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
        read_model.isListOp(op);
}

fn isV3Only(op: []const u8) bool {
    return std.mem.eql(u8, op, "config.get") or
        std.mem.eql(u8, op, "config.validate") or
        std.mem.eql(u8, op, "config.diff") or
        std.mem.eql(u8, op, "config.apply") or
        std.mem.eql(u8, op, "config.rollback") or
        std.mem.eql(u8, op, "ports.list") or
        std.mem.eql(u8, op, "bridges.list") or
        std.mem.eql(u8, op, "interfaces.list") or
        std.mem.eql(u8, op, "routes.list") or
        std.mem.eql(u8, op, "dhcp.list") or
        std.mem.eql(u8, op, "dhcp.leases") or
        std.mem.eql(u8, op, "dns.list") or
        std.mem.eql(u8, op, "firewall.list") or
        std.mem.eql(u8, op, "firewall.counters") or
        std.mem.eql(u8, op, "journal.list") or
        std.mem.eql(u8, op, "audit.list") or
        std.mem.eql(u8, op, "doctor.status");
}

fn writeField(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
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

fn writeNat(json: *std.json.Stringify, snapshot: *const state.Snapshot) !void {
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try json.objectField("snat");
    try json.beginArray();
    for (snapshot.snatSlice()) |rule| {
        try json.beginObject();
        try writeField(json, "out", rule.out);
        try json.objectField("addr");
        try json.print("\"{f}\"", .{rule.addr});
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
    snapshot.snat[0] = .{ .out = "wan", .addr = try types.Ipv4.parse("203.0.113.1") };
    snapshot.snat_len = 1;
    snapshot.port_forward[0] = .{
        .proto = 6,
        .ext_port = 8080,
        .to_addr = try types.Ipv4.parse("10.0.0.5"),
        .to_port = 80,
        .ingress = "wan",
    };
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

    const v2_ping_line = try sendRequest(testing.io, path, "{\"id\":12,\"op\":\"ping\"}\n", &input);
    var v2_ping = try std.json.parseFromSlice(protocol.Response, testing.allocator, v2_ping_line, .{});
    defer v2_ping.deinit();
    try testing.expectEqual(@as(?u32, 2), v2_ping.value.version);

    const nat_line = try sendRequest(testing.io, path, "{\"id\":2,\"op\":\"nat.list\"}\n", &input);
    var nat = try std.json.parseFromSlice(protocol.Response, testing.allocator, nat_line, .{});
    defer nat.deinit();
    try testing.expect(nat.value.ok);
    try testing.expectEqualStrings("test", nat.value.nat.?.instance);
    try testing.expectEqualStrings("wan", nat.value.nat.?.snat[0].out);
    try testing.expectEqualStrings("203.0.113.1", nat.value.nat.?.snat[0].addr);
    try testing.expectEqual(@as(u16, 8080), nat.value.nat.?.port_forward[0].ext_port);
    try testing.expectEqualStrings("10.0.0.5", nat.value.nat.?.port_forward[0].to_addr);

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
