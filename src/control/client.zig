//! Unix-socket control client used by the CLI and, later, the web adapter.

const std = @import("std");
const protocol = @import("protocol.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");

const max_request_bytes = 64 * 1024;
const max_response_bytes = 128 * 1024;
const max_config_response_bytes: usize = 16 * 1024 * 1024;
const response_timeout_ms = 5_000;
const config_response_timeout_ms = 30_000;

pub const Client = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    stream: std.Io.net.Stream,
    next_id: u64 = 1,

    pub fn connect(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !Client {
        return .{
            .io = io,
            .gpa = gpa,
            .stream = try unix.connect(path),
        };
    }

    pub fn deinit(self: *Client) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn callOp(
        self: *Client,
        op: []const u8,
        state_filter: ?[]const u8,
        limit: ?u32,
    ) !std.json.Parsed(protocol.Response) {
        const request: protocol.Request = .{
            .id = self.next_id,
            .op = op,
            .state = state_filter,
            .limit = limit,
        };
        self.next_id += 1;
        return self.call(request);
    }

    pub fn call(self: *Client, request: protocol.Request) !std.json.Parsed(protocol.Response) {
        var request_buf: [max_request_bytes]u8 = undefined;
        var request_writer: std.Io.Writer = .fixed(&request_buf);
        try std.json.Stringify.value(request, .{ .emit_null_optional_fields = false }, &request_writer);
        try request_writer.writeByte('\n');

        var socket_buf: [4096]u8 = undefined;
        var stream_writer = self.stream.writer(self.io, &socket_buf);
        try stream_writer.interface.writeAll(request_writer.buffered());
        try stream_writer.interface.flush();

        const is_config = std.mem.eql(u8, request.op, "config.get");
        const response_limit: usize = if (is_config) max_config_response_bytes else max_response_bytes;
        const response_buf = try self.gpa.alloc(u8, response_limit);
        defer self.gpa.free(response_buf);
        const line = (try transport.readLine(
            self.io,
            self.stream.socket.handle,
            response_buf,
            if (is_config) config_response_timeout_ms else response_timeout_ms,
        )) orelse return error.ConnectionClosed;

        return std.json.parseFromSlice(protocol.Response, self.gpa, line, .{
            .allocate = .alloc_always,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidResponse,
        };
    }
};
