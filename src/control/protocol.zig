//! Line-delimited JSON control protocol. Each connection carries one request
//! and one response; `id` is echoed so clients can match replies.

const std = @import("std");
const state = @import("state.zig");

pub const version: u32 = 3;
pub const v2_version: u32 = 2;

pub const NatMasquerade = struct {
    out: []const u8 = "",
    src: ?[]const u8 = null,
    addr: ?[]const u8 = null,
};

pub const NatForward = struct {
    proto: []const u8 = "",
    ext_port: u16 = 0,
    to: []const u8 = "",
    ingress: ?[]const u8 = null,
    description: ?[]const u8 = null,
    enabled: bool = true,
};

pub const NatApply = struct {
    instance: []const u8 = "",
    masquerade: []const NatMasquerade = &.{},
    port_forward: []const NatForward = &.{},
};

pub const Request = struct {
    version: ?u32 = null,
    id: ?u64 = null,
    op: []const u8,
    instance: ?[]const u8 = null,
    revision: ?[]const u8 = null,
    confirm: ?[]const u8 = null,
    restart_token: ?[]const u8 = null,
    idempotency_key: ?[]const u8 = null,
    state: ?[]const u8 = null,
    limit: ?u32 = null,
    nat: ?NatApply = null,
    config: ?std.json.Value = null,
    target_revision: ?[]const u8 = null,
};

pub const Status = struct {
    instance: []const u8 = "",
    version: []const u8 = "",
    pid: u32 = 0,
    started_ms: i64 = 0,
    updated_ms: i64 = 0,
    uptime_ms: i64 = 0,
    state_dir: []const u8 = "",
    control_path: []const u8 = "",
    ports: u32 = 0,
    counters: state.Counters = .{},
    protocol_version: ?u32 = null,
    config_revision: ?[]const u8 = null,
    restart_pending: ?bool = null,
    config_writable: ?bool = null,
    restart_supported: ?bool = null,
};

pub const Snat = struct {
    out: []const u8 = "",
    addr: []const u8 = "",
    src: ?[]const u8 = null,
    explicit: bool = false,
};

pub const PortForward = struct {
    proto: []const u8 = "",
    ext_port: u16 = 0,
    to_addr: []const u8 = "",
    to_port: u16 = 0,
    ingress: ?[]const u8 = null,
    description: ?[]const u8 = null,
    enabled: bool = true,
};

pub const Nat = struct {
    instance: []const u8 = "",
    snat: []const Snat = &.{},
    port_forward: []const PortForward = &.{},
};

pub const ConntrackEntry = struct {
    proto: []const u8 = "",
    state: []const u8 = "",
    src: []const u8 = "",
    sport: u16 = 0,
    dst: []const u8 = "",
    dport: u16 = 0,
    translated_src: ?[]const u8 = null,
    translated_sport: u16 = 0,
    translated_dst: ?[]const u8 = null,
    translated_dport: u16 = 0,
    packets: u64 = 0,
    bytes: u64 = 0,
    reply_packets: u64 = 0,
    reply_bytes: u64 = 0,
    created_ms: i64 = 0,
    last_seen_ms: i64 = 0,
    timeout_ms: i64 = 0,
};

pub const Conntrack = struct {
    instance: []const u8 = "",
    total: u32 = 0,
    returned: u32 = 0,
    entries: []const ConntrackEntry = &.{},
};

pub const AuditEntry = struct {
    ts_ms: i64 = 0,
    transaction: []const u8 = "",
    audit_id: []const u8 = "",
    kind: ?[]const u8 = null,
    op: []const u8 = "",
    instance: []const u8 = "",
    revision_before: ?[]const u8 = null,
    revision_after: ?[]const u8 = null,
    actor_uid: ?u32 = null,
    actor_pid: ?i32 = null,
    affected: ?[]const []const u8 = null,
    restart_required: ?bool = null,
    result: []const u8 = "",
    recovered: ?bool = null,
};

pub const Audit = struct {
    instance: []const u8 = "",
    path: []const u8 = "",
    total: u32 = 0,
    returned: u32 = 0,
    malformed: u32 = 0,
    truncated: bool = false,
    entries: []const AuditEntry = &.{},
};

pub const JournalEntry = struct {
    line: u64 = 0,
    valid: bool = true,
    raw: []const u8 = "",
    op: []const u8 = "",
    dev: ?[]const u8 = null,
    cidr: ?[]const u8 = null,
    up: ?bool = null,
    dst: ?[]const u8 = null,
    via: ?[]const u8 = null,
    metric: ?u32 = null,
    table: ?u32 = null,
    kind: ?[]const u8 = null,
    peer: ?[]const u8 = null,
    stp: ?bool = null,
    vlan_filtering: ?bool = null,
    master: ?[]const u8 = null,
    vid: ?u16 = null,
    pvid: ?bool = null,
    untagged: ?bool = null,
};

pub const Journal = struct {
    instance: []const u8 = "",
    path: []const u8 = "",
    entries: u32 = 0,
    valid: u32 = 0,
    malformed: u32 = 0,
    malformed_tail: bool = false,
    returned: u32 = 0,
    truncated: bool = false,
    lines: []const JournalEntry = &.{},
};

pub const Response = struct {
    ok: bool = false,
    id: ?u64 = null,
    op: ?[]const u8 = null,
    error_code: ?[]const u8 = null,
    message: ?[]const u8 = null,
    version: ?u32 = null,
    protocol_version: ?u32 = null,
    status: ?Status = null,
    nat: ?Nat = null,
    conntrack: ?Conntrack = null,
    audit: ?Audit = null,
    journal: ?Journal = null,
    revision: ?[]const u8 = null,
    source_path: ?[]const u8 = null,
    writable: ?bool = null,
    config: ?std.json.Value = null,
    ports: ?std.json.Value = null,
    bridges: ?std.json.Value = null,
    interfaces: ?std.json.Value = null,
    routes: ?std.json.Value = null,
    dhcp: ?std.json.Value = null,
    dns: ?std.json.Value = null,
    firewall: ?std.json.Value = null,
    transaction: ?[]const u8 = null,
    result: ?[]const u8 = null,
    affected: ?[]const []const u8 = null,
    diff: ?[]const u8 = null,
    warnings: ?[]const []const u8 = null,
    confirm: ?[]const u8 = null,
    restart_required: ?bool = null,
    restart_supported: ?bool = null,
    restart_token: ?[]const u8 = null,
};

pub const ParseError = error{InvalidRequest};

pub fn isV3Only(op: []const u8) bool {
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
        std.mem.eql(u8, op, "doctor.status") or
        std.mem.eql(u8, op, "daemon.stop") or
        std.mem.eql(u8, op, "daemon.restart");
}

pub fn isConfigSized(op: []const u8) bool {
    return std.mem.eql(u8, op, "config.get") or
        std.mem.eql(u8, op, "config.validate") or
        std.mem.eql(u8, op, "config.diff") or
        std.mem.eql(u8, op, "config.apply") or
        std.mem.eql(u8, op, "config.rollback");
}

pub fn parseRequest(gpa: std.mem.Allocator, line: []const u8) !std.json.Parsed(Request) {
    return std.json.parseFromSlice(Request, gpa, line, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidRequest,
    };
}

test "request parses and rejects malformed input" {
    var parsed = try parseRequest(std.testing.allocator, "{\"id\":7,\"op\":\"conntrack.list\",\"state\":\"established\",\"limit\":10}");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?u64, 7), parsed.value.id);
    try std.testing.expectEqualStrings("conntrack.list", parsed.value.op);
    try std.testing.expectEqual(@as(?u32, 10), parsed.value.limit);
    try std.testing.expectError(error.InvalidRequest, parseRequest(std.testing.allocator, "{"));
}

test "v3 request parses version and config fields" {
    var parsed = try parseRequest(
        std.testing.allocator,
        "{\"version\":3,\"id\":8,\"op\":\"config.get\",\"instance\":\"test\",\"revision\":\"sha256:abc\",\"confirm\":\"yes\",\"idempotency_key\":\"k1\"}",
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?u32, 3), parsed.value.version);
    try std.testing.expectEqualStrings("config.get", parsed.value.op);
    try std.testing.expectEqualStrings("test", parsed.value.instance.?);
    try std.testing.expectEqualStrings("sha256:abc", parsed.value.revision.?);
    try std.testing.expectEqualStrings("yes", parsed.value.confirm.?);
    try std.testing.expectEqualStrings("k1", parsed.value.idempotency_key.?);
}

test "restart request parses the one-time token" {
    var parsed = try parseRequest(
        std.testing.allocator,
        "{\"version\":3,\"id\":9,\"op\":\"daemon.restart\",\"restart_token\":\"abc\"}",
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings("daemon.restart", parsed.value.op);
    try std.testing.expectEqualStrings("abc", parsed.value.restart_token.?);
}

test "v2 request serialization omits null optional fields" {
    const request: Request = .{ .id = 1, .op = "status" };
    var buf: [512]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buf);
    try std.json.Stringify.value(request, .{ .emit_null_optional_fields = false }, &out);
    try std.testing.expectEqualStrings("{\"id\":1,\"op\":\"status\"}", out.buffered());
}

test "response round-trips status counters" {
    const response: Response = .{
        .ok = true,
        .id = 3,
        .op = "status",
        .status = .{
            .instance = "test",
            .version = "0.1.0",
            .pid = 42,
            .ports = 2,
            .counters = .{ .forwarded = 9, .conntrack_created = 4 },
        },
    };
    var buf: [2048]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buf);
    try std.json.Stringify.value(response, .{}, &out);
    var parsed = try std.json.parseFromSlice(Response, std.testing.allocator, out.buffered(), .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.ok);
    try std.testing.expectEqual(@as(u32, 42), parsed.value.status.?.pid);
    try std.testing.expectEqual(@as(u64, 9), parsed.value.status.?.counters.forwarded);
}

test "v3 response round-trips config fields" {
    var config = try std.json.ObjectMap.init(std.testing.allocator, &.{}, &.{});
    defer config.deinit(std.testing.allocator);
    try config.put(std.testing.allocator, "instance", .{ .string = "test" });
    const response: Response = .{
        .ok = true,
        .id = 4,
        .op = "config.get",
        .protocol_version = version,
        .revision = "sha256:abc",
        .source_path = "/etc/vrouter/vrouter.json",
        .writable = true,
        .config = .{ .object = config },
    };

    var buf: [2048]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buf);
    try std.json.Stringify.value(response, .{ .emit_null_optional_fields = false }, &out);
    var parsed = try std.json.parseFromSlice(Response, std.testing.allocator, out.buffered(), .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.ok);
    try std.testing.expectEqual(@as(?u32, version), parsed.value.protocol_version);
    try std.testing.expectEqualStrings("sha256:abc", parsed.value.revision.?);
    try std.testing.expectEqualStrings("test", parsed.value.config.?.object.get("instance").?.string);
}
