//! Read-only web admin API and static frontend server.
//!
//! The process is deliberately unprivileged and derives every piece of state
//! from the existing Unix control socket. It never mutates the host directly.

const std = @import("std");
const vrouter = @import("vrouter");
const auth = @import("auth.zig");
const protocol = vrouter.control_protocol;

const cookie_name = "vrouter_session";
const max_body = 4096;
const max_password_len = 256;
const login_max_failures = 5;
const login_lock_ms = 30_000;
const max_asset_bytes = 16 * 1024 * 1024;

pub const Options = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    listen: []const u8 = "127.0.0.1:8080",
    control_path: []const u8 = "/run/vrouter/control.sock",
    password_phc: []const u8,
    session_ttl_ms: i64 = auth.default_session_ttl_ms,
    assets_dir: []const u8 = "zig-out/share/vrouter-web",
};

pub fn run(options: Options) !void {
    const address = try std.Io.net.IpAddress.parseLiteral(options.listen);
    if (!isLoopback(address)) return error.NonLoopbackListen;

    var app = App{
        .io = options.io,
        .gpa = options.gpa,
        .listen = options.listen,
        .port = address.getPort(),
        .control_path = options.control_path,
        .password_phc = options.password_phc,
        .session_ttl_ms = options.session_ttl_ms,
        .assets_dir = options.assets_dir,
        .sessions = auth.Store.init(options.gpa),
    };
    defer app.sessions.deinit();

    var listener = try address.listen(options.io, .{ .reuse_address = true });
    defer listener.deinit(options.io);

    std.log.info("vrouter-web listening on {s} (control {s})", .{ options.listen, options.control_path });
    while (true) {
        const stream = try listener.accept(options.io);
        app.handleConnection(stream) catch |err| {
            std.log.err("web connection failed: {t}", .{err});
        };
    }
}

fn isLoopback(address: std.Io.net.IpAddress) bool {
    return switch (address) {
        .ip4 => |a| a.bytes[0] == 127,
        .ip6 => |a| a.isLoopBack(),
    };
}

const SessionPayload = struct {
    authenticated: bool,
    csrf: ?[]const u8 = null,
};

const LoginPayload = struct {
    ok: bool,
    csrf: ?[]const u8 = null,
    code: ?[]const u8 = null,
    message: ?[]const u8 = null,
};

const OkPayload = struct {
    ok: bool = true,
};

const ErrorPayload = struct {
    ok: bool = false,
    code: []const u8,
    message: []const u8,
};

const StatusPayload = struct {
    ok: bool = true,
    status: protocol.Status,
};

const NatPayload = struct {
    ok: bool = true,
    nat: protocol.Nat,
};

const ConntrackPayload = struct {
    ok: bool = true,
    conntrack: protocol.Conntrack,
};

const LoginRequest = struct {
    password: []const u8 = "",
};

const LogoutRequest = struct {
    csrf: []const u8 = "",
};

const App = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    listen: []const u8,
    port: u16,
    control_path: []const u8,
    password_phc: []const u8,
    session_ttl_ms: i64,
    assets_dir: []const u8,
    sessions: auth.Store,
    login_failures: u32 = 0,
    login_locked_until_ms: i64 = 0,

    fn handleConnection(self: *App, stream: std.Io.net.Stream) !void {
        defer stream.close(self.io);

        var recv_buf: [16 * 1024]u8 = undefined;
        var send_buf: [64 * 1024]u8 = undefined;
        var reader = stream.reader(self.io, &recv_buf);
        var writer = stream.writer(self.io, &send_buf);
        var server = std.http.Server.init(&reader.interface, &writer.interface);

        var request = server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => return err,
        };
        self.serve(&request) catch |err| {
            std.log.err("web request {s} failed: {t}", .{ request.head.target, err });
            return;
        };
    }

    fn serve(self: *App, request: *std.http.Server.Request) !void {
        const path = std.mem.sliceTo(request.head.target, '?');
        const method = request.head.method;
        fixMissingBodyLength(request);

        if (!self.hostAllowed(request)) {
            return self.apiError(request, .bad_request, "unexpected_host", "Unexpected Host header.");
        }

        if (std.mem.eql(u8, path, "/healthz")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowed(request);
            return self.respond(request, .ok, "text/plain; charset=utf-8", "ok\n", "no-store", &.{});
        }

        if (std.mem.eql(u8, path, "/api/session")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveSession(request);
        }
        if (std.mem.eql(u8, path, "/api/login")) {
            if (method != .POST) return self.methodNotAllowed(request);
            return self.serveLogin(request);
        }
        if (std.mem.eql(u8, path, "/api/logout")) {
            if (method != .POST) return self.methodNotAllowed(request);
            return self.serveLogout(request);
        }
        if (std.mem.eql(u8, path, "/api/status")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveStatus(request);
        }
        if (std.mem.eql(u8, path, "/api/nat")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveNat(request);
        }
        if (std.mem.eql(u8, path, "/api/conntrack")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveConntrack(request);
        }
        if (std.mem.eql(u8, path, "/api") or std.mem.startsWith(u8, path, "/api/")) {
            return self.apiError(request, .not_found, "not_found", "API endpoint not found.");
        }

        if (method != .GET and method != .HEAD) return self.methodNotAllowed(request);
        return self.serveStatic(request, path);
    }

    fn serveSession(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request)) |csrf| {
            return self.respondJson(request, .ok, SessionPayload{
                .authenticated = true,
                .csrf = csrf[0..],
            });
        }
        return self.respondJson(request, .ok, SessionPayload{ .authenticated = false });
    }

    fn serveLogin(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.apiError(request, .forbidden, "cross_origin", "Cross-origin request rejected.");
        }

        const now = std.Io.Clock.real.now(self.io).toMilliseconds();
        if (now < self.login_locked_until_ms) {
            return self.apiError(request, .too_many_requests, "rate_limited", "Too many attempts. Try again shortly.");
        }

        var body_buf: [max_body]u8 = undefined;
        const body_reader = request.readerExpectContinue(&body_buf) catch
            return self.apiError(request, .bad_request, "bad_request", "Unsupported request expectation.");
        const body = body_reader.allocRemaining(self.gpa, .limited(max_body)) catch
            return self.apiError(request, .bad_request, "body_too_large", "Request body is too large.");
        defer self.gpa.free(body);

        var parsed = std.json.parseFromSlice(LoginRequest, self.gpa, body, .{ .allocate = .alloc_always }) catch
            return self.apiError(request, .bad_request, "invalid_json", "Expected a JSON login body.");
        defer parsed.deinit();

        const password = parsed.value.password;
        if (password.len == 0 or password.len > max_password_len or
            !auth.verifyPassword(self.io, self.gpa, self.password_phc, password))
        {
            self.login_failures += 1;
            if (self.login_failures >= login_max_failures) {
                self.login_failures = 0;
                self.login_locked_until_ms = now + login_lock_ms;
            }
            return self.respondJson(request, .unauthorized, LoginPayload{
                .ok = false,
                .code = "invalid_credentials",
                .message = "Invalid password.",
            });
        }

        self.login_failures = 0;
        const created = try self.sessions.create(self.io, now, self.session_ttl_ms);
        var cookie_buf: [192]u8 = undefined;
        const cookie = try std.fmt.bufPrint(&cookie_buf, "{s}={s}; HttpOnly; SameSite=Strict; Path=/; Max-Age={d}", .{
            cookie_name,
            created.token,
            @divTrunc(self.session_ttl_ms, 1000),
        });
        return self.respondJsonWithHeaders(request, .ok, LoginPayload{ .ok = true, .csrf = created.csrf[0..] }, &.{
            .{ .name = "set-cookie", .value = cookie },
        });
    }

    fn serveLogout(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.apiError(request, .forbidden, "cross_origin", "Cross-origin request rejected.");
        }
        const token = getCookie(request, cookie_name) orelse
            return self.apiError(request, .unauthorized, "unauthenticated", "Missing session.");
        const expected = self.sessions.csrfFor(self.io, token, std.Io.Clock.real.now(self.io).toMilliseconds()) orelse
            return self.apiError(request, .unauthorized, "unauthenticated", "Session expired.");

        var body_buf: [max_body]u8 = undefined;
        const body_reader = request.readerExpectContinue(&body_buf) catch
            return self.apiError(request, .bad_request, "bad_request", "Unsupported request expectation.");
        const body = body_reader.allocRemaining(self.gpa, .limited(max_body)) catch
            return self.apiError(request, .bad_request, "body_too_large", "Request body is too large.");
        defer self.gpa.free(body);

        var parsed = std.json.parseFromSlice(LogoutRequest, self.gpa, body, .{ .allocate = .alloc_always }) catch
            return self.apiError(request, .bad_request, "invalid_json", "Expected a JSON logout body.");
        defer parsed.deinit();

        const csrf = parsed.value.csrf;
        if (csrf.len != auth.token_hex_len) {
            return self.apiError(request, .forbidden, "invalid_csrf", "Invalid CSRF token.");
        }
        var candidate: [auth.token_hex_len]u8 = undefined;
        @memcpy(&candidate, csrf);
        if (!std.crypto.timing_safe.eql([auth.token_hex_len]u8, expected, candidate)) {
            return self.apiError(request, .forbidden, "invalid_csrf", "Invalid CSRF token.");
        }

        self.sessions.remove(self.io, token);
        return self.respondJsonWithHeaders(request, .ok, OkPayload{}, &.{
            .{ .name = "set-cookie", .value = cookie_name ++ "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" },
        });
    }

    fn serveStatus(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("status", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const status = response.value.status orelse return self.controlError(request, error.MissingStatus);
        return self.respondJson(request, .ok, StatusPayload{ .status = status });
    }

    fn serveNat(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("nat.list", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const nat = response.value.nat orelse return self.controlError(request, error.MissingNat);
        return self.respondJson(request, .ok, NatPayload{ .nat = nat });
    }

    fn serveConntrack(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("conntrack.list", null, 100) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const conntrack = response.value.conntrack orelse return self.controlError(request, error.MissingConntrack);
        return self.respondJson(request, .ok, ConntrackPayload{ .conntrack = conntrack });
    }

    fn serveStatic(self: *App, request: *std.http.Server.Request, path: []const u8) !void {
        if (assetPath(path)) |relative| {
            const cache = if (std.mem.startsWith(u8, relative, "assets/"))
                "public, max-age=31536000, immutable"
            else
                "no-store";
            return self.serveFile(request, relative, cache);
        }
        if (std.fs.path.extension(path).len == 0) {
            return self.serveFile(request, "index.html", "no-store");
        }
        return self.apiError(request, .not_found, "not_found", "Asset not found.");
    }

    fn serveFile(self: *App, request: *std.http.Server.Request, relative: []const u8, cache: []const u8) !void {
        const joined = try std.fs.path.join(self.gpa, &.{ self.assets_dir, relative });
        defer self.gpa.free(joined);
        const data = std.Io.Dir.cwd().readFileAlloc(self.io, joined, self.gpa, .limited(max_asset_bytes)) catch |err| switch (err) {
            error.FileNotFound => return self.respondText(request, .not_found, "Frontend asset not found. Run `zig build web`.\n"),
            else => {
                std.log.err("failed to read frontend asset {s}: {t}", .{ joined, err });
                return self.respondText(request, .internal_server_error, "Failed to read frontend asset.\n");
            },
        };
        defer self.gpa.free(data);
        return self.respond(request, .ok, contentType(relative), data, cache, &.{});
    }

    fn call(self: *App, op: []const u8, state_filter: ?[]const u8, limit: ?u32) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.callOp(op, state_filter, limit);
    }

    fn controlError(self: *App, request: *std.http.Server.Request, err: anyerror) !void {
        return self.apiError(request, .service_unavailable, "control_unavailable", @errorName(err));
    }

    fn apiError(self: *App, request: *std.http.Server.Request, status: std.http.Status, code: []const u8, message: []const u8) !void {
        return self.respondJson(request, status, ErrorPayload{ .code = code, .message = message });
    }

    fn methodNotAllowed(self: *App, request: *std.http.Server.Request) !void {
        return self.apiError(request, .method_not_allowed, "method_not_allowed", "Method not allowed.");
    }

    fn respondJson(self: *App, request: *std.http.Server.Request, status: std.http.Status, payload: anytype) !void {
        return self.respondJsonWithHeaders(request, status, payload, &.{});
    }

    fn respondJsonWithHeaders(
        self: *App,
        request: *std.http.Server.Request,
        status: std.http.Status,
        payload: anytype,
        extra: []const std.http.Header,
    ) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try std.json.Stringify.value(payload, .{ .emit_null_optional_fields = false }, &out.writer);
        return self.respond(request, status, "application/json; charset=utf-8", out.written(), "no-store", extra);
    }

    fn respondText(self: *App, request: *std.http.Server.Request, status: std.http.Status, body: []const u8) !void {
        return self.respond(request, status, "text/plain; charset=utf-8", body, "no-store", &.{});
    }

    fn respond(
        self: *App,
        request: *std.http.Server.Request,
        status: std.http.Status,
        content_type: []const u8,
        body: []const u8,
        cache: []const u8,
        extra: []const std.http.Header,
    ) !void {
        _ = self;
        fixMissingBodyLength(request);
        var headers: [16]std.http.Header = undefined;
        var n: usize = 0;
        headers[n] = .{ .name = "content-type", .value = content_type };
        n += 1;
        headers[n] = .{ .name = "cache-control", .value = cache };
        n += 1;
        headers[n] = .{ .name = "x-content-type-options", .value = "nosniff" };
        n += 1;
        headers[n] = .{ .name = "x-frame-options", .value = "DENY" };
        n += 1;
        headers[n] = .{ .name = "referrer-policy", .value = "no-referrer" };
        n += 1;
        headers[n] = .{ .name = "content-security-policy", .value = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" };
        n += 1;
        headers[n] = .{ .name = "connection", .value = "close" };
        n += 1;
        for (extra) |header| {
            if (n == headers.len) return error.TooManyHeaders;
            headers[n] = header;
            n += 1;
        }
        try request.respond(body, .{ .status = status, .extra_headers = headers[0..n] });
    }

    fn sessionCsrf(self: *App, request: *std.http.Server.Request) ?[auth.token_hex_len]u8 {
        const token = getCookie(request, cookie_name) orelse return null;
        return self.sessions.csrfFor(self.io, token, std.Io.Clock.real.now(self.io).toMilliseconds());
    }

    fn hostAllowed(self: *App, request: *std.http.Server.Request) bool {
        var headers = request.iterateHeaders();
        while (headers.next()) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "host")) continue;
            if (std.mem.eql(u8, header.value, self.listen)) return true;
            var buf: [128]u8 = undefined;
            if (std.mem.eql(u8, header.value, std.fmt.bufPrint(&buf, "127.0.0.1:{d}", .{self.port}) catch return false)) return true;
            if (std.mem.eql(u8, header.value, std.fmt.bufPrint(&buf, "localhost:{d}", .{self.port}) catch return false)) return true;
            if (std.mem.eql(u8, header.value, std.fmt.bufPrint(&buf, "[::1]:{d}", .{self.port}) catch return false)) return true;
            return false;
        }
        return false;
    }

    fn sameOrigin(self: *App, request: *std.http.Server.Request) bool {
        _ = self;
        var origin: ?[]const u8 = null;
        var host: ?[]const u8 = null;
        var headers = request.iterateHeaders();
        while (headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "origin")) origin = header.value;
            if (std.ascii.eqlIgnoreCase(header.name, "host")) host = header.value;
        }
        const value = origin orelse return true;
        const host_value = host orelse return false;
        var expected: [256]u8 = undefined;
        const expected_origin = std.fmt.bufPrint(&expected, "http://{s}", .{host_value}) catch return false;
        return std.mem.eql(u8, value, expected_origin);
    }
};

fn fixMissingBodyLength(request: *std.http.Server.Request) void {
    if (request.head.method.requestHasBody() and
        request.head.transfer_encoding == .none and
        request.head.content_length == null)
    {
        request.head.content_length = 0;
    }
}

fn getCookie(request: *std.http.Server.Request, name: []const u8) ?[]const u8 {
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        var parts = std.mem.splitScalar(u8, header.value, ';');
        while (parts.next()) |part| {
            const item = std.mem.trim(u8, part, " \t");
            if (std.mem.startsWith(u8, item, name) and item.len > name.len and item[name.len] == '=') {
                return item[name.len + 1 ..];
            }
        }
    }
    return null;
}

fn assetPath(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html")) return "index.html";
    if (std.mem.eql(u8, path, "/favicon.svg") or std.mem.eql(u8, path, "/theme-init.js")) return path[1..];
    if (!std.mem.startsWith(u8, path, "/assets/")) return null;
    const relative = path[1..];
    if (std.mem.indexOf(u8, relative, "..") != null) return null;
    if (std.mem.indexOfScalar(u8, relative, '\\') != null) return null;
    return relative;
}

fn contentType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    if (std.mem.eql(u8, ext, ".html")) return "text/html; charset=utf-8";
    if (std.mem.eql(u8, ext, ".js")) return "text/javascript; charset=utf-8";
    if (std.mem.eql(u8, ext, ".css")) return "text/css; charset=utf-8";
    if (std.mem.eql(u8, ext, ".json")) return "application/json; charset=utf-8";
    if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
    if (std.mem.eql(u8, ext, ".png")) return "image/png";
    if (std.mem.eql(u8, ext, ".webp")) return "image/webp";
    if (std.mem.eql(u8, ext, ".woff2")) return "font/woff2";
    return "application/octet-stream";
}

test "asset paths reject traversal and accept hashed bundles" {
    try std.testing.expectEqualStrings("index.html", assetPath("/").?);
    try std.testing.expectEqualStrings("index.html", assetPath("/index.html").?);
    try std.testing.expectEqualStrings("assets/index-abc.js", assetPath("/assets/index-abc.js").?);
    try std.testing.expect(assetPath("/assets/../secret") == null);
    try std.testing.expect(assetPath("/overview") == null);
}

test "content types" {
    try std.testing.expectEqualStrings("text/html; charset=utf-8", contentType("index.html"));
    try std.testing.expectEqualStrings("text/javascript; charset=utf-8", contentType("assets/app.js"));
    try std.testing.expectEqualStrings("font/woff2", contentType("assets/font.woff2"));
}

test "loopback detection" {
    try std.testing.expect(isLoopback(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080")));
    try std.testing.expect(isLoopback(try std.Io.net.IpAddress.parseLiteral("[::1]:8080")));
    try std.testing.expect(!isLoopback(try std.Io.net.IpAddress.parseLiteral("192.0.2.1:8080")));
    try std.testing.expect(!isLoopback(try std.Io.net.IpAddress.parseLiteral("[2001:db8::1]:8080")));
}
