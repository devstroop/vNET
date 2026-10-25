//! Read-only web admin server. Pages are rendered in Zig and refreshed with
//! HTMX fragments; the process stays unprivileged and reads every value from
//! the existing Unix control socket.

const std = @import("std");
const vrouter = @import("vrouter");
const auth = @import("auth.zig");
const assets = @import("assets.zig");
const html = @import("html.zig");
const pages = @import("pages.zig");
const protocol = vrouter.control_protocol;

const cookie_name = "vrouter_session";
const max_body = 4096;
const max_password_len = 256;
const login_max_failures = 5;
const login_lock_ms = 30_000;
const conntrack_page_limit = 200;

pub const Options = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    listen: []const u8 = "127.0.0.1:8080",
    control_path: []const u8 = "/run/vrouter/control.sock",
    password_phc: []const u8,
    session_ttl_ms: i64 = auth.default_session_ttl_ms,
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
            return self.respondText(request, .bad_request, "Unexpected Host header.\n");
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

        if (std.mem.eql(u8, path, "/login")) {
            if (method == .POST) return self.serveLoginForm(request);
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveLoginPage(request);
        }
        if (std.mem.eql(u8, path, "/logout")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveLogoutForm(request);
        }
        if (std.mem.eql(u8, path, "/")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.redirect(request, "/overview");
        }
        if (std.mem.eql(u8, path, "/overview")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveOverviewPage(request);
        }
        if (std.mem.eql(u8, path, "/nat")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveNatPage(request);
        }
        if (std.mem.eql(u8, path, "/connections")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveConnectionsPage(request);
        }
        if (std.mem.eql(u8, path, "/system")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveSystemPage(request);
        }
        if (std.mem.eql(u8, path, "/partials/status")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveStatusFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/nat")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveNatFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/conntrack")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveConntrackFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/system")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveSystemFragment(request);
        }

        if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
        if (assets.find(path)) |asset| {
            return self.respond(request, .ok, asset.content_type, asset.data, asset.cache, &.{});
        }
        return self.notFoundHtml(request);
    }

    fn serveLoginPage(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) != null) return self.redirect(request, "/overview");
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try html.writeLoginPage(&out.writer, null);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveLoginForm(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.renderLoginError(request, .forbidden, "Cross-origin request rejected.");
        }

        const now = self.nowMs();
        if (now < self.login_locked_until_ms) {
            return self.renderLoginError(request, .too_many_requests, "Too many attempts. Try again shortly.");
        }

        const body = self.readRequestBody(request) catch |err| {
            return self.renderLoginError(request, bodyErrorStatus(err), bodyErrorMessage(err));
        };
        defer self.gpa.free(body);

        var password_buf: [max_password_len]u8 = undefined;
        const password = formValue(body, "password", &password_buf) orelse "";
        if (password.len == 0 or password.len > max_password_len or
            !auth.verifyPassword(self.io, self.gpa, self.password_phc, password))
        {
            self.recordLoginFailure(now);
            return self.renderLoginError(request, .unauthorized, "Invalid password.");
        }

        self.login_failures = 0;
        const created = try self.sessions.create(self.io, now, self.session_ttl_ms);
        var cookie_buf: [192]u8 = undefined;
        const cookie = try std.fmt.bufPrint(&cookie_buf, "{s}={s}; HttpOnly; SameSite=Strict; Path=/; Max-Age={d}", .{
            cookie_name,
            created.token,
            @divTrunc(self.session_ttl_ms, 1000),
        });
        return self.redirectWithHeaders(request, "/overview", &.{
            .{ .name = "set-cookie", .value = cookie },
        });
    }

    fn serveLogoutForm(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const token = getCookie(request, cookie_name) orelse return self.redirect(request, "/login");
        const expected = self.sessions.csrfFor(self.io, token, self.nowMs()) orelse
            return self.redirect(request, "/login");

        const body = self.readRequestBody(request) catch |err| {
            return self.respondHtml(request, bodyErrorStatus(err), "<h1>Invalid logout request.</h1>");
        };
        defer self.gpa.free(body);

        var csrf_buf: [auth.token_hex_len]u8 = undefined;
        const csrf = formValue(body, "csrf", &csrf_buf) orelse "";
        if (csrf.len != auth.token_hex_len) {
            return self.respondHtml(request, .forbidden, "<h1>Invalid CSRF token.</h1>");
        }
        var candidate: [auth.token_hex_len]u8 = undefined;
        @memcpy(&candidate, csrf);
        if (!std.crypto.timing_safe.eql([auth.token_hex_len]u8, expected, candidate)) {
            return self.respondHtml(request, .forbidden, "<h1>Invalid CSRF token.</h1>");
        }

        self.sessions.remove(self.io, token);
        return self.redirectWithHeaders(request, "/login", &.{
            .{ .name = "set-cookie", .value = cookie_name ++ "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" },
        });
    }

    fn serveOverviewPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        const now = self.nowMs();
        var response = self.call("status", null, null) catch |err| {
            return self.renderOverviewPage(request, csrf[0..], null, @errorName(err), now);
        };
        defer response.deinit();
        const status = response.value.status orelse
            return self.renderOverviewPage(request, csrf[0..], null, "Missing status", now);
        return self.renderOverviewPage(request, csrf[0..], status, null, now);
    }

    fn serveStatusFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        _ = csrf;
        const now = self.nowMs();
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.call("status", null, null) catch |err| {
            try pages.overviewFragment(&out.writer, null, @errorName(err), now);
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const status = response.value.status orelse {
            try pages.overviewFragment(&out.writer, null, "Missing status", now);
            return self.respondHtml(request, .ok, out.written());
        };
        try pages.overviewFragment(&out.writer, status, null, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveNatPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        const now = self.nowMs();
        var response = self.call("nat.list", null, null) catch |err| {
            return self.renderNatPage(request, csrf[0..], null, @errorName(err), now);
        };
        defer response.deinit();
        const nat = response.value.nat orelse
            return self.renderNatPage(request, csrf[0..], null, "Missing NAT snapshot", now);
        return self.renderNatPage(request, csrf[0..], nat, null, now);
    }

    fn serveNatFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        const now = self.nowMs();
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.call("nat.list", null, null) catch |err| {
            try pages.natFragment(&out.writer, null, @errorName(err), now);
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const nat = response.value.nat orelse {
            try pages.natFragment(&out.writer, null, "Missing NAT snapshot", now);
            return self.respondHtml(request, .ok, out.written());
        };
        try pages.natFragment(&out.writer, nat, null, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveConnectionsPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        const now = self.nowMs();
        var state_buf: [32]u8 = undefined;
        var query_buf: [256]u8 = undefined;
        const state_filter = queryValue(request.head.target, "state", &state_buf) orelse "all";
        const query = queryValue(request.head.target, "q", &query_buf) orelse "";

        var response = self.call("conntrack.list", protocolStateFilter(state_filter), conntrack_page_limit) catch |err| {
            return self.renderConnectionsPage(request, csrf[0..], null, state_filter, query, @errorName(err), now);
        };
        defer response.deinit();
        const conntrack = response.value.conntrack orelse
            return self.renderConnectionsPage(request, csrf[0..], null, state_filter, query, "Missing conntrack snapshot", now);
        return self.renderConnectionsPage(request, csrf[0..], conntrack, state_filter, query, null, now);
    }

    fn serveConntrackFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        const now = self.nowMs();
        var state_buf: [32]u8 = undefined;
        var query_buf: [256]u8 = undefined;
        const state_filter = queryValue(request.head.target, "state", &state_buf) orelse "all";
        const query = queryValue(request.head.target, "q", &query_buf) orelse "";

        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.call("conntrack.list", protocolStateFilter(state_filter), conntrack_page_limit) catch |err| {
            try pages.connectionsFragment(&out.writer, null, state_filter, query, @errorName(err), now);
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const conntrack = response.value.conntrack orelse {
            try pages.connectionsFragment(&out.writer, null, state_filter, query, "Missing conntrack snapshot", now);
            return self.respondHtml(request, .ok, out.written());
        };
        try pages.connectionsFragment(&out.writer, conntrack, state_filter, query, null, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveSystemPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        const now = self.nowMs();
        var response = self.call("status", null, null) catch |err| {
            return self.renderSystemPage(request, csrf[0..], null, @errorName(err), now);
        };
        defer response.deinit();
        const status = response.value.status orelse
            return self.renderSystemPage(request, csrf[0..], null, "Missing status", now);
        return self.renderSystemPage(request, csrf[0..], status, null, now);
    }

    fn serveSystemFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        const now = self.nowMs();
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.call("status", null, null) catch |err| {
            try pages.systemFragment(&out.writer, null, @errorName(err), now);
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const status = response.value.status orelse {
            try pages.systemFragment(&out.writer, null, "Missing status", now);
            return self.respondHtml(request, .ok, out.written());
        };
        try pages.systemFragment(&out.writer, status, null, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderOverviewPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, status: ?protocol.Status, err: ?[]const u8, now: i64) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.overviewPage(self.gpa, &out.writer, csrf, status, err, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderNatPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, nat: ?protocol.Nat, err: ?[]const u8, now: i64) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.natPage(self.gpa, &out.writer, csrf, nat, err, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderConnectionsPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, conntrack: ?protocol.Conntrack, state_filter: []const u8, query: []const u8, err: ?[]const u8, now: i64) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.connectionsPage(self.gpa, &out.writer, csrf, conntrack, state_filter, query, err, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderSystemPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, status: ?protocol.Status, err: ?[]const u8, now: i64) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.systemPage(self.gpa, &out.writer, csrf, status, err, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderLoginError(self: *App, request: *std.http.Server.Request, status: std.http.Status, message: []const u8) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try html.writeLoginPage(&out.writer, message);
        return self.respondHtml(request, status, out.written());
    }

    fn requireSession(self: *App, request: *std.http.Server.Request) !?[auth.token_hex_len]u8 {
        if (self.sessionCsrf(request)) |csrf| return csrf;
        try self.redirect(request, "/login");
        return null;
    }

    fn requireSessionFragment(self: *App, request: *std.http.Server.Request) !?[auth.token_hex_len]u8 {
        if (self.sessionCsrf(request)) |csrf| return csrf;
        try self.respondHtmlWithHeaders(request, .unauthorized, "Sign in required.", &.{
            .{ .name = "hx-redirect", .value = "/login" },
        });
        return null;
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

        const now = self.nowMs();
        if (now < self.login_locked_until_ms) {
            return self.apiError(request, .too_many_requests, "rate_limited", "Too many attempts. Try again shortly.");
        }

        const body = self.readRequestBody(request) catch |err| {
            return self.apiError(request, bodyErrorStatus(err), "bad_request", bodyErrorMessage(err));
        };
        defer self.gpa.free(body);

        var parsed = std.json.parseFromSlice(LoginRequest, self.gpa, body, .{ .allocate = .alloc_always }) catch
            return self.apiError(request, .bad_request, "invalid_json", "Expected a JSON login body.");
        defer parsed.deinit();

        const password = parsed.value.password;
        if (password.len == 0 or password.len > max_password_len or
            !auth.verifyPassword(self.io, self.gpa, self.password_phc, password))
        {
            self.recordLoginFailure(now);
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
        const expected = self.sessions.csrfFor(self.io, token, self.nowMs()) orelse
            return self.apiError(request, .unauthorized, "unauthenticated", "Session expired.");

        const body = self.readRequestBody(request) catch |err| {
            return self.apiError(request, bodyErrorStatus(err), "bad_request", bodyErrorMessage(err));
        };
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

    fn methodNotAllowedHtml(self: *App, request: *std.http.Server.Request) !void {
        return self.respondHtml(request, .method_not_allowed, "<h1>Method not allowed.</h1>");
    }

    fn notFoundHtml(self: *App, request: *std.http.Server.Request) !void {
        return self.respondHtml(request, .not_found, "<h1>Page not found.</h1><p><a href=\"/overview\">Return to the overview</a>.</p>");
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

    fn respondHtml(self: *App, request: *std.http.Server.Request, status: std.http.Status, body: []const u8) !void {
        return self.respondHtmlWithHeaders(request, status, body, &.{});
    }

    fn respondHtmlWithHeaders(
        self: *App,
        request: *std.http.Server.Request,
        status: std.http.Status,
        body: []const u8,
        extra: []const std.http.Header,
    ) !void {
        return self.respond(request, status, "text/html; charset=utf-8", body, "no-store", extra);
    }

    fn respondText(self: *App, request: *std.http.Server.Request, status: std.http.Status, body: []const u8) !void {
        return self.respond(request, status, "text/plain; charset=utf-8", body, "no-store", &.{});
    }

    fn redirect(self: *App, request: *std.http.Server.Request, location: []const u8) !void {
        return self.redirectWithHeaders(request, location, &.{});
    }

    fn redirectWithHeaders(self: *App, request: *std.http.Server.Request, location: []const u8, extra: []const std.http.Header) !void {
        var headers: [4]std.http.Header = undefined;
        var n: usize = 0;
        headers[n] = .{ .name = "location", .value = location };
        n += 1;
        for (extra) |header| {
            if (n == headers.len) return error.TooManyHeaders;
            headers[n] = header;
            n += 1;
        }
        return self.respond(request, .see_other, "text/plain; charset=utf-8", "", "no-store", headers[0..n]);
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

    fn readRequestBody(self: *App, request: *std.http.Server.Request) ![]u8 {
        var body_buf: [max_body]u8 = undefined;
        const body_reader = try request.readerExpectContinue(&body_buf);
        return body_reader.allocRemaining(self.gpa, .limited(max_body));
    }

    fn recordLoginFailure(self: *App, now: i64) void {
        self.login_failures += 1;
        if (self.login_failures >= login_max_failures) {
            self.login_failures = 0;
            self.login_locked_until_ms = now + login_lock_ms;
        }
    }

    fn nowMs(self: *App) i64 {
        return std.Io.Clock.real.now(self.io).toMilliseconds();
    }

    fn sessionCsrf(self: *App, request: *std.http.Server.Request) ?[auth.token_hex_len]u8 {
        const token = getCookie(request, cookie_name) orelse return null;
        return self.sessions.csrfFor(self.io, token, self.nowMs());
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
        var origin: ?[]const u8 = null;
        var host: ?[]const u8 = null;
        var headers = request.iterateHeaders();
        while (headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "origin")) origin = header.value;
            if (std.ascii.eqlIgnoreCase(header.name, "host")) host = header.value;
        }
        const value = origin orelse return true;
        // Some local browser contexts report Origin: null for a same-document
        // form post. Host is already pinned to loopback and session cookies are
        // SameSite=Strict, so treat that as a local request rather than breaking
        // the sign-in form.
        if (std.mem.eql(u8, value, "null")) return self.hostAllowed(request);
        const host_value = host orelse return false;
        var expected: [256]u8 = undefined;
        const expected_origin = std.fmt.bufPrint(&expected, "http://{s}", .{host_value}) catch return false;
        return std.mem.eql(u8, value, expected_origin);
    }
};

fn bodyErrorStatus(err: anyerror) std.http.Status {
    return if (err == error.StreamTooLong) .payload_too_large else .bad_request;
}

fn bodyErrorMessage(err: anyerror) []const u8 {
    return if (err == error.StreamTooLong) "Request body is too large." else "Unsupported request body.";
}

fn protocolStateFilter(state: []const u8) ?[]const u8 {
    if (state.len == 0 or std.mem.eql(u8, state, "all") or std.mem.eql(u8, state, "other")) return null;
    return state;
}

fn formValue(body: []const u8, name: []const u8, out: []u8) ?[]const u8 {
    var pairs = std.mem.splitScalar(u8, body, '&');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!std.mem.eql(u8, pair[0..eq], name)) continue;
        return decodeComponent(pair[eq + 1 ..], out);
    }
    return null;
}

fn queryValue(target: []const u8, name: []const u8, out: []u8) ?[]const u8 {
    const question = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var pairs = std.mem.splitScalar(u8, target[question + 1 ..], '&');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!std.mem.eql(u8, pair[0..eq], name)) continue;
        return decodeComponent(pair[eq + 1 ..], out);
    }
    return null;
}

fn decodeComponent(raw: []const u8, out: []u8) ?[]const u8 {
    if (raw.len > out.len) return null;
    @memcpy(out[0..raw.len], raw);
    for (out[0..raw.len]) |*byte| {
        if (byte.* == '+') byte.* = ' ';
    }
    return std.Uri.percentDecodeInPlace(out[0..raw.len]);
}

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

test "form and query decoding handles plus and percent escapes" {
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a b+c", formValue("x=1&note=a+b%2Bc", "note", &out).?);
    try std.testing.expectEqualStrings("established", queryValue("/partials/conntrack?state=established&q=10.0.0.1", "state", &out).?);
    try std.testing.expectEqualStrings("10.0.0.1", queryValue("/partials/conntrack?state=established&q=10.0.0.1", "q", &out).?);
    try std.testing.expect(formValue("x=1", "note", &out) == null);
}

test "protocol state filter passes only concrete states" {
    try std.testing.expect(protocolStateFilter("all") == null);
    try std.testing.expect(protocolStateFilter("other") == null);
    try std.testing.expectEqualStrings("established", protocolStateFilter("established").?);
}

test "loopback detection" {
    try std.testing.expect(isLoopback(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080")));
    try std.testing.expect(isLoopback(try std.Io.net.IpAddress.parseLiteral("[::1]:8080")));
    try std.testing.expect(!isLoopback(try std.Io.net.IpAddress.parseLiteral("192.0.2.1:8080")));
    try std.testing.expect(!isLoopback(try std.Io.net.IpAddress.parseLiteral("[2001:db8::1]:8080")));
}
