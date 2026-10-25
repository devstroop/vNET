//! Web admin server. Pages are rendered in Zig and refreshed with HTMX
//! fragments; the process stays unprivileged and performs every read and NAT
//! write through the existing Unix control socket.

const std = @import("std");
const vrouter = @import("vrouter");
const auth = @import("auth.zig");
const assets = @import("assets.zig");
const html = @import("html.zig");
const pages = @import("pages.zig");
const protocol = vrouter.control_protocol;

const cookie_name = "vrouter_session";
const max_body = 65536;
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
        if (std.mem.eql(u8, path, "/nat/rules")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveNatRules(request);
        }
        if (std.mem.eql(u8, path, "/nat/review")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveNatReview(request);
        }
        if (std.mem.eql(u8, path, "/nat/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveNatApply(request);
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
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();

        var response = self.call("nat.list", null, null) catch |err| {
            return self.renderNatPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const nat = response.value.nat orelse
            return self.renderNatPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing NAT snapshot" });
        const draft = natDraftFromRunning(allocator, nat) catch |err|
            return self.renderNatPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        const draft_json = natDraftJson(allocator, draft) catch |err|
            return self.renderNatPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        const view = buildNatView(allocator, csrf[0..], nat, draft, draft_json, null, null, null) catch |err|
            return self.renderNatPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderNatPageView(request, view);
    }

    fn serveNatFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();

        var response = self.call("nat.list", null, null) catch |err| {
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const nat = response.value.nat orelse
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing NAT snapshot" });
        const draft = natDraftFromRunning(allocator, nat) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        const draft_json = natDraftJson(allocator, draft) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        const view = buildNatView(allocator, csrf[0..], nat, draft, draft_json, null, null, null) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderNatFragmentView(request, view);
    }

    fn serveNatRules(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var action_buf: [64]u8 = undefined;
        const action = formValue(body, "action", &action_buf) orelse
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing NAT action." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var nat_response = self.fetchNat() catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer nat_response.deinit();
        const running = nat_response.value.nat;
        var input = readDraftInput(allocator, body) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(err));
        const draft_object = switch (input.value) {
            .object => |*object| object,
            else => return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(error.InvalidDraft)),
        };
        applyNatForm(allocator, draft_object, body, action) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, natFormError(err));
        const draft = natDraftFromValue(allocator, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildNatView(allocator, csrf[0..], running, draft, draft_json, null, null, null) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderNatFragmentView(request, view);
    }

    fn serveNatReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var nat_response = self.fetchNat() catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer nat_response.deinit();
        const running = nat_response.value.nat;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(err));
        const draft = natDraftFromValue(allocator, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));

        var config_response = self.configGet() catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        installDraftConfig(config_allocator, root, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, natFormError(err));
        const revision = config_response.value.revision orelse
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        const diff = diff_response.value.diff orelse "";
        if (diff.len == 0 or isNoopResult(diff_response.value.result)) {
            const review = pages.NatReview{ .message = "No changes to review." };
            const view = buildNatView(allocator, csrf[0..], running, draft, draft_json, null, null, review) catch |err|
                return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
            return self.renderNatFragmentView(request, view);
        }
        const review = pages.NatReview{
            .diff = diff,
            .affected = diff_response.value.affected orelse &.{},
            .restart_required = diff_response.value.restart_required orelse false,
        };
        const view = buildNatView(allocator, csrf[0..], running, draft, draft_json, null, null, review) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderNatFragmentView(request, view);
    }

    fn serveNatApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var nat_response = self.fetchNat() catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer nat_response.deinit();
        const running = nat_response.value.nat;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(err));
        const draft = natDraftFromValue(allocator, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, null, natFormError(err));
        const changes = natChangeCount(allocator, running, draft) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));

        var config_response = self.configGet() catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        installDraftConfig(config_allocator, root, input.value) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, natFormError(err));
        const revision = config_response.value.revision orelse
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        if (diff_response.value.restart_required orelse false) {
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "This change requires a daemon restart and cannot be applied from the web preview.");
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            const nat_apply = natApplyFromConfig(config_allocator, config_value.*) catch |err| {
                const message = std.fmt.allocPrint(allocator, "Config is unchanged, but the live NAT update could not be prepared: {s}", .{@errorName(err)}) catch "Config is unchanged, but the live NAT update could not be prepared.";
                return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, message);
            };
            var live_response = self.callNatApply(nat_apply) catch |err| {
                const message = std.fmt.allocPrint(allocator, "No config change was needed, but the live NAT update failed: {s}", .{@errorName(err)}) catch "No config change was needed, but the live NAT update failed.";
                return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, message);
            };
            defer live_response.deinit();
            if (!live_response.value.ok) {
                const detail = live_response.value.message orelse "unknown error";
                const message = std.fmt.allocPrint(allocator, "No config change was needed, but the live NAT update failed: {s}", .{detail}) catch "No config change was needed, but the live NAT update failed.";
                return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, message);
            }
            return self.renderNatApplied(request, csrf[0..], allocator, "NAT is already up to date.");
        }
        const confirm = diff_response.value.confirm orelse
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Daemon did not return a confirm token.");

        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", config_value.*, revision, confirm, &idempotency_key) catch |err|
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, apply_response.value.message orelse "Config apply failed.");
        }
        if (apply_response.value.restart_required orelse false) {
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, "Config was saved but requires a daemon restart before it is live.");
        }

        const nat_apply = natApplyFromConfig(config_allocator, config_value.*) catch |err| {
            const message = std.fmt.allocPrint(allocator, "Config was saved, but the live NAT update could not be prepared: {s}", .{@errorName(err)}) catch "Config was saved, but the live NAT update could not be prepared.";
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, message);
        };
        var live_response = self.callNatApply(nat_apply) catch |err| {
            const message = std.fmt.allocPrint(allocator, "Config was saved, but the live NAT update failed: {s}", .{@errorName(err)}) catch "Config was saved, but the live NAT update failed.";
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, message);
        };
        defer live_response.deinit();
        if (!live_response.value.ok) {
            const detail = live_response.value.message orelse "unknown error";
            const message = std.fmt.allocPrint(allocator, "Config was saved, but the live NAT update failed: {s}", .{detail}) catch "Config was saved, but the live NAT update failed.";
            return self.renderNatDraftError(request, csrf[0..], allocator, running, input.value, message);
        }

        var notice_buf: [160]u8 = undefined;
        const notice = std.fmt.bufPrint(&notice_buf, "{d} NAT change{s} applied.", .{ changes, if (changes == 1) "" else "s" }) catch "NAT changes applied.";
        return self.renderNatApplied(request, csrf[0..], allocator, notice);
    }

    fn renderNatApplied(self: *App, request: *std.http.Server.Request, csrf: []const u8, allocator: std.mem.Allocator, notice: []const u8) !void {
        var refreshed = self.call("nat.list", null, null) catch |err| {
            return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        };
        defer refreshed.deinit();
        const nat = refreshed.value.nat orelse {
            return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = "Missing NAT snapshot after apply" });
        };
        const draft = natDraftFromRunning(allocator, nat) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        const draft_json = natDraftJson(allocator, draft) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        const view = buildNatView(allocator, csrf, nat, draft, draft_json, notice, null, null) catch |err|
            return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        return self.renderNatFragmentView(request, view);
    }

    fn verifyFormCsrf(self: *App, request: *std.http.Server.Request, csrf: [auth.token_hex_len]u8, body: []const u8) !bool {
        var csrf_buf: [auth.token_hex_len]u8 = undefined;
        const supplied = formValue(body, "csrf", &csrf_buf) orelse "";
        if (supplied.len != auth.token_hex_len) {
            try self.respondHtml(request, .forbidden, "<h1>Invalid CSRF token.</h1>");
            return false;
        }
        var candidate: [auth.token_hex_len]u8 = undefined;
        @memcpy(&candidate, supplied);
        if (!std.crypto.timing_safe.eql([auth.token_hex_len]u8, csrf, candidate)) {
            try self.respondHtml(request, .forbidden, "<h1>Invalid CSRF token.</h1>");
            return false;
        }
        return true;
    }

    fn fetchNat(self: *App) !std.json.Parsed(protocol.Response) {
        return self.call("nat.list", null, null);
    }

    fn renderNatDraftError(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        running: ?protocol.Nat,
        value: ?std.json.Value,
        message: []const u8,
    ) !void {
        if (value) |draft_value| {
            const draft = natDraftFromValue(allocator, draft_value) catch
                return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
            const draft_json = jsonStringify(allocator, draft_value) catch "";
            const view = buildNatView(allocator, csrf, running, draft, draft_json, null, message, null) catch
                return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
            return self.renderNatFragmentView(request, view);
        }
        return self.renderNatFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
    }

    fn configGet(self: *App) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        var status = try client.call(.{ .version = protocol.version, .op = "status" });
        defer status.deinit();
        const instance = if (status.value.status) |status_value| status_value.instance else return error.MissingStatus;
        return client.call(.{ .version = protocol.version, .op = "config.get", .instance = instance });
    }

    fn configCall(
        self: *App,
        op: []const u8,
        config: std.json.Value,
        revision: []const u8,
        confirm: ?[]const u8,
        idempotency_key: ?[]const u8,
    ) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        var status = try client.call(.{ .version = protocol.version, .op = "status" });
        defer status.deinit();
        const instance = if (status.value.status) |status_value| status_value.instance else return error.MissingStatus;
        return client.call(.{
            .version = protocol.version,
            .op = op,
            .instance = instance,
            .revision = revision,
            .confirm = confirm,
            .idempotency_key = idempotency_key,
            .config = config,
        });
    }

    fn callNatApply(self: *App, nat: protocol.NatApply) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.call(.{ .op = "nat.apply", .nat = nat });
    }

    fn applyNatForm(
        allocator: std.mem.Allocator,
        nat: *std.json.ObjectMap,
        body: []const u8,
        action: []const u8,
    ) !void {
        if (std.mem.eql(u8, action, "add_masquerade")) {
            const rules = try ensureArrayField(allocator, nat, "masquerade");
            try rules.append(.{ .object = try masqueradeRuleFromForm(allocator, body) });
            return;
        }
        if (std.mem.eql(u8, action, "edit_masquerade")) {
            const rules = try ensureArrayField(allocator, nat, "masquerade");
            const index = try formIndex(body);
            if (index >= rules.items.len) return error.InvalidIndex;
            rules.items[index] = .{ .object = try masqueradeRuleFromForm(allocator, body) };
            return;
        }
        if (std.mem.eql(u8, action, "remove_masquerade")) {
            const rules = try ensureArrayField(allocator, nat, "masquerade");
            const index = try formIndex(body);
            if (index >= rules.items.len) return error.InvalidIndex;
            _ = rules.orderedRemove(index);
            return;
        }
        if (std.mem.eql(u8, action, "add_forward")) {
            const rules = try ensureArrayField(allocator, nat, "port_forward");
            try rules.append(.{ .object = try forwardRuleFromForm(allocator, body) });
            return;
        }
        if (std.mem.eql(u8, action, "edit_forward")) {
            const rules = try ensureArrayField(allocator, nat, "port_forward");
            const index = try formIndex(body);
            if (index >= rules.items.len) return error.InvalidIndex;
            rules.items[index] = .{ .object = try forwardRuleFromForm(allocator, body) };
            return;
        }
        if (std.mem.eql(u8, action, "remove_forward")) {
            const rules = try ensureArrayField(allocator, nat, "port_forward");
            const index = try formIndex(body);
            if (index >= rules.items.len) return error.InvalidIndex;
            _ = rules.orderedRemove(index);
            return;
        }
        return error.InvalidAction;
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

    fn renderNatPageView(self: *App, request: *std.http.Server.Request, view: pages.NatView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.natPage(self.gpa, &out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderNatFragmentView(self: *App, request: *std.http.Server.Request, view: pages.NatView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.natFragment(&out.writer, view);
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

const NatDraft = struct {
    masquerade: []const NatDraftMasquerade = &.{},
    port_forward: []const NatDraftForward = &.{},
};

const NatDraftMasquerade = struct {
    out: []const u8 = "",
};

const NatDraftForward = struct {
    proto: []const u8 = "",
    ext_port: u16 = 0,
    to: []const u8 = "",
    ingress: ?[]const u8 = null,
};

const DraftInput = struct {
    value: std.json.Value,
};

fn readDraftInput(allocator: std.mem.Allocator, body: []const u8) !DraftInput {
    const text = (try formValueAlloc(allocator, body, "draft")) orelse return error.MissingDraft;
    const value = std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{}) catch return error.InvalidDraft;
    return switch (value) {
        .object => .{ .value = value },
        else => error.InvalidDraft,
    };
}

fn formValueAlloc(allocator: std.mem.Allocator, body: []const u8, name: []const u8) !?[]u8 {
    var pairs = std.mem.splitScalar(u8, body, '&');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!std.mem.eql(u8, pair[0..eq], name)) continue;
        const raw = pair[eq + 1 ..];
        const out = try allocator.alloc(u8, raw.len);
        return decodeComponent(raw, out) orelse return error.InvalidField;
    }
    return null;
}

fn jsonStringify(allocator: std.mem.Allocator, value: std.json.Value) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(value, .{}, &out.writer);
    return try allocator.dupe(u8, out.written());
}

fn installDraftConfig(allocator: std.mem.Allocator, root: *std.json.ObjectMap, draft_value: std.json.Value) !void {
    switch (draft_value) {
        .object => {},
        else => return error.InvalidDraft,
    }
    try root.put(allocator, "nat", draft_value);
}

fn isNoopResult(result: ?[]const u8) bool {
    return if (result) |value| std.mem.eql(u8, value, "noop") else false;
}

fn buildNatView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    running: ?protocol.Nat,
    draft: ?NatDraft,
    draft_json: []const u8,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.NatReview,
) !pages.NatView {
    var view = pages.NatView{
        .csrf = csrf,
        .draft_json = draft_json,
        .notice = notice,
        .err = err,
        .review = review,
    };
    if (draft) |value| {
        const masquerade = try allocator.alloc(pages.NatMasqueradeRow, value.masquerade.len);
        for (value.masquerade, 0..) |rule, index| {
            masquerade[index] = .{
                .out = rule.out,
                .addr = findSnatAddr(running, rule.out),
            };
        }
        view.masquerade = masquerade;
        const port_forward = try allocator.alloc(pages.NatForwardRow, value.port_forward.len);
        for (value.port_forward, 0..) |rule, index| {
            port_forward[index] = .{
                .proto = rule.proto,
                .ext_port = rule.ext_port,
                .to = rule.to,
                .ingress = rule.ingress,
            };
        }
        view.port_forward = port_forward;
        view.pending = try natChangeCount(allocator, running, value);
    }
    return view;
}

fn findSnatAddr(running: ?protocol.Nat, out: []const u8) []const u8 {
    if (running) |nat| {
        for (nat.snat) |rule| {
            if (std.mem.eql(u8, rule.out, out)) return rule.addr;
        }
    }
    return "";
}

fn natDraftFromRunning(allocator: std.mem.Allocator, nat: protocol.Nat) !NatDraft {
    const masquerade = try allocator.alloc(NatDraftMasquerade, nat.snat.len);
    for (nat.snat, 0..) |rule, index| {
        masquerade[index] = .{ .out = rule.out };
    }
    const port_forward = try allocator.alloc(NatDraftForward, nat.port_forward.len);
    for (nat.port_forward, 0..) |rule, index| {
        port_forward[index] = .{
            .proto = rule.proto,
            .ext_port = rule.ext_port,
            .to = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ rule.to_addr, rule.to_port }),
            .ingress = rule.ingress,
        };
    }
    return .{ .masquerade = masquerade, .port_forward = port_forward };
}

fn natDraftFromValue(allocator: std.mem.Allocator, value: std.json.Value) !NatDraft {
    const root = switch (value) {
        .object => |object| object,
        else => return error.InvalidDraft,
    };

    var masquerade: []NatDraftMasquerade = &.{};
    if (root.get("masquerade")) |field| {
        const rules = switch (field) {
            .array => |array| array,
            else => return error.InvalidDraft,
        };
        masquerade = try allocator.alloc(NatDraftMasquerade, rules.items.len);
        for (rules.items, 0..) |rule_value, index| {
            const rule = switch (rule_value) {
                .object => |object| object,
                else => return error.InvalidDraft,
            };
            const out = switch (rule.get("out") orelse return error.InvalidDraft) {
                .string => |text| text,
                else => return error.InvalidDraft,
            };
            if (out.len == 0) return error.InvalidDraft;
            masquerade[index] = .{ .out = out };
        }
    }

    var port_forward: []NatDraftForward = &.{};
    if (root.get("port_forward")) |field| {
        const rules = switch (field) {
            .array => |array| array,
            else => return error.InvalidDraft,
        };
        port_forward = try allocator.alloc(NatDraftForward, rules.items.len);
        for (rules.items, 0..) |rule_value, index| {
            const rule = switch (rule_value) {
                .object => |object| object,
                else => return error.InvalidDraft,
            };
            const proto = switch (rule.get("proto") orelse return error.InvalidDraft) {
                .string => |text| text,
                else => return error.InvalidDraft,
            };
            const ext_port = switch (rule.get("ext_port") orelse return error.InvalidDraft) {
                .integer => |number| number,
                else => return error.InvalidDraft,
            };
            if (ext_port <= 0 or ext_port > 65535) return error.InvalidDraft;
            const to = switch (rule.get("to") orelse return error.InvalidDraft) {
                .string => |text| text,
                else => return error.InvalidDraft,
            };
            _ = splitHostPort(to) orelse return error.InvalidDraft;
            const ingress = if (rule.get("in")) |ingress_value| switch (ingress_value) {
                .string => |text| text,
                else => return error.InvalidDraft,
            } else null;
            port_forward[index] = .{
                .proto = proto,
                .ext_port = @intCast(ext_port),
                .to = to,
                .ingress = ingress,
            };
        }
    }

    return .{ .masquerade = masquerade, .port_forward = port_forward };
}

fn natDraftValue(allocator: std.mem.Allocator, draft: NatDraft) !std.json.Value {
    var root = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    var masquerade = std.json.Array.init(allocator);
    for (draft.masquerade) |source| {
        var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
        try rule.put(allocator, "out", .{ .string = source.out });
        try masquerade.append(.{ .object = rule });
    }
    try root.put(allocator, "masquerade", .{ .array = masquerade });

    var port_forward = std.json.Array.init(allocator);
    for (draft.port_forward) |source| {
        var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
        try rule.put(allocator, "proto", .{ .string = source.proto });
        try rule.put(allocator, "ext_port", .{ .integer = source.ext_port });
        try rule.put(allocator, "to", .{ .string = source.to });
        if (source.ingress) |ingress| {
            if (ingress.len > 0) try rule.put(allocator, "in", .{ .string = ingress });
        }
        try port_forward.append(.{ .object = rule });
    }
    try root.put(allocator, "port_forward", .{ .array = port_forward });

    return .{ .object = root };
}

fn natDraftJson(allocator: std.mem.Allocator, draft: NatDraft) ![]const u8 {
    return jsonStringify(allocator, try natDraftValue(allocator, draft));
}

fn natChangeCount(allocator: std.mem.Allocator, running: ?protocol.Nat, draft: NatDraft) !usize {
    const nat = running orelse return draft.masquerade.len + draft.port_forward.len;
    var changes: usize = 0;

    const masquerade_used = try allocator.alloc(bool, nat.snat.len);
    @memset(masquerade_used, false);
    for (draft.masquerade) |candidate| {
        var found = false;
        for (nat.snat, 0..) |current, index| {
            if (!masquerade_used[index] and std.mem.eql(u8, current.out, candidate.out)) {
                masquerade_used[index] = true;
                found = true;
                break;
            }
        }
        if (!found) changes += 1;
    }
    for (masquerade_used) |used| {
        if (!used) changes += 1;
    }

    const forward_used = try allocator.alloc(bool, nat.port_forward.len);
    @memset(forward_used, false);
    for (draft.port_forward) |candidate| {
        var found = false;
        for (nat.port_forward, 0..) |current, index| {
            if (!forward_used[index] and forwardMatches(candidate, current)) {
                forward_used[index] = true;
                found = true;
                break;
            }
        }
        if (!found) changes += 1;
    }
    for (forward_used) |used| {
        if (!used) changes += 1;
    }
    return changes;
}

fn forwardMatches(draft: NatDraftForward, running: protocol.PortForward) bool {
    const parsed = splitHostPort(draft.to) orelse return false;
    return std.mem.eql(u8, draft.proto, running.proto) and
        draft.ext_port == running.ext_port and
        std.mem.eql(u8, parsed.host, running.to_addr) and
        parsed.port == running.to_port and
        optionalStringEql(draft.ingress, running.ingress);
}

fn optionalStringEql(a: ?[]const u8, b: ?[]const u8) bool {
    return std.mem.eql(u8, a orelse "", b orelse "");
}

fn ensureArrayField(allocator: std.mem.Allocator, root: *std.json.ObjectMap, name: []const u8) !*std.json.Array {
    if (root.getPtr(name)) |value| {
        return switch (value.*) {
            .array => |*array| array,
            else => error.InvalidConfig,
        };
    }
    try root.put(allocator, name, .{ .array = std.json.Array.init(allocator) });
    return switch (root.getPtr(name).?.*) {
        .array => |*array| array,
        else => unreachable,
    };
}

fn masqueradeRuleFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var out_buf: [256]u8 = undefined;
    const out = formValue(body, "out", &out_buf) orelse return error.MissingField;
    if (out.len == 0) return error.MissingField;
    var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try rule.put(allocator, "out", .{ .string = try allocator.dupe(u8, out) });
    return rule;
}

fn forwardRuleFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var proto_buf: [16]u8 = undefined;
    var port_buf: [16]u8 = undefined;
    var to_buf: [256]u8 = undefined;
    var ingress_buf: [128]u8 = undefined;
    const proto = formValue(body, "proto", &proto_buf) orelse "tcp";
    const port_text = formValue(body, "ext_port", &port_buf) orelse return error.MissingField;
    const to = formValue(body, "to", &to_buf) orelse return error.MissingField;
    const ingress = formValue(body, "ingress", &ingress_buf) orelse "";
    const ext_port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidField;
    if (ext_port == 0 or to.len == 0) return error.InvalidField;
    _ = splitHostPort(to) orelse return error.InvalidField;
    var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try rule.put(allocator, "proto", .{ .string = try allocator.dupe(u8, proto) });
    try rule.put(allocator, "ext_port", .{ .integer = ext_port });
    try rule.put(allocator, "to", .{ .string = try allocator.dupe(u8, to) });
    if (ingress.len != 0) {
        try rule.put(allocator, "in", .{ .string = try allocator.dupe(u8, ingress) });
    }
    return rule;
}

fn formIndex(body: []const u8) !usize {
    var index_buf: [24]u8 = undefined;
    const text = formValue(body, "index", &index_buf) orelse return error.MissingField;
    return std.fmt.parseInt(usize, text, 10) catch error.InvalidField;
}

fn natFormError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingField => "A required field is missing.",
        error.InvalidField => "A field has an invalid value.",
        error.InvalidIndex => "That NAT rule no longer exists.",
        error.InvalidAction => "Unknown NAT action.",
        error.MissingDraft => "The draft is missing. Reload the page and try again.",
        error.InvalidDraft => "The draft is invalid. Reload the page and try again.",
        error.InvalidConfig => "The current NAT config has an unexpected shape.",
        else => @errorName(err),
    };
}

fn natApplyFromConfig(allocator: std.mem.Allocator, config: std.json.Value) !protocol.NatApply {
    const root = switch (config) {
        .object => |object| object,
        else => return error.InvalidConfig,
    };
    const instance = switch (root.get("instance") orelse return error.InvalidConfig) {
        .string => |value| value,
        else => return error.InvalidConfig,
    };
    const nat_value = root.get("nat") orelse return .{ .instance = instance };
    const nat = switch (nat_value) {
        .object => |object| object,
        else => return error.InvalidConfig,
    };

    var masquerade: []protocol.NatMasquerade = &.{};
    if (nat.get("masquerade")) |value| {
        const rules = switch (value) {
            .array => |array| array,
            else => return error.InvalidConfig,
        };
        masquerade = try allocator.alloc(protocol.NatMasquerade, rules.items.len);
        for (rules.items, 0..) |rule_value, index| {
            const rule = switch (rule_value) {
                .object => |object| object,
                else => return error.InvalidConfig,
            };
            const out = switch (rule.get("out") orelse return error.InvalidConfig) {
                .string => |value_string| value_string,
                else => return error.InvalidConfig,
            };
            masquerade[index] = .{ .out = out };
        }
    }

    var port_forward: []protocol.NatForward = &.{};
    if (nat.get("port_forward")) |value| {
        const rules = switch (value) {
            .array => |array| array,
            else => return error.InvalidConfig,
        };
        port_forward = try allocator.alloc(protocol.NatForward, rules.items.len);
        for (rules.items, 0..) |rule_value, index| {
            const rule = switch (rule_value) {
                .object => |object| object,
                else => return error.InvalidConfig,
            };
            const proto = switch (rule.get("proto") orelse return error.InvalidConfig) {
                .string => |value_string| value_string,
                else => return error.InvalidConfig,
            };
            const ext_port = switch (rule.get("ext_port") orelse return error.InvalidConfig) {
                .integer => |value_integer| value_integer,
                else => return error.InvalidConfig,
            };
            if (ext_port <= 0 or ext_port > 65535) return error.InvalidConfig;
            const to = switch (rule.get("to") orelse return error.InvalidConfig) {
                .string => |value_string| value_string,
                else => return error.InvalidConfig,
            };
            _ = splitHostPort(to) orelse return error.InvalidConfig;
            const ingress = if (rule.get("in")) |ingress_value| switch (ingress_value) {
                .string => |value_string| value_string,
                else => return error.InvalidConfig,
            } else null;
            port_forward[index] = .{
                .proto = proto,
                .ext_port = @intCast(ext_port),
                .to = to,
                .ingress = ingress,
            };
        }
    }
    return .{ .instance = instance, .masquerade = masquerade, .port_forward = port_forward };
}

fn splitHostPort(value: []const u8) ?struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return null;
    if (colon == 0 or colon + 1 >= value.len) return null;
    const port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch return null;
    if (port == 0) return null;
    return .{ .host = value[0..colon], .port = port };
}

test "NAT draft stages edits and counts pending changes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const running = protocol.Nat{
        .snat = &.{.{ .out = "wan0", .addr = "203.0.113.2" }},
        .port_forward = &.{.{
            .proto = "tcp",
            .ext_port = 8080,
            .to_addr = "10.0.0.10",
            .to_port = 80,
            .ingress = "wan0",
        }},
    };
    const draft = try natDraftFromRunning(allocator, running);
    var value = try natDraftValue(allocator, draft);
    const object = switch (value) {
        .object => |*map| map,
        else => return error.TestUnexpectedResult,
    };
    try App.applyNatForm(allocator, object, "action=add_masquerade&out=wan1", "add_masquerade");
    const staged = try natDraftFromValue(allocator, value);
    try std.testing.expectEqual(@as(usize, 2), staged.masquerade.len);
    try std.testing.expectEqual(@as(usize, 1), try natChangeCount(allocator, running, staged));
    const json = try jsonStringify(allocator, value);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"wan1\"") != null);
}

test "NAT draft rejects invalid rules" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        "{\"port_forward\":[{\"proto\":\"tcp\",\"ext_port\":0,\"to\":\"10.0.0.1:80\"}]}",
        .{},
    );
    try std.testing.expectError(error.InvalidDraft, natDraftFromValue(allocator, parsed.value));
}

test "NAT form mutates the config document" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        "{\"instance\":\"test\",\"nat\":{\"masquerade\":[{\"out\":\"wan0\"}],\"port_forward\":[]}}",
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |*object| object,
        else => return error.TestUnexpectedResult,
    };
    const arena = parsed.arena.allocator();
    const nat_object = switch (root.getPtr("nat").?.*) {
        .object => |*object| object,
        else => return error.TestUnexpectedResult,
    };

    try App.applyNatForm(arena, nat_object, "action=add_masquerade&out=wan1", "add_masquerade");
    try App.applyNatForm(arena, nat_object, "action=add_forward&proto=udp&ext_port=5353&to=10.0.0.2:53&ingress=lan", "add_forward");
    var nat = try natApplyFromConfig(arena, parsed.value);
    try std.testing.expectEqual(@as(usize, 2), nat.masquerade.len);
    try std.testing.expectEqualStrings("wan1", nat.masquerade[1].out);
    try std.testing.expectEqual(@as(usize, 1), nat.port_forward.len);
    try std.testing.expectEqualStrings("udp", nat.port_forward[0].proto);
    try std.testing.expectEqual(@as(u16, 5353), nat.port_forward[0].ext_port);
    try std.testing.expectEqualStrings("10.0.0.2:53", nat.port_forward[0].to);
    try std.testing.expectEqualStrings("lan", nat.port_forward[0].ingress.?);

    try App.applyNatForm(arena, nat_object, "action=edit_masquerade&index=1&out=wan9", "edit_masquerade");
    try App.applyNatForm(arena, nat_object, "action=edit_forward&index=0&proto=tcp&ext_port=8081&to=10.0.0.3:81&ingress=wan9", "edit_forward");
    nat = try natApplyFromConfig(arena, parsed.value);
    try std.testing.expectEqualStrings("wan9", nat.masquerade[1].out);
    try std.testing.expectEqualStrings("tcp", nat.port_forward[0].proto);
    try std.testing.expectEqual(@as(u16, 8081), nat.port_forward[0].ext_port);
    try std.testing.expectEqualStrings("10.0.0.3:81", nat.port_forward[0].to);

    try App.applyNatForm(arena, nat_object, "action=remove_forward&index=0", "remove_forward");
    nat = try natApplyFromConfig(arena, parsed.value);
    try std.testing.expectEqual(@as(usize, 0), nat.port_forward.len);
    try std.testing.expectError(error.InvalidIndex, App.applyNatForm(arena, nat_object, "action=remove_forward&index=4", "remove_forward"));
}

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

fn decodeComponent(raw: []const u8, out: []u8) ?[]u8 {
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
