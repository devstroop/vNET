//! Web admin server. Pages are rendered in Zig and refreshed with HTMX
//! fragments; the process stays unprivileged and performs every read and NAT
//! write through the existing Unix control socket.

const std = @import("std");
const vrouter = @import("vrouter");
const auth = @import("auth.zig");
const assets = @import("assets.zig");
const html = @import("html.zig");
const pages = @import("pages.zig");
const operations = @import("operations.zig");
const protocol = vrouter.control_protocol;

const cookie_name = "vrouter_session";
const max_body = 65536;
const max_password_len = 256;
const login_max_failures = 5;
const login_lock_ms = 30_000;
const conntrack_page_limit = 200;
const audit_page_limit = 200;
const journal_page_limit = 200;

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

const NetworkPayload = struct {
    ok: bool = true,
    network: protocol.Network,
};

const LeasesPayload = struct {
    ok: bool = true,
    leases: protocol.DhcpLeases,
};

const FirewallCountersPayload = struct {
    ok: bool = true,
    counters: protocol.FirewallCounters,
};

const LogsPayload = struct {
    ok: bool = true,
    logs: protocol.LogTail,
};

const ConfigPayload = struct {
    ok: bool = true,
    revision: ?[]const u8 = null,
    source_path: ?[]const u8 = null,
    writable: ?bool = null,
    config: ?std.json.Value = null,
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
    restart_token_buf: [64]u8 = undefined,
    restart_token_len: usize = 0,
    restart_supported: bool = false,
    restart_pending: bool = false,

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
        if (std.mem.eql(u8, path, "/api/network") or std.mem.eql(u8, path, "/api/interfaces")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveNetworkApi(request);
        }
        if (std.mem.eql(u8, path, "/api/leases") or std.mem.eql(u8, path, "/api/clients")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveLeasesApi(request);
        }
        if (std.mem.eql(u8, path, "/api/firewall/counters") or std.mem.eql(u8, path, "/api/firewall")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveFirewallCountersApi(request);
        }
        if (std.mem.eql(u8, path, "/api/logs")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveLogsApi(request);
        }
        if (std.mem.eql(u8, path, "/api/config")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveConfigApi(request);
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
        if (std.mem.eql(u8, path, "/interfaces/link")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveInterfacesLink(request);
        }
        if (std.mem.eql(u8, path, "/interfaces/rules")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveInterfacesRules(request);
        }
        if (std.mem.eql(u8, path, "/interfaces/review")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveInterfacesReview(request);
        }
        if (std.mem.eql(u8, path, "/interfaces/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveInterfacesApply(request);
        }
        if (std.mem.eql(u8, path, "/interfaces")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveInterfacesPage(request);
        }
        if (std.mem.eql(u8, path, "/clients/lease")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveClientsLease(request);
        }
        if (std.mem.eql(u8, path, "/clients")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveClientsPage(request);
        }
        if (std.mem.eql(u8, path, "/routes/rules")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveRoutesRules(request);
        }
        if (std.mem.eql(u8, path, "/routes/review")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveRoutesReview(request);
        }
        if (std.mem.eql(u8, path, "/routes/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveRoutesApply(request);
        }
        if (std.mem.eql(u8, path, "/routes")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveRoutesPage(request);
        }
        if (std.mem.eql(u8, path, "/firewall/rules")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveFirewallRules(request);
        }
        if (std.mem.eql(u8, path, "/firewall/review")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveFirewallReview(request);
        }
        if (std.mem.eql(u8, path, "/firewall/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveFirewallApply(request);
        }
        if (std.mem.eql(u8, path, "/firewall")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveFirewallPage(request);
        }
        if (std.mem.eql(u8, path, "/diagnostics")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveDiagnosticsPage(request);
        }
        if (std.mem.eql(u8, path, "/logs")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveLogsPage(request);
        }
        if (std.mem.eql(u8, path, "/config/logging")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveLoggingReview(request);
        }
        if (std.mem.eql(u8, path, "/config/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveLoggingApply(request);
        }
        if (std.mem.eql(u8, path, "/config")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveConfigPage(request);
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
        if (std.mem.eql(u8, path, "/dhcp/rules")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDhcpRules(request);
        }
        if (std.mem.eql(u8, path, "/dhcp/review")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDhcpReview(request);
        }
        if (std.mem.eql(u8, path, "/dhcp/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDhcpApply(request);
        }
        if (std.mem.eql(u8, path, "/dhcp")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveDhcpPage(request);
        }
        if (std.mem.eql(u8, path, "/dns/query")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDnsQuery(request);
        }
        if (std.mem.eql(u8, path, "/dns/rules")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDnsRules(request);
        }
        if (std.mem.eql(u8, path, "/dns/review")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDnsReview(request);
        }
        if (std.mem.eql(u8, path, "/dns/apply")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveDnsApply(request);
        }
        if (std.mem.eql(u8, path, "/dns")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveDnsPage(request);
        }
        if (std.mem.eql(u8, path, "/connections")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveConnectionsPage(request);
        }
        if (std.mem.eql(u8, path, "/audit")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveAuditPage(request);
        }
        if (std.mem.eql(u8, path, "/journal")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveJournalPage(request);
        }
        if (std.mem.eql(u8, path, "/system")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowedHtml(request);
            return self.serveSystemPage(request);
        }
        if (std.mem.eql(u8, path, "/restart")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveRestart(request);
        }
        if (std.mem.eql(u8, path, "/stop")) {
            if (method != .POST) return self.methodNotAllowedHtml(request);
            return self.serveStop(request);
        }
        if (std.mem.eql(u8, path, "/partials/interfaces")) {
            if (method != .GET and method != .POST) return self.methodNotAllowed(request);
            return self.serveInterfacesFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/clients")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveClientsFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/routes")) {
            if (method != .GET and method != .POST) return self.methodNotAllowed(request);
            return self.serveRoutesFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/firewall")) {
            if (method != .GET and method != .POST) return self.methodNotAllowed(request);
            return self.serveFirewallFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/diagnostics")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveDiagnosticsFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/logs")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveLogsFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/status")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveStatusFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/nat")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveNatFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/dhcp")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveDhcpFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/dns")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveDnsFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/conntrack")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveConntrackFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/system")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveSystemFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/audit")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveAuditFragment(request);
        }
        if (std.mem.eql(u8, path, "/partials/journal")) {
            if (method != .GET) return self.methodNotAllowed(request);
            return self.serveJournalFragment(request);
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

        self.clearRestartToken();
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
        var status = try v3Status(&client);
        defer status.deinit();
        const status_value = status.value.status orelse return error.MissingStatus;
        return client.call(.{
            .version = protocol.version,
            .op = "config.get",
            .instance = status_value.instance,
        });
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
        var status = try v3Status(&client);
        defer status.deinit();
        const status_value = status.value.status orelse return error.MissingStatus;
        return client.call(.{
            .version = protocol.version,
            .op = op,
            .instance = status_value.instance,
            .revision = revision,
            .confirm = confirm,
            .idempotency_key = idempotency_key,
            .config = config,
        });
    }

    fn v3Status(client: *vrouter.control_client.Client) !std.json.Parsed(protocol.Response) {
        var status = try client.call(.{ .version = protocol.version, .op = "status" });
        if (status.value.ok) {
            const status_value = status.value.status orelse {
                status.deinit();
                return error.MissingStatus;
            };
            const version = status_value.protocol_version orelse {
                status.deinit();
                return error.ProtocolVersionUnsupported;
            };
            if (version < protocol.version) {
                status.deinit();
                return error.ProtocolVersionUnsupported;
            }
            return status;
        }
        const code = status.value.error_code orelse "";
        const rejected_v3 = std.mem.eql(u8, code, "invalid_request") or
            std.mem.eql(u8, code, "version_unsupported");
        status.deinit();
        if (rejected_v3) {
            var legacy = try client.call(.{ .version = protocol.v2_version, .op = "status" });
            defer legacy.deinit();
            if (legacy.value.ok) return error.ProtocolVersionUnsupported;
        }
        return error.ControlStatusFailed;
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

    fn serveDhcpPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();

        var response = self.call("dhcp.list", null, null) catch |err| {
            return self.renderDhcpPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dhcp orelse
            return self.renderDhcpPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing DHCP snapshot" });
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderDhcpPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        var view = buildDhcpView(allocator, csrf[0..], running, running, draft_json, null, null, null) catch |err|
            return self.renderDhcpPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        self.decorateDhcpView(&view);
        return self.renderDhcpPageView(request, view);
    }

    fn serveDhcpFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();

        var response = self.call("dhcp.list", null, null) catch |err| {
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dhcp orelse
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing DHCP snapshot" });
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        var view = buildDhcpView(allocator, csrf[0..], running, running, draft_json, null, null, null) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        self.decorateDhcpView(&view);
        return self.renderDhcpFragmentView(request, view);
    }

    fn serveDhcpRules(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var action_buf: [64]u8 = undefined;
        const action = formValue(body, "action", &action_buf) orelse
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing DHCP action." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("dhcp.list", null, null) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.dhcp;
        var input = readDraftInput(allocator, body) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, null, dhcpFormError(err));
        const servers = switch (input.value) {
            .array => |*array| array,
            else => return self.renderDhcpDraftError(request, csrf[0..], allocator, running, null, dhcpFormError(error.InvalidDraft)),
        };
        applyDhcpForm(allocator, servers, body, action) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, dhcpFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildDhcpView(allocator, csrf[0..], running, input.value, draft_json, null, null, null) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderDhcpFragmentView(request, view);
    }

    fn serveDhcpReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("dhcp.list", null, null) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.dhcp;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, null, dhcpFormError(err));
        if (input.value != .array) return self.renderDhcpDraftError(request, csrf[0..], allocator, running, null, dhcpFormError(error.InvalidDraft));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const review = self.reviewConfigSection(allocator, "dhcp", input.value) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildDhcpView(allocator, csrf[0..], running, input.value, draft_json, null, null, review) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderDhcpFragmentView(request, view);
    }

    fn serveDhcpApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("dhcp.list", null, null) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.dhcp;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, null, dhcpFormError(err));
        if (input.value != .array) return self.renderDhcpDraftError(request, csrf[0..], allocator, running, null, dhcpFormError(error.InvalidDraft));
        var config_response = self.configGet() catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        root.put(config_allocator, "dhcp", input.value) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const revision = config_response.value.revision orelse
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            return self.renderDhcpApplied(request, csrf[0..], allocator, "DHCP is already up to date.");
        }
        const confirm = diff_response.value.confirm orelse
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, "Daemon did not return a confirm token.");
        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", config_value.*, revision, confirm, &idempotency_key) catch |err|
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            return self.renderDhcpDraftError(request, csrf[0..], allocator, running, input.value, apply_response.value.message orelse "Config apply failed.");
        }
        if (apply_response.value.restart_required orelse false) {
            self.rememberRestartResponse(&apply_response.value);
            const notice = if (apply_response.value.restart_token != null)
                "DHCP configuration saved. Restart vrouterd to activate it."
            else
                "DHCP configuration saved. Run systemctl restart vrouterd to activate it.";
            return self.renderDhcpApplied(request, csrf[0..], allocator, notice);
        }
        self.clearRestartToken();
        return self.renderDhcpApplied(request, csrf[0..], allocator, "DHCP configuration applied.");
    }

    fn reviewConfigSection(
        self: *App,
        allocator: std.mem.Allocator,
        section: []const u8,
        draft_value: std.json.Value,
    ) !pages.ConfigReview {
        var config_response = try self.configGet();
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return error.MissingConfig;
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return error.InvalidConfig,
        };
        const config_allocator = config_response.arena.allocator();
        try root.put(config_allocator, section, draft_value);
        const revision = config_response.value.revision orelse return error.MissingRevision;
        var diff_response = try self.configCall("config.diff", config_value.*, revision, null, null);
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            const message = diff_response.value.message orelse "Config diff failed.";
            return .{ .message = try allocator.dupe(u8, message) };
        }
        const diff = diff_response.value.diff orelse "";
        if (diff.len == 0 or isNoopResult(diff_response.value.result)) {
            return .{ .message = "No changes to review." };
        }
        const affected = diff_response.value.affected orelse &.{};
        const diff_copy = try allocator.dupe(u8, diff);
        const affected_copy = try allocator.alloc([]const u8, affected.len);
        for (affected, 0..) |item, index| {
            affected_copy[index] = try allocator.dupe(u8, item);
        }
        return .{
            .diff = diff_copy,
            .affected = affected_copy,
            .restart_required = diff_response.value.restart_required orelse false,
        };
    }

    fn decorateDhcpView(self: *App, view: *pages.DhcpView) void {
        view.restart_pending = self.restart_pending;
        view.restart_supported = self.restart_supported;
        view.restart_token = self.restartToken();
    }

    fn decorateDnsView(self: *App, view: *pages.DnsView) void {
        view.restart_pending = self.restart_pending;
        view.restart_supported = self.restart_supported;
        view.restart_token = self.restartToken();
    }

    fn renderDhcpApplied(self: *App, request: *std.http.Server.Request, csrf: []const u8, allocator: std.mem.Allocator, notice: []const u8) !void {
        var response = self.call("dhcp.list", null, null) catch |err| {
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dhcp orelse {
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = "Missing DHCP snapshot after save" });
        };
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        var view = buildDhcpView(allocator, csrf, running, running, draft_json, notice, null, null) catch |err|
            return self.renderDhcpFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        self.decorateDhcpView(&view);
        return self.renderDhcpFragmentView(request, view);
    }

    fn renderDhcpDraftError(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        running: ?std.json.Value,
        value: ?std.json.Value,
        message: []const u8,
    ) !void {
        if (value) |draft_value| {
            const draft_json = jsonStringify(allocator, draft_value) catch "";
            const view = buildDhcpView(allocator, csrf, running, draft_value, draft_json, null, message, null) catch
                return self.renderDhcpFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
            return self.renderDhcpFragmentView(request, view);
        }
        return self.renderDhcpFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
    }

    fn renderDhcpPageView(self: *App, request: *std.http.Server.Request, view: pages.DhcpView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.dhcpPage(self.gpa, &out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderDhcpFragmentView(self: *App, request: *std.http.Server.Request, view: pages.DhcpView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.dhcpFragment(&out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveDnsPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("dns.list", null, null) catch |err| {
            return self.renderDnsPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dns orelse
            return self.renderDnsPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing DNS snapshot" });
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderDnsPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        var view = buildDnsView(allocator, csrf[0..], running, running, draft_json, null, null, null) catch |err|
            return self.renderDnsPageView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        self.decorateDnsView(&view);
        return self.renderDnsPageView(request, view);
    }

    fn serveDnsFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("dns.list", null, null) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dns orelse
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing DNS snapshot" });
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        var view = buildDnsView(allocator, csrf[0..], running, running, draft_json, null, null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        self.decorateDnsView(&view);
        return self.renderDnsFragmentView(request, view);
    }

    fn serveDnsQuery(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var name_buf: [254]u8 = undefined;
        var type_buf: [16]u8 = undefined;
        const name = formValue(body, "name", &name_buf) orelse "";
        const qtype = formValue(body, "type", &type_buf) orelse "A";
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const draft_value = readOptionalDraft(allocator, body) catch |err|
            return self.renderDnsQueryResult(request, csrf[0..], name, qtype, null, null, dnsFormError(err));
        if (name.len == 0) {
            return self.renderDnsQueryResult(request, csrf[0..], name, qtype, draft_value, null, "Enter a name to query.");
        }
        if (!std.mem.eql(u8, qtype, "A") and !std.mem.eql(u8, qtype, "AAAA")) {
            return self.renderDnsQueryResult(request, csrf[0..], name, qtype, draft_value, null, "Only A and AAAA queries are supported.");
        }

        var response = self.callDnsQuery(name, qtype) catch |err| {
            return self.renderDnsQueryResult(request, csrf[0..], name, qtype, draft_value, null, @errorName(err));
        };
        defer response.deinit();
        if (!response.value.ok) {
            return self.renderDnsQueryResult(
                request,
                csrf[0..],
                name,
                qtype,
                draft_value,
                null,
                response.value.message orelse "DNS query failed.",
            );
        }
        const result = response.value.dns_query orelse
            return self.renderDnsQueryResult(request, csrf[0..], name, qtype, draft_value, null, "Daemon did not return a DNS answer.");
        return self.renderDnsQueryResult(request, csrf[0..], name, qtype, draft_value, result, null);
    }

    fn renderDnsQueryResult(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        name: []const u8,
        qtype: []const u8,
        draft_value: ?std.json.Value,
        result: ?protocol.DnsQueryResult,
        message: ?[]const u8,
    ) !void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("dns.list", null, null) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dns orelse
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = "Missing DNS snapshot" });
        const draft = draft_value orelse running;
        const draft_json = jsonStringify(allocator, draft) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        var view = buildDnsView(allocator, csrf, running, draft, draft_json, null, null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        view.query_name = name;
        view.query_type = qtype;
        view.query_result = result;
        view.query_error = message;
        self.decorateDnsView(&view);
        return self.renderDnsFragmentView(request, view);
    }

    fn callDnsQuery(self: *App, name: []const u8, qtype: []const u8) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.call(.{
            .version = protocol.version,
            .op = "dns.query",
            .dns_query = .{ .name = name, .qtype = qtype },
        });
    }

    fn serveDnsRules(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var action_buf: [64]u8 = undefined;
        const action = formValue(body, "action", &action_buf) orelse
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = "Missing DNS action." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("dns.list", null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.dns;
        var input = readDraftInput(allocator, body) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, null, dnsFormError(err));
        const draft_object = switch (input.value) {
            .object => |*object| object,
            else => return self.renderDnsDraftError(request, csrf[0..], allocator, running, null, dnsFormError(error.InvalidDraft)),
        };
        applyDnsForm(allocator, draft_object, body, action) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, dnsFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildDnsView(allocator, csrf[0..], running, input.value, draft_json, null, null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderDnsFragmentView(request, view);
    }

    fn serveDnsReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("dns.list", null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.dns;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, null, dnsFormError(err));
        if (input.value != .object) return self.renderDnsDraftError(request, csrf[0..], allocator, running, null, dnsFormError(error.InvalidDraft));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const review = self.reviewConfigSection(allocator, "dns", input.value) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildDnsView(allocator, csrf[0..], running, input.value, draft_json, null, null, review) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        return self.renderDnsFragmentView(request, view);
    }

    fn serveDnsApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("dns.list", null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf[0..], .draft_json = "", .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.dns;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, null, dnsFormError(err));
        if (input.value != .object) return self.renderDnsDraftError(request, csrf[0..], allocator, running, null, dnsFormError(error.InvalidDraft));

        var config_response = self.configGet() catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        root.put(config_allocator, "dns", input.value) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const revision = config_response.value.revision orelse
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            return self.renderDnsApplied(request, csrf[0..], allocator, "DNS is already up to date.");
        }
        const confirm = diff_response.value.confirm orelse
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, "Daemon did not return a confirm token.");
        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", config_value.*, revision, confirm, &idempotency_key) catch |err|
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            return self.renderDnsDraftError(request, csrf[0..], allocator, running, input.value, apply_response.value.message orelse "Config apply failed.");
        }
        if (apply_response.value.restart_required orelse false) {
            self.rememberRestartResponse(&apply_response.value);
            const notice = if (apply_response.value.restart_token != null)
                "DNS configuration saved. Restart vrouterd to activate it."
            else
                "DNS configuration saved. Run systemctl restart vrouterd to activate it.";
            return self.renderDnsApplied(request, csrf[0..], allocator, notice);
        }
        self.clearRestartToken();
        return self.renderDnsApplied(request, csrf[0..], allocator, "DNS configuration applied.");
    }

    fn renderDnsApplied(self: *App, request: *std.http.Server.Request, csrf: []const u8, allocator: std.mem.Allocator, notice: []const u8) !void {
        var response = self.call("dns.list", null, null) catch |err| {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.dns orelse {
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = "Missing DNS snapshot after save" });
        };
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        var view = buildDnsView(allocator, csrf, running, running, draft_json, notice, null, null) catch |err|
            return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = @errorName(err) });
        self.decorateDnsView(&view);
        return self.renderDnsFragmentView(request, view);
    }

    fn renderDnsDraftError(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        running: ?std.json.Value,
        value: ?std.json.Value,
        message: []const u8,
    ) !void {
        if (value) |draft_value| {
            const draft_json = jsonStringify(allocator, draft_value) catch "";
            const view = buildDnsView(allocator, csrf, running, draft_value, draft_json, null, message, null) catch
                return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
            return self.renderDnsFragmentView(request, view);
        }
        return self.renderDnsFragmentView(request, .{ .csrf = csrf, .draft_json = "", .err = message });
    }

    fn renderDnsPageView(self: *App, request: *std.http.Server.Request, view: pages.DnsView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.dnsPage(self.gpa, &out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderDnsFragmentView(self: *App, request: *std.http.Server.Request, view: pages.DnsView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.dnsFragment(&out.writer, view);
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

    fn serveAuditPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        const now = self.nowMs();
        var query_buf: [256]u8 = undefined;
        var result_buf: [32]u8 = undefined;
        const query = queryValue(request.head.target, "q", &query_buf) orelse "";
        const result_filter = queryValue(request.head.target, "result", &result_buf) orelse "all";

        var response = self.call("audit.list", null, audit_page_limit) catch |err| {
            return self.renderAuditPage(request, csrf[0..], null, query, result_filter, @errorName(err), now);
        };
        defer response.deinit();
        const audit = response.value.audit orelse
            return self.renderAuditPage(request, csrf[0..], null, query, result_filter, "Missing audit snapshot", now);
        return self.renderAuditPage(request, csrf[0..], audit, query, result_filter, null, now);
    }

    fn serveAuditFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        const now = self.nowMs();
        var query_buf: [256]u8 = undefined;
        var result_buf: [32]u8 = undefined;
        const query = queryValue(request.head.target, "q", &query_buf) orelse "";
        const result_filter = queryValue(request.head.target, "result", &result_buf) orelse "all";

        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.call("audit.list", null, audit_page_limit) catch |err| {
            try pages.auditFragment(&out.writer, null, query, result_filter, @errorName(err), now);
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const audit = response.value.audit orelse {
            try pages.auditFragment(&out.writer, null, query, result_filter, "Missing audit snapshot", now);
            return self.respondHtml(request, .ok, out.written());
        };
        try pages.auditFragment(&out.writer, audit, query, result_filter, null, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveJournalPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var query_buf: [256]u8 = undefined;
        var state_buf: [32]u8 = undefined;
        const query = queryValue(request.head.target, "q", &query_buf) orelse "";
        const state_filter = queryValue(request.head.target, "state", &state_buf) orelse "all";

        var response = self.call("journal.list", null, journal_page_limit) catch |err| {
            return self.renderJournalPage(request, csrf[0..], null, query, state_filter, @errorName(err));
        };
        defer response.deinit();
        const journal = response.value.journal orelse
            return self.renderJournalPage(request, csrf[0..], null, query, state_filter, "Missing journal snapshot");
        return self.renderJournalPage(request, csrf[0..], journal, query, state_filter, null);
    }

    fn serveJournalFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        var query_buf: [256]u8 = undefined;
        var state_buf: [32]u8 = undefined;
        const query = queryValue(request.head.target, "q", &query_buf) orelse "";
        const state_filter = queryValue(request.head.target, "state", &state_buf) orelse "all";

        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.call("journal.list", null, journal_page_limit) catch |err| {
            try pages.journalFragment(&out.writer, null, query, state_filter, @errorName(err));
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const journal = response.value.journal orelse {
            try pages.journalFragment(&out.writer, null, query, state_filter, "Missing journal snapshot");
            return self.respondHtml(request, .ok, out.written());
        };
        try pages.journalFragment(&out.writer, journal, query, state_filter, null);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveSystemPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        const now = self.nowMs();
        var response = self.callStatus() catch |err| {
            return self.renderSystemPage(request, csrf[0..], null, @errorName(err), now);
        };
        defer response.deinit();
        const status = response.value.status orelse
            return self.renderSystemPage(request, csrf[0..], null, "Missing status", now);
        if (status.restart_supported) |supported| self.restart_supported = supported;
        return self.renderSystemPage(request, csrf[0..], status, null, now);
    }

    fn serveSystemFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const now = self.nowMs();
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        var response = self.callStatus() catch |err| {
            try pages.systemFragment(&out.writer, null, @errorName(err), now, self.restartUi(csrf[0..]));
            return self.respondHtml(request, .ok, out.written());
        };
        defer response.deinit();
        const status = response.value.status orelse {
            try pages.systemFragment(&out.writer, null, "Missing status", now, self.restartUi(csrf[0..]));
            return self.respondHtml(request, .ok, out.written());
        };
        if (status.restart_supported) |supported| self.restart_supported = supported;
        try pages.systemFragment(&out.writer, status, null, now, self.restartUi(csrf[0..]));
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveInterfacesPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.ports, "ports.list", null);
        if (err == null) err = self.fetchInto(&fetch.bridges, "bridges.list", null);
        if (err == null) err = self.fetchInto(&fetch.interfaces, "interfaces.list", null);
        const network = if (fetch.network) |*parsed| parsed.value.network else null;
        if (network == null and err == null) err = "Missing live network state";
        const draft = interfaceDraft(allocator, if (fetch.ports) |*parsed| parsed.value.ports else null, if (fetch.bridges) |*parsed| parsed.value.bridges else null, if (fetch.interfaces) |*parsed| parsed.value.interfaces else null) catch |draft_err|
            return self.renderInterfacesPageView(request, .{ .csrf = csrf[0..], .network = network, .err = @errorName(draft_err) });
        const draft_json = jsonStringify(allocator, draft) catch |json_err|
            return self.renderInterfacesPageView(request, .{ .csrf = csrf[0..], .network = network, .err = @errorName(json_err) });
        var view = buildInterfacesView(allocator, csrf[0..], network, draft, draft_json, null, err, null) catch |view_err|
            return self.renderInterfacesPageView(request, .{ .csrf = csrf[0..], .network = network, .err = @errorName(view_err) });
        self.decorateInterfacesView(&view);
        return self.renderInterfacesPageView(request, view);
    }

    fn serveInterfacesFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.ports, "ports.list", null);
        if (err == null) err = self.fetchInto(&fetch.bridges, "bridges.list", null);
        if (err == null) err = self.fetchInto(&fetch.interfaces, "interfaces.list", null);
        const network = if (fetch.network) |*parsed| parsed.value.network else null;
        if (network == null and err == null) err = "Missing live network state";
        const draft = interfaceDraft(allocator, if (fetch.ports) |*parsed| parsed.value.ports else null, if (fetch.bridges) |*parsed| parsed.value.bridges else null, if (fetch.interfaces) |*parsed| parsed.value.interfaces else null) catch |draft_err|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .network = network, .err = @errorName(draft_err) });
        const draft_json = jsonStringify(allocator, draft) catch |json_err|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .network = network, .err = @errorName(json_err) });
        var view = buildInterfacesView(allocator, csrf[0..], network, draft, draft_json, null, err, null) catch |view_err|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .network = network, .err = @errorName(view_err) });
        self.decorateInterfacesView(&view);
        return self.renderInterfacesFragmentView(request, view);
    }

    fn serveInterfacesLink(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var dev_buf: [16]u8 = undefined;
        var confirm_buf: [16]u8 = undefined;
        var up_buf: [8]u8 = undefined;
        const dev = formValue(body, "dev", &dev_buf) orelse "";
        const confirm = formValue(body, "confirm", &confirm_buf) orelse "";
        const up_text = formValue(body, "up", &up_buf) orelse "";
        const up = if (std.mem.eql(u8, up_text, "true"))
            true
        else if (std.mem.eql(u8, up_text, "false"))
            false
        else
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = "Invalid link state." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const draft_text = formValueAlloc(allocator, body, "draft") catch |err|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        const draft_value: ?std.json.Value = if (draft_text) |text|
            if (text.len == 0) null else std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{}) catch
                return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = "Invalid staged draft." })
        else
            null;

        if (!std.mem.eql(u8, dev, confirm)) {
            return self.renderInterfacesResult(
                request,
                csrf[0..],
                allocator,
                draft_value,
                null,
                "Type the link name exactly to confirm.",
            );
        }

        var response = self.callLinkSet(dev, up, confirm) catch |err| {
            return self.renderInterfacesResult(request, csrf[0..], allocator, draft_value, null, @errorName(err));
        };
        defer response.deinit();
        if (!response.value.ok) {
            return self.renderInterfacesResult(
                request,
                csrf[0..],
                allocator,
                draft_value,
                null,
                response.value.message orelse "Link update failed.",
            );
        }
        const state = response.value.link orelse
            return self.renderInterfacesResult(request, csrf[0..], allocator, draft_value, null, "Daemon did not return a link state.");
        const notice = std.fmt.allocPrint(allocator, "{s} is already {s}.", .{
            state.dev,
            if (state.up) "up" else "down",
        }) catch "Link is already in the requested state.";
        const applied = std.fmt.allocPrint(allocator, "{s} is now {s}.", .{
            state.dev,
            if (state.up) "up" else "down",
        }) catch "Link state changed.";
        return self.renderInterfacesResult(
            request,
            csrf[0..],
            allocator,
            draft_value,
            if (std.mem.eql(u8, state.change, "noop")) notice else applied,
            null,
        );
    }

    fn callLinkSet(self: *App, dev: []const u8, up: bool, confirm: []const u8) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.call(.{
            .version = protocol.version,
            .op = "link.set",
            .confirm = confirm,
            .link = .{ .dev = dev, .up = up },
        });
    }

    fn serveInterfacesRules(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var action_buf: [64]u8 = undefined;
        const action = formValue(body, "action", &action_buf) orelse
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = "Missing interface action." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const running = interfaceDraft(
            allocator,
            self.listSection(allocator, "ports.list") catch null,
            self.listSection(allocator, "bridges.list") catch null,
            self.listSection(allocator, "interfaces.list") catch null,
        ) catch |err| return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        var input = readDraftInput(allocator, body) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, null, interfaceFormError(err));
        const draft_object = switch (input.value) {
            .object => |*object| object,
            else => return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, null, interfaceFormError(error.InvalidDraft)),
        };
        applyInterfacesForm(allocator, draft_object, body, action) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, interfaceFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildInterfacesView(allocator, csrf[0..], null, input.value, draft_json, null, null, null) catch |err|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        return self.renderInterfacesFragmentView(request, view);
    }

    fn serveInterfacesReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const running = interfaceDraft(
            allocator,
            self.listSection(allocator, "ports.list") catch null,
            self.listSection(allocator, "bridges.list") catch null,
            self.listSection(allocator, "interfaces.list") catch null,
        ) catch |err| return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, null, interfaceFormError(err));
        if (input.value != .object) return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, null, interfaceFormError(error.InvalidDraft));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const review = self.reviewInterfacesSection(allocator, input.value) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildInterfacesView(allocator, csrf[0..], null, input.value, draft_json, null, null, review) catch |err|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        return self.renderInterfacesFragmentView(request, view);
    }

    fn serveInterfacesApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const running = interfaceDraft(
            allocator,
            self.listSection(allocator, "ports.list") catch null,
            self.listSection(allocator, "bridges.list") catch null,
            self.listSection(allocator, "interfaces.list") catch null,
        ) catch |err| return self.renderInterfacesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, null, interfaceFormError(err));
        if (input.value != .object) return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, null, interfaceFormError(error.InvalidDraft));

        var config_response = self.configGet() catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        installInterfaceSections(config_allocator, root, input.value) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const revision = config_response.value.revision orelse
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            return self.renderInterfacesApplied(request, csrf[0..], allocator, "Interfaces are already up to date.");
        }
        const confirm = diff_response.value.confirm orelse
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, "Daemon did not return a confirm token.");
        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", config_value.*, revision, confirm, &idempotency_key) catch |err|
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            return self.renderInterfacesDraftError(request, csrf[0..], allocator, running, input.value, apply_response.value.message orelse "Config apply failed.");
        }
        if (apply_response.value.restart_required orelse false) {
            self.rememberRestartResponse(&apply_response.value);
            const notice = if (apply_response.value.restart_token != null)
                "Interface configuration saved. Restart vrouterd to activate it."
            else
                "Interface configuration saved. Run systemctl restart vrouterd to activate it.";
            return self.renderInterfacesApplied(request, csrf[0..], allocator, notice);
        }
        self.clearRestartToken();
        return self.renderInterfacesApplied(request, csrf[0..], allocator, "Interface configuration applied.");
    }

    fn listSection(self: *App, allocator: std.mem.Allocator, op: []const u8) !?std.json.Value {
        var response = try self.call(op, null, null);
        defer response.deinit();
        const section = if (std.mem.eql(u8, op, "ports.list"))
            response.value.ports
        else if (std.mem.eql(u8, op, "bridges.list"))
            response.value.bridges
        else if (std.mem.eql(u8, op, "interfaces.list"))
            response.value.interfaces
        else
            null;
        const value = section orelse return null;
        const text = try jsonStringify(allocator, value);
        return std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{}) catch return error.InvalidResponse;
    }

    fn reviewInterfacesSection(self: *App, allocator: std.mem.Allocator, draft_value: std.json.Value) !pages.ConfigReview {
        var config_response = try self.configGet();
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return error.MissingConfig;
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return error.InvalidConfig,
        };
        const config_allocator = config_response.arena.allocator();
        try installInterfaceSections(config_allocator, root, draft_value);
        const revision = config_response.value.revision orelse return error.MissingRevision;
        var diff_response = try self.configCall("config.diff", config_value.*, revision, null, null);
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            const message = diff_response.value.message orelse "Config diff failed.";
            return .{ .message = try allocator.dupe(u8, message) };
        }
        const diff = diff_response.value.diff orelse "";
        if (diff.len == 0 or isNoopResult(diff_response.value.result)) {
            return .{ .message = "No changes to review." };
        }
        const affected = diff_response.value.affected orelse &.{};
        const diff_copy = try allocator.dupe(u8, diff);
        const affected_copy = try allocator.alloc([]const u8, affected.len);
        for (affected, 0..) |item, index| {
            affected_copy[index] = try allocator.dupe(u8, item);
        }
        return .{
            .diff = diff_copy,
            .affected = affected_copy,
            .restart_required = diff_response.value.restart_required orelse false,
        };
    }

    fn decorateInterfacesView(self: *App, view: *operations.InterfacesView) void {
        view.restart_pending = self.restart_pending;
        view.restart_supported = self.restart_supported;
        view.restart_token = self.restartToken();
    }

    fn renderInterfacesApplied(self: *App, request: *std.http.Server.Request, csrf: []const u8, allocator: std.mem.Allocator, notice: []const u8) !void {
        return self.renderInterfacesResult(request, csrf, allocator, null, notice, null);
    }

    fn renderInterfacesResult(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        draft_override: ?std.json.Value,
        notice: ?[]const u8,
        err: ?[]const u8,
    ) !void {
        const running = interfaceDraft(
            allocator,
            self.listSection(allocator, "ports.list") catch null,
            self.listSection(allocator, "bridges.list") catch null,
            self.listSection(allocator, "interfaces.list") catch null,
        ) catch |err2| return self.renderInterfacesFragmentView(request, .{ .csrf = csrf, .err = @errorName(err2) });
        const draft = draft_override orelse running;
        const draft_json = jsonStringify(allocator, draft) catch |err2|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf, .err = @errorName(err2) });
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        _ = self.fetchInto(&fetch.network, "network.status", null);
        const network = if (fetch.network) |*parsed| parsed.value.network else null;
        var view = buildInterfacesView(allocator, csrf, network, draft, draft_json, notice, err, null) catch |err2|
            return self.renderInterfacesFragmentView(request, .{ .csrf = csrf, .network = network, .err = @errorName(err2) });
        self.decorateInterfacesView(&view);
        return self.renderInterfacesFragmentView(request, view);
    }

    fn renderInterfacesDraftError(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        running: ?std.json.Value,
        value: ?std.json.Value,
        message: []const u8,
    ) !void {
        _ = running;
        if (value) |draft_value| {
            var fetch: FetchSet = .{};
            defer fetch.deinit();
            _ = self.fetchInto(&fetch.network, "network.status", null);
            const network = if (fetch.network) |*parsed| parsed.value.network else null;
            const draft_json = jsonStringify(allocator, draft_value) catch "";
            const view = buildInterfacesView(allocator, csrf, network, draft_value, draft_json, null, message, null) catch
                return self.renderInterfacesFragmentView(request, .{ .csrf = csrf, .network = network, .err = message });
            return self.renderInterfacesFragmentView(request, view);
        }
        return self.renderInterfacesFragmentView(request, .{ .csrf = csrf, .err = message });
    }

    fn renderInterfacesPageView(self: *App, request: *std.http.Server.Request, view: operations.InterfacesView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.interfacesPage(self.gpa, &out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderInterfacesFragmentView(self: *App, request: *std.http.Server.Request, view: operations.InterfacesView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.interfacesFragment(&out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveClientsPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.leases, "dhcp.leases", 512);
        if (err == null) err = self.fetchInto(&fetch.dhcp, "dhcp.list", null);
        var data: operations.PageData = .{
            .network = if (fetch.network) |*parsed| parsed.value.network else null,
            .leases = if (fetch.leases) |*parsed| parsed.value.leases else null,
            .dhcp = if (fetch.dhcp) |*parsed| parsed.value.dhcp else null,
            .err = err,
            .csrf = csrf[0..],
            .now_ms = self.nowMs(),
        };
        if (data.leases == null and data.err == null) data.err = "Missing DHCP lease state";
        return self.renderClientsPage(request, csrf[0..], data);
    }

    fn serveClientsFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.leases, "dhcp.leases", 512);
        if (err == null) err = self.fetchInto(&fetch.dhcp, "dhcp.list", null);
        var data: operations.PageData = .{
            .network = if (fetch.network) |*parsed| parsed.value.network else null,
            .leases = if (fetch.leases) |*parsed| parsed.value.leases else null,
            .dhcp = if (fetch.dhcp) |*parsed| parsed.value.dhcp else null,
            .err = err,
            .csrf = csrf[0..],
            .now_ms = self.nowMs(),
        };
        if (data.leases == null and data.err == null) data.err = "Missing DHCP lease state";
        return self.renderClientsFragment(request, data);
    }

    fn serveClientsLease(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderClientsActionResult(request, csrf[0..], null, bodyErrorMessage(err));
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var iface_buf: [16]u8 = undefined;
        var ip_buf: [16]u8 = undefined;
        var confirm_buf: [16]u8 = undefined;
        const iface = formValue(body, "iface", &iface_buf) orelse "";
        const ip = formValue(body, "ip", &ip_buf) orelse "";
        const confirm = formValue(body, "confirm", &confirm_buf) orelse "";
        if (iface.len == 0 or ip.len == 0) {
            return self.renderClientsActionResult(request, csrf[0..], null, "Missing lease target.");
        }
        if (!std.mem.eql(u8, confirm, ip)) {
            return self.renderClientsActionResult(request, csrf[0..], null, "Type the lease address exactly to confirm.");
        }

        var response = self.callDhcpLeaseRevoke(iface, ip, confirm) catch |err| {
            return self.renderClientsActionResult(request, csrf[0..], null, @errorName(err));
        };
        defer response.deinit();
        if (!response.value.ok) {
            return self.renderClientsActionResult(
                request,
                csrf[0..],
                null,
                response.value.message orelse "Lease update failed.",
            );
        }

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const notice = std.fmt.allocPrint(arena.allocator(), "Lease {s} on {s} was forgotten.", .{ ip, iface }) catch
            "Lease was forgotten.";
        return self.renderClientsActionResult(request, csrf[0..], notice, null);
    }

    fn callDhcpLeaseRevoke(self: *App, iface: []const u8, ip: []const u8, confirm: []const u8) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.call(.{
            .version = protocol.version,
            .op = "dhcp.lease.revoke",
            .confirm = confirm,
            .dhcp_lease = .{ .iface = iface, .ip = ip },
        });
    }

    fn renderClientsActionResult(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        notice: ?[]const u8,
        action_err: ?[]const u8,
    ) !void {
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.leases, "dhcp.leases", 512);
        if (err == null) err = self.fetchInto(&fetch.dhcp, "dhcp.list", null);
        var data: operations.PageData = .{
            .network = if (fetch.network) |*parsed| parsed.value.network else null,
            .leases = if (fetch.leases) |*parsed| parsed.value.leases else null,
            .dhcp = if (fetch.dhcp) |*parsed| parsed.value.dhcp else null,
            .err = action_err orelse err,
            .notice = notice,
            .csrf = csrf,
            .now_ms = self.nowMs(),
        };
        if (data.leases == null and data.err == null) data.err = "Missing DHCP lease state";
        return self.renderClientsFragment(request, data);
    }

    fn serveRoutesPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("routes.list", null, null) catch |err| {
            return self.renderRoutesPageView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.routes orelse
            return self.renderRoutesPageView(request, .{ .csrf = csrf[0..], .err = "Missing routing table" });
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderRoutesPageView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        var view = buildRoutesView(allocator, csrf[0..], running, running, draft_json, null, null, null) catch |err|
            return self.renderRoutesPageView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        self.decorateRoutesView(&view);
        return self.renderRoutesPageView(request, view);
    }

    fn serveRoutesFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("routes.list", null, null) catch |err| {
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.routes orelse
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = "Missing routing table" });
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        var view = buildRoutesView(allocator, csrf[0..], running, running, draft_json, null, null, null) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        self.decorateRoutesView(&view);
        return self.renderRoutesFragmentView(request, view);
    }

    fn serveRoutesRules(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var action_buf: [64]u8 = undefined;
        const action = formValue(body, "action", &action_buf) orelse
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = "Missing route action." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("routes.list", null, null) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.routes;
        var input = readDraftInput(allocator, body) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, null, routeFormError(err));
        const draft_array = switch (input.value) {
            .array => |*array| array,
            else => return self.renderRoutesDraftError(request, csrf[0..], allocator, running, null, routeFormError(error.InvalidDraft)),
        };
        applyRoutesForm(allocator, draft_array, body, action) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, routeFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildRoutesView(allocator, csrf[0..], running, input.value, draft_json, null, null, null) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        return self.renderRoutesFragmentView(request, view);
    }

    fn serveRoutesReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("routes.list", null, null) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.routes;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, null, routeFormError(err));
        if (input.value != .array) return self.renderRoutesDraftError(request, csrf[0..], allocator, running, null, routeFormError(error.InvalidDraft));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const review = self.reviewConfigSection(allocator, "routes", input.value) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildRoutesView(allocator, csrf[0..], running, input.value, draft_json, null, null, review) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        return self.renderRoutesFragmentView(request, view);
    }

    fn serveRoutesApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("routes.list", null, null) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.routes;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, null, routeFormError(err));
        if (input.value != .array) return self.renderRoutesDraftError(request, csrf[0..], allocator, running, null, routeFormError(error.InvalidDraft));

        var config_response = self.configGet() catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        root.put(config_allocator, "routes", input.value) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        stripNulls(config_value);
        const revision = config_response.value.revision orelse
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            return self.renderRoutesApplied(request, csrf[0..], allocator, "Routes are already up to date.");
        }
        const confirm = diff_response.value.confirm orelse
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, "Daemon did not return a confirm token.");
        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", config_value.*, revision, confirm, &idempotency_key) catch |err|
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            return self.renderRoutesDraftError(request, csrf[0..], allocator, running, input.value, apply_response.value.message orelse "Config apply failed.");
        }
        if (apply_response.value.restart_required orelse false) {
            self.rememberRestartResponse(&apply_response.value);
            const notice = if (apply_response.value.restart_token != null)
                "Route configuration saved. Restart vrouterd to activate it."
            else
                "Route configuration saved. Run systemctl restart vrouterd to activate it.";
            return self.renderRoutesApplied(request, csrf[0..], allocator, notice);
        }
        self.clearRestartToken();
        return self.renderRoutesApplied(request, csrf[0..], allocator, "Route configuration applied.");
    }

    fn decorateRoutesView(self: *App, view: *operations.RoutesView) void {
        view.restart_pending = self.restart_pending;
        view.restart_supported = self.restart_supported;
        view.restart_token = self.restartToken();
    }

    fn renderRoutesApplied(self: *App, request: *std.http.Server.Request, csrf: []const u8, allocator: std.mem.Allocator, notice: []const u8) !void {
        var response = self.call("routes.list", null, null) catch |err| {
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf, .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.routes orelse {
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf, .err = "Missing routing table after save" });
        };
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf, .err = @errorName(err) });
        var view = buildRoutesView(allocator, csrf, running, running, draft_json, notice, null, null) catch |err|
            return self.renderRoutesFragmentView(request, .{ .csrf = csrf, .err = @errorName(err) });
        self.decorateRoutesView(&view);
        return self.renderRoutesFragmentView(request, view);
    }

    fn renderRoutesDraftError(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        running: ?std.json.Value,
        value: ?std.json.Value,
        message: []const u8,
    ) !void {
        if (value) |draft_value| {
            const draft_json = jsonStringify(allocator, draft_value) catch "";
            const view = buildRoutesView(allocator, csrf, running, draft_value, draft_json, null, message, null) catch
                return self.renderRoutesFragmentView(request, .{ .csrf = csrf, .err = message });
            return self.renderRoutesFragmentView(request, view);
        }
        return self.renderRoutesFragmentView(request, .{ .csrf = csrf, .err = message });
    }

    fn renderRoutesPageView(self: *App, request: *std.http.Server.Request, view: operations.RoutesView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.routesPage(self.gpa, &out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderRoutesFragmentView(self: *App, request: *std.http.Server.Request, view: operations.RoutesView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.routesFragment(&out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveFirewallPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("firewall.list", null, null) catch |err| {
            return self.renderFirewallPageView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.firewall orelse
            return self.renderFirewallPageView(request, .{ .csrf = csrf[0..], .err = "Missing firewall configuration" });
        var counters_response = self.call("firewall.counters", null, null) catch null;
        defer if (counters_response) |*parsed| parsed.deinit();
        const counters = if (counters_response) |*parsed| parsed.value.firewall_counters else null;
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderFirewallPageView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        var view = buildFirewallView(allocator, csrf[0..], running, running, draft_json, counters, null, null, null) catch |err|
            return self.renderFirewallPageView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        self.decorateFirewallView(&view);
        return self.renderFirewallPageView(request, view);
    }

    fn serveFirewallFragment(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.call("firewall.list", null, null) catch |err| {
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.firewall orelse
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = "Missing firewall configuration" });
        var counters_response = self.call("firewall.counters", null, null) catch null;
        defer if (counters_response) |*parsed| parsed.deinit();
        const counters = if (counters_response) |*parsed| parsed.value.firewall_counters else null;
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        var view = buildFirewallView(allocator, csrf[0..], running, running, draft_json, counters, null, null, null) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        self.decorateFirewallView(&view);
        return self.renderFirewallFragmentView(request, view);
    }

    fn serveFirewallRules(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var action_buf: [64]u8 = undefined;
        const action = formValue(body, "action", &action_buf) orelse
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = "Missing firewall action." });

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("firewall.list", null, null) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.firewall;
        var input = readDraftInput(allocator, body) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, null, firewallFormError(err));
        const draft_object = switch (input.value) {
            .object => |*object| object,
            else => return self.renderFirewallDraftError(request, csrf[0..], allocator, running, null, firewallFormError(error.InvalidDraft)),
        };
        applyFirewallForm(allocator, draft_object, body, action) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, firewallFormError(err));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildFirewallView(allocator, csrf[0..], running, input.value, draft_json, null, null, null, null) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        return self.renderFirewallFragmentView(request, view);
    }

    fn serveFirewallReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("firewall.list", null, null) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.firewall;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, null, firewallFormError(err));
        if (input.value != .object) return self.renderFirewallDraftError(request, csrf[0..], allocator, running, null, firewallFormError(error.InvalidDraft));
        const draft_json = jsonStringify(allocator, input.value) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const review = self.reviewConfigSection(allocator, "firewall", input.value) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        const view = buildFirewallView(allocator, csrf[0..], running, input.value, draft_json, null, null, null, review) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        return self.renderFirewallFragmentView(request, view);
    }

    fn serveFirewallApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = bodyErrorMessage(err) });
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var running_response = self.call("firewall.list", null, null) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf[0..], .err = @errorName(err) });
        defer running_response.deinit();
        const running = running_response.value.firewall;
        const input = readDraftInput(allocator, body) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, null, firewallFormError(err));
        if (input.value != .object) return self.renderFirewallDraftError(request, csrf[0..], allocator, running, null, firewallFormError(error.InvalidDraft));

        var config_response = self.configGet() catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer config_response.deinit();
        const config_value = if (config_response.value.config) |*value| value else return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, "Missing config from daemon.");
        const root = switch (config_value.*) {
            .object => |*object| object,
            else => return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, "Config is not an object."),
        };
        const config_allocator = config_response.arena.allocator();
        root.put(config_allocator, "firewall", input.value) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        stripNulls(config_value);
        const revision = config_response.value.revision orelse
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, "Missing config revision.");
        var diff_response = self.configCall("config.diff", config_value.*, revision, null, null) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, diff_response.value.message orelse "Config diff failed.");
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            return self.renderFirewallApplied(request, csrf[0..], allocator, "Firewall is already up to date.");
        }
        const confirm = diff_response.value.confirm orelse
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, "Daemon did not return a confirm token.");
        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", config_value.*, revision, confirm, &idempotency_key) catch |err|
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, @errorName(err));
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            return self.renderFirewallDraftError(request, csrf[0..], allocator, running, input.value, apply_response.value.message orelse "Config apply failed.");
        }
        if (apply_response.value.restart_required orelse false) {
            self.rememberRestartResponse(&apply_response.value);
            const notice = if (apply_response.value.restart_token != null)
                "Firewall configuration saved. Restart vrouterd to activate it."
            else
                "Firewall configuration saved. Run systemctl restart vrouterd to activate it.";
            return self.renderFirewallApplied(request, csrf[0..], allocator, notice);
        }
        self.clearRestartToken();
        return self.renderFirewallApplied(request, csrf[0..], allocator, "Firewall configuration applied.");
    }

    fn decorateFirewallView(self: *App, view: *operations.FirewallView) void {
        view.restart_pending = self.restart_pending;
        view.restart_supported = self.restart_supported;
        view.restart_token = self.restartToken();
    }

    fn renderFirewallApplied(self: *App, request: *std.http.Server.Request, csrf: []const u8, allocator: std.mem.Allocator, notice: []const u8) !void {
        var response = self.call("firewall.list", null, null) catch |err| {
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf, .err = @errorName(err) });
        };
        defer response.deinit();
        const running = response.value.firewall orelse {
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf, .err = "Missing firewall configuration after save" });
        };
        const draft_json = jsonStringify(allocator, running) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf, .err = @errorName(err) });
        var view = buildFirewallView(allocator, csrf, running, running, draft_json, null, notice, null, null) catch |err|
            return self.renderFirewallFragmentView(request, .{ .csrf = csrf, .err = @errorName(err) });
        self.decorateFirewallView(&view);
        return self.renderFirewallFragmentView(request, view);
    }

    fn renderFirewallDraftError(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        allocator: std.mem.Allocator,
        running: ?std.json.Value,
        value: ?std.json.Value,
        message: []const u8,
    ) !void {
        if (value) |draft_value| {
            const draft_json = jsonStringify(allocator, draft_value) catch "";
            const view = buildFirewallView(allocator, csrf, running, draft_value, draft_json, null, null, message, null) catch
                return self.renderFirewallFragmentView(request, .{ .csrf = csrf, .err = message });
            return self.renderFirewallFragmentView(request, view);
        }
        return self.renderFirewallFragmentView(request, .{ .csrf = csrf, .err = message });
    }

    fn renderFirewallPageView(self: *App, request: *std.http.Server.Request, view: operations.FirewallView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.firewallPage(self.gpa, &out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderFirewallFragmentView(self: *App, request: *std.http.Server.Request, view: operations.FirewallView) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.firewallFragment(&out.writer, view);
        return self.respondHtml(request, .ok, out.written());
    }

    fn serveDiagnosticsPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.status, "status", null);
        const data: operations.PageData = .{
            .network = if (fetch.network) |*parsed| parsed.value.network else null,
            .status = if (fetch.status) |*parsed| parsed.value.status else null,
            .err = err,
            .now_ms = self.nowMs(),
        };
        return self.renderDiagnosticsPage(request, csrf[0..], data);
    }

    fn serveDiagnosticsFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        var err: ?[]const u8 = self.fetchInto(&fetch.network, "network.status", null);
        if (err == null) err = self.fetchInto(&fetch.status, "status", null);
        const data: operations.PageData = .{
            .network = if (fetch.network) |*parsed| parsed.value.network else null,
            .status = if (fetch.status) |*parsed| parsed.value.status else null,
            .err = err,
            .now_ms = self.nowMs(),
        };
        return self.renderDiagnosticsFragment(request, data);
    }

    fn serveLogsPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        const err = self.fetchInto(&fetch.logs, "logs.tail", null);
        const data: operations.PageData = .{
            .logs = if (fetch.logs) |*parsed| parsed.value.logs else null,
            .err = err,
        };
        return self.renderLogsPage(request, csrf[0..], data);
    }

    fn serveLogsFragment(self: *App, request: *std.http.Server.Request) !void {
        if ((try self.requireSessionFragment(request)) == null) return;
        var fetch: FetchSet = .{};
        defer fetch.deinit();
        const err = self.fetchInto(&fetch.logs, "logs.tail", null);
        const data: operations.PageData = .{
            .logs = if (fetch.logs) |*parsed| parsed.value.logs else null,
            .err = err,
        };
        return self.renderLogsFragment(request, data);
    }

    fn serveConfigPage(self: *App, request: *std.http.Server.Request) !void {
        const csrf = (try self.requireSession(request)) orelse return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        var response = self.configGet() catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], null, null, null, null, null, null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, @errorName(err), logging);
        };
        defer response.deinit();
        const config_err: ?[]const u8 = if (response.value.ok) null else (response.value.error_code orelse "config.get failed");
        const logging = buildLoggingView(allocator, csrf[0..], response.value.config, response.value.revision, null, null, null, null, config_err, null) catch null;
        return self.renderConfigPage(
            request,
            csrf[0..],
            response.value.config,
            response.value.revision,
            response.value.source_path,
            response.value.writable,
            config_err,
            logging,
        );
    }

    fn serveLoggingReview(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSession(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, bodyErrorMessage(err), null);
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const draft = loggingDraftFromBody(allocator, body) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], null, null, null, null, "", null, loggingDraftError(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, loggingDraftError(err), logging);
        };
        var response = self.configGet() catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], null, null, null, null, null, null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, @errorName(err), logging);
        };
        defer response.deinit();
        const config_err: ?[]const u8 = if (response.value.ok) null else (response.value.error_code orelse "config.get failed");
        const config_value = if (response.value.config) |*value| value else {
            const logging = buildLoggingView(allocator, csrf[0..], null, null, draft.level, draft.format, loggingDraftJson(allocator, draft.level, draft.format, draft.revision) catch "", null, config_err orelse "Missing config.", null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, config_err orelse "Missing config.", logging);
        };
        const current_revision = response.value.revision orelse "";
        if (draft.revision.len != 0 and !std.mem.eql(u8, draft.revision, current_revision)) {
            const message = "Configuration changed since the page loaded. Reload and review again.";
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, current_revision, draft.level, draft.format, loggingDraftJson(allocator, draft.level, draft.format, current_revision) catch "", null, message, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, current_revision, response.value.source_path, response.value.writable, null, logging);
        }
        var draft_value = cloneJsonValue(allocator, config_value.*) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, current_revision, draft.level, draft.format, loggingDraftJson(allocator, draft.level, draft.format, current_revision) catch "", null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, current_revision, response.value.source_path, response.value.writable, null, logging);
        };
        installLog(allocator, &draft_value, draft.level, draft.format) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, current_revision, draft.level, draft.format, loggingDraftJson(allocator, draft.level, draft.format, current_revision) catch "", null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, current_revision, response.value.source_path, response.value.writable, null, logging);
        };
        const review = self.reviewConfigValue(allocator, draft_value, current_revision) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, current_revision, draft.level, draft.format, loggingDraftJson(allocator, draft.level, draft.format, current_revision) catch "", null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, current_revision, response.value.source_path, response.value.writable, null, logging);
        };
        const draft_json = loggingDraftJson(allocator, draft.level, draft.format, current_revision) catch "";
        const logging = buildLoggingView(allocator, csrf[0..], config_value.*, current_revision, draft.level, draft.format, draft_json, null, null, review) catch null;
        return self.renderConfigPage(request, csrf[0..], response.value.config, current_revision, response.value.source_path, response.value.writable, null, logging);
    }

    fn serveLoggingApply(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSession(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, bodyErrorMessage(err), null);
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const allocator = arena.allocator();
        const draft = loggingDraftFromBody(allocator, body) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], null, null, null, null, "", null, loggingDraftError(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, loggingDraftError(err), logging);
        };
        var response = self.configGet() catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], null, null, draft.level, draft.format, "", null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, @errorName(err), logging);
        };
        defer response.deinit();
        const config_value = if (response.value.config) |*value| value else {
            const message = "Missing config from daemon.";
            const logging = buildLoggingView(allocator, csrf[0..], null, null, draft.level, draft.format, "", null, message, null) catch null;
            return self.renderConfigPage(request, csrf[0..], null, null, null, null, message, logging);
        };
        const revision = response.value.revision orelse {
            const message = "Missing config revision.";
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, null, draft.level, draft.format, "", null, message, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, null, response.value.source_path, response.value.writable, null, logging);
        };
        if (draft.revision.len != 0 and !std.mem.eql(u8, draft.revision, revision)) {
            const message = "Configuration changed since review. Reload and review again.";
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, "", null, message, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        }
        var draft_value = cloneJsonValue(allocator, config_value.*) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, "", null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        };
        installLog(allocator, &draft_value, draft.level, draft.format) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, "", null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        };
        const draft_json = loggingDraftJson(allocator, draft.level, draft.format, revision) catch "";
        var diff_response = self.configCall("config.diff", draft_value, revision, null, null) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, draft_json, null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        };
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            const message = diff_response.value.message orelse "Config diff failed.";
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, draft_json, null, message, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        }
        const no_affected = if (diff_response.value.affected) |affected| affected.len == 0 else true;
        if (isNoopResult(diff_response.value.result) or no_affected) {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, draft_json, "Logging is already up to date.", null, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        }
        const confirm = diff_response.value.confirm orelse {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, draft_json, "Daemon did not return a confirm token.", null, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        };
        var raw_key: [32]u8 = undefined;
        try self.io.randomSecure(&raw_key);
        const idempotency_key = std.fmt.bytesToHex(raw_key, .lower);
        var apply_response = self.configCall("config.apply", draft_value, revision, confirm, &idempotency_key) catch |err| {
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, draft_json, null, @errorName(err), null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        };
        defer apply_response.deinit();
        if (!apply_response.value.ok) {
            const message = apply_response.value.message orelse "Config apply failed.";
            const logging = buildLoggingView(allocator, csrf[0..], config_value.*, revision, draft.level, draft.format, draft_json, null, message, null) catch null;
            return self.renderConfigPage(request, csrf[0..], response.value.config, revision, response.value.source_path, response.value.writable, null, logging);
        }
        var refreshed = self.configGet() catch null;
        defer if (refreshed) |*item| item.deinit();
        var final_config: ?std.json.Value = response.value.config;
        var final_revision: []const u8 = revision;
        if (refreshed) |*item| {
            if (item.value.config) |value| final_config = value;
            if (item.value.revision) |value| final_revision = value;
        }
        var notice: []const u8 = "Logging configuration applied.";
        var restart_pending = false;
        var restart_supported = self.restart_supported;
        var restart_token: []const u8 = "";
        if (apply_response.value.restart_required orelse false) {
            self.rememberRestartResponse(&apply_response.value);
            restart_pending = true;
            restart_supported = self.restart_supported;
            restart_token = self.restartToken() orelse "";
            notice = if (apply_response.value.restart_token != null)
                "Logging configuration saved. Restart vrouterd to activate it."
            else
                "Logging configuration saved. Run systemctl restart vrouterd to activate it.";
        } else {
            self.clearRestartToken();
        }
        const logging = buildLoggingView(allocator, csrf[0..], final_config, final_revision, draft.level, draft.format, draft_json, notice, null, null) catch null;
        if (logging) |view| {
            var decorated = view;
            decorated.restart_pending = restart_pending;
            decorated.restart_supported = restart_supported;
            decorated.restart_token = restart_token;
            return self.renderConfigPage(request, csrf[0..], final_config, final_revision, response.value.source_path, response.value.writable, null, decorated);
        }
        return self.renderConfigPage(request, csrf[0..], final_config, final_revision, response.value.source_path, response.value.writable, null, null);
    }

    fn reviewConfigValue(self: *App, allocator: std.mem.Allocator, draft_value: std.json.Value, revision: []const u8) !pages.ConfigReview {
        var diff_response = try self.configCall("config.diff", draft_value, revision, null, null);
        defer diff_response.deinit();
        if (!diff_response.value.ok) {
            const message = diff_response.value.message orelse "Config diff failed.";
            return .{ .message = try allocator.dupe(u8, message) };
        }
        const diff = diff_response.value.diff orelse "";
        if (diff.len == 0 or isNoopResult(diff_response.value.result)) {
            return .{ .message = "No changes to review." };
        }
        const affected = diff_response.value.affected orelse &.{};
        const diff_copy = try allocator.dupe(u8, diff);
        const affected_copy = try allocator.alloc([]const u8, affected.len);
        for (affected, 0..) |item, index| {
            affected_copy[index] = try allocator.dupe(u8, item);
        }
        return .{
            .diff = diff_copy,
            .affected = affected_copy,
            .restart_required = diff_response.value.restart_required orelse false,
        };
    }

    fn renderClientsPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, data: operations.PageData) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.clientsPage(self.gpa, &out.writer, csrf, data);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderClientsFragment(self: *App, request: *std.http.Server.Request, data: operations.PageData) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.clientsFragment(&out.writer, data);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderDiagnosticsPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, data: operations.PageData) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.diagnosticsPage(self.gpa, &out.writer, csrf, data);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderDiagnosticsFragment(self: *App, request: *std.http.Server.Request, data: operations.PageData) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.diagnosticsFragment(&out.writer, data);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderLogsPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, data: operations.PageData) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.logsPage(self.gpa, &out.writer, csrf, data);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderLogsFragment(self: *App, request: *std.http.Server.Request, data: operations.PageData) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.logsFragment(&out.writer, data);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderConfigPage(
        self: *App,
        request: *std.http.Server.Request,
        csrf: []const u8,
        config: ?std.json.Value,
        revision: ?[]const u8,
        source_path: ?[]const u8,
        writable: ?bool,
        err: ?[]const u8,
        logging: ?operations.LoggingView,
    ) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try operations.configPage(self.gpa, &out.writer, csrf, config, revision, source_path, writable, err, logging);
        return self.respondHtml(request, .ok, out.written());
    }

    fn fetchInto(
        self: *App,
        out: *?std.json.Parsed(protocol.Response),
        op: []const u8,
        limit: ?u32,
    ) ?[]const u8 {
        const parsed = self.call(op, null, limit) catch |err| return @errorName(err);
        out.* = parsed;
        if (!parsed.value.ok) return parsed.value.error_code orelse "control request failed";
        return null;
    }

    fn rememberRestartResponse(self: *App, response: *const protocol.Response) void {
        self.restart_supported = response.restart_supported orelse self.restart_supported;
        if (response.restart_required orelse false) {
            self.restart_pending = true;
            if (response.restart_token) |token| {
                if (token.len <= self.restart_token_buf.len) {
                    @memcpy(self.restart_token_buf[0..token.len], token);
                    self.restart_token_len = token.len;
                    return;
                }
            }
        }
        self.clearRestartToken();
    }

    fn clearRestartToken(self: *App) void {
        self.restart_token_len = 0;
    }

    fn restartToken(self: *const App) ?[]const u8 {
        if (self.restart_token_len == 0) return null;
        return self.restart_token_buf[0..self.restart_token_len];
    }

    fn serveRestart(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.respondRestartResult(request, bodyErrorMessage(err), true);
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var token_buf: [64]u8 = undefined;
        const token = formValue(body, "restart_token", &token_buf) orelse
            formValue(body, "token", &token_buf) orelse "";
        var response = self.restartDaemon(token) catch |err| {
            return self.respondRestartResult(request, @errorName(err), true);
        };
        defer response.deinit();
        if (!response.value.ok) {
            return self.respondRestartResult(
                request,
                response.value.message orelse response.value.error_code orelse "Restart request failed.",
                true,
            );
        }
        self.clearRestartToken();
        self.restart_pending = false;
        return self.respondRestartResult(
            request,
            "Restart accepted. vrouterd is stopping cleanly and will come back up; refresh in a few seconds.",
            false,
        );
    }

    fn restartDaemon(self: *App, token: []const u8) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.call(.{
            .version = protocol.version,
            .op = "daemon.restart",
            .restart_token = token,
        });
    }

    fn serveStop(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) {
            return self.respondHtml(request, .forbidden, "<h1>Cross-origin request rejected.</h1>");
        }
        const csrf = (try self.requireSessionFragment(request)) orelse return;
        const body = self.readRequestBody(request) catch |err| {
            return self.respondStopResult(request, bodyErrorMessage(err), true);
        };
        defer self.gpa.free(body);
        if (!try self.verifyFormCsrf(request, csrf, body)) return;

        var confirm_buf: [16]u8 = undefined;
        const confirm = formValue(body, "confirm", &confirm_buf) orelse "";
        if (!std.mem.eql(u8, confirm, "stop")) {
            return self.respondStopResult(request, "Type stop to confirm.", true);
        }
        var response = self.stopDaemon(confirm) catch |err| {
            return self.respondStopResult(request, @errorName(err), true);
        };
        defer response.deinit();
        if (!response.value.ok) {
            return self.respondStopResult(
                request,
                response.value.message orelse response.value.error_code orelse "Stop request failed.",
                true,
            );
        }
        self.clearRestartToken();
        self.restart_pending = false;
        return self.respondStopResult(
            request,
            "Stop accepted. vrouterd is shutting down; forwarding stops and this page will disconnect. Start it again with your service manager.",
            false,
        );
    }

    fn stopDaemon(self: *App, confirm: []const u8) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.call(.{
            .version = protocol.version,
            .op = "daemon.stop",
            .confirm = confirm,
        });
    }

    fn respondRestartResult(self: *App, request: *std.http.Server.Request, message: []const u8, is_error: bool) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.restartResultDialog(&out.writer, message, is_error);
        return self.respondHtml(request, .ok, out.written());
    }

    fn respondStopResult(self: *App, request: *std.http.Server.Request, message: []const u8, is_error: bool) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.stopResultDialog(&out.writer, message, is_error);
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

    fn renderAuditPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, audit: ?protocol.Audit, query: []const u8, result_filter: []const u8, err: ?[]const u8, now: i64) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.auditPage(self.gpa, &out.writer, csrf, audit, query, result_filter, err, now);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderJournalPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, journal: ?protocol.Journal, query: []const u8, state_filter: []const u8, err: ?[]const u8) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.journalPage(self.gpa, &out.writer, csrf, journal, query, state_filter, err);
        return self.respondHtml(request, .ok, out.written());
    }

    fn renderSystemPage(self: *App, request: *std.http.Server.Request, csrf: []const u8, status: ?protocol.Status, err: ?[]const u8, now: i64) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try pages.systemPage(self.gpa, &out.writer, csrf, status, err, now, self.restartUi(csrf));
        return self.respondHtml(request, .ok, out.written());
    }

    fn restartUi(self: *const App, csrf: []const u8) pages.RestartUi {
        return .{
            .csrf = csrf,
            .pending = self.restart_pending,
            .supported = self.restart_supported,
            .token = self.restartToken(),
        };
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

    fn serveNetworkApi(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("network.status", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const network = response.value.network orelse return self.controlError(request, error.MissingNetwork);
        return self.respondJson(request, .ok, NetworkPayload{ .network = network });
    }

    fn serveLeasesApi(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("dhcp.leases", null, 512) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const leases = response.value.leases orelse return self.controlError(request, error.MissingLeases);
        return self.respondJson(request, .ok, LeasesPayload{ .leases = leases });
    }

    fn serveFirewallCountersApi(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("firewall.counters", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const counters = response.value.firewall_counters orelse return self.controlError(request, error.MissingCounters);
        return self.respondJson(request, .ok, FirewallCountersPayload{ .counters = counters });
    }

    fn serveLogsApi(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.call("logs.tail", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const logs = response.value.logs orelse return self.controlError(request, error.MissingLogs);
        return self.respondJson(request, .ok, LogsPayload{ .logs = logs });
    }

    fn serveConfigApi(self: *App, request: *std.http.Server.Request) !void {
        if (self.sessionCsrf(request) == null) {
            return self.apiError(request, .unauthorized, "unauthenticated", "Sign in required.");
        }
        var response = self.configGet() catch |err| return self.controlError(request, err);
        defer response.deinit();
        return self.respondJson(request, .ok, ConfigPayload{
            .revision = response.value.revision,
            .source_path = response.value.source_path,
            .writable = response.value.writable,
            .config = response.value.config,
        });
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

    fn callStatus(self: *App) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return v3Status(&client) catch |err| switch (err) {
            error.ProtocolVersionUnsupported => client.callOpVersion(protocol.v2_version, "status", null, null),
            else => return err,
        };
    }

    fn call(self: *App, op: []const u8, state_filter: ?[]const u8, limit: ?u32) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        const version: ?u32 = if (protocol.isV3Only(op) or std.mem.eql(u8, op, "nat.list"))
            protocol.version
        else
            null;
        return client.callOpVersion(version, op, state_filter, limit);
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

const FetchSet = struct {
    network: ?std.json.Parsed(protocol.Response) = null,
    status: ?std.json.Parsed(protocol.Response) = null,
    leases: ?std.json.Parsed(protocol.Response) = null,
    counters: ?std.json.Parsed(protocol.Response) = null,
    logs: ?std.json.Parsed(protocol.Response) = null,
    ports: ?std.json.Parsed(protocol.Response) = null,
    bridges: ?std.json.Parsed(protocol.Response) = null,
    interfaces: ?std.json.Parsed(protocol.Response) = null,
    routes: ?std.json.Parsed(protocol.Response) = null,
    dhcp: ?std.json.Parsed(protocol.Response) = null,
    firewall: ?std.json.Parsed(protocol.Response) = null,

    fn deinit(self: *FetchSet) void {
        if (self.network) |*parsed| parsed.deinit();
        if (self.status) |*parsed| parsed.deinit();
        if (self.leases) |*parsed| parsed.deinit();
        if (self.counters) |*parsed| parsed.deinit();
        if (self.logs) |*parsed| parsed.deinit();
        if (self.ports) |*parsed| parsed.deinit();
        if (self.bridges) |*parsed| parsed.deinit();
        if (self.interfaces) |*parsed| parsed.deinit();
        if (self.routes) |*parsed| parsed.deinit();
        if (self.dhcp) |*parsed| parsed.deinit();
        if (self.firewall) |*parsed| parsed.deinit();
        self.* = .{};
    }
};

const NatDraft = struct {
    masquerade: []const NatDraftMasquerade = &.{},
    port_forward: []const NatDraftForward = &.{},
};

const NatDraftMasquerade = struct {
    out: []const u8 = "",
    src: ?[]const u8 = null,
    addr: ?[]const u8 = null,
};

const NatDraftForward = struct {
    proto: []const u8 = "",
    ext_port: u16 = 0,
    to: []const u8 = "",
    ingress: ?[]const u8 = null,
    description: ?[]const u8 = null,
    enabled: bool = true,
};

const DraftInput = struct {
    value: std.json.Value,
};

const LoggingDraft = struct {
    level: []const u8,
    format: []const u8,
    revision: []const u8,
};

fn buildLoggingView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    config: ?std.json.Value,
    revision: ?[]const u8,
    level_override: ?[]const u8,
    format_override: ?[]const u8,
    draft_override: ?[]const u8,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.ConfigReview,
) !operations.LoggingView {
    var level: []const u8 = "info";
    var format: []const u8 = "text";
    if (config) |value| {
        if (value == .object) {
            if (value.object.get("log")) |log| {
                if (log == .object) {
                    if (log.object.get("level")) |item| {
                        if (item == .string and item.string.len != 0) level = item.string;
                    }
                    if (log.object.get("format")) |item| {
                        if (item == .string and item.string.len != 0) format = item.string;
                    }
                }
            }
        }
    }
    if (level_override) |value| level = value;
    if (format_override) |value| format = value;
    const rev = revision orelse "";
    const draft_json = if (draft_override) |value|
        value
    else
        try loggingDraftJson(allocator, level, format, rev);
    return .{
        .csrf = csrf,
        .level = level,
        .format = format,
        .revision = rev,
        .draft_json = draft_json,
        .notice = notice,
        .err = err,
        .review = review,
    };
}

fn loggingDraftJson(allocator: std.mem.Allocator, level: []const u8, format: []const u8, revision: []const u8) ![]const u8 {
    var object = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try object.put(allocator, "level", .{ .string = level });
    try object.put(allocator, "format", .{ .string = format });
    try object.put(allocator, "revision", .{ .string = revision });
    return jsonStringify(allocator, std.json.Value{ .object = object });
}

fn loggingDraftFromBody(allocator: std.mem.Allocator, body: []const u8) !LoggingDraft {
    if (try formValueAlloc(allocator, body, "draft")) |text| {
        if (text.len != 0) {
            const value = std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{}) catch return error.InvalidDraft;
            return loggingDraftFromValue(value);
        }
    }
    var level_buf: [16]u8 = undefined;
    var format_buf: [16]u8 = undefined;
    var revision_buf: [80]u8 = undefined;
    const level = formValue(body, "level", &level_buf) orelse return error.InvalidLevel;
    const format = formValue(body, "format", &format_buf) orelse return error.InvalidFormat;
    const revision = formValue(body, "revision", &revision_buf) orelse "";
    if (!validLogLevel(level)) return error.InvalidLevel;
    if (!validLogFormat(format)) return error.InvalidFormat;
    return .{
        .level = try allocator.dupe(u8, level),
        .format = try allocator.dupe(u8, format),
        .revision = try allocator.dupe(u8, revision),
    };
}

fn loggingDraftFromValue(value: std.json.Value) !LoggingDraft {
    if (value != .object) return error.InvalidDraft;
    const level_value = value.object.get("level") orelse return error.InvalidLevel;
    const format_value = value.object.get("format") orelse return error.InvalidFormat;
    const level = switch (level_value) {
        .string => |text| text,
        else => return error.InvalidLevel,
    };
    const format = switch (format_value) {
        .string => |text| text,
        else => return error.InvalidFormat,
    };
    if (!validLogLevel(level)) return error.InvalidLevel;
    if (!validLogFormat(format)) return error.InvalidFormat;
    const revision = if (value.object.get("revision")) |item|
        switch (item) {
            .string => |text| text,
            else => "",
        }
    else
        "";
    return .{ .level = level, .format = format, .revision = revision };
}

fn validLogLevel(value: []const u8) bool {
    return std.mem.eql(u8, value, "err") or
        std.mem.eql(u8, value, "warn") or
        std.mem.eql(u8, value, "info") or
        std.mem.eql(u8, value, "debug");
}

fn validLogFormat(value: []const u8) bool {
    return std.mem.eql(u8, value, "text") or std.mem.eql(u8, value, "json");
}

fn loggingDraftError(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidLevel => "Choose a valid log level.",
        error.InvalidFormat => "Choose a valid log format.",
        error.InvalidDraft => "The logging draft is invalid. Reload and try again.",
        error.MissingField => "Logging fields are required.",
        else => @errorName(err),
    };
}

fn stripNulls(value: *std.json.Value) void {
    switch (value.*) {
        .object => |*object| {
            var index: usize = 0;
            while (index < object.count()) {
                const key = object.keys()[index];
                const item = object.getPtr(key).?;
                if (item.* == .null) {
                    _ = object.orderedRemove(key);
                    continue;
                }
                stripNulls(item);
                index += 1;
            }
        },
        .array => |*array| {
            for (array.items) |*item| stripNulls(item);
        },
        else => {},
    }
}

fn cloneJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !std.json.Value {
    const text = try jsonStringify(allocator, value);
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{});
}

fn installLog(allocator: std.mem.Allocator, value: *std.json.Value, level: []const u8, format: []const u8) !void {
    const root = switch (value.*) {
        .object => |*object| object,
        else => return error.InvalidConfig,
    };
    var log = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try log.put(allocator, "level", .{ .string = try allocator.dupe(u8, level) });
    try log.put(allocator, "format", .{ .string = try allocator.dupe(u8, format) });
    try root.put(allocator, "log", .{ .object = log });
}

fn readDraftInput(allocator: std.mem.Allocator, body: []const u8) !DraftInput {
    const value = (try readOptionalDraft(allocator, body)) orelse return error.MissingDraft;
    return .{ .value = value };
}

fn readOptionalDraft(allocator: std.mem.Allocator, body: []const u8) !?std.json.Value {
    const text = (try formValueAlloc(allocator, body, "draft")) orelse return null;
    if (text.len == 0) return null;
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{}) catch error.InvalidDraft;
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

fn jsonValuesEqual(allocator: std.mem.Allocator, a: std.json.Value, b: std.json.Value) !bool {
    const a_bytes = try vrouter.config_apply.canonicalize(allocator, a);
    defer allocator.free(a_bytes);
    const b_bytes = try vrouter.config_apply.canonicalize(allocator, b);
    defer allocator.free(b_bytes);
    return std.mem.eql(u8, a_bytes, b_bytes);
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

fn buildDhcpView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    running: ?std.json.Value,
    draft: ?std.json.Value,
    draft_json: []const u8,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.ConfigReview,
) !pages.DhcpView {
    var view = pages.DhcpView{
        .csrf = csrf,
        .draft_json = draft_json,
        .notice = notice,
        .err = err,
        .review = review,
    };
    if (draft) |value| {
        view.servers = try dhcpServersFromValue(allocator, value);
    }
    if (draft_json.len != 0) {
        if (running) |running_value| {
            if (draft) |draft_value| {
                if (!try jsonValuesEqual(allocator, running_value, draft_value)) view.pending = 1;
            }
        }
    }
    return view;
}

fn dhcpServersFromValue(allocator: std.mem.Allocator, value: std.json.Value) ![]pages.DhcpServerRow {
    const servers = switch (value) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(pages.DhcpServerRow, servers.items.len);
    for (servers.items, 0..) |server_value, index| {
        const server = switch (server_value) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .iface = objectString(server, "iface") orelse "",
            .pool = objectString(server, "pool") orelse "",
            .lease = objectString(server, "lease") orelse "12h",
            .dns = objectString(server, "dns"),
            .domain = objectString(server, "domain"),
            .mtu = if (server.get("mtu")) |mtu_value| switch (mtu_value) {
                .integer => |number| if (number >= 0 and number <= 65535) @intCast(number) else null,
                else => null,
            } else null,
            .ntp = objectString(server, "ntp"),
            .reservations = try dhcpReservationsFromValue(allocator, server),
        };
    }
    return rows;
}

fn dhcpReservationsFromValue(allocator: std.mem.Allocator, server: std.json.ObjectMap) ![]pages.DhcpReservationRow {
    const field = server.get("reservations") orelse return &.{};
    const reservations = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(pages.DhcpReservationRow, reservations.items.len);
    for (reservations.items, 0..) |reservation_value, index| {
        const reservation = switch (reservation_value) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .mac = objectString(reservation, "mac") orelse "",
            .ip = objectString(reservation, "ip") orelse "",
        };
    }
    return rows;
}

fn objectString(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| if (text.len == 0) null else text,
        .null => null,
        else => null,
    };
}

fn buildDnsView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    running: ?std.json.Value,
    draft: ?std.json.Value,
    draft_json: []const u8,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.ConfigReview,
) !pages.DnsView {
    var view = pages.DnsView{
        .csrf = csrf,
        .draft_json = draft_json,
        .notice = notice,
        .err = err,
        .review = review,
    };
    if (draft) |value| {
        const object = switch (value) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        view.upstreams = try joinJsonStrings(allocator, object.get("upstreams"));
        if (object.get("listen")) |listen| {
            view.listen = switch (listen) {
                .string => |text| text,
                .null => "",
                else => return error.InvalidDraft,
            };
        }
        if (object.get("cache")) |cache| {
            view.cache = switch (cache) {
                .bool => |flag| flag,
                else => return error.InvalidDraft,
            };
        }
        if (object.get("tcp")) |tcp| {
            view.tcp = switch (tcp) {
                .bool => |flag| flag,
                else => return error.InvalidDraft,
            };
        }
        if (object.get("max_entries")) |entries| {
            view.max_entries = switch (entries) {
                .integer => |number| if (number >= 0 and number <= 1_000_000) @intCast(number) else return error.InvalidDraft,
                else => return error.InvalidDraft,
            };
        }
        view.zones = try dnsZonesFromValue(allocator, object.get("zones"));
    }
    if (draft_json.len != 0) {
        if (running) |running_value| {
            if (draft) |draft_value| {
                if (!try jsonValuesEqual(allocator, running_value, draft_value)) view.pending = 1;
            }
        }
    }
    return view;
}

fn joinJsonStrings(allocator: std.mem.Allocator, value: ?std.json.Value) ![]const u8 {
    const field = value orelse return "";
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    for (array.items, 0..) |item, index| {
        const text = switch (item) {
            .string => |string| string,
            else => return error.InvalidDraft,
        };
        if (index != 0) try out.writer.writeAll(", ");
        try out.writer.writeAll(text);
    }
    return try allocator.dupe(u8, out.written());
}

fn dnsZonesFromValue(allocator: std.mem.Allocator, value: ?std.json.Value) ![]pages.DnsZoneRow {
    const field = value orelse return &.{};
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(pages.DnsZoneRow, array.items.len);
    for (array.items, 0..) |item, index| {
        const object = switch (item) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .suffix = objectString(object, "suffix") orelse "",
            .upstreams = try joinJsonStrings(allocator, object.get("upstreams")),
        };
    }
    return rows;
}

fn applyDnsForm(allocator: std.mem.Allocator, object: *std.json.ObjectMap, body: []const u8, action: []const u8) !void {
    if (std.mem.eql(u8, action, "save_settings")) {
        var upstreams_buf: [2048]u8 = undefined;
        var listen_buf: [64]u8 = undefined;
        var entries_buf: [32]u8 = undefined;
        const upstreams_text = formValue(body, "upstreams", &upstreams_buf) orelse "";
        const listen = formValue(body, "listen", &listen_buf) orelse "";
        const entries_text = formValue(body, "max_entries", &entries_buf) orelse "1024";
        const upstreams = try dnsUpstreamArray(allocator, upstreams_text, false);
        if (listen.len != 0) {
            _ = vrouter.types.Ipv4.parse(listen) catch return error.InvalidField;
        }
        const zones_nonempty = if (object.get("zones")) |zones| switch (zones) {
            .array => |array| array.items.len != 0,
            else => false,
        } else false;
        if (listen.len == 0 and (upstreams.items.len != 0 or zones_nonempty)) return error.InvalidField;
        const max_entries = std.fmt.parseInt(u32, entries_text, 10) catch return error.InvalidField;
        if (max_entries == 0 or max_entries > 1_000_000) return error.InvalidField;
        try object.put(allocator, "upstreams", .{ .array = upstreams });
        try object.put(allocator, "cache", .{ .bool = formChecked(body, "cache") });
        try object.put(allocator, "tcp", .{ .bool = formChecked(body, "tcp") });
        try object.put(allocator, "max_entries", .{ .integer = max_entries });
        if (listen.len == 0) {
            _ = object.orderedRemove("listen");
        } else {
            try object.put(allocator, "listen", .{ .string = try allocator.dupe(u8, listen) });
        }
        return;
    }
    if (std.mem.eql(u8, action, "add_zone")) {
        const zones = try ensureArrayField(allocator, object, "zones");
        try zones.append(.{ .object = try dnsZoneFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_zone")) {
        const index = try formIndex(body);
        const zones = try ensureArrayField(allocator, object, "zones");
        if (index >= zones.items.len) return error.InvalidIndex;
        zones.items[index] = .{ .object = try dnsZoneFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_zone")) {
        const index = try formIndex(body);
        const zones = try ensureArrayField(allocator, object, "zones");
        if (index >= zones.items.len) return error.InvalidIndex;
        _ = zones.orderedRemove(index);
        return;
    }
    return error.InvalidAction;
}

fn dnsZoneFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var suffix_buf: [256]u8 = undefined;
    var upstreams_buf: [2048]u8 = undefined;
    const suffix = formValue(body, "suffix", &suffix_buf) orelse return error.MissingField;
    const upstreams_text = formValue(body, "zone_upstreams", &upstreams_buf) orelse return error.MissingField;
    if (suffix.len == 0 or suffix.len > 255) return error.InvalidField;
    const upstreams = try dnsUpstreamArray(allocator, upstreams_text, true);
    var zone = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try zone.put(allocator, "suffix", .{ .string = try allocator.dupe(u8, suffix) });
    try zone.put(allocator, "upstreams", .{ .array = upstreams });
    return zone;
}

fn dnsUpstreamArray(allocator: std.mem.Allocator, text: []const u8, required: bool) !std.json.Array {
    var array = std.json.Array.init(allocator);
    var tokens = std.mem.tokenizeAny(u8, text, ", \t\r\n");
    while (tokens.next()) |token| {
        _ = vrouter.types.Ipv4.parse(token) catch return error.InvalidField;
        try array.append(.{ .string = try allocator.dupe(u8, token) });
    }
    if (required and array.items.len == 0) return error.InvalidField;
    return array;
}

fn formChecked(body: []const u8, name: []const u8) bool {
    var pairs = std.mem.splitScalar(u8, body, '&');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        if (!std.mem.eql(u8, key, name)) continue;
        const value = pair[eq + 1 ..];
        return value.len != 0 and !std.mem.eql(u8, value, "0") and !std.mem.eql(u8, value, "false");
    }
    return false;
}

fn dnsFormError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingField => "A required field is missing.",
        error.InvalidField => "A field has an invalid value. Use IPv4 addresses and a listener when upstreams or zones are set.",
        error.InvalidIndex => "That DNS zone no longer exists.",
        error.InvalidAction => "Unknown DNS action.",
        error.MissingDraft => "The draft is missing. Reload the page and try again.",
        error.InvalidDraft => "The draft is invalid. Reload the page and try again.",
        else => @errorName(err),
    };
}

fn interfaceDraft(
    allocator: std.mem.Allocator,
    ports: ?std.json.Value,
    bridges: ?std.json.Value,
    interfaces: ?std.json.Value,
) !std.json.Value {
    var object = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try object.put(allocator, "ports", ports orelse .{ .array = std.json.Array.init(allocator) });
    try object.put(allocator, "bridges", bridges orelse .{ .array = std.json.Array.init(allocator) });
    try object.put(allocator, "interfaces", interfaces orelse .{ .array = std.json.Array.init(allocator) });
    return .{ .object = object };
}

fn buildInterfacesView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    network: ?protocol.Network,
    draft: ?std.json.Value,
    draft_json: []const u8,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.ConfigReview,
) !operations.InterfacesView {
    var view = operations.InterfacesView{
        .csrf = csrf,
        .network = network,
        .draft_json = draft_json,
        .notice = notice,
        .err = err,
        .review = review,
    };
    if (draft) |value| {
        const object = switch (value) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        view.ports = try interfacePortRows(allocator, object.get("ports"));
        view.bridges = try interfaceBridgeRows(allocator, object.get("bridges"));
        view.interfaces = try interfaceRows(allocator, object.get("interfaces"));
    }
    return view;
}

fn interfacePortRows(allocator: std.mem.Allocator, value: ?std.json.Value) ![]operations.PortRow {
    const field = value orelse return &.{};
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(operations.PortRow, array.items.len);
    for (array.items, 0..) |item, index| {
        const port = switch (item) {
            .object => |port| port,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .name = objectString(port, "name") orelse "",
            .kind = objectString(port, "kind") orelse "l2",
            .device = objectString(port, "device") orelse "",
            .create = objectString(port, "create") orelse "",
            .mtu = objectInteger(port, "mtu"),
            .pvid = objectInteger(port, "pvid"),
            .tagged = try joinJsonNumbers(allocator, port.get("tagged")),
            .storm_control = objectInteger(port, "storm_control") orelse 1000,
        };
    }
    return rows;
}

fn interfaceBridgeRows(allocator: std.mem.Allocator, value: ?std.json.Value) ![]operations.BridgeRow {
    const field = value orelse return &.{};
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(operations.BridgeRow, array.items.len);
    for (array.items, 0..) |item, index| {
        const bridge = switch (item) {
            .object => |bridge| bridge,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .name = objectString(bridge, "name") orelse "",
            .ports = try joinJsonStrings(allocator, bridge.get("ports")),
            .stp = objectBool(bridge, "stp") orelse false,
            .vlan_aware = objectBool(bridge, "vlan_aware") orelse false,
            .offload = objectString(bridge, "offload") orelse "none",
            .svi_count = objectInteger(bridge, "svi_count") orelse 0,
        };
    }
    return rows;
}

fn interfaceRows(allocator: std.mem.Allocator, value: ?std.json.Value) ![]operations.InterfaceRow {
    const field = value orelse return &.{};
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(operations.InterfaceRow, array.items.len);
    for (array.items, 0..) |item, index| {
        const iface = switch (item) {
            .object => |iface| iface,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .name = objectString(iface, "name") orelse "",
            .bridge = objectString(iface, "bridge") orelse "",
            .port = objectString(iface, "port") orelse "",
            .address = objectString(iface, "address") orelse "",
            .addresses = try joinJsonStrings(allocator, iface.get("addresses")),
            .vlan = objectInteger(iface, "vlan"),
        };
    }
    return rows;
}

fn joinJsonNumbers(allocator: std.mem.Allocator, value: ?std.json.Value) ![]const u8 {
    const field = value orelse return "";
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    for (array.items, 0..) |item, index| {
        const number = switch (item) {
            .integer => |number| number,
            else => return error.InvalidDraft,
        };
        if (index != 0) try out.writer.writeAll(", ");
        try out.writer.print("{d}", .{number});
    }
    return try allocator.dupe(u8, out.written());
}

fn installInterfaceSections(allocator: std.mem.Allocator, root: *std.json.ObjectMap, draft_value: std.json.Value) !void {
    const draft = switch (draft_value) {
        .object => |object| object,
        else => return error.InvalidDraft,
    };
    const ports = try interfaceMapFromRows(allocator, draft.get("ports"), &.{"name"});
    const bridges = try interfaceMapFromRows(allocator, draft.get("bridges"), &.{ "name", "svi_count" });
    const interfaces = try interfaceMapFromRows(allocator, draft.get("interfaces"), &.{"name"});
    try root.put(allocator, "ports", .{ .object = ports });
    try root.put(allocator, "bridges", .{ .object = bridges });
    try root.put(allocator, "interfaces", .{ .object = interfaces });
}

fn interfaceMapFromRows(allocator: std.mem.Allocator, value: ?std.json.Value, drop: []const []const u8) !std.json.ObjectMap {
    const field = value orelse return std.json.ObjectMap.init(allocator, &.{}, &.{});
    const array = switch (field) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    var map = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    for (array.items) |item| {
        const object = switch (item) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        const name = objectString(object, "name") orelse return error.InvalidDraft;
        if (name.len == 0) return error.InvalidDraft;
        var entry = try std.json.ObjectMap.init(allocator, &.{}, &.{});
        var it = object.iterator();
        while (it.next()) |pair| {
            if (std.mem.eql(u8, pair.key_ptr.*, "name")) continue;
            if (pair.value_ptr.* == .null) continue;
            var skip = false;
            for (drop) |field_name| {
                if (std.mem.eql(u8, pair.key_ptr.*, field_name)) skip = true;
            }
            if (skip) continue;
            try entry.put(allocator, pair.key_ptr.*, pair.value_ptr.*);
        }
        try map.put(allocator, name, .{ .object = entry });
    }
    return map;
}

fn applyInterfacesForm(allocator: std.mem.Allocator, draft: *std.json.ObjectMap, body: []const u8, action: []const u8) !void {
    const original: std.json.Value = .{ .object = draft.* };
    const text = try jsonStringify(allocator, original);
    var clone = try std.json.parseFromSliceLeaky(std.json.Value, allocator, text, .{});
    const candidate = switch (clone) {
        .object => |*object| object,
        else => return error.InvalidDraft,
    };
    try applyInterfacesFormInner(allocator, candidate, body, action);
    try validateInterfaceDraft(allocator, candidate);
    draft.* = candidate.*;
}

fn applyInterfacesFormInner(allocator: std.mem.Allocator, draft: *std.json.ObjectMap, body: []const u8, action: []const u8) !void {
    if (std.mem.eql(u8, action, "add_port")) {
        const ports = try ensureArrayField(allocator, draft, "ports");
        try ports.append(.{ .object = try portFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_port")) {
        const index = try formIndex(body);
        const ports = try ensureArrayField(allocator, draft, "ports");
        if (index >= ports.items.len) return error.InvalidIndex;
        ports.items[index] = .{ .object = try portFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_port")) {
        const index = try formIndex(body);
        const ports = try ensureArrayField(allocator, draft, "ports");
        if (index >= ports.items.len) return error.InvalidIndex;
        _ = ports.orderedRemove(index);
        return;
    }
    if (std.mem.eql(u8, action, "add_bridge")) {
        const bridges = try ensureArrayField(allocator, draft, "bridges");
        try bridges.append(.{ .object = try bridgeFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_bridge")) {
        const index = try formIndex(body);
        const bridges = try ensureArrayField(allocator, draft, "bridges");
        if (index >= bridges.items.len) return error.InvalidIndex;
        bridges.items[index] = .{ .object = try bridgeFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_bridge")) {
        const index = try formIndex(body);
        const bridges = try ensureArrayField(allocator, draft, "bridges");
        if (index >= bridges.items.len) return error.InvalidIndex;
        _ = bridges.orderedRemove(index);
        return;
    }
    if (std.mem.eql(u8, action, "add_interface")) {
        const interfaces = try ensureArrayField(allocator, draft, "interfaces");
        try interfaces.append(.{ .object = try interfaceFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_interface")) {
        const index = try formIndex(body);
        const interfaces = try ensureArrayField(allocator, draft, "interfaces");
        if (index >= interfaces.items.len) return error.InvalidIndex;
        interfaces.items[index] = .{ .object = try interfaceFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_interface")) {
        const index = try formIndex(body);
        const interfaces = try ensureArrayField(allocator, draft, "interfaces");
        if (index >= interfaces.items.len) return error.InvalidIndex;
        _ = interfaces.orderedRemove(index);
        return;
    }
    return error.InvalidAction;
}

fn validateInterfaceDraft(allocator: std.mem.Allocator, draft: *std.json.ObjectMap) !void {
    _ = allocator;
    const ports = rowArray(draft.get("ports")) orelse return error.InvalidDraft;
    const bridges = rowArray(draft.get("bridges")) orelse return error.InvalidDraft;
    const interfaces = rowArray(draft.get("interfaces")) orelse return error.InvalidDraft;

    for (ports.items, 0..) |item, index| {
        const name = rowName(item) orelse return error.InvalidField;
        if (findRow(bridges, name) != null or findRow(interfaces, name) != null) return error.InvalidField;
        const device = objectString(item.object, "device") orelse return error.InvalidField;
        if (device.len == 0) return error.InvalidField;
        const bridged = portBridged(bridges, name);
        const has_vlan = portHasVlans(item.object);
        if (!bridged and has_vlan) return error.InvalidField;
        for (ports.items[0..index]) |previous| {
            if (std.mem.eql(u8, rowName(previous).?, name)) return error.InvalidField;
            if (std.mem.eql(u8, objectString(previous.object, "device") orelse "", device)) return error.InvalidField;
        }
    }

    for (bridges.items) |item| {
        const name = rowName(item) orelse return error.InvalidField;
        if (findRow(ports, name) != null or findRow(interfaces, name) != null) return error.InvalidField;
        const members_value = item.object.get("ports") orelse return error.InvalidField;
        const members = switch (members_value) {
            .array => |array| array,
            else => return error.InvalidField,
        };
        if (members.items.len == 0) return error.InvalidField;
        const vlan_aware = objectBool(item.object, "vlan_aware") orelse false;
        const offload = objectString(item.object, "offload") orelse "none";
        for (members.items, 0..) |member, index| {
            const member_name = switch (member) {
                .string => |text| text,
                else => return error.InvalidField,
            };
            const port = findRow(ports, member_name) orelse return error.InvalidField;
            if (!std.mem.eql(u8, objectString(port.object, "kind") orelse "", "l2")) return error.InvalidField;
            if (!vlan_aware and portHasVlans(port.object)) return error.InvalidField;
            if (!std.mem.eql(u8, offload, "none") and
                (port.object.get("create") != null or port.object.get("mtu") != null)) return error.InvalidField;
            for (members.items[0..index]) |previous| {
                if (previous == .string and std.mem.eql(u8, previous.string, member_name)) return error.InvalidField;
            }
        }
    }

    for (interfaces.items) |item| {
        const name = rowName(item) orelse return error.InvalidField;
        if (findRow(ports, name) != null or findRow(bridges, name) != null) return error.InvalidField;
        const bridge = objectString(item.object, "bridge");
        const port = objectString(item.object, "port");
        const has_bridge = bridge != null and bridge.?.len != 0;
        const has_port = port != null and port.?.len != 0;
        if (has_bridge == has_port) return error.InvalidField;
        if (has_bridge and findRow(bridges, bridge.?) == null) return error.InvalidField;
        if (has_port and findRow(ports, port.?) == null) return error.InvalidField;
        if (has_port and portBridged(bridges, port.?)) return error.InvalidField;
        const has_vlan = item.object.get("vlan") != null;
        if (has_port and has_vlan) return error.InvalidField;
        if (has_bridge) {
            const bridge_row = findRow(bridges, bridge.?).?;
            if (has_vlan and !(objectBool(bridge_row.object, "vlan_aware") orelse false)) return error.InvalidField;
            if (objectString(item.object, "address")) |address| {
                if (std.mem.eql(u8, address, "dhcp")) return error.InvalidField;
            }
        }
    }
}

fn rowArray(value: ?std.json.Value) ?std.json.Array {
    const item = value orelse return null;
    return switch (item) {
        .array => |array| array,
        else => null,
    };
}

fn rowName(value: std.json.Value) ?[]const u8 {
    if (value != .object) return null;
    return objectString(value.object, "name");
}

fn findRow(array: std.json.Array, name: []const u8) ?std.json.Value {
    for (array.items) |item| {
        const candidate = rowName(item) orelse continue;
        if (std.mem.eql(u8, candidate, name)) return item;
    }
    return null;
}

fn portBridged(bridges: std.json.Array, name: []const u8) bool {
    for (bridges.items) |item| {
        const members_value = item.object.get("ports") orelse continue;
        const members = switch (members_value) {
            .array => |array| array,
            else => continue,
        };
        for (members.items) |member| {
            if (member == .string and std.mem.eql(u8, member.string, name)) return true;
        }
    }
    return false;
}

fn portHasVlans(object: std.json.ObjectMap) bool {
    if (object.get("pvid") != null) return true;
    const tagged = object.get("tagged") orelse return false;
    return switch (tagged) {
        .array => |array| array.items.len != 0,
        else => false,
    };
}

fn portFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var name_buf: [64]u8 = undefined;
    var kind_buf: [16]u8 = undefined;
    var device_buf: [128]u8 = undefined;
    var create_buf: [16]u8 = undefined;
    var mtu_buf: [24]u8 = undefined;
    var pvid_buf: [24]u8 = undefined;
    var tagged_buf: [512]u8 = undefined;
    var storm_buf: [24]u8 = undefined;
    const name = formValue(body, "name", &name_buf) orelse return error.MissingField;
    const kind = formValue(body, "kind", &kind_buf) orelse "l2";
    const device = formValue(body, "device", &device_buf) orelse return error.MissingField;
    const create = formValue(body, "create", &create_buf) orelse "";
    const mtu = formValue(body, "mtu", &mtu_buf) orelse "";
    const pvid = formValue(body, "pvid", &pvid_buf) orelse "";
    const tagged = formValue(body, "tagged", &tagged_buf) orelse "";
    const storm = formValue(body, "storm_control", &storm_buf) orelse "1000";
    if (!validName(name)) return error.InvalidField;
    if (device.len == 0 or device.len > 15) return error.InvalidField;
    if (!std.mem.eql(u8, kind, "l2") and !std.mem.eql(u8, kind, "l3")) return error.InvalidField;
    if (create.len != 0 and !std.mem.eql(u8, create, "tun") and !std.mem.eql(u8, create, "tap")) return error.InvalidField;
    if (std.mem.eql(u8, create, "tun") and !std.mem.eql(u8, kind, "l3")) return error.InvalidField;
    if (std.mem.eql(u8, create, "tap") and !std.mem.eql(u8, kind, "l2")) return error.InvalidField;

    var port = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try port.put(allocator, "name", .{ .string = try allocator.dupe(u8, name) });
    try port.put(allocator, "kind", .{ .string = try allocator.dupe(u8, kind) });
    try port.put(allocator, "device", .{ .string = try allocator.dupe(u8, device) });
    if (create.len != 0) try port.put(allocator, "create", .{ .string = try allocator.dupe(u8, create) });
    if (mtu.len != 0) {
        const value = std.fmt.parseInt(u16, mtu, 10) catch return error.InvalidField;
        if (value < 576 or value > vrouter.types.max_supported_mtu) return error.InvalidField;
        try port.put(allocator, "mtu", .{ .integer = value });
    }
    if (pvid.len != 0) {
        const value = std.fmt.parseInt(u16, pvid, 10) catch return error.InvalidField;
        if (value == 0 or value > 4094) return error.InvalidField;
        try port.put(allocator, "pvid", .{ .integer = value });
    }
    try port.put(allocator, "tagged", .{ .array = try vlanArray(allocator, tagged) });
    try port.put(allocator, "storm_control", .{ .integer = std.fmt.parseInt(u32, storm, 10) catch return error.InvalidField });
    return port;
}

fn vlanArray(allocator: std.mem.Allocator, text: []const u8) !std.json.Array {
    var array = std.json.Array.init(allocator);
    var tokens = std.mem.tokenizeAny(u8, text, ", \t\r\n");
    while (tokens.next()) |token| {
        const vlan = std.fmt.parseInt(u16, token, 10) catch return error.InvalidField;
        if (vlan == 0 or vlan > 4094) return error.InvalidField;
        try array.append(.{ .integer = vlan });
    }
    return array;
}

fn bridgeFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var name_buf: [64]u8 = undefined;
    var ports_buf: [1024]u8 = undefined;
    var offload_buf: [16]u8 = undefined;
    const name = formValue(body, "name", &name_buf) orelse return error.MissingField;
    const ports_text = formValue(body, "ports", &ports_buf) orelse "";
    const offload = formValue(body, "offload", &offload_buf) orelse "none";
    if (!validName(name)) return error.InvalidField;
    if (!std.mem.eql(u8, offload, "none") and !std.mem.eql(u8, offload, "kernel")) return error.InvalidField;
    var bridge = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try bridge.put(allocator, "name", .{ .string = try allocator.dupe(u8, name) });
    try bridge.put(allocator, "ports", .{ .array = try nameArray(allocator, ports_text) });
    try bridge.put(allocator, "stp", .{ .bool = formChecked(body, "stp") });
    try bridge.put(allocator, "vlan_aware", .{ .bool = formChecked(body, "vlan_aware") });
    try bridge.put(allocator, "offload", .{ .string = try allocator.dupe(u8, offload) });
    return bridge;
}

fn interfaceFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var name_buf: [64]u8 = undefined;
    var bridge_buf: [64]u8 = undefined;
    var port_buf: [64]u8 = undefined;
    var address_buf: [128]u8 = undefined;
    var addresses_buf: [1024]u8 = undefined;
    var vlan_buf: [24]u8 = undefined;
    const name = formValue(body, "name", &name_buf) orelse return error.MissingField;
    const bridge = formValue(body, "bridge", &bridge_buf) orelse "";
    const port = formValue(body, "port", &port_buf) orelse "";
    const address = formValue(body, "address", &address_buf) orelse "";
    const addresses_text = formValue(body, "addresses", &addresses_buf) orelse "";
    const vlan = formValue(body, "vlan", &vlan_buf) orelse "";
    if (!validName(name)) return error.InvalidField;
    if (bridge.len != 0 and !validName(bridge)) return error.InvalidField;
    if (port.len != 0 and !validName(port)) return error.InvalidField;
    if ((bridge.len == 0) == (port.len == 0)) return error.InvalidField;
    if (address.len != 0 and !std.mem.eql(u8, address, "dhcp") and !validPrefix(address)) return error.InvalidField;
    var addresses = std.json.Array.init(allocator);
    var address_tokens = std.mem.tokenizeAny(u8, addresses_text, ", \t\r\n");
    while (address_tokens.next()) |token| {
        if (!validPrefix(token)) return error.InvalidField;
        try addresses.append(.{ .string = try allocator.dupe(u8, token) });
    }
    const vlan_value = if (vlan.len != 0) std.fmt.parseInt(u16, vlan, 10) catch return error.InvalidField else 0;
    if (vlan.len != 0 and (vlan_value == 0 or vlan_value > 4094)) return error.InvalidField;
    var iface = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try iface.put(allocator, "name", .{ .string = try allocator.dupe(u8, name) });
    if (bridge.len != 0) try iface.put(allocator, "bridge", .{ .string = try allocator.dupe(u8, bridge) });
    if (port.len != 0) try iface.put(allocator, "port", .{ .string = try allocator.dupe(u8, port) });
    if (address.len != 0) try iface.put(allocator, "address", .{ .string = try allocator.dupe(u8, address) });
    try iface.put(allocator, "addresses", .{ .array = addresses });
    if (vlan.len != 0) try iface.put(allocator, "vlan", .{ .integer = vlan_value });
    return iface;
}

fn nameArray(allocator: std.mem.Allocator, text: []const u8) !std.json.Array {
    var array = std.json.Array.init(allocator);
    var tokens = std.mem.tokenizeAny(u8, text, ", \t\r\n");
    while (tokens.next()) |token| {
        if (!validName(token)) return error.InvalidField;
        try array.append(.{ .string = try allocator.dupe(u8, token) });
    }
    return array;
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 63) return false;
    if (!std.ascii.isAlphanumeric(name[0])) return false;
    for (name) |char| {
        if (!std.ascii.isAlphanumeric(char) and char != '.' and char != '_' and char != '-') return false;
    }
    return true;
}

fn interfaceFormError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingField => "A required interface field is missing.",
        error.InvalidField => "An interface field has an invalid value. Check names, devices, VLANs and addresses.",
        error.InvalidIndex => "That interface object no longer exists.",
        error.InvalidAction => "Unknown interface action.",
        error.InvalidDraft => "The draft is invalid. Reload the page and try again.",
        error.InvalidResponse => "The daemon returned an unexpected response.",
        error.MissingDraft => "The draft is missing. Reload the page and try again.",
        else => @errorName(err),
    };
}

fn buildRoutesView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    running: ?std.json.Value,
    draft: ?std.json.Value,
    draft_json: []const u8,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.ConfigReview,
) !operations.RoutesView {
    var view = operations.RoutesView{
        .csrf = csrf,
        .draft_json = draft_json,
        .notice = notice,
        .err = err,
        .review = review,
    };
    if (draft) |value| view.routes = try routeRowsFromValue(allocator, value);
    if (draft_json.len != 0) {
        if (running) |running_value| {
            if (draft) |draft_value| {
                if (!try jsonValuesEqual(allocator, running_value, draft_value)) view.pending = 1;
            }
        }
    }
    return view;
}

fn routeRowsFromValue(allocator: std.mem.Allocator, value: std.json.Value) ![]operations.RouteRow {
    const array = switch (value) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(operations.RouteRow, array.items.len);
    for (array.items, 0..) |item, index| {
        const object = switch (item) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .dst = objectString(object, "dst") orelse "",
            .via = objectString(object, "via") orelse "",
            .dev = objectString(object, "dev") orelse "",
            .metric = objectInteger(object, "metric") orelse 0,
            .table = objectInteger(object, "table") orelse 0,
        };
    }
    return rows;
}

fn objectInteger(object: std.json.ObjectMap, key: []const u8) ?i64 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .integer => |number| number,
        else => null,
    };
}

fn objectBool(object: std.json.ObjectMap, key: []const u8) ?bool {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .bool => |flag| flag,
        else => null,
    };
}

fn applyRoutesForm(allocator: std.mem.Allocator, routes: *std.json.Array, body: []const u8, action: []const u8) !void {
    if (std.mem.eql(u8, action, "add_route")) {
        try routes.append(.{ .object = try routeFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_route")) {
        const index = try formIndex(body);
        if (index >= routes.items.len) return error.InvalidIndex;
        routes.items[index] = .{ .object = try routeFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_route")) {
        const index = try formIndex(body);
        if (index >= routes.items.len) return error.InvalidIndex;
        _ = routes.orderedRemove(index);
        return;
    }
    return error.InvalidAction;
}

fn validPrefix(text: []const u8) bool {
    _ = vrouter.types.IpPrefix.parse(text) catch return false;
    return true;
}

fn validIp(text: []const u8) bool {
    _ = vrouter.types.IpAddr.parse(text) catch return false;
    return true;
}

fn ruleFamilyAllows(rule_family: []const u8, value_family: vrouter.types.IpFamily) bool {
    return std.mem.eql(u8, rule_family, "any") or
        (std.mem.eql(u8, rule_family, "ipv4") and value_family == .ipv4) or
        (std.mem.eql(u8, rule_family, "ipv6") and value_family == .ipv6);
}

fn routeFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var dst_buf: [256]u8 = undefined;
    var via_buf: [128]u8 = undefined;
    var dev_buf: [128]u8 = undefined;
    var metric_buf: [24]u8 = undefined;
    var table_buf: [24]u8 = undefined;
    const dst = formValue(body, "dst", &dst_buf) orelse return error.MissingField;
    const via = formValue(body, "via", &via_buf) orelse "";
    const dev = formValue(body, "dev", &dev_buf) orelse "";
    const metric_text = formValue(body, "metric", &metric_buf) orelse "0";
    const table_text = formValue(body, "table", &table_buf) orelse "0";
    if (dst.len == 0 or dst.len > 255) return error.InvalidField;
    if (!validPrefix(dst)) return error.InvalidField;
    if (via.len != 0 and !validIp(via)) return error.InvalidField;
    if (dev.len == 0 or dev.len > 127) return error.InvalidField;
    if (std.mem.indexOfAny(u8, dev, " \t\r\n") != null) return error.InvalidField;
    const dst_prefix = vrouter.types.IpPrefix.parse(dst) catch return error.InvalidField;
    if (via.len != 0) {
        const via_addr = vrouter.types.IpAddr.parse(via) catch return error.InvalidField;
        if (via_addr.family() != dst_prefix.family()) return error.InvalidField;
    }
    const metric = std.fmt.parseInt(u32, metric_text, 10) catch return error.InvalidField;
    const table = std.fmt.parseInt(u32, table_text, 10) catch return error.InvalidField;

    var route = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try route.put(allocator, "dst", .{ .string = try allocator.dupe(u8, dst) });
    if (via.len != 0) try route.put(allocator, "via", .{ .string = try allocator.dupe(u8, via) });
    if (dev.len != 0) try route.put(allocator, "dev", .{ .string = try allocator.dupe(u8, dev) });
    try route.put(allocator, "metric", .{ .integer = metric });
    try route.put(allocator, "table", .{ .integer = table });
    return route;
}

fn routeFormError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingField => "A required route field is missing.",
        error.InvalidField => "A route field has an invalid value. Check the destination, gateway, device, metric and table.",
        error.InvalidIndex => "That route no longer exists.",
        error.InvalidAction => "Unknown route action.",
        error.MissingDraft => "The draft is missing. Reload the page and try again.",
        error.InvalidDraft => "The draft is invalid. Reload the page and try again.",
        else => @errorName(err),
    };
}

fn buildFirewallView(
    allocator: std.mem.Allocator,
    csrf: []const u8,
    running: ?std.json.Value,
    draft: ?std.json.Value,
    draft_json: []const u8,
    counters: ?protocol.FirewallCounters,
    notice: ?[]const u8,
    err: ?[]const u8,
    review: ?pages.ConfigReview,
) !operations.FirewallView {
    var view = operations.FirewallView{
        .csrf = csrf,
        .draft_json = draft_json,
        .counters = counters,
        .notice = notice,
        .err = err,
        .review = review,
    };
    if (draft) |value| {
        const object = switch (value) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        view.default_in = objectString(object, "default_in") orelse "drop";
        view.default_forward = objectString(object, "default_forward") orelse "drop";
        view.default_out = objectString(object, "default_out") orelse "accept";
        view.rp_filter = objectBool(object, "rp_filter") orelse false;
        if (object.get("rate_limit")) |limits_value| {
            const limits = switch (limits_value) {
                .object => |limits_object| limits_object,
                else => return error.InvalidDraft,
            };
            view.rate_icmp = objectInteger(limits, "icmp") orelse 0;
            view.rate_arp = objectInteger(limits, "arp") orelse 0;
            view.rate_dhcp = objectInteger(limits, "dhcp") orelse 0;
            view.rate_ndp = objectInteger(limits, "ndp") orelse 0;
        }
        view.rules = try firewallRulesFromValue(allocator, object);
    }
    if (draft_json.len != 0) {
        if (running) |running_value| {
            if (draft) |draft_value| {
                if (!try jsonValuesEqual(allocator, running_value, draft_value)) view.pending = 1;
            }
        }
    }
    return view;
}

fn firewallRulesFromValue(allocator: std.mem.Allocator, object: std.json.ObjectMap) ![]operations.FirewallRuleRow {
    const rules_value = object.get("rules") orelse return &.{};
    const array = switch (rules_value) {
        .array => |array| array,
        else => return error.InvalidDraft,
    };
    const rows = try allocator.alloc(operations.FirewallRuleRow, array.items.len);
    for (array.items, 0..) |item, index| {
        const rule = switch (item) {
            .object => |rule| rule,
            else => return error.InvalidDraft,
        };
        rows[index] = .{
            .action = objectString(rule, "action") orelse "drop",
            .family = objectString(rule, "family") orelse "ipv4",
            .proto = objectString(rule, "proto") orelse "",
            .src = objectString(rule, "src") orelse "",
            .dst = objectString(rule, "dst") orelse "",
            .sport = objectInteger(rule, "sport"),
            .dport = objectInteger(rule, "dport"),
            .iif = objectString(rule, "iif") orelse "",
            .oif = objectString(rule, "oif") orelse "",
            .ct_state = try joinJsonStrings(allocator, rule.get("ct_state")),
        };
    }
    return rows;
}

fn applyFirewallForm(allocator: std.mem.Allocator, object: *std.json.ObjectMap, body: []const u8, action: []const u8) !void {
    if (std.mem.eql(u8, action, "save_policy")) {
        var in_buf: [16]u8 = undefined;
        var forward_buf: [16]u8 = undefined;
        var out_buf: [16]u8 = undefined;
        const default_in = formValue(body, "default_in", &in_buf) orelse return error.MissingField;
        const default_forward = formValue(body, "default_forward", &forward_buf) orelse return error.MissingField;
        const default_out = formValue(body, "default_out", &out_buf) orelse return error.MissingField;
        if (!firewallActionValid(default_in) or !firewallActionValid(default_forward) or !firewallActionValid(default_out)) return error.InvalidField;
        if (!std.mem.eql(u8, default_out, "accept")) return error.InvalidField;
        try object.put(allocator, "default_in", .{ .string = try allocator.dupe(u8, default_in) });
        try object.put(allocator, "default_forward", .{ .string = try allocator.dupe(u8, default_forward) });
        try object.put(allocator, "default_out", .{ .string = try allocator.dupe(u8, default_out) });
        try object.put(allocator, "rp_filter", .{ .bool = formChecked(body, "rp_filter") });
        return;
    }
    if (std.mem.eql(u8, action, "save_limits")) {
        const rates = try ensureObjectField(allocator, object, "rate_limit");
        try rates.put(allocator, "icmp", .{ .integer = try formRate(body, "rate_icmp") });
        try rates.put(allocator, "arp", .{ .integer = try formRate(body, "rate_arp") });
        try rates.put(allocator, "dhcp", .{ .integer = try formRate(body, "rate_dhcp") });
        try rates.put(allocator, "ndp", .{ .integer = try formRate(body, "rate_ndp") });
        return;
    }
    if (std.mem.eql(u8, action, "add_rule")) {
        const rules = try ensureArrayField(allocator, object, "rules");
        try rules.append(.{ .object = try firewallRuleFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_rule")) {
        const index = try formIndex(body);
        const rules = try ensureArrayField(allocator, object, "rules");
        if (index >= rules.items.len) return error.InvalidIndex;
        rules.items[index] = .{ .object = try firewallRuleFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_rule")) {
        const index = try formIndex(body);
        const rules = try ensureArrayField(allocator, object, "rules");
        if (index >= rules.items.len) return error.InvalidIndex;
        _ = rules.orderedRemove(index);
        return;
    }
    return error.InvalidAction;
}

fn ensureObjectField(allocator: std.mem.Allocator, root: *std.json.ObjectMap, name: []const u8) !*std.json.ObjectMap {
    if (root.getPtr(name)) |value| {
        return switch (value.*) {
            .object => |*object| object,
            else => error.InvalidConfig,
        };
    }
    try root.put(allocator, name, .{ .object = try std.json.ObjectMap.init(allocator, &.{}, &.{}) });
    return switch (root.getPtr(name).?.*) {
        .object => |*object| object,
        else => unreachable,
    };
}

fn formRate(body: []const u8, name: []const u8) !i64 {
    var buf: [24]u8 = undefined;
    const text = formValue(body, name, &buf) orelse return error.MissingField;
    const value = std.fmt.parseInt(u32, text, 10) catch return error.InvalidField;
    return value;
}

fn firewallRuleFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var action_buf: [16]u8 = undefined;
    var family_buf: [16]u8 = undefined;
    var proto_buf: [16]u8 = undefined;
    var src_buf: [256]u8 = undefined;
    var dst_buf: [256]u8 = undefined;
    var sport_buf: [24]u8 = undefined;
    var dport_buf: [24]u8 = undefined;
    var iif_buf: [128]u8 = undefined;
    var oif_buf: [128]u8 = undefined;
    var states_buf: [256]u8 = undefined;
    const action = formValue(body, "rule_action", &action_buf) orelse return error.MissingField;
    const family = formValue(body, "family", &family_buf) orelse return error.MissingField;
    const proto = formValue(body, "proto", &proto_buf) orelse "";
    const src = formValue(body, "src", &src_buf) orelse "";
    const dst = formValue(body, "dst", &dst_buf) orelse "";
    const sport = formValue(body, "sport", &sport_buf) orelse "";
    const dport = formValue(body, "dport", &dport_buf) orelse "";
    const iif = formValue(body, "iif", &iif_buf) orelse "";
    const oif = formValue(body, "oif", &oif_buf) orelse "";
    const states = formValue(body, "ct_state", &states_buf) orelse "";
    if (!firewallActionValid(action)) return error.InvalidField;
    if (!std.mem.eql(u8, family, "ipv4") and !std.mem.eql(u8, family, "ipv6") and !std.mem.eql(u8, family, "any")) return error.InvalidField;
    if (proto.len != 0 and
        !std.mem.eql(u8, proto, "tcp") and !std.mem.eql(u8, proto, "udp") and
        !std.mem.eql(u8, proto, "icmp") and !std.mem.eql(u8, proto, "icmpv6")) return error.InvalidField;
    if (iif.len != 0 and !validName(iif)) return error.InvalidField;
    if (oif.len != 0 and !validName(oif)) return error.InvalidField;
    var src_family: ?vrouter.types.IpFamily = null;
    var dst_family: ?vrouter.types.IpFamily = null;
    if (src.len != 0) {
        if (!validPrefix(src)) return error.InvalidField;
        src_family = (vrouter.types.IpPrefix.parse(src) catch return error.InvalidField).family();
    }
    if (dst.len != 0) {
        if (!validPrefix(dst)) return error.InvalidField;
        dst_family = (vrouter.types.IpPrefix.parse(dst) catch return error.InvalidField).family();
    }
    if (src_family != null and dst_family != null and src_family.? != dst_family.?) return error.InvalidField;
    if (src_family) |value_family| if (!ruleFamilyAllows(family, value_family)) return error.InvalidField;
    if (dst_family) |value_family| if (!ruleFamilyAllows(family, value_family)) return error.InvalidField;
    if (std.mem.eql(u8, proto, "icmp") and !std.mem.eql(u8, family, "ipv4")) return error.InvalidField;
    if (std.mem.eql(u8, proto, "icmpv6") and std.mem.eql(u8, family, "ipv4")) return error.InvalidField;
    const sport_value = if (sport.len != 0) std.fmt.parseInt(u16, sport, 10) catch return error.InvalidField else 0;
    const dport_value = if (dport.len != 0) std.fmt.parseInt(u16, dport, 10) catch return error.InvalidField else 0;
    const port_proto = std.mem.eql(u8, proto, "tcp") or std.mem.eql(u8, proto, "udp");
    if (sport.len != 0 and (sport_value == 0 or !port_proto)) return error.InvalidField;
    if (dport.len != 0 and (dport_value == 0 or !port_proto)) return error.InvalidField;
    if (states.len != 0 and !std.mem.eql(u8, family, "ipv4")) return error.InvalidField;

    var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try rule.put(allocator, "action", .{ .string = try allocator.dupe(u8, action) });
    try rule.put(allocator, "family", .{ .string = try allocator.dupe(u8, family) });
    if (proto.len != 0) try rule.put(allocator, "proto", .{ .string = try allocator.dupe(u8, proto) });
    if (src.len != 0) try rule.put(allocator, "src", .{ .string = try allocator.dupe(u8, src) });
    if (dst.len != 0) try rule.put(allocator, "dst", .{ .string = try allocator.dupe(u8, dst) });
    if (sport.len != 0) try rule.put(allocator, "sport", .{ .integer = sport_value });
    if (dport.len != 0) try rule.put(allocator, "dport", .{ .integer = dport_value });
    if (iif.len != 0) try rule.put(allocator, "iif", .{ .string = try allocator.dupe(u8, iif) });
    if (oif.len != 0) try rule.put(allocator, "oif", .{ .string = try allocator.dupe(u8, oif) });
    var states_array = std.json.Array.init(allocator);
    var tokens = std.mem.tokenizeAny(u8, states, ", \t\r\n");
    while (tokens.next()) |token| {
        if (!firewallStateValid(token)) return error.InvalidField;
        for (states_array.items) |previous| {
            if (previous == .string and std.mem.eql(u8, previous.string, token)) return error.InvalidField;
        }
        try states_array.append(.{ .string = try allocator.dupe(u8, token) });
    }
    try rule.put(allocator, "ct_state", .{ .array = states_array });
    return rule;
}

fn firewallActionValid(action: []const u8) bool {
    return std.mem.eql(u8, action, "accept") or std.mem.eql(u8, action, "drop") or std.mem.eql(u8, action, "reject");
}

fn firewallStateValid(state: []const u8) bool {
    return std.mem.eql(u8, state, "new") or std.mem.eql(u8, state, "established") or
        std.mem.eql(u8, state, "related") or std.mem.eql(u8, state, "invalid");
}

fn firewallFormError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingField => "A required firewall field is missing.",
        error.InvalidField => "A firewall field has an invalid value. Check actions, addresses, ports and connection states.",
        error.InvalidIndex => "That firewall rule no longer exists.",
        error.InvalidAction => "Unknown firewall action.",
        error.InvalidConfig => "The firewall configuration has an unexpected shape.",
        error.MissingDraft => "The draft is missing. Reload the page and try again.",
        error.InvalidDraft => "The draft is invalid. Reload the page and try again.",
        else => @errorName(err),
    };
}

fn applyDhcpForm(allocator: std.mem.Allocator, servers: *std.json.Array, body: []const u8, action: []const u8) !void {
    if (std.mem.eql(u8, action, "add_server")) {
        try servers.append(.{ .object = try dhcpServerFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_server")) {
        const index = try formIndex(body);
        if (index >= servers.items.len) return error.InvalidIndex;
        const old = switch (servers.items[index]) {
            .object => |object| object,
            else => return error.InvalidDraft,
        };
        var server = try dhcpServerFromForm(allocator, body);
        if (old.get("reservations")) |reservations| {
            try server.put(allocator, "reservations", reservations);
        }
        servers.items[index] = .{ .object = server };
        return;
    }
    if (std.mem.eql(u8, action, "remove_server")) {
        const index = try formIndex(body);
        if (index >= servers.items.len) return error.InvalidIndex;
        _ = servers.orderedRemove(index);
        return;
    }
    if (std.mem.eql(u8, action, "add_reservation")) {
        const index = try formIndex(body);
        if (index >= servers.items.len) return error.InvalidIndex;
        const server = switch (servers.items[index]) {
            .object => |*object| object,
            else => return error.InvalidDraft,
        };
        const reservations = try ensureArrayField(allocator, server, "reservations");
        try reservations.append(.{ .object = try dhcpReservationFromForm(allocator, body) });
        return;
    }
    if (std.mem.eql(u8, action, "edit_reservation")) {
        const index = try formIndex(body);
        if (index >= servers.items.len) return error.InvalidIndex;
        const server = switch (servers.items[index]) {
            .object => |*object| object,
            else => return error.InvalidDraft,
        };
        const reservations = try ensureArrayField(allocator, server, "reservations");
        const res_index = try formReservationIndex(body);
        if (res_index >= reservations.items.len) return error.InvalidIndex;
        reservations.items[res_index] = .{ .object = try dhcpReservationFromForm(allocator, body) };
        return;
    }
    if (std.mem.eql(u8, action, "remove_reservation")) {
        const index = try formIndex(body);
        if (index >= servers.items.len) return error.InvalidIndex;
        const server = switch (servers.items[index]) {
            .object => |*object| object,
            else => return error.InvalidDraft,
        };
        const reservations = try ensureArrayField(allocator, server, "reservations");
        const res_index = try formReservationIndex(body);
        if (res_index >= reservations.items.len) return error.InvalidIndex;
        _ = reservations.orderedRemove(res_index);
        return;
    }
    return error.InvalidAction;
}

fn dhcpServerFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var iface_buf: [256]u8 = undefined;
    var pool_buf: [256]u8 = undefined;
    var lease_buf: [64]u8 = undefined;
    var dns_buf: [64]u8 = undefined;
    var domain_buf: [256]u8 = undefined;
    var mtu_buf: [16]u8 = undefined;
    var ntp_buf: [64]u8 = undefined;
    const iface = formValue(body, "iface", &iface_buf) orelse return error.MissingField;
    const pool = formValue(body, "pool", &pool_buf) orelse return error.MissingField;
    const lease = formValue(body, "lease", &lease_buf) orelse "12h";
    const dns = formValue(body, "dns", &dns_buf) orelse "";
    const domain = formValue(body, "domain", &domain_buf) orelse "";
    const mtu_text = formValue(body, "mtu", &mtu_buf) orelse "";
    const ntp = formValue(body, "ntp", &ntp_buf) orelse "";
    if (iface.len == 0 or pool.len == 0) return error.MissingField;
    var server = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try server.put(allocator, "iface", .{ .string = try allocator.dupe(u8, iface) });
    try server.put(allocator, "pool", .{ .string = try allocator.dupe(u8, pool) });
    if (lease.len != 0) try server.put(allocator, "lease", .{ .string = try allocator.dupe(u8, lease) });
    if (dns.len != 0) try server.put(allocator, "dns", .{ .string = try allocator.dupe(u8, dns) });
    if (domain.len != 0) try server.put(allocator, "domain", .{ .string = try allocator.dupe(u8, domain) });
    if (mtu_text.len != 0) {
        const mtu = std.fmt.parseInt(u16, mtu_text, 10) catch return error.InvalidField;
        if (mtu < 576) return error.InvalidField;
        try server.put(allocator, "mtu", .{ .integer = mtu });
    }
    if (ntp.len != 0) try server.put(allocator, "ntp", .{ .string = try allocator.dupe(u8, ntp) });
    return server;
}

fn dhcpReservationFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var mac_buf: [64]u8 = undefined;
    var ip_buf: [64]u8 = undefined;
    const mac = formValue(body, "mac", &mac_buf) orelse return error.MissingField;
    const ip = formValue(body, "ip", &ip_buf) orelse return error.MissingField;
    if (mac.len == 0 or ip.len == 0) return error.MissingField;
    _ = vrouter.types.Mac.parse(mac) catch return error.InvalidField;
    _ = vrouter.types.Ipv4.parse(ip) catch return error.InvalidField;
    var reservation = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try reservation.put(allocator, "mac", .{ .string = try allocator.dupe(u8, mac) });
    try reservation.put(allocator, "ip", .{ .string = try allocator.dupe(u8, ip) });
    return reservation;
}

fn formReservationIndex(body: []const u8) !usize {
    var index_buf: [24]u8 = undefined;
    const text = formValue(body, "res_index", &index_buf) orelse return error.MissingField;
    return std.fmt.parseInt(usize, text, 10) catch error.InvalidField;
}

fn dhcpFormError(err: anyerror) []const u8 {
    return switch (err) {
        error.MissingField => "A required field is missing.",
        error.InvalidField => "A field has an invalid value.",
        error.InvalidIndex => "That DHCP entry no longer exists.",
        error.InvalidAction => "Unknown DHCP action.",
        error.MissingDraft => "The draft is missing. Reload the page and try again.",
        error.InvalidDraft => "The draft is invalid. Reload the page and try again.",
        else => @errorName(err),
    };
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
            const live = findSnat(running, rule.out);
            masquerade[index] = .{
                .out = rule.out,
                .src = rule.src,
                .addr = rule.addr,
                .translated = if (live) |snat| snat.addr else "",
            };
        }
        view.masquerade = masquerade;
        const port_forward = try allocator.alloc(pages.NatForwardRow, value.port_forward.len);
        for (value.port_forward, 0..) |rule, index| {
            const parsed = splitHostPort(rule.to);
            port_forward[index] = .{
                .proto = rule.proto,
                .ext_port = rule.ext_port,
                .to_addr = if (parsed) |target| target.host else "",
                .to_port = if (parsed) |target| target.port else 0,
                .ingress = rule.ingress,
                .description = rule.description,
                .enabled = rule.enabled,
            };
        }
        view.port_forward = port_forward;
        view.pending = try natChangeCount(allocator, running, value);
    }
    return view;
}

fn findSnat(running: ?protocol.Nat, out: []const u8) ?protocol.Snat {
    if (running) |nat| {
        for (nat.snat) |rule| {
            if (std.mem.eql(u8, rule.out, out)) return rule;
        }
    }
    return null;
}

fn natDraftFromRunning(allocator: std.mem.Allocator, nat: protocol.Nat) !NatDraft {
    const masquerade = try allocator.alloc(NatDraftMasquerade, nat.snat.len);
    for (nat.snat, 0..) |rule, index| {
        masquerade[index] = .{
            .out = rule.out,
            .src = rule.src,
            .addr = if (rule.explicit) rule.addr else null,
        };
    }
    const port_forward = try allocator.alloc(NatDraftForward, nat.port_forward.len);
    for (nat.port_forward, 0..) |rule, index| {
        port_forward[index] = .{
            .proto = rule.proto,
            .ext_port = rule.ext_port,
            .to = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ rule.to_addr, rule.to_port }),
            .ingress = rule.ingress,
            .description = rule.description,
            .enabled = rule.enabled,
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
            const src = optionalDraftString(rule, "src") catch return error.InvalidDraft;
            const addr = optionalDraftString(rule, "addr") catch return error.InvalidDraft;
            masquerade[index] = .{ .out = out, .src = src, .addr = addr };
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
            const description = optionalDraftString(rule, "description") catch return error.InvalidDraft;
            const enabled = if (rule.get("enabled")) |enabled_value| switch (enabled_value) {
                .bool => |flag| flag,
                else => return error.InvalidDraft,
            } else true;
            port_forward[index] = .{
                .proto = proto,
                .ext_port = @intCast(ext_port),
                .to = to,
                .ingress = ingress,
                .description = description,
                .enabled = enabled,
            };
        }
    }

    return .{ .masquerade = masquerade, .port_forward = port_forward };
}

fn optionalDraftString(object: std.json.ObjectMap, name: []const u8) !?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| if (text.len == 0) null else text,
        .null => null,
        else => error.InvalidDraft,
    };
}

fn natDraftValue(allocator: std.mem.Allocator, draft: NatDraft) !std.json.Value {
    var root = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    var masquerade = std.json.Array.init(allocator);
    for (draft.masquerade) |source| {
        var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
        try rule.put(allocator, "out", .{ .string = source.out });
        if (source.src) |src| {
            if (src.len != 0) try rule.put(allocator, "src", .{ .string = src });
        }
        if (source.addr) |addr| {
            if (addr.len != 0) try rule.put(allocator, "addr", .{ .string = addr });
        }
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
        if (source.description) |description| {
            if (description.len > 0) try rule.put(allocator, "description", .{ .string = description });
        }
        if (!source.enabled) try rule.put(allocator, "enabled", .{ .bool = false });
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
            if (!masquerade_used[index] and masqueradeMatches(candidate, current)) {
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

fn masqueradeMatches(draft: NatDraftMasquerade, running: protocol.Snat) bool {
    return std.mem.eql(u8, draft.out, running.out) and
        optionalStringEql(draft.src, running.src) and
        optionalStringEql(draft.addr, if (running.explicit) running.addr else null);
}

fn forwardMatches(draft: NatDraftForward, running: protocol.PortForward) bool {
    const parsed = splitHostPort(draft.to) orelse return false;
    return std.mem.eql(u8, draft.proto, running.proto) and
        draft.ext_port == running.ext_port and
        std.mem.eql(u8, parsed.host, running.to_addr) and
        parsed.port == running.to_port and
        optionalStringEql(draft.ingress, running.ingress) and
        optionalStringEql(draft.description, running.description) and
        draft.enabled == running.enabled;
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
    var src_buf: [256]u8 = undefined;
    var addr_buf: [64]u8 = undefined;
    const out = formValue(body, "out", &out_buf) orelse return error.MissingField;
    const src = formValue(body, "src", &src_buf) orelse "";
    const addr = formValue(body, "addr", &addr_buf) orelse "";
    if (out.len == 0) return error.MissingField;
    if (src.len != 0) _ = vrouter.types.Prefix4.parse(src) catch return error.InvalidField;
    if (addr.len != 0) {
        const parsed = vrouter.types.Ipv4.parse(addr) catch return error.InvalidField;
        if (parsed.isUnspecified() or parsed.isMulticast()) return error.InvalidField;
    }
    var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try rule.put(allocator, "out", .{ .string = try allocator.dupe(u8, out) });
    if (src.len != 0) try rule.put(allocator, "src", .{ .string = try allocator.dupe(u8, src) });
    if (addr.len != 0) try rule.put(allocator, "addr", .{ .string = try allocator.dupe(u8, addr) });
    return rule;
}

fn forwardRuleFromForm(allocator: std.mem.Allocator, body: []const u8) !std.json.ObjectMap {
    var proto_buf: [16]u8 = undefined;
    var port_buf: [16]u8 = undefined;
    var to_buf: [256]u8 = undefined;
    var to_addr_buf: [64]u8 = undefined;
    var to_port_buf: [16]u8 = undefined;
    var ingress_buf: [128]u8 = undefined;
    var description_buf: [256]u8 = undefined;
    var enabled_buf: [8]u8 = undefined;
    const proto = formValue(body, "proto", &proto_buf) orelse "tcp";
    const port_text = formValue(body, "ext_port", &port_buf) orelse return error.MissingField;
    const combined = formValue(body, "to", &to_buf);
    const to_addr = formValue(body, "to_addr", &to_addr_buf) orelse "";
    const to_port_text = formValue(body, "to_port", &to_port_buf) orelse "";
    const ingress = formValue(body, "ingress", &ingress_buf) orelse "";
    const description = formValue(body, "description", &description_buf) orelse "";
    const ext_port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidField;
    if (ext_port == 0) return error.InvalidField;
    if (description.len > 128) return error.InvalidField;
    const to = if (combined) |value| value else blk: {
        if (to_addr.len == 0 or to_port_text.len == 0) return error.MissingField;
        const to_port = std.fmt.parseInt(u16, to_port_text, 10) catch return error.InvalidField;
        if (to_port == 0) return error.InvalidField;
        const ip = vrouter.types.Ipv4.parse(to_addr) catch return error.InvalidField;
        if (ip.isUnspecified() or ip.isMulticast()) return error.InvalidField;
        break :blk try std.fmt.allocPrint(allocator, "{s}:{d}", .{ to_addr, to_port });
    };
    _ = splitHostPort(to) orelse return error.InvalidField;
    var rule = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try rule.put(allocator, "proto", .{ .string = try allocator.dupe(u8, proto) });
    try rule.put(allocator, "ext_port", .{ .integer = ext_port });
    try rule.put(allocator, "to", .{ .string = try allocator.dupe(u8, to) });
    if (ingress.len != 0) {
        try rule.put(allocator, "in", .{ .string = try allocator.dupe(u8, ingress) });
    }
    if (description.len != 0) {
        try rule.put(allocator, "description", .{ .string = try allocator.dupe(u8, description) });
    }
    if (formValue(body, "enabled", &enabled_buf) == null) {
        try rule.put(allocator, "enabled", .{ .bool = false });
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
            const src = if (rule.get("src")) |value_string| switch (value_string) {
                .string => |text| text,
                else => return error.InvalidConfig,
            } else null;
            const addr = if (rule.get("addr")) |value_string| switch (value_string) {
                .string => |text| text,
                else => return error.InvalidConfig,
            } else null;
            masquerade[index] = .{ .out = out, .src = src, .addr = addr };
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
            const description = optionalDraftString(rule, "description") catch return error.InvalidDraft;
            const enabled = if (rule.get("enabled")) |enabled_value| switch (enabled_value) {
                .bool => |flag| flag,
                else => return error.InvalidDraft,
            } else true;
            port_forward[index] = .{
                .proto = proto,
                .ext_port = @intCast(ext_port),
                .to = to,
                .ingress = ingress,
                .description = description,
                .enabled = enabled,
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
    try std.testing.expectEqualStrings("wan0", staged.port_forward[0].ingress.?);
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

test "DHCP form stages servers and reservations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var servers = std.json.Array.init(allocator);

    try applyDhcpForm(
        allocator,
        &servers,
        "action=add_server&iface=lan0&pool=10.0.0.100-10.0.0.199&lease=1h&dns=10.0.0.1&domain=lan&mtu=1400",
        "add_server",
    );
    try std.testing.expectEqual(@as(usize, 1), servers.items.len);
    const server = switch (servers.items[0]) {
        .object => |object| object,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("lan0", server.get("iface").?.string);
    try std.testing.expectEqual(@as(i64, 1400), server.get("mtu").?.integer);

    try applyDhcpForm(
        allocator,
        &servers,
        "action=add_reservation&index=0&mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&ip=10.0.0.50",
        "add_reservation",
    );
    const with_reservation = switch (servers.items[0]) {
        .object => |object| object,
        else => return error.TestUnexpectedResult,
    };
    const reservations = with_reservation.get("reservations").?.array;
    try std.testing.expectEqual(@as(usize, 1), reservations.items.len);
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", reservations.items[0].object.get("mac").?.string);

    try applyDhcpForm(
        allocator,
        &servers,
        "action=edit_server&index=0&iface=lan9&pool=10.9.0.100-10.9.0.150&lease=2h",
        "edit_server",
    );
    const edited = switch (servers.items[0]) {
        .object => |object| object,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("lan9", edited.get("iface").?.string);
    try std.testing.expectEqual(@as(usize, 1), edited.get("reservations").?.array.items.len);
}

test "DNS form stages resolver settings and zones" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var dns = try std.json.ObjectMap.init(allocator, &.{}, &.{});

    try applyDnsForm(
        allocator,
        &dns,
        "action=save_settings&upstreams=1.1.1.1%2C+8.8.8.8&listen=10.0.0.1&max_entries=2048&cache=1&tcp=1",
        "save_settings",
    );
    try std.testing.expectEqual(@as(usize, 2), dns.get("upstreams").?.array.items.len);
    try std.testing.expectEqualStrings("10.0.0.1", dns.get("listen").?.string);
    try std.testing.expectEqual(@as(i64, 2048), dns.get("max_entries").?.integer);
    try std.testing.expect(dns.get("cache").?.bool);
    try std.testing.expect(dns.get("tcp").?.bool);

    try applyDnsForm(
        allocator,
        &dns,
        "action=add_zone&suffix=corp.example&zone_upstreams=10.0.0.53",
        "add_zone",
    );
    const zones = dns.get("zones").?.array;
    try std.testing.expectEqual(@as(usize, 1), zones.items.len);
    try std.testing.expectEqualStrings("corp.example", zones.items[0].object.get("suffix").?.string);
    try std.testing.expectEqualStrings("10.0.0.53", zones.items[0].object.get("upstreams").?.array.items[0].string);

    try applyDnsForm(allocator, &dns, "action=remove_zone&index=0", "remove_zone");
    try std.testing.expectEqual(@as(usize, 0), dns.get("zones").?.array.items.len);
}

test "DHCP drafts may be JSON arrays" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const input = try readDraftInput(arena.allocator(), "draft=%5B%5D");
    try std.testing.expect(input.value == .array);
}

test "pending detection ignores object order and null optionals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var running = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[{"iface":"lan0","pool":"192.168.1.100/24","lease":"12h","dns":null,"reservations":[]}]
    ,
        .{ .allocate = .alloc_always },
    );
    defer running.deinit();
    var draft = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[{"reservations":[],"lease":"12h","pool":"192.168.1.100/24","iface":"lan0"}]
    ,
        .{ .allocate = .alloc_always },
    );
    defer draft.deinit();

    const view = try buildDhcpView(allocator, "csrf", running.value, draft.value, "[]", null, null, null);
    try std.testing.expectEqual(@as(u8, 0), view.pending);
    try std.testing.expectEqual(@as(usize, 1), view.servers.len);

    var changed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[{"iface":"lan0","pool":"192.168.1.200/24","lease":"12h","reservations":[]}]
    ,
        .{ .allocate = .alloc_always },
    );
    defer changed.deinit();
    const pending = try buildDhcpView(allocator, "csrf", running.value, changed.value, "[]", null, null, null);
    try std.testing.expectEqual(@as(u8, 1), pending.pending);
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

test "route form stages add edit and remove" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var routes = std.json.Array.init(allocator);
    try applyRoutesForm(allocator, &routes, "action=add_route&dst=198.51.100.0/24&via=203.0.113.1&dev=wan0&metric=50&table=254", "add_route");
    try std.testing.expectEqual(@as(usize, 1), routes.items.len);
    try applyRoutesForm(allocator, &routes, "action=edit_route&index=0&dst=198.51.100.0/24&via=203.0.113.2&dev=wan0&metric=51&table=254", "edit_route");
    const row = try routeRowsFromValue(allocator, .{ .array = routes });
    try std.testing.expectEqualStrings("203.0.113.2", row[0].via);
    try std.testing.expectEqual(@as(i64, 51), row[0].metric);
    try applyRoutesForm(allocator, &routes, "action=remove_route&index=0", "remove_route");
    try std.testing.expectEqual(@as(usize, 0), routes.items.len);
}

test "interface draft converts rows to config maps" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const draft = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        \\{"ports":[{"name":"lan0","kind":"l2","device":"eth0"}],"bridges":[{"name":"br0","svi_count":1,"stp":true}],"interfaces":[{"name":"br0","address":"10.0.0.1/24"}]}
    ,
        .{},
    );
    var root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"ports\":{},\"bridges\":{},\"interfaces\":{}}", .{});
    try installInterfaceSections(allocator, &root.object, draft);
    const ports = root.object.get("ports").?.object;
    try std.testing.expect(ports.get("lan0") != null);
    try std.testing.expect(ports.get("lan0").?.object.get("name") == null);
    const bridges = root.object.get("bridges").?.object;
    try std.testing.expect(bridges.get("br0").?.object.get("svi_count") == null);
    try std.testing.expect(root.object.get("interfaces").?.object.get("br0") != null);
}

test "strip nulls removes optional fields recursively" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var value = try std.json.parseFromSliceLeaky(
        std.json.Value,
        allocator,
        \\{"a":null,"b":{"c":null,"d":1},"e":[{"f":null,"g":"x"}]}
    ,
        .{},
    );
    stripNulls(&value);
    try std.testing.expect(value.object.get("a") == null);
    try std.testing.expect(value.object.get("b").?.object.get("c") == null);
    try std.testing.expect(value.object.get("b").?.object.get("d") != null);
    try std.testing.expect(value.object.get("e").?.array.items[0].object.get("f") == null);
    try std.testing.expect(value.object.get("e").?.array.items[0].object.get("g") != null);
}

test "logging draft validates level and format" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const valid = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"level\":\"debug\",\"format\":\"json\",\"revision\":\"sha256:abc\"}", .{});
    const draft = try loggingDraftFromValue(valid);
    try std.testing.expectEqualStrings("debug", draft.level);
    try std.testing.expectEqualStrings("json", draft.format);
    try std.testing.expectEqualStrings("sha256:abc", draft.revision);
    const bad_level = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"level\":\"verbose\",\"format\":\"text\"}", .{});
    try std.testing.expectError(error.InvalidLevel, loggingDraftFromValue(bad_level));
    const bad_trace = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"level\":\"trace\",\"format\":\"text\"}", .{});
    try std.testing.expectError(error.InvalidLevel, loggingDraftFromValue(bad_trace));
    const bad_format = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"level\":\"info\",\"format\":\"xml\"}", .{});
    try std.testing.expectError(error.InvalidFormat, loggingDraftFromValue(bad_format));

    var config = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"instance\":\"test\",\"log\":{\"level\":\"info\",\"format\":\"text\"}}", .{});
    try installLog(allocator, &config, "err", "json");
    const log = config.object.get("log").?.object;
    try std.testing.expectEqualStrings("err", log.get("level").?.string);
    try std.testing.expectEqualStrings("json", log.get("format").?.string);
}

test "route form rejects malformed prefixes and gateways" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectError(error.InvalidField, routeFromForm(allocator, "dst=198.51.100.0&dev=wan0"));
    try std.testing.expectError(error.InvalidField, routeFromForm(allocator, "dst=198.51.100.0/24&dev="));
    try std.testing.expectError(error.InvalidField, routeFromForm(allocator, "dst=198.51.100.0/24&via=2001:db8::1&dev=wan0"));
    try std.testing.expectError(error.InvalidField, routeFromForm(allocator, "dst=198.51.100.0/24&via=not-an-ip&dev=wan0"));
}

test "firewall form rejects invalid families ports and states" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try std.testing.expectError(error.InvalidField, firewallRuleFromForm(allocator, "rule_action=accept&family=ipv4&dst=10.0.0.1"));
    try std.testing.expectError(error.InvalidField, firewallRuleFromForm(allocator, "rule_action=accept&family=ipv6&proto=icmp"));
    try std.testing.expectError(error.InvalidField, firewallRuleFromForm(allocator, "rule_action=accept&family=ipv6&ct_state=new"));
    try std.testing.expectError(error.InvalidField, firewallRuleFromForm(allocator, "rule_action=accept&family=ipv4&proto=tcp&dport=0"));
    try std.testing.expectError(error.InvalidField, firewallRuleFromForm(allocator, "rule_action=accept&family=ipv4&dport=80"));
    try std.testing.expectError(error.InvalidField, firewallRuleFromForm(allocator, "rule_action=accept&family=ipv4&proto=icmp&src=2001:db8::1/64"));
}

test "interface form rejects cross-resource names and bridge vlan conflicts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const input =
        \\{"ports":[{"name":"lan0","kind":"l2","device":"eth0"}],"bridges":[{"name":"br0","ports":["lan0"],"vlan_aware":false,"offload":"none"}],"interfaces":[]}
    ;
    var first = try std.json.parseFromSliceLeaky(std.json.Value, allocator, input, .{});
    try std.testing.expectError(error.InvalidField, applyInterfacesForm(allocator, &first.object, "action=add_interface&name=lan0&bridge=br0&address=10.0.0.1/24", "add_interface"));
    var second = try std.json.parseFromSliceLeaky(std.json.Value, allocator, input, .{});
    try std.testing.expectError(error.InvalidField, applyInterfacesForm(allocator, &second.object, "action=add_interface&name=svi&bridge=br0&address=10.0.0.1/24&vlan=5", "add_interface"));
    try std.testing.expect(findRow(rowArray(second.object.get("interfaces")).?, "svi") == null);
    var third = try std.json.parseFromSliceLeaky(std.json.Value, allocator, input, .{});
    try applyInterfacesForm(allocator, &third.object, "action=add_interface&name=svi&bridge=br0&address=10.0.0.1/24", "add_interface");
    try std.testing.expect(findRow(rowArray(third.object.get("interfaces")).?, "svi") != null);
}

test "generated interface route and firewall config passes the real parser" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ports = std.json.Array.init(allocator);
    try ports.append(.{ .object = try portFromForm(allocator, "name=lan9&kind=l2&device=eth9&mtu=1500&pvid=1&tagged=10%2C20&storm_control=1000") });
    var bridges = std.json.Array.init(allocator);
    try bridges.append(.{ .object = try bridgeFromForm(allocator, "name=br9&ports=lan9&offload=none&stp=1&vlan_aware=1") });
    var interfaces = std.json.Array.init(allocator);
    try interfaces.append(.{ .object = try interfaceFromForm(allocator, "name=svi9&bridge=br9&address=10.99.0.1/24&addresses=2001%3Adb8%3A99%3A%3A1/64&vlan=10") });
    var draft = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try draft.put(allocator, "ports", .{ .array = ports });
    try draft.put(allocator, "bridges", .{ .array = bridges });
    try draft.put(allocator, "interfaces", .{ .array = interfaces });
    try validateInterfaceDraft(allocator, &draft);

    var root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, "{\"version\":1,\"instance\":\"web-test\"}", .{});
    try installInterfaceSections(allocator, &root.object, .{ .object = draft });
    var routes = std.json.Array.init(allocator);
    try routes.append(.{ .object = try routeFromForm(allocator, "dst=198.51.100.0/24&via=203.0.113.1&dev=svi9&metric=50&table=254") });
    try root.object.put(allocator, "routes", .{ .array = routes });
    var firewall = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try firewall.put(allocator, "default_out", .{ .string = "accept" });
    var rules = std.json.Array.init(allocator);
    try rules.append(.{ .object = try firewallRuleFromForm(allocator, "rule_action=accept&family=ipv4&proto=tcp&dst=10.99.0.10/32&dport=8080") });
    try firewall.put(allocator, "rules", .{ .array = rules });
    try root.object.put(allocator, "firewall", .{ .object = firewall });

    stripNulls(&root);
    const text = try jsonStringify(allocator, root);
    var parsed = try vrouter.config_parse.parse(allocator, text);
    defer parsed.deinit();
    try vrouter.config_validate.validate(&parsed.config);
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
