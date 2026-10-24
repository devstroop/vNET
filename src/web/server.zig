//! Read-only web admin preview.
//!
//! The process is deliberately unprivileged and derives every piece of state
//! from the existing Unix control socket. It never mutates the host directly.

const std = @import("std");
const vrouter = @import("vrouter");
const auth = @import("auth.zig");
const html = @import("html.zig");
const protocol = vrouter.control_protocol;

const cookie_name = "vrouter_session";
const max_login_body = 512;
const max_password_len = 256;
const login_max_failures = 5;
const login_lock_ms = 30_000;

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
        var send_buf: [32 * 1024]u8 = undefined;
        var reader = stream.reader(self.io, &recv_buf);
        var writer = stream.writer(self.io, &send_buf);
        var server = std.http.Server.init(&reader.interface, &writer.interface);

        while (server.reader.state == .ready) {
            var request = server.receiveHead() catch |err| switch (err) {
                error.HttpConnectionClosing => return,
                else => return err,
            };
            self.serve(&request) catch |err| {
                std.log.err("web request {s} failed: {t}", .{ request.head.target, err });
                return;
            };
        }
    }

    fn serve(self: *App, request: *std.http.Server.Request) !void {
        const path = std.mem.sliceTo(request.head.target, '?');
        const method = request.head.method;
        fixMissingBodyLength(request);

        if (!self.hostAllowed(request)) return self.htmlError(request, .bad_request, "Unexpected Host header.");

        if (std.mem.eql(u8, path, "/healthz")) {
            if (method != .GET and method != .HEAD) return self.methodNotAllowed(request);
            return self.respond(request, .ok, "text/plain; charset=utf-8", "ok\n", &.{});
        }

        if (std.mem.eql(u8, path, "/login")) {
            return switch (method) {
                .GET, .HEAD => self.serveLogin(request, false),
                .POST => self.serveLoginPost(request),
                else => self.methodNotAllowed(request),
            };
        }

        if (std.mem.eql(u8, path, "/logout")) {
            if (method != .POST) return self.methodNotAllowed(request);
            return self.serveLogout(request);
        }

        if (method != .GET and method != .HEAD) return self.methodNotAllowed(request);

        if (self.sessionCsrf(request) == null) return self.redirect(request, "/login", &.{});

        if (std.mem.eql(u8, path, "/")) return self.serveStatus(request);
        if (std.mem.eql(u8, path, "/nat")) return self.serveNat(request);
        if (std.mem.eql(u8, path, "/conntrack")) return self.serveConntrack(request);
        return self.notFound(request);
    }

    fn serveLogin(self: *App, request: *std.http.Server.Request, failed: bool) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try html.begin(&out.writer, "Sign in", null);
        try out.writer.writeAll(
            \\<h1>Sign in</h1>
            \\<p class="sub">Read-only access to the running vRouter instance.</p>
            \\<section>
            \\<form method="post" action="/login">
            \\<label for="password">Admin password</label>
            \\<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
            \\<p></p>
            \\<button type="submit">Sign in</button>
            \\</form>
        );
        if (failed) try out.writer.writeAll("<p class=\"error\">Invalid password.</p>");
        try out.writer.writeAll("</section>");
        try html.end(&out.writer);
        try self.respond(request, .ok, "text/html; charset=utf-8", out.written(), &.{});
    }

    fn serveLoginPost(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) return self.htmlError(request, .forbidden, "Cross-origin request rejected.");

        const now = std.Io.Clock.real.now(self.io).toMilliseconds();
        if (now < self.login_locked_until_ms) return self.htmlError(request, .too_many_requests, "Too many attempts. Try again shortly.");

        var body_buf: [max_login_body]u8 = undefined;
        const body_reader = request.readerExpectContinue(&body_buf) catch
            return self.htmlError(request, .bad_request, "Unsupported request expectation.");
        const body = body_reader.allocRemaining(self.gpa, .limited(max_login_body)) catch
            return self.htmlError(request, .bad_request, "Request body is too large.");
        defer self.gpa.free(body);

        var password_buf: [max_password_len]u8 = undefined;
        const password = formValue(&password_buf, body, "password") orelse "";
        if (password.len == 0 or !auth.verifyPassword(self.io, self.gpa, self.password_phc, password)) {
            self.login_failures += 1;
            if (self.login_failures >= login_max_failures) {
                self.login_failures = 0;
                self.login_locked_until_ms = now + login_lock_ms;
            }
            return self.serveLogin(request, true);
        }

        self.login_failures = 0;
        const created = try self.sessions.create(self.io, now, self.session_ttl_ms);
        var cookie_buf: [192]u8 = undefined;
        const cookie = try std.fmt.bufPrint(&cookie_buf, "{s}={s}; HttpOnly; SameSite=Strict; Path=/; Max-Age={d}", .{
            cookie_name,
            created.token,
            @divTrunc(self.session_ttl_ms, 1000),
        });
        return self.redirect(request, "/", &.{.{ .name = "set-cookie", .value = cookie }});
    }

    fn serveLogout(self: *App, request: *std.http.Server.Request) !void {
        if (!self.sameOrigin(request)) return self.htmlError(request, .forbidden, "Cross-origin request rejected.");
        const token = getCookie(request, cookie_name) orelse return self.htmlError(request, .forbidden, "Missing session.");
        const expected = self.sessions.csrfFor(self.io, token, std.Io.Clock.real.now(self.io).toMilliseconds()) orelse
            return self.htmlError(request, .forbidden, "Session expired.");

        var body_buf: [max_login_body]u8 = undefined;
        const body_reader = request.readerExpectContinue(&body_buf) catch
            return self.htmlError(request, .bad_request, "Unsupported request expectation.");
        const body = body_reader.allocRemaining(self.gpa, .limited(max_login_body)) catch
            return self.htmlError(request, .bad_request, "Request body is too large.");
        defer self.gpa.free(body);

        var csrf_buf: [max_password_len]u8 = undefined;
        const csrf = formValue(&csrf_buf, body, "csrf") orelse "";
        if (csrf.len != auth.token_hex_len) return self.htmlError(request, .forbidden, "Invalid CSRF token.");
        var candidate: [auth.token_hex_len]u8 = undefined;
        @memcpy(&candidate, csrf);
        if (!std.crypto.timing_safe.eql([auth.token_hex_len]u8, expected, candidate)) {
            return self.htmlError(request, .forbidden, "Invalid CSRF token.");
        }

        self.sessions.remove(self.io, token);
        return self.redirect(request, "/login", &.{.{ .name = "set-cookie", .value = cookie_name ++ "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" }});
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

    fn serveStatus(self: *App, request: *std.http.Server.Request) !void {
        var response = self.call("status", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const status = response.value.status orelse return self.controlError(request, error.MissingStatus);

        const csrf = self.sessionCsrf(request) orelse return self.redirect(request, "/login", &.{});
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const w = &out.writer;
        try html.begin(w, "Overview", csrf[0..]);
        try w.writeAll("<h1>Overview</h1><p class=\"sub\">Live control-plane snapshot.</p>");
        try w.writeAll("<section><h2>Instance</h2><div class=\"grid\">");
        try statText(w, "Instance", status.instance);
        try statText(w, "Version", status.version);
        try statInt(w, "PID", status.pid);
        try statInt(w, "Ports", status.ports);
        try w.writeAll("</div></section>");

        try w.writeAll("<section><h2>Uptime</h2><div class=\"grid\">");
        try durationStat(w, "Uptime", status.uptime_ms);
        try durationStat(w, "Since update", @max(0, std.Io.Clock.real.now(self.io).toMilliseconds() - status.updated_ms));
        try w.writeAll("</div></section>");

        const c = status.counters;
        try w.writeAll("<section><h2>Traffic</h2><table><thead><tr><th>Counter</th><th>Value</th></tr></thead><tbody>");
        try counterRow(w, "IPv4 forwarded", c.forwarded);
        try counterRow(w, "Bridged", c.bridged);
        try counterRow(w, "Dropped", c.dropped);
        try counterRow(w, "Firewall dropped", c.firewall_dropped);
        try counterRow(w, "Conntrack created", c.conntrack_created);
        try counterRow(w, "Conntrack hits", c.conntrack_hits);
        try counterRow(w, "SNAT packets", c.snat_packets);
        try counterRow(w, "DNAT packets", c.dnat_packets);
        try counterRow(w, "DHCP ACKs", c.dhcp_acks);
        try counterRow(w, "IPv6 forwarded", c.ipv6_forwarded);
        try w.writeAll("</tbody></table></section>");

        try w.writeAll("<section><h2>Runtime paths</h2><table><tbody>");
        try pathRow(w, "State directory", status.state_dir);
        try pathRow(w, "Control socket", status.control_path);
        try w.writeAll("</tbody></table></section>");
        try html.end(w);
        try self.respond(request, .ok, "text/html; charset=utf-8", out.written(), &.{});
    }

    fn serveNat(self: *App, request: *std.http.Server.Request) !void {
        var response = self.call("nat.list", null, null) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const nat = response.value.nat orelse return self.controlError(request, error.MissingNat);

        const csrf = self.sessionCsrf(request) orelse return self.redirect(request, "/login", &.{});
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const w = &out.writer;
        try html.begin(w, "NAT", csrf[0..]);
        try w.writeAll("<h1>NAT</h1><p class=\"sub\">Configured source NAT and port forwards.</p>");
        try w.writeAll("<section><h2>Masquerade</h2>");
        if (nat.snat.len == 0) {
            try w.writeAll("<p class=\"empty\">No masquerade rules.</p>");
        } else {
            try w.writeAll("<table><thead><tr><th>Egress</th><th>Source address</th></tr></thead><tbody>");
            for (nat.snat) |rule| {
                try w.writeAll("<tr><td><code>");
                try html.writeEscaped(w, rule.out);
                try w.writeAll("</code></td><td><code>");
                try html.writeEscaped(w, rule.addr);
                try w.writeAll("</code></td></tr>");
            }
            try w.writeAll("</tbody></table>");
        }
        try w.writeAll("</section><section><h2>Port forwards</h2>");
        if (nat.port_forward.len == 0) {
            try w.writeAll("<p class=\"empty\">No port-forward rules.</p>");
        } else {
            try w.writeAll("<table><thead><tr><th>Proto</th><th>External</th><th>Destination</th><th>Ingress</th></tr></thead><tbody>");
            for (nat.port_forward) |rule| {
                try w.writeAll("<tr><td><code>");
                try html.writeEscaped(w, rule.proto);
                try w.print("</code></td><td>{d}</td><td><code>", .{rule.ext_port});
                try html.writeEscaped(w, rule.to_addr);
                try w.print(":{d}</code></td><td>", .{rule.to_port});
                if (rule.ingress) |ingress| try html.writeEscaped(w, ingress) else try w.writeAll("<span class=\"muted\">any</span>");
                try w.writeAll("</td></tr>");
            }
            try w.writeAll("</tbody></table>");
        }
        try w.writeAll("</section>");
        try html.end(w);
        try self.respond(request, .ok, "text/html; charset=utf-8", out.written(), &.{});
    }

    fn serveConntrack(self: *App, request: *std.http.Server.Request) !void {
        var response = self.call("conntrack.list", null, 100) catch |err| return self.controlError(request, err);
        defer response.deinit();
        const table = response.value.conntrack orelse return self.controlError(request, error.MissingConntrack);

        const csrf = self.sessionCsrf(request) orelse return self.redirect(request, "/login", &.{});
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const w = &out.writer;
        try html.begin(w, "Conntrack", csrf[0..]);
        try w.print("<h1>Conntrack</h1><p class=\"sub\">Showing {d} of {d} active flows.</p>", .{ table.returned, table.total });
        if (table.entries.len == 0) {
            try w.writeAll("<section><p class=\"empty\">No active flows.</p></section>");
        } else {
            try w.writeAll("<section><table><thead><tr><th>Proto</th><th>State</th><th>Source</th><th>Destination</th><th>Translated</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>");
            for (table.entries) |entry| {
                try w.writeAll("<tr><td><code>");
                try html.writeEscaped(w, entry.proto);
                try w.writeAll("</code></td><td><span class=\"pill\">");
                try html.writeEscaped(w, entry.state);
                try w.writeAll("</span></td><td><code>");
                try html.writeEscaped(w, entry.src);
                try w.print(":{d}</code></td><td><code>", .{entry.sport});
                try html.writeEscaped(w, entry.dst);
                try w.print(":{d}</code></td><td><code>", .{entry.dport});
                try connectionLabel(w, entry);
                try w.print("</code></td><td>{d}</td><td>{d}</td></tr>", .{ entry.packets, entry.bytes });
            }
            try w.writeAll("</tbody></table></section>");
        }
        try html.end(w);
        try self.respond(request, .ok, "text/html; charset=utf-8", out.written(), &.{});
    }

    fn call(self: *App, op: []const u8, state_filter: ?[]const u8, limit: ?u32) !std.json.Parsed(protocol.Response) {
        var client = try vrouter.control_client.Client.connect(self.io, self.gpa, self.control_path);
        defer client.deinit();
        return client.callOp(op, state_filter, limit);
    }

    fn controlError(self: *App, request: *std.http.Server.Request, err: anyerror) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const w = &out.writer;
        const csrf = self.sessionCsrf(request);
        try html.begin(w, "Daemon unavailable", if (csrf) |value| @as([]const u8, &value) else null);
        try w.writeAll("<h1>Daemon unavailable</h1><p class=\"sub\">The web preview cannot reach the control socket.</p><section><p>");
        try w.print("Control error: <code>{s}</code>", .{@errorName(err)});
        try w.writeAll("</p><p class=\"muted\">Start <code>vrouterd</code> and refresh this page.</p></section>");
        try html.end(w);
        try self.respond(request, .service_unavailable, "text/html; charset=utf-8", out.written(), &.{});
    }

    fn htmlError(self: *App, request: *std.http.Server.Request, status: std.http.Status, message: []const u8) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        const w = &out.writer;
        try html.begin(w, "Error", null);
        try w.writeAll("<h1>Request rejected</h1><section><p>");
        try html.writeEscaped(w, message);
        try w.writeAll("</p></section>");
        try html.end(w);
        try self.respond(request, status, "text/html; charset=utf-8", out.written(), &.{});
    }

    fn notFound(self: *App, request: *std.http.Server.Request) !void {
        return self.htmlError(request, .not_found, "Page not found.");
    }

    fn methodNotAllowed(self: *App, request: *std.http.Server.Request) !void {
        return self.htmlError(request, .method_not_allowed, "Method not allowed.");
    }

    fn redirect(self: *App, request: *std.http.Server.Request, location: []const u8, extra: []const std.http.Header) !void {
        _ = self;
        fixMissingBodyLength(request);
        var headers: [8]std.http.Header = undefined;
        var n: usize = 0;
        headers[n] = .{ .name = "location", .value = location };
        n += 1;
        headers[n] = .{ .name = "cache-control", .value = "no-store" };
        n += 1;
        for (extra) |header| {
            if (n == headers.len) return error.TooManyHeaders;
            headers[n] = header;
            n += 1;
        }
        try request.respond("", .{ .status = .see_other, .extra_headers = headers[0..n] });
    }

    fn respond(
        self: *App,
        request: *std.http.Server.Request,
        status: std.http.Status,
        content_type: []const u8,
        body: []const u8,
        extra: []const std.http.Header,
    ) !void {
        _ = self;
        fixMissingBodyLength(request);
        var headers: [16]std.http.Header = undefined;
        var n: usize = 0;
        headers[n] = .{ .name = "content-type", .value = content_type };
        n += 1;
        headers[n] = .{ .name = "cache-control", .value = "no-store" };
        n += 1;
        headers[n] = .{ .name = "x-content-type-options", .value = "nosniff" };
        n += 1;
        headers[n] = .{ .name = "x-frame-options", .value = "DENY" };
        n += 1;
        headers[n] = .{ .name = "referrer-policy", .value = "no-referrer" };
        n += 1;
        headers[n] = .{ .name = "content-security-policy", .value = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" };
        n += 1;
        for (extra) |header| {
            if (n == headers.len) return error.TooManyHeaders;
            headers[n] = header;
            n += 1;
        }
        try request.respond(body, .{ .status = status, .extra_headers = headers[0..n] });
    }
};

/// A POST with neither Content-Length nor Transfer-Encoding has no body. The
/// HTTP server's discard helper asserts on that combination, so normalize it
/// before responding.
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

fn formValue(out: []u8, body: []const u8, key: []const u8) ?[]const u8 {
    var fields = std.mem.splitScalar(u8, body, '&');
    while (fields.next()) |field| {
        const eq = std.mem.findScalar(u8, field, '=') orelse continue;
        if (!std.mem.eql(u8, field[0..eq], key)) continue;
        return urlDecode(out, field[eq + 1 ..]);
    }
    return null;
}

fn urlDecode(out: []u8, input: []const u8) ?[]const u8 {
    var i: usize = 0;
    var o: usize = 0;
    while (i < input.len) {
        if (o == out.len) return null;
        switch (input[i]) {
            '+' => {
                out[o] = ' ';
                i += 1;
            },
            '%' => {
                if (i + 2 >= input.len) return null;
                const hi = hexDigit(input[i + 1]) orelse return null;
                const lo = hexDigit(input[i + 2]) orelse return null;
                out[o] = (hi << 4) | lo;
                i += 3;
            },
            else => {
                out[o] = input[i];
                i += 1;
            },
        }
        o += 1;
    }
    return out[0..o];
}

fn hexDigit(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn statText(w: *std.Io.Writer, label: []const u8, value: []const u8) !void {
    try w.writeAll("<div class=\"stat\"><span class=\"muted\">");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><b>");
    try html.writeEscaped(w, value);
    try w.writeAll("</b></div>");
}

fn statInt(w: *std.Io.Writer, label: []const u8, value: u64) !void {
    try w.writeAll("<div class=\"stat\"><span class=\"muted\">");
    try html.writeEscaped(w, label);
    try w.print("</span><b>{d}</b></div>", .{value});
}

fn durationStat(w: *std.Io.Writer, label: []const u8, ms: i64) !void {
    try w.writeAll("<div class=\"stat\"><span class=\"muted\">");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><b>");
    try formatDuration(w, ms);
    try w.writeAll("</b></div>");
}

fn formatDuration(w: *std.Io.Writer, ms: i64) !void {
    const total_seconds: i64 = @divTrunc(@max(ms, 0), 1000);
    const days = @divTrunc(total_seconds, 86_400);
    const hours = @divTrunc(@mod(total_seconds, 86_400), 3_600);
    const minutes = @divTrunc(@mod(total_seconds, 3_600), 60);
    const seconds = @mod(total_seconds, 60);
    if (days > 0) {
        try w.print("{d}d {d}h {d}m", .{ days, hours, minutes });
    } else if (hours > 0) {
        try w.print("{d}h {d}m {d}s", .{ hours, minutes, seconds });
    } else if (minutes > 0) {
        try w.print("{d}m {d}s", .{ minutes, seconds });
    } else {
        try w.print("{d}s", .{seconds});
    }
}

fn counterRow(w: *std.Io.Writer, label: []const u8, value: u64) !void {
    try w.writeAll("<tr><td>");
    try html.writeEscaped(w, label);
    try w.print("</td><td>{d}</td></tr>", .{value});
}

fn pathRow(w: *std.Io.Writer, label: []const u8, value: []const u8) !void {
    try w.writeAll("<tr><td>");
    try html.writeEscaped(w, label);
    try w.writeAll("</td><td><code>");
    try html.writeEscaped(w, value);
    try w.writeAll("</code></td></tr>");
}

fn connectionLabel(w: *std.Io.Writer, entry: protocol.ConntrackEntry) !void {
    if (entry.translated_src) |src| {
        try html.writeEscaped(w, src);
        try w.print(":{d}", .{entry.translated_sport});
        if (entry.translated_dst) |dst| {
            try w.writeAll(" -> ");
            try html.writeEscaped(w, dst);
            try w.print(":{d}", .{entry.translated_dport});
        }
        return;
    }
    if (entry.translated_dst) |dst| {
        try html.writeEscaped(w, dst);
        try w.print(":{d}", .{entry.translated_dport});
        return;
    }
    try w.writeAll("direct");
}

test "url decoding" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a b%c", urlDecode(&buf, "a+b%25c").?);
    try std.testing.expect(urlDecode(&buf, "%zz") == null);
}

test "form values" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("form-value", formValue(&buf, "x=1&field=form-value", "field").?);
    try std.testing.expect(formValue(&buf, "field=", "field").?.len == 0);
    try std.testing.expect(formValue(&buf, "other=1", "field") == null);
}

test "loopback detection" {
    try std.testing.expect(isLoopback(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080")));
    try std.testing.expect(isLoopback(try std.Io.net.IpAddress.parseLiteral("[::1]:8080")));
    try std.testing.expect(!isLoopback(try std.Io.net.IpAddress.parseLiteral("192.0.2.1:8080")));
    try std.testing.expect(!isLoopback(try std.Io.net.IpAddress.parseLiteral("[2001:db8::1]:8080")));
}
