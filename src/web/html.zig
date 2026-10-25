//! Small server-side HTML helpers for the HTMX admin. Every value that comes
//! from the control plane or the request is escaped at the boundary.

const std = @import("std");
const assets = @import("assets.zig");

pub const Page = enum { overview, nat, dhcp, dns, connections, system };

pub const PageOptions = struct {
    title: []const u8,
    subtitle: []const u8,
    active: Page,
    csrf: []const u8,
    body: []const u8,
};

pub fn writeEscaped(w: *std.Io.Writer, value: []const u8) !void {
    for (value) |byte| {
        switch (byte) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&#39;"),
            else => try w.writeByte(byte),
        }
    }
}

pub fn writePage(w: *std.Io.Writer, opts: PageOptions) !void {
    try w.writeAll(
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\  <meta charset="utf-8">
        \\  <meta name="viewport" content="width=device-width, initial-scale=1">
        \\  <title>
    );
    try writeEscaped(w, opts.title);
    try w.writeAll(
        \\ · vRouter</title>
        \\  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        \\  <script src="/assets/theme-init.js"></script>
        \\  <link rel="stylesheet" href="/assets/app.css?v=
    );
    try w.writeAll(assets.app_css_rev);
    try w.writeAll(
        \\">
        \\  <script src="/assets/htmx.min.js" defer></script>
        \\  <script src="/assets/app.js?v=
    );
    try w.writeAll(assets.app_js_rev);
    try w.writeAll(
        \\" defer></script>
        \\</head>
        \\<body>
        \\<div class="app-shell">
        \\  <aside class="sidebar">
        \\    <a class="brand" href="/overview" aria-label="vRouter overview">
        \\      <span class="brand-mark">VR</span>
        \\      <span class="brand-copy"><strong>vRouter</strong><small>Admin preview</small></span>
        \\    </a>
        \\    <nav class="nav" aria-label="Primary">
    );
    try writeNav(w, opts.active);
    try w.writeAll(
        \\    </nav>
        \\    <div class="sidebar-foot">
        \\      <span class="status-dot"></span>
        \\      <span>Local administration</span>
        \\    </div>
        \\  </aside>
        \\  <main class="main">
        \\    <header class="topbar">
        \\      <div class="topbar-title">
        \\        <p class="eyebrow">Local control plane</p>
        \\        <h1>
    );
    try writeEscaped(w, opts.title);
    try w.writeAll(
        \\</h1>
        \\        <p class="subtitle">
    );
    try writeEscaped(w, opts.subtitle);
    try w.writeAll(
        \\</p>
        \\      </div>
        \\      <div class="topbar-actions">
        \\        <button class="button button-ghost" type="button" data-theme-toggle>Theme</button>
        \\        <form method="post" action="/logout" class="inline-form">
        \\          <input type="hidden" name="csrf" value="
    );
    try writeEscaped(w, opts.csrf);
    try w.writeAll(
        \\">
        \\          <button class="button button-ghost" type="submit">Sign out</button>
        \\        </form>
        \\      </div>
        \\    </header>
        \\    <div id="refresh-indicator" class="htmx-indicator" aria-live="polite">Refreshing…</div>
        \\
    );
    try w.writeAll(opts.body);
    try w.writeAll(
        \\  </main>
        \\</div>
        \\</body>
        \\</html>
        \\
    );
}

fn writeNav(w: *std.Io.Writer, active: Page) !void {
    const items = [_]struct { page: Page, href: []const u8, label: []const u8 }{
        .{ .page = .overview, .href = "/overview", .label = "Overview" },
        .{ .page = .nat, .href = "/nat", .label = "NAT" },
        .{ .page = .dhcp, .href = "/dhcp", .label = "DHCP" },
        .{ .page = .dns, .href = "/dns", .label = "DNS" },
        .{ .page = .connections, .href = "/connections", .label = "Connections" },
        .{ .page = .system, .href = "/system", .label = "System" },
    };
    for (items) |item| {
        try w.writeAll("<a class=\"nav-link");
        if (item.page == active) try w.writeAll(" is-active");
        try w.writeAll("\" href=\"");
        try w.writeAll(item.href);
        try w.writeAll("\"");
        if (item.page == active) try w.writeAll(" aria-current=\"page\"");
        try w.writeAll(">");
        try w.writeAll(item.label);
        try w.writeAll("</a>");
    }
}

pub fn writeLoginPage(w: *std.Io.Writer, error_message: ?[]const u8) !void {
    try w.writeAll(
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\  <meta charset="utf-8">
        \\  <meta name="viewport" content="width=device-width, initial-scale=1">
        \\  <title>Sign in · vRouter</title>
        \\  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
        \\  <script src="/assets/theme-init.js"></script>
        \\  <link rel="stylesheet" href="/assets/app.css?v=
    );
    try w.writeAll(assets.app_css_rev);
    try w.writeAll(
        \\">
        \\</head>
        \\<body class="login-body">
        \\<main class="login-shell">
        \\  <section class="login-hero">
        \\    <a class="brand brand-on-dark" href="/login" aria-label="vRouter">
        \\      <span class="brand-mark">VR</span>
        \\      <span class="brand-copy"><strong>vRouter</strong><small>Admin preview</small></span>
        \\    </a>
        \\    <div class="login-hero-copy">
        \\      <span class="pill">Local control plane</span>
        \\      <h1>Your network,<br>without the noise.</h1>
        \\      <p>Inspect forwarding, NAT and live connection state from a focused local console. NAT edits are staged and applied explicitly.</p>
        \\      <ul class="check-list">
        \\        <li>Session-protected, loopback-only access</li>
        \\        <li>State and transactions go through the local Unix socket</li>
        \\        <li>Changes are staged; nothing is applied implicitly</li>
        \\      </ul>
        \\    </div>
        \\    <p class="login-hero-foot">vRouter 0.2 preview · loopback only</p>
        \\  </section>
        \\  <section class="login-panel">
        \\    <div class="login-card">
        \\      <p class="eyebrow">vRouter admin</p>
        \\      <h2>Sign in</h2>
        \\      <p class="muted">Use the password configured for the local web admin.</p>
        \\
    );
    if (error_message) |message| {
        try w.writeAll("<div class=\"alert alert-error\" role=\"alert\"><strong>Sign-in failed.</strong> ");
        try writeEscaped(w, message);
        try w.writeAll("</div>");
    }
    try w.writeAll(
        \\      <form class="login-form" method="post" action="/login">
        \\        <label for="password">Admin password</label>
        \\        <input id="password" name="password" type="password" autocomplete="current-password" autofocus required maxlength="256" placeholder="Enter password">
        \\        <button class="button button-primary" type="submit">Sign in</button>
        \\      </form>
        \\      <p class="fine-print">TLS and remote access are intentionally out of scope. Bind to loopback and use an SSH tunnel if needed.</p>
        \\    </div>
        \\  </section>
        \\</main>
        \\</body>
        \\</html>
        \\
    );
}

pub fn writeError(w: *std.Io.Writer, message: []const u8) !void {
    try w.writeAll("<div class=\"alert alert-error\" role=\"alert\"><strong>Control plane unavailable.</strong> ");
    try writeEscaped(w, message);
    try w.writeAll("</div>");
}

pub fn writeEmpty(w: *std.Io.Writer, title: []const u8, message: []const u8) !void {
    try w.writeAll("<div class=\"empty\"><strong>");
    try writeEscaped(w, title);
    try w.writeAll("</strong><p>");
    try writeEscaped(w, message);
    try w.writeAll("</p></div>");
}

pub fn writeNumber(w: *std.Io.Writer, value: anytype) !void {
    try w.print("{d}", .{value});
}

pub fn writeDuration(w: *std.Io.Writer, milliseconds: i64) !void {
    if (milliseconds <= 0) {
        try w.writeAll("—");
        return;
    }
    const seconds: u64 = @intCast(@divTrunc(milliseconds, 1000));
    if (seconds < 60) {
        try w.print("{d}s", .{seconds});
    } else if (seconds < 3600) {
        try w.print("{d}m {d}s", .{ seconds / 60, seconds % 60 });
    } else if (seconds < 86_400) {
        try w.print("{d}h {d}m", .{ seconds / 3600, (seconds % 3600) / 60 });
    } else {
        try w.print("{d}d {d}h", .{ seconds / 86_400, (seconds % 86_400) / 3600 });
    }
}

pub fn writeAgo(w: *std.Io.Writer, timestamp_ms: i64, now_ms: i64) !void {
    if (timestamp_ms <= 0) {
        try w.writeAll("—");
        return;
    }
    const delta = now_ms - timestamp_ms;
    if (delta <= 1000) {
        try w.writeAll("just now");
        return;
    }
    try writeDuration(w, delta);
    try w.writeAll(" ago");
}

pub fn writeBytes(w: *std.Io.Writer, bytes: u64) !void {
    if (bytes < 1024) {
        try w.print("{d} B", .{bytes});
    } else if (bytes < 1024 * 1024) {
        try w.print("{d:.1} KiB", .{@as(f64, @floatFromInt(bytes)) / 1024.0});
    } else if (bytes < 1024 * 1024 * 1024) {
        try w.print("{d:.1} MiB", .{@as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0)});
    } else {
        try w.print("{d:.1} GiB", .{@as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0 * 1024.0)});
    }
}

pub fn writeEndpoint(w: *std.Io.Writer, address: []const u8, port: u16) !void {
    if (address.len == 0) {
        try w.writeAll("—");
        return;
    }
    try writeEscaped(w, address);
    try w.print(":{d}", .{port});
}

pub fn stateClass(state: []const u8) []const u8 {
    if (std.mem.eql(u8, state, "established")) return "badge badge-ok";
    if (std.mem.eql(u8, state, "new")) return "badge badge-info";
    if (std.mem.eql(u8, state, "related")) return "badge badge-warn";
    return "badge badge-muted";
}

test "html escaping covers attribute and text delimiters" {
    var buf: [128]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buf);
    try writeEscaped(&out, "<a href=\"x\">'&'</a>");
    try std.testing.expectEqualStrings("&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;", out.buffered());
}

test "durations render compactly" {
    var buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buf);
    try writeDuration(&out, 3_725_000);
    try std.testing.expectEqualStrings("1h 2m", out.buffered());
}
