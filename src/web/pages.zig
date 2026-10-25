//! Server-rendered HTMX pages and fragments. The control plane stays the only
//! source of truth; these functions only format a read-only snapshot.

const std = @import("std");
const vrouter = @import("vrouter");
const protocol = vrouter.control_protocol;
const html = @import("html.zig");

pub fn overviewPage(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    csrf: []const u8,
    status: ?protocol.Status,
    err: ?[]const u8,
    now_ms: i64,
) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeOverviewBody(&body.writer, status, err, now_ms);
    try html.writePage(w, .{
        .title = "Overview",
        .subtitle = "A live snapshot of forwarding, connection tracking and NAT activity.",
        .active = .overview,
        .csrf = csrf,
        .body = body.written(),
    });
}

fn writeOverviewBody(w: *std.Io.Writer, status: ?protocol.Status, err: ?[]const u8, now_ms: i64) !void {
    try w.writeAll(
        \\<section class="page-head">
        \\  <div>
        \\    <p class="eyebrow">Datapath</p>
        \\    <h2>Forwarding at a glance</h2>
        \\  </div>
        \\  <div class="page-actions">
        \\    <span class="live-pill"><span class="live-dot"></span>Live</span>
        \\    <button class="button" type="button" hx-get="/partials/status" hx-target="#overview-live" hx-swap="innerHTML" hx-indicator="#refresh-indicator">Refresh</button>
        \\  </div>
        \\</section>
        \\<div id="overview-live" hx-get="/partials/status" hx-trigger="every 5s" hx-target="this" hx-swap="innerHTML">
        \\
    );
    try overviewFragment(w, status, err, now_ms);
    try w.writeAll("</div>\n");
}

pub fn overviewFragment(w: *std.Io.Writer, status: ?protocol.Status, err: ?[]const u8, now_ms: i64) !void {
    const value = status orelse {
        try html.writeError(w, err orelse "No status was returned by the daemon.");
        return;
    };
    const c = value.counters;
    const forwarded = c.forwarded + c.bridged;
    const dropped = c.dropped + c.firewall_dropped;
    const nat_packets = c.snat_packets + c.dnat_packets;

    try w.writeAll("<div class=\"stat-grid\">");
    try statCard(w, "Ports", value.ports, "Attached datapath ports", "neutral");
    try statCard(w, "Uptime", value.uptime_ms, "Since the daemon started", "neutral");
    try statCard(w, "Forwarded", forwarded, "L3 + bridged packets", "ok");
    try statCard(w, "Dropped", dropped, "Forwarding + firewall drops", if (dropped > 0) "warn" else "ok");
    try statCard(w, "Conntrack hits", c.conntrack_hits, "Flows matched in the table", "info");
    try statCard(w, "NAT packets", nat_packets, "SNAT + DNAT translations", "info");
    try w.writeAll("</div>");

    try w.writeAll("<div class=\"content-grid\"><section class=\"card card-wide\"><header class=\"card-head\"><div><h3>Traffic counters</h3><p>Cumulative counters since the daemon started.</p></div></header><div class=\"table-wrap\"><table><thead><tr><th>Counter</th><th class=\"right\">Value</th></tr></thead><tbody>");
    try counterRow(w, "Forwarded (L3)", c.forwarded);
    try counterRow(w, "Bridged (L2)", c.bridged);
    try counterRow(w, "Dropped", c.dropped);
    try counterRow(w, "Firewall dropped", c.firewall_dropped);
    try counterRow(w, "Conntrack created", c.conntrack_created);
    try counterRow(w, "Conntrack hits", c.conntrack_hits);
    try counterRow(w, "SNAT packets", c.snat_packets);
    try counterRow(w, "DNAT packets", c.dnat_packets);
    try counterRow(w, "DHCP ACKs", c.dhcp_acks);
    try counterRow(w, "IPv6 forwarded", c.ipv6_forwarded);
    try w.writeAll("</tbody></table></div></section><div class=\"stack\">");

    try healthCard(w, dropped + c.ipv6_dropped + c.storm_dropped, c.conntrack_table_full);

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Runtime</h3><p>Instance metadata from the control plane.</p></div></header><div class=\"meta-list\">");
    try metaRow(w, "Instance", value.instance, true);
    try metaRow(w, "Version", value.version, true);
    try metaRowNumber(w, "PID", value.pid);
    try metaRowNumber(w, "Ports", value.ports);
    try metaRowAgo(w, "Updated", value.updated_ms, now_ms);
    try metaRow(w, "State dir", value.state_dir, true);
    try metaRow(w, "Control", value.control_path, true);
    try w.writeAll("</div></section></div></div>");
    try w.writeAll("<p class=\"refresh-note\">Auto-refreshes every 5 seconds.</p>");
}

fn statCard(w: *std.Io.Writer, label: []const u8, value: anytype, hint: []const u8, tone: []const u8) !void {
    try w.writeAll("<article class=\"stat-card tone-");
    try w.writeAll(tone);
    try w.writeAll("\"><p class=\"stat-label\">");
    try html.writeEscaped(w, label);
    try w.writeAll("</p><p class=\"stat-value\">");
    switch (@TypeOf(value)) {
        i64 => try html.writeDuration(w, value),
        u64, u32, usize => try html.writeNumber(w, value),
        else => try html.writeNumber(w, value),
    }
    try w.writeAll("</p><p class=\"stat-hint\">");
    try html.writeEscaped(w, hint);
    try w.writeAll("</p></article>");
}

fn statCardText(w: *std.Io.Writer, label: []const u8, value: []const u8, hint: []const u8, tone: []const u8) !void {
    try w.writeAll("<article class=\"stat-card tone-");
    try w.writeAll(tone);
    try w.writeAll("\"><p class=\"stat-label\">");
    try html.writeEscaped(w, label);
    try w.writeAll("</p><p class=\"stat-value stat-value-text\">");
    try html.writeEscaped(w, if (value.len == 0) "—" else value);
    try w.writeAll("</p><p class=\"stat-hint\">");
    try html.writeEscaped(w, hint);
    try w.writeAll("</p></article>");
}

fn counterRow(w: *std.Io.Writer, label: []const u8, value: u64) !void {
    try w.writeAll("<tr><td>");
    try html.writeEscaped(w, label);
    try w.writeAll("</td><td class=\"right mono\">");
    try html.writeNumber(w, value);
    try w.writeAll("</td></tr>");
}

fn healthCard(w: *std.Io.Writer, drops: u64, table_full: u64) !void {
    if (table_full > 0) {
        try w.writeAll("<section class=\"card card-error\"><header class=\"card-head\"><div><h3>Conntrack table full</h3><p>");
        try html.writeNumber(w, table_full);
        try w.writeAll(" new flows were dropped because the table reached capacity.</p></div></header></section>");
        return;
    }
    if (drops > 0) {
        try w.writeAll("<section class=\"card card-warn\"><header class=\"card-head\"><div><h3>Drops recorded</h3><p>");
        try html.writeNumber(w, drops);
        try w.writeAll(" packets were dropped across forwarding, firewall, IPv6 and storm-control paths.</p></div></header></section>");
        return;
    }
    try w.writeAll("<section class=\"card card-ok\"><header class=\"card-head\"><div><h3>No drops recorded</h3><p>Forwarding, firewall, IPv6 and storm-control counters are all clear.</p></div></header></section>");
}

pub fn natPage(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    csrf: []const u8,
    nat: ?protocol.Nat,
    err: ?[]const u8,
    now_ms: i64,
) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeNatBody(&body.writer, nat, err, now_ms);
    try html.writePage(w, .{
        .title = "NAT",
        .subtitle = "Source NAT and port-forwarding rules currently installed by the control plane.",
        .active = .nat,
        .csrf = csrf,
        .body = body.written(),
    });
}

fn writeNatBody(w: *std.Io.Writer, nat: ?protocol.Nat, err: ?[]const u8, now_ms: i64) !void {
    try w.writeAll(
        \\<section class="page-head">
        \\  <div>
        \\    <p class="eyebrow">Translation</p>
        \\    <h2>Installed NAT rules</h2>
        \\  </div>
        \\  <div class="page-actions">
        \\    <span class="live-pill"><span class="live-dot"></span>Live</span>
        \\    <button class="button" type="button" hx-get="/partials/nat" hx-target="#nat-live" hx-swap="innerHTML" hx-indicator="#refresh-indicator">Refresh</button>
        \\  </div>
        \\</section>
        \\<div id="nat-live" hx-get="/partials/nat" hx-trigger="every 10s" hx-target="this" hx-swap="innerHTML">
        \\
    );
    try natFragment(w, nat, err, now_ms);
    try w.writeAll("</div>\n");
}

pub fn natFragment(w: *std.Io.Writer, nat: ?protocol.Nat, err: ?[]const u8, now_ms: i64) !void {
    _ = now_ms;
    const value = nat orelse {
        try html.writeError(w, err orelse "No NAT snapshot was returned by the daemon.");
        return;
    };
    try w.writeAll("<div class=\"stat-grid stat-grid-2\">");
    try statCard(w, "Masquerade rules", value.snat.len, "Outbound interfaces using SNAT", "ok");
    try statCard(w, "Port forwards", value.port_forward.len, "Destination NAT rules", "info");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Source NAT</h3><p>Outbound interfaces and the address used for masquerading.</p></div></header>");
    if (value.snat.len == 0) {
        try html.writeEmpty(w, "No masquerade rules", "Source NAT rules appear here after they are configured on the daemon.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Outbound interface</th><th>Translated address</th></tr></thead><tbody>");
        for (value.snat) |rule| {
            try w.writeAll("<tr><td class=\"strong\">");
            try html.writeEscaped(w, if (rule.out.len == 0) "—" else rule.out);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (rule.addr.len == 0) "—" else rule.addr);
            try w.writeAll("</td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Port forwards</h3><p>External ports redirected to hosts behind the router.</p></div></header>");
    if (value.port_forward.len == 0) {
        try html.writeEmpty(w, "No port forwards", "Destination NAT rules appear here after they are configured on the daemon.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Protocol</th><th>External port</th><th>Destination</th><th>Ingress</th></tr></thead><tbody>");
        for (value.port_forward) |rule| {
            try w.writeAll("<tr><td><span class=\"badge badge-muted\">");
            try html.writeEscaped(w, if (rule.proto.len == 0) "any" else rule.proto);
            try w.writeAll("</span></td><td class=\"mono\">");
            try html.writeNumber(w, rule.ext_port);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEndpoint(w, rule.to_addr, rule.to_port);
            try w.writeAll("</td><td class=\"muted\">");
            try html.writeEscaped(w, if (rule.ingress) |ingress| if (ingress.len == 0) "any" else ingress else "any");
            try w.writeAll("</td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section><p class=\"refresh-note\">Auto-refreshes every 10 seconds.</p>");
}

pub fn connectionsPage(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    csrf: []const u8,
    conntrack: ?protocol.Conntrack,
    state_filter: []const u8,
    query: []const u8,
    err: ?[]const u8,
    now_ms: i64,
) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeConnectionsBody(&body.writer, conntrack, state_filter, query, err, now_ms);
    try html.writePage(w, .{
        .title = "Connections",
        .subtitle = "Live connection-tracking entries, newest state first.",
        .active = .connections,
        .csrf = csrf,
        .body = body.written(),
    });
}

fn writeConnectionsBody(
    w: *std.Io.Writer,
    conntrack: ?protocol.Conntrack,
    state_filter: []const u8,
    query: []const u8,
    err: ?[]const u8,
    now_ms: i64,
) !void {
    try w.writeAll(
        \\<section class="page-head">
        \\  <div>
        \\    <p class="eyebrow">Conntrack</p>
        \\    <h2>Active flows</h2>
        \\  </div>
        \\  <div class="page-actions">
        \\    <span class="live-pill"><span class="live-dot"></span>Live</span>
        \\    <button class="button" type="button" hx-get="/partials/conntrack" hx-include="#conntrack-filters" hx-target="#conntrack-live" hx-swap="innerHTML" hx-indicator="#refresh-indicator">Refresh</button>
        \\  </div>
        \\</section>
        \\<form id="conntrack-filters" class="filters" hx-get="/partials/conntrack" hx-target="#conntrack-live" hx-swap="innerHTML" hx-trigger="change, keyup changed delay:400ms, submit" hx-indicator="#refresh-indicator">
        \\  <label class="field"><span>State</span><select name="state">
        \\
    );
    try selectOption(w, "all", "All", state_filter);
    try selectOption(w, "established", "Established", state_filter);
    try selectOption(w, "new", "New", state_filter);
    try selectOption(w, "related", "Related", state_filter);
    try selectOption(w, "other", "Other", state_filter);
    try w.writeAll(
        \\  </select></label>
        \\  <label class="field field-grow"><span>Search</span><input name="q" type="search" value="
    );
    try html.writeEscaped(w, query);
    try w.writeAll(
        \\" placeholder="Address, protocol or state" autocomplete="off"></label>
        \\  <button class="button" type="submit">Apply</button>
        \\</form>
        \\<div id="conntrack-live" hx-get="/partials/conntrack" hx-include="#conntrack-filters" hx-trigger="every 5s" hx-target="this" hx-swap="innerHTML">
        \\
    );
    try connectionsFragment(w, conntrack, state_filter, query, err, now_ms);
    try w.writeAll("</div>\n");
}

fn selectOption(w: *std.Io.Writer, value: []const u8, label: []const u8, selected: []const u8) !void {
    try w.writeAll("<option value=\"");
    try w.writeAll(value);
    try w.writeAll("\"");
    if (std.mem.eql(u8, value, selected)) try w.writeAll(" selected");
    try w.writeAll(">");
    try w.writeAll(label);
    try w.writeAll("</option>");
}

pub fn connectionsFragment(
    w: *std.Io.Writer,
    conntrack: ?protocol.Conntrack,
    state_filter: []const u8,
    query: []const u8,
    err: ?[]const u8,
    now_ms: i64,
) !void {
    const value = conntrack orelse {
        try html.writeError(w, err orelse "No conntrack snapshot was returned by the daemon.");
        return;
    };
    var visible: usize = 0;
    for (value.entries) |entry| {
        if (entryMatches(entry, state_filter, query)) visible += 1;
    }

    try w.writeAll("<div class=\"stat-grid stat-grid-3\">");
    try statCard(w, "Total flows", value.total, "Entries in the conntrack table", "neutral");
    try statCard(w, "Returned", value.returned, "Rows in this snapshot", "neutral");
    try statCard(w, "Visible", visible, "Rows matching the current filter", "info");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Connection table</h3><p>Search by address, protocol or state. Timestamps are relative to now.</p></div>");
    if (value.total > value.returned) {
        try w.writeAll("<p class=\"card-note\">Showing the first ");
        try html.writeNumber(w, value.returned);
        try w.writeAll(" of ");
        try html.writeNumber(w, value.total);
        try w.writeAll(" flows.</p>");
    }
    try w.writeAll("</header>");
    if (value.entries.len == 0) {
        try html.writeEmpty(w, "No active connections", "Connection-tracking entries appear here once traffic passes through the router.");
    } else if (visible == 0) {
        try html.writeEmpty(w, "No matching connections", "Adjust the search text or state filter to see more entries.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Protocol</th><th>State</th><th>Source</th><th>Destination</th><th class=\"hide-md\">Translation</th><th class=\"right hide-sm\">Packets</th><th class=\"right hide-sm\">Bytes</th><th class=\"right\">Last seen</th></tr></thead><tbody>");
        for (value.entries) |entry| {
            if (!entryMatches(entry, state_filter, query)) continue;
            try w.writeAll("<tr><td><span class=\"badge badge-muted\">");
            try html.writeEscaped(w, if (entry.proto.len == 0) "—" else entry.proto);
            try w.writeAll("</span></td><td><span class=\"");
            try w.writeAll(html.stateClass(entry.state));
            try w.writeAll("\">");
            try html.writeEscaped(w, if (entry.state.len == 0) "—" else entry.state);
            try w.writeAll("</span></td><td class=\"mono small\">");
            try html.writeEndpoint(w, entry.src, entry.sport);
            try w.writeAll("</td><td class=\"mono small\">");
            try html.writeEndpoint(w, entry.dst, entry.dport);
            try w.writeAll("</td><td class=\"mono small muted hide-md\">");
            try writeTranslation(w, entry);
            try w.writeAll("</td><td class=\"right mono hide-sm\">");
            try html.writeNumber(w, entry.packets);
            try w.writeAll("</td><td class=\"right mono hide-sm\">");
            try html.writeBytes(w, entry.bytes);
            try w.writeAll("</td><td class=\"right muted\">");
            try html.writeAgo(w, entry.last_seen_ms, now_ms);
            try w.writeAll("</td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section><p class=\"refresh-note\">Auto-refreshes every 5 seconds.</p>");
}

fn writeTranslation(w: *std.Io.Writer, entry: protocol.ConntrackEntry) !void {
    var wrote = false;
    if (entry.translated_src) |src| {
        try w.writeAll("SNAT ");
        try html.writeEndpoint(w, src, entry.translated_sport);
        wrote = true;
    }
    if (entry.translated_dst) |dst| {
        if (wrote) try w.writeAll(" · ");
        try w.writeAll("DNAT ");
        try html.writeEndpoint(w, dst, entry.translated_dport);
        wrote = true;
    }
    if (!wrote) try w.writeAll("—");
}

fn entryMatches(entry: protocol.ConntrackEntry, state_filter: []const u8, query: []const u8) bool {
    const known = std.mem.eql(u8, entry.state, "established") or
        std.mem.eql(u8, entry.state, "new") or
        std.mem.eql(u8, entry.state, "related") or
        std.mem.eql(u8, entry.state, "closed");
    if (std.mem.eql(u8, state_filter, "other")) {
        if (known) return false;
    } else if (!std.mem.eql(u8, state_filter, "all") and state_filter.len > 0) {
        if (!std.ascii.eqlIgnoreCase(entry.state, state_filter)) return false;
    }
    if (query.len == 0) return true;
    return containsIgnoreCase(entry.proto, query) or
        containsIgnoreCase(entry.state, query) or
        containsIgnoreCase(entry.src, query) or
        containsIgnoreCase(entry.dst, query) or
        (entry.translated_src != null and containsIgnoreCase(entry.translated_src.?, query)) or
        (entry.translated_dst != null and containsIgnoreCase(entry.translated_dst.?, query));
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

pub fn systemPage(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    csrf: []const u8,
    status: ?protocol.Status,
    err: ?[]const u8,
    now_ms: i64,
) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeSystemBody(&body.writer, status, err, now_ms);
    try html.writePage(w, .{
        .title = "System",
        .subtitle = "Runtime identity and paths reported by the vRouter daemon.",
        .active = .system,
        .csrf = csrf,
        .body = body.written(),
    });
}

fn writeSystemBody(w: *std.Io.Writer, status: ?protocol.Status, err: ?[]const u8, now_ms: i64) !void {
    try w.writeAll(
        \\<section class="page-head">
        \\  <div>
        \\    <p class="eyebrow">Runtime</p>
        \\    <h2>Process and lifecycle</h2>
        \\  </div>
        \\  <div class="page-actions">
        \\    <button class="button" type="button" hx-get="/partials/system" hx-target="#system-live" hx-swap="innerHTML" hx-indicator="#refresh-indicator">Refresh</button>
        \\  </div>
        \\</section>
        \\<div id="system-live" hx-get="/partials/system" hx-trigger="every 10s" hx-target="this" hx-swap="innerHTML">
        \\
    );
    try systemFragment(w, status, err, now_ms);
    try w.writeAll("</div>\n");
}

pub fn systemFragment(w: *std.Io.Writer, status: ?protocol.Status, err: ?[]const u8, now_ms: i64) !void {
    const value = status orelse {
        try html.writeError(w, err orelse "No status was returned by the daemon.");
        return;
    };
    try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
    try statCardText(w, "Instance", value.instance, "Configured instance name", "neutral");
    try statCardText(w, "Version", value.version, "Daemon build version", "neutral");
    try statCard(w, "PID", value.pid, "Process identifier", "neutral");
    try statCard(w, "Ports", value.ports, "Attached datapath ports", "neutral");
    try w.writeAll("</div>");

    try w.writeAll("<div class=\"content-grid\"><section class=\"card\"><header class=\"card-head\"><div><h3>Runtime</h3><p>Process and lifecycle metadata.</p></div></header><div class=\"meta-list\">");
    try metaRowAgo(w, "Started", value.started_ms, now_ms);
    try metaRowAgo(w, "Updated", value.updated_ms, now_ms);
    try metaRowDuration(w, "Uptime", value.uptime_ms);
    try metaRow(w, "Instance", value.instance, true);
    try metaRow(w, "Version", value.version, true);
    try metaRow(w, "State directory", value.state_dir, true);
    try metaRow(w, "Control socket", value.control_path, true);
    try w.writeAll("</div></section><section class=\"card\"><header class=\"card-head\"><div><h3>Read-only preview</h3><p>This console is an observer, not a configuration surface.</p></div></header><div class=\"prose\"><p>All state is read through the local Unix control socket. The web process never edits routes, addresses, NAT rules or firewall state.</p><p>Configuration changes still belong to the vRouter CLI and daemon journal.</p><p class=\"badge-row\"><span class=\"badge badge-ok\">loopback only</span><span class=\"badge badge-info\">session protected</span><span class=\"badge badge-muted\">no host mutation</span></p></div></section></div>");
    try w.writeAll("<section class=\"card card-note\"><header class=\"card-head\"><div><h3>Preview scope</h3><p>The web admin is an opt-in post-v1 preview. TLS termination and remote access are intentionally out of scope; bind it to loopback and use an SSH tunnel or a separately secured reverse proxy if you need remote access.</p></div></header></section><p class=\"refresh-note\">Auto-refreshes every 10 seconds.</p>");
}

fn metaRow(w: *std.Io.Writer, label: []const u8, value: []const u8, mono: bool) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong class=\"");
    try w.writeAll(if (mono) "mono small" else "small");
    try w.writeAll("\">");
    try html.writeEscaped(w, if (value.len == 0) "—" else value);
    try w.writeAll("</strong></div>");
}

fn metaRowNumber(w: *std.Io.Writer, label: []const u8, value: anytype) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong class=\"small mono\">");
    try html.writeNumber(w, value);
    try w.writeAll("</strong></div>");
}

fn metaRowAgo(w: *std.Io.Writer, label: []const u8, value: i64, now_ms: i64) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong class=\"small\">");
    try html.writeAgo(w, value, now_ms);
    try w.writeAll("</strong></div>");
}

fn metaRowDuration(w: *std.Io.Writer, label: []const u8, value: i64) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong class=\"small\">");
    try html.writeDuration(w, value);
    try w.writeAll("</strong></div>");
}

test "connection filters match state and search text" {
    const entry: protocol.ConntrackEntry = .{
        .proto = "tcp",
        .state = "established",
        .src = "192.0.2.10",
        .dst = "198.51.100.20",
    };
    try std.testing.expect(entryMatches(entry, "all", ""));
    try std.testing.expect(entryMatches(entry, "established", "192.0.2"));
    try std.testing.expect(!entryMatches(entry, "new", ""));
    try std.testing.expect(!entryMatches(entry, "other", ""));
    try std.testing.expect(!entryMatches(entry, "all", "10.0.0.1"));
}
