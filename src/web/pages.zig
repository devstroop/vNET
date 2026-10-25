//! Server-rendered HTMX pages and fragments. The control plane stays the only
//! source of truth; these functions format running snapshots and staged drafts.

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

pub const NatMasqueradeRow = struct {
    out: []const u8 = "",
    src: ?[]const u8 = null,
    addr: ?[]const u8 = null,
    translated: []const u8 = "",
};

pub const NatForwardRow = struct {
    proto: []const u8 = "",
    ext_port: u16 = 0,
    to_addr: []const u8 = "",
    to_port: u16 = 0,
    ingress: ?[]const u8 = null,
    description: ?[]const u8 = null,
    enabled: bool = true,
};

pub const NatReview = struct {
    diff: []const u8 = "",
    affected: []const []const u8 = &.{},
    restart_required: bool = false,
    message: ?[]const u8 = null,
};

pub const ConfigReview = NatReview;

pub const NatView = struct {
    csrf: []const u8,
    draft_json: []const u8,
    masquerade: []const NatMasqueradeRow = &.{},
    port_forward: []const NatForwardRow = &.{},
    pending: usize = 0,
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?NatReview = null,
};

pub fn natPage(gpa: std.mem.Allocator, w: *std.Io.Writer, view: NatView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeNatBody(&body.writer, view);
    try html.writePage(w, .{
        .title = "NAT",
        .subtitle = "Source NAT and port-forwarding rules. Edits are staged until you apply them.",
        .active = .nat,
        .csrf = view.csrf,
        .body = body.written(),
    });
}

fn writeNatBody(w: *std.Io.Writer, view: NatView) !void {
    try w.writeAll(
        \\<section class="page-head">
        \\  <div>
        \\    <p class="eyebrow">Network services</p>
        \\    <h2>NAT</h2>
        \\  </div>
        \\  <div class="page-actions">
        \\
    );
    if (view.draft_json.len > 0) {
        try w.writeAll(
            \\    <button class="button" type="button" data-dialog-open="nat-add-masq">Add masquerade</button>
            \\    <button class="button" type="button" data-dialog-open="nat-add-fwd">Add port forward</button>
            \\
        );
    }
    try w.writeAll(
        \\  </div>
        \\</section>
        \\<div id="nat-live">
        \\
    );
    try natFragment(w, view);
    try w.writeAll("</div>\n");
}

pub fn natFragment(w: *std.Io.Writer, view: NatView) !void {
    if (view.review) |review| {
        try writeReviewDialog(w, view, review);
    } else if (view.notice) |message| {
        try writeMessageDialog(w, "NAT result", message, false);
    } else if (view.err) |message| {
        try writeMessageDialog(w, "NAT change failed", message, true);
    }

    try w.writeAll("<section class=\"config-bar");
    if (view.pending > 0) try w.writeAll(" config-bar-pending");
    try w.writeAll("\"><div class=\"config-state\">");
    if (view.pending > 0) {
        try w.writeAll("<span class=\"badge badge-warn\">Pending</span><div><strong>");
        try html.writeNumber(w, view.pending);
        try w.writeAll(" pending change");
        if (view.pending != 1) try w.writeAll("s");
        try w.writeAll("</strong><p>The running router is unchanged until you apply this draft.</p></div>");
    } else {
        try w.writeAll("<span class=\"badge badge-ok\">Running</span><div><strong>Running configuration</strong><p>Add or edit rules to stage a draft. Nothing changes until Apply.</p></div>");
    }
    try w.writeAll("</div><div class=\"config-actions\">");
    if (view.pending > 0) {
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/nat/review\" hx-post=\"/nat/review\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeDraftFields(w, view);
        try w.writeAll("<button class=\"button\" type=\"submit\">Review changes</button></form>");
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/nat/apply\" hx-post=\"/nat/apply\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeDraftFields(w, view);
        try w.writeAll("<button class=\"button button-primary button-inline\" type=\"submit\">Apply changes</button></form>");
        try w.writeAll("<button class=\"button button-ghost\" type=\"button\" hx-get=\"/partials/nat\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">Discard</button>");
    }
    try w.writeAll("</div></section>");

    try w.writeAll("<div class=\"stat-grid stat-grid-2\">");
    try statCard(w, "Masquerade rules", view.masquerade.len, "Outbound interfaces using SNAT", "ok");
    try statCard(w, "Port forwards", view.port_forward.len, "Destination NAT rules", "info");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Source NAT</h3><p>Outbound interfaces and the address used for masquerading.</p></div>");
    if (view.pending > 0) try w.writeAll("<span class=\"badge badge-warn\">Draft</span>");
    try w.writeAll("</header>");
    if (view.masquerade.len == 0) {
        try html.writeEmpty(w, "No masquerade rules", "Use Add masquerade to stage an outbound interface.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Outbound interface</th><th>Source network</th><th>Translated address</th><th></th></tr></thead><tbody>");
        for (view.masquerade, 0..) |rule, index| {
            try w.writeAll("<tr><td class=\"strong\">");
            try html.writeEscaped(w, if (rule.out.len == 0) "—" else rule.out);
            try w.writeAll("</td><td class=\"mono muted\">");
            try html.writeEscaped(w, if (rule.src) |src| if (src.len == 0) "any" else src else "any");
            try w.writeAll("</td><td class=\"mono\">");
            const translated = if (rule.translated.len != 0)
                rule.translated
            else if (rule.addr) |addr|
                if (addr.len == 0) "interface address" else addr
            else
                "interface address";
            try html.writeEscaped(w, translated);
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-ghost button-small\" type=\"button\" data-dialog-open=\"nat-edit-masq-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><button class=\"button button-ghost button-small\" type=\"button\" data-confirm-open=\"nat-confirm\" data-action=\"remove_masquerade\" data-index=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\" data-label=\"Masquerade on ");
            try html.writeEscaped(w, if (rule.out.len == 0) "this interface" else rule.out);
            try w.writeAll("\">Remove</button></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Port forwards</h3><p>External ports redirected to hosts behind the router.</p></div>");
    if (view.pending > 0) try w.writeAll("<span class=\"badge badge-warn\">Draft</span>");
    try w.writeAll("</header>");
    if (view.port_forward.len == 0) {
        try html.writeEmpty(w, "No port forwards", "Use Add port forward to stage a destination NAT rule.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Protocol</th><th>External</th><th>Internal</th><th>Ingress</th><th>Status</th><th></th></tr></thead><tbody>");
        for (view.port_forward, 0..) |rule, index| {
            try w.writeAll("<tr><td>");
            try html.writeEscaped(w, if (rule.description) |description| if (description.len == 0) "—" else description else "—");
            try w.writeAll("</td><td><span class=\"badge badge-muted\">");
            try html.writeEscaped(w, if (rule.proto.len == 0) "any" else rule.proto);
            try w.writeAll("</span></td><td class=\"mono\">");
            try html.writeNumber(w, rule.ext_port);
            try w.writeAll("</td><td class=\"mono\">");
            if (rule.to_addr.len == 0) {
                try w.writeAll("—");
            } else {
                try html.writeEscaped(w, rule.to_addr);
                try w.writeAll(":");
                try html.writeNumber(w, rule.to_port);
            }
            try w.writeAll("</td><td class=\"muted\">");
            try html.writeEscaped(w, if (rule.ingress) |ingress| if (ingress.len == 0) "any" else ingress else "any");
            try w.writeAll("</td><td>");
            if (rule.enabled) {
                try w.writeAll("<span class=\"badge badge-ok\">Enabled</span>");
            } else {
                try w.writeAll("<span class=\"badge badge-muted\">Disabled</span>");
            }
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-ghost button-small\" type=\"button\" data-dialog-open=\"nat-edit-fwd-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><button class=\"button button-ghost button-small\" type=\"button\" data-confirm-open=\"nat-confirm\" data-action=\"remove_forward\" data-index=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\" data-label=\"Port forward ");
            try html.writeEscaped(w, if (rule.proto.len == 0) "any" else rule.proto);
            try w.writeAll("/");
            try html.writeNumber(w, rule.ext_port);
            try w.writeAll("\">Remove</button></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section>");

    for (view.masquerade, 0..) |rule, index| {
        var id_buf: [64]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "nat-edit-masq-{d}", .{index});
        try writeMasqueradeDialog(w, view, id, "Edit masquerade", "Match a source network and translate it out of this interface.", "edit_masquerade", index, rule.out, rule.src, rule.addr, "Stage change");
    }
    for (view.port_forward, 0..) |rule, index| {
        var id_buf: [64]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "nat-edit-fwd-{d}", .{index});
        try writeForwardDialog(w, view, id, "Edit port forward", "Change the external port, internal host, or rule state.", "edit_forward", index, rule.proto, rule.ext_port, rule.to_addr, rule.to_port, rule.ingress, rule.description, rule.enabled, "Stage change");
    }
    try writeMasqueradeDialog(w, view, "nat-add-masq", "Add masquerade", "Translate a source network leaving this interface.", "add_masquerade", null, "", null, null, "Stage rule");
    try writeForwardDialog(w, view, "nat-add-fwd", "Add port forward", "Redirect an external port to a host behind the router.", "add_forward", null, "tcp", null, "", null, null, null, true, "Stage rule");

    try w.writeAll("<dialog id=\"nat-confirm\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Remove rule?</h3><p>This stages a removal. The running router changes only after Apply.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form id=\"nat-confirm-form\" class=\"dialog-form\" method=\"post\" action=\"/nat/rules\" hx-post=\"/nat/rules\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeDraftFields(w, view);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"\" data-confirm-field=\"action\"><input type=\"hidden\" name=\"index\" value=\"\" data-confirm-field=\"index\"><p class=\"dialog-copy\" data-confirm-message>Remove this rule from the draft?</p><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-danger\" type=\"submit\">Stage removal</button></footer></form></div></dialog>");
    try w.writeAll("<p class=\"refresh-note\">Drafts live in this page. Reloading or signing out discards them.</p>");
}

fn writeDraftFields(w: *std.Io.Writer, view: NatView) !void {
    try writeStagedFields(w, view.csrf, view.draft_json);
}

fn writeStagedFields(w: *std.Io.Writer, csrf: []const u8, draft_json: []const u8) !void {
    try w.writeAll("<input type=\"hidden\" name=\"csrf\" value=\"");
    try html.writeEscaped(w, csrf);
    try w.writeAll("\"><input type=\"hidden\" name=\"draft\" value=\"");
    try html.writeEscaped(w, draft_json);
    try w.writeAll("\">");
}

fn writeReviewDialog(w: *std.Io.Writer, view: NatView, review: NatReview) !void {
    try writeStagedReviewDialog(w, view.csrf, view.draft_json, "/nat/apply", "#nat-live", review, "Apply changes", false);
}

fn writeStagedReviewDialog(
    w: *std.Io.Writer,
    csrf: []const u8,
    draft_json: []const u8,
    action: []const u8,
    target: []const u8,
    review: NatReview,
    apply_label: []const u8,
    allow_restart: bool,
) !void {
    try w.writeAll("<dialog id=\"nat-review\" class=\"dialog dialog-wide\" data-auto-open><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Review changes</h3><p>This is the proposed diff from the running configuration. Nothing has been applied yet.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\">");
    if (review.message) |message| {
        try w.writeAll("<p class=\"dialog-copy\">");
        try html.writeEscaped(w, message);
        try w.writeAll("</p>");
    }
    if (review.affected.len > 0) {
        try w.writeAll("<p class=\"review-label\">Affected resources</p><div class=\"badge-row\">");
        for (review.affected) |item| {
            try w.writeAll("<span class=\"badge badge-info\">");
            try html.writeEscaped(w, item);
            try w.writeAll("</span>");
        }
        try w.writeAll("</div>");
    }
    if (review.restart_required) {
        try w.writeAll("<div class=\"alert alert-warn\" role=\"alert\"><strong>Restart required.</strong> This change cannot be applied live; it is saved and applied after vrouterd restarts.</div>");
    }
    if (review.diff.len > 0) {
        try w.writeAll("<pre class=\"diff\">");
        try html.writeEscaped(w, review.diff);
        try w.writeAll("</pre>");
    } else if (review.message == null) {
        try w.writeAll("<p class=\"muted\">No changes were detected.</p>");
    }
    try w.writeAll("</div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Keep editing</button>");
    if (review.diff.len > 0 and (allow_restart or !review.restart_required)) {
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"");
        try html.writeEscaped(w, action);
        try w.writeAll("\" hx-post=\"");
        try html.writeEscaped(w, action);
        try w.writeAll("\" hx-target=\"");
        try html.writeEscaped(w, target);
        try w.writeAll("\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, csrf, draft_json);
        try w.writeAll("<button class=\"button button-primary button-inline\" type=\"submit\">");
        try html.writeEscaped(w, apply_label);
        try w.writeAll("</button></form>");
    }
    try w.writeAll("</footer></div></dialog>");
}

fn writeMessageDialog(w: *std.Io.Writer, title: []const u8, message: []const u8, is_error: bool) !void {
    try w.writeAll("<dialog id=\"nat-message\" class=\"dialog dialog-sm\" data-auto-open><div class=\"dialog-card");
    if (is_error) try w.writeAll(" dialog-card-error");
    try w.writeAll("\"><header class=\"dialog-head\"><div><h3>");
    try html.writeEscaped(w, title);
    try w.writeAll("</h3><p>");
    try html.writeEscaped(w, message);
    try w.writeAll("</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form method=\"dialog\" class=\"dialog-actions\"><button class=\"button\" type=\"submit\">Close</button></form></div></dialog>");
}

fn writeMasqueradeDialog(
    w: *std.Io.Writer,
    view: NatView,
    id: []const u8,
    title: []const u8,
    description: []const u8,
    action: []const u8,
    index: ?usize,
    out: []const u8,
    src: ?[]const u8,
    addr: ?[]const u8,
    submit_label: []const u8,
) !void {
    try w.writeAll("<dialog id=\"");
    try html.writeEscaped(w, id);
    try w.writeAll("\" class=\"dialog\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try html.writeEscaped(w, title);
    try w.writeAll("</h3><p>");
    try html.writeEscaped(w, description);
    try w.writeAll("</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/nat/rules\" hx-post=\"/nat/rules\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeDraftFields(w, view);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try html.writeEscaped(w, action);
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try w.writeAll("<label class=\"field\"><span>Outbound interface</span><input name=\"out\" required placeholder=\"wan\" value=\"");
    try html.writeEscaped(w, out);
    try w.writeAll("\"></label><label class=\"field\"><span>Source network (optional)</span><input name=\"src\" placeholder=\"10.0.0.0/24\" value=\"");
    if (src) |value| try html.writeEscaped(w, value);
    try w.writeAll("\"><small>Only translate traffic from this IPv4 prefix. Leave blank for any source.</small></label><label class=\"field\"><span>Translated source address (optional)</span><input name=\"addr\" placeholder=\"203.0.113.2\" value=\"");
    if (addr) |value| try html.writeEscaped(w, value);
    try w.writeAll("\"><small>Leave blank to use the outbound interface address. A fixed address survives DHCP renewals.</small></label><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary button-inline\" type=\"submit\">");
    try html.writeEscaped(w, submit_label);
    try w.writeAll("</button></footer></form></div></dialog>");
}

fn writeForwardDialog(
    w: *std.Io.Writer,
    view: NatView,
    id: []const u8,
    title: []const u8,
    description: []const u8,
    action: []const u8,
    index: ?usize,
    proto: []const u8,
    ext_port: ?u16,
    to_addr: []const u8,
    to_port: ?u16,
    ingress: ?[]const u8,
    rule_description: ?[]const u8,
    enabled: bool,
    submit_label: []const u8,
) !void {
    try w.writeAll("<dialog id=\"");
    try html.writeEscaped(w, id);
    try w.writeAll("\" class=\"dialog dialog-wide\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try html.writeEscaped(w, title);
    try w.writeAll("</h3><p>");
    try html.writeEscaped(w, description);
    try w.writeAll("</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/nat/rules\" hx-post=\"/nat/rules\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeDraftFields(w, view);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try html.writeEscaped(w, action);
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try w.writeAll("<label class=\"field field-full\"><span>Name (optional)</span><input name=\"description\" maxlength=\"128\" placeholder=\"Web server\" value=\"");
    if (rule_description) |value| try html.writeEscaped(w, value);
    try w.writeAll("\"></label><div class=\"dialog-grid\"><label class=\"field\"><span>Protocol</span><select name=\"proto\">");
    try writeProtoOptions(w, proto);
    try w.writeAll("</select></label><label class=\"field\"><span>External port</span><input name=\"ext_port\" type=\"number\" min=\"1\" max=\"65535\" required");
    if (ext_port) |value| {
        try w.writeAll(" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\"");
    }
    try w.writeAll("></label><label class=\"field\"><span>Internal IP</span><input name=\"to_addr\" required placeholder=\"10.0.0.10\" value=\"");
    try html.writeEscaped(w, to_addr);
    try w.writeAll("\"></label><label class=\"field\"><span>Internal port</span><input name=\"to_port\" type=\"number\" min=\"1\" max=\"65535\" required");
    if (to_port) |value| {
        try w.writeAll(" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\"");
    }
    try w.writeAll("></label><label class=\"field\"><span>Ingress (optional)</span><input name=\"ingress\" placeholder=\"wan\" value=\"");
    if (ingress) |value| try html.writeEscaped(w, value);
    try w.writeAll("\"></label><label class=\"field checkbox-field\"><input type=\"checkbox\" name=\"enabled\" value=\"1\"");
    if (enabled) try w.writeAll(" checked");
    try w.writeAll("><span>Rule enabled</span></label></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary button-inline\" type=\"submit\">");
    try html.writeEscaped(w, submit_label);
    try w.writeAll("</button></footer></form></div></dialog>");
}

fn writeProtoOptions(w: *std.Io.Writer, selected: []const u8) !void {
    const protos = [_][]const u8{ "tcp", "udp" };
    for (protos) |proto| {
        try w.writeAll("<option value=\"");
        try html.writeEscaped(w, proto);
        try w.writeAll("\"");
        if (std.mem.eql(u8, proto, selected)) try w.writeAll(" selected");
        try w.writeAll(">");
        try html.writeEscaped(w, proto);
        try w.writeAll("</option>");
    }
}

pub const DhcpReservationRow = struct {
    mac: []const u8 = "",
    ip: []const u8 = "",
};

pub const DhcpServerRow = struct {
    iface: []const u8 = "",
    pool: []const u8 = "",
    lease: []const u8 = "",
    dns: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    mtu: ?u16 = null,
    ntp: ?[]const u8 = null,
    reservations: []const DhcpReservationRow = &.{},
};

pub const DhcpView = struct {
    csrf: []const u8,
    draft_json: []const u8,
    servers: []const DhcpServerRow = &.{},
    pending: usize = 0,
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?ConfigReview = null,
};

pub fn dhcpPage(gpa: std.mem.Allocator, w: *std.Io.Writer, view: DhcpView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeDhcpBody(&body.writer, view);
    try html.writePage(w, .{
        .title = "DHCP",
        .subtitle = "Address pools, lease policy and static reservations. Saved changes take effect after vrouterd restarts.",
        .active = .dhcp,
        .csrf = view.csrf,
        .body = body.written(),
    });
}

fn writeDhcpBody(w: *std.Io.Writer, view: DhcpView) !void {
    try w.writeAll("<section class=\"page-head\"><div><p class=\"eyebrow\">Network services</p><h2>DHCP</h2></div><div class=\"page-actions\">");
    if (view.draft_json.len > 0) {
        try w.writeAll("<button class=\"button\" type=\"button\" data-dialog-open=\"dhcp-add-server\">Add DHCP server</button>");
    }
    try w.writeAll("</div></section><div id=\"nat-live\">");
    try dhcpFragment(w, view);
    try w.writeAll("</div>\n");
}

pub fn dhcpFragment(w: *std.Io.Writer, view: DhcpView) !void {
    if (view.review) |review| {
        try writeStagedReviewDialog(w, view.csrf, view.draft_json, "/dhcp/apply", "#nat-live", review, "Save changes", true);
    } else if (view.notice) |message| {
        try writeMessageDialog(w, "DHCP result", message, false);
    } else if (view.err) |message| {
        try writeMessageDialog(w, "DHCP change failed", message, true);
    }

    try w.writeAll("<section class=\"config-bar");
    if (view.pending > 0) try w.writeAll(" config-bar-pending");
    try w.writeAll("\"><div class=\"config-state\">");
    if (view.pending > 0) {
        try w.writeAll("<span class=\"badge badge-warn\">Pending</span><div><strong>");
        try html.writeNumber(w, view.pending);
        try w.writeAll(" pending change");
        if (view.pending != 1) try w.writeAll("s");
        try w.writeAll("</strong><p>DHCP config is staged. Saving writes the config file; restart vrouterd to activate it.</p></div>");
    } else {
        try w.writeAll("<span class=\"badge badge-ok\">Running</span><div><strong>Running configuration</strong><p>Add or edit servers to stage a draft. Nothing changes until Save.</p></div>");
    }
    try w.writeAll("</div><div class=\"config-actions\">");
    if (view.pending > 0) {
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/dhcp/review\" hx-post=\"/dhcp/review\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button\" type=\"submit\">Review changes</button></form><form class=\"inline-form\" method=\"post\" action=\"/dhcp/apply\" hx-post=\"/dhcp/apply\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button button-primary button-inline\" type=\"submit\">Save changes</button></form><button class=\"button button-ghost\" type=\"button\" hx-get=\"/partials/dhcp\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">Discard</button>");
    }
    try w.writeAll("</div></section>");

    var reservation_count: usize = 0;
    for (view.servers) |server| reservation_count += server.reservations.len;
    try w.writeAll("<div class=\"stat-grid stat-grid-2\">");
    try statCard(w, "DHCP servers", view.servers.len, "Interfaces serving addresses", "ok");
    try statCard(w, "Reservations", reservation_count, "Static MAC-to-IP bindings", "info");
    try w.writeAll("</div>");

    if (view.servers.len == 0) {
        try w.writeAll("<section class=\"card\">");
        try html.writeEmpty(w, "No DHCP servers", "Use Add DHCP server to stage a pool.");
        try w.writeAll("</section>");
    }
    for (view.servers, 0..) |server, index| {
        try w.writeAll("<article class=\"card\"><header class=\"card-head\"><div><h3>");
        try html.writeEscaped(w, if (server.iface.len == 0) "Unnamed interface" else server.iface);
        try w.writeAll("</h3><p>");
        try html.writeEscaped(w, server.pool);
        try w.writeAll(" · lease ");
        try html.writeEscaped(w, server.lease);
        try w.writeAll("</p></div><div class=\"row-actions\"><button class=\"button button-ghost button-small\" type=\"button\" data-dialog-open=\"dhcp-edit-server-");
        try html.writeNumber(w, index);
        try w.writeAll("\">Edit</button><button class=\"button button-ghost button-small\" type=\"button\" data-confirm-open=\"dhcp-confirm\" data-action=\"remove_server\" data-index=\"");
        try html.writeNumber(w, index);
        try w.writeAll("\" data-resindex=\"\" data-label=\"DHCP server on ");
        try html.writeEscaped(w, server.iface);
        try w.writeAll("\">Remove</button></div></header><div class=\"table-wrap\"><table><tbody><tr><th>Pool</th><td class=\"mono\">");
        try html.writeEscaped(w, server.pool);
        try w.writeAll("</td><th>Lease</th><td class=\"mono\">");
        try html.writeEscaped(w, server.lease);
        try w.writeAll("</td></tr><tr><th>DNS</th><td class=\"mono\">");
        try html.writeEscaped(w, if (server.dns) |value| if (value.len == 0) "—" else value else "—");
        try w.writeAll("</td><th>Domain</th><td class=\"mono\">");
        try html.writeEscaped(w, if (server.domain) |value| if (value.len == 0) "—" else value else "—");
        try w.writeAll("</td></tr><tr><th>MTU</th><td class=\"mono\">");
        if (server.mtu) |mtu| try html.writeNumber(w, mtu) else try w.writeAll("—");
        try w.writeAll("</td><th>NTP</th><td class=\"mono\">");
        try html.writeEscaped(w, if (server.ntp) |value| if (value.len == 0) "—" else value else "—");
        try w.writeAll("</td></tr></tbody></table></div><div class=\"card-subhead\"><h4>Reservations</h4><button class=\"button button-ghost button-small\" type=\"button\" data-dialog-open=\"dhcp-add-res-");
        try html.writeNumber(w, index);
        try w.writeAll("\">Add reservation</button></div>");
        if (server.reservations.len == 0) {
            try html.writeEmpty(w, "No reservations", "Add a MAC-to-IP binding for this pool.");
        } else {
            try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>MAC address</th><th>IP address</th><th></th></tr></thead><tbody>");
            for (server.reservations, 0..) |reservation, res_index| {
                try w.writeAll("<tr><td class=\"mono\">");
                try html.writeEscaped(w, reservation.mac);
                try w.writeAll("</td><td class=\"mono\">");
                try html.writeEscaped(w, reservation.ip);
                try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-ghost button-small\" type=\"button\" data-dialog-open=\"dhcp-edit-res-");
                try html.writeNumber(w, index);
                try w.writeAll("-");
                try html.writeNumber(w, res_index);
                try w.writeAll("\">Edit</button><button class=\"button button-ghost button-small\" type=\"button\" data-confirm-open=\"dhcp-confirm\" data-action=\"remove_reservation\" data-index=\"");
                try html.writeNumber(w, index);
                try w.writeAll("\" data-resindex=\"");
                try html.writeNumber(w, res_index);
                try w.writeAll("\" data-label=\"reservation ");
                try html.writeEscaped(w, reservation.mac);
                try w.writeAll("\">Remove</button></div></td></tr>");
            }
            try w.writeAll("</tbody></table></div>");
        }
        try w.writeAll("</article>");
    }

    for (view.servers, 0..) |server, index| {
        var id_buf: [64]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "dhcp-edit-server-{d}", .{index});
        try writeDhcpServerDialog(w, view, id, "Edit DHCP server", "Update the pool or lease settings.", "edit_server", index, server, "Stage change");
        const add_id = try std.fmt.bufPrint(&id_buf, "dhcp-add-res-{d}", .{index});
        try writeDhcpReservationDialog(w, view, add_id, "Add reservation", "Bind a MAC address to a fixed address.", "add_reservation", index, null, "", "", "Stage reservation");
        for (server.reservations, 0..) |reservation, res_index| {
            const res_id = try std.fmt.bufPrint(&id_buf, "dhcp-edit-res-{d}-{d}", .{ index, res_index });
            try writeDhcpReservationDialog(w, view, res_id, "Edit reservation", "Update the MAC or IP binding.", "edit_reservation", index, res_index, reservation.mac, reservation.ip, "Stage change");
        }
    }
    try writeDhcpServerDialog(w, view, "dhcp-add-server", "Add DHCP server", "Serve addresses on an interface with a static address.", "add_server", null, .{}, "Stage server");
    try w.writeAll("<dialog id=\"dhcp-confirm\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Remove entry?</h3><p>This stages a removal. Nothing changes until Save.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/dhcp/rules\" hx-post=\"/dhcp/rules\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"\" data-confirm-field=\"action\"><input type=\"hidden\" name=\"index\" value=\"\" data-confirm-field=\"index\"><input type=\"hidden\" name=\"res_index\" value=\"\" data-confirm-field=\"resindex\"><p class=\"dialog-copy\" data-confirm-message>Remove this DHCP entry?</p><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-danger\" type=\"submit\">Stage removal</button></footer></form></div></dialog>");
    try w.writeAll("<p class=\"refresh-note\">DHCP drafts live in this page. Reloading or signing out discards them.</p>");
}

fn writeDhcpServerDialog(
    w: *std.Io.Writer,
    view: DhcpView,
    id: []const u8,
    title: []const u8,
    description: []const u8,
    action: []const u8,
    index: ?usize,
    server: DhcpServerRow,
    submit_label: []const u8,
) !void {
    try w.writeAll("<dialog id=\"");
    try html.writeEscaped(w, id);
    try w.writeAll("\" class=\"dialog\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try html.writeEscaped(w, title);
    try w.writeAll("</h3><p>");
    try html.writeEscaped(w, description);
    try w.writeAll("</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/dhcp/rules\" hx-post=\"/dhcp/rules\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try html.writeEscaped(w, action);
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try w.writeAll("<div class=\"dialog-grid\"><label class=\"field\"><span>Interface</span><input name=\"iface\" required placeholder=\"lan\" value=\"");
    try html.writeEscaped(w, server.iface);
    try w.writeAll("\"></label><label class=\"field\"><span>Pool</span><input name=\"pool\" required placeholder=\"192.168.1.100-192.168.1.200\" value=\"");
    try html.writeEscaped(w, server.pool);
    try w.writeAll("\"></label><label class=\"field\"><span>Lease time</span><input name=\"lease\" placeholder=\"12h\" value=\"");
    try html.writeEscaped(w, if (server.lease.len == 0) "12h" else server.lease);
    try w.writeAll("\"></label><label class=\"field\"><span>DNS server (optional)</span><input name=\"dns\" placeholder=\"192.168.1.1\" value=\"");
    try html.writeEscaped(w, server.dns orelse "");
    try w.writeAll("\"></label><label class=\"field\"><span>Domain (optional)</span><input name=\"domain\" placeholder=\"lan\" value=\"");
    try html.writeEscaped(w, server.domain orelse "");
    try w.writeAll("\"></label><label class=\"field\"><span>MTU (optional)</span><input name=\"mtu\" type=\"number\" min=\"576\" max=\"9000\"");
    if (server.mtu) |mtu| {
        try w.writeAll(" value=\"");
        try html.writeNumber(w, mtu);
        try w.writeAll("\"");
    }
    try w.writeAll("></label><label class=\"field\"><span>NTP server (optional)</span><input name=\"ntp\" placeholder=\"192.168.1.1\" value=\"");
    try html.writeEscaped(w, server.ntp orelse "");
    try w.writeAll("\"></label></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary button-inline\" type=\"submit\">");
    try html.writeEscaped(w, submit_label);
    try w.writeAll("</button></footer></form></div></dialog>");
}

fn writeDhcpReservationDialog(
    w: *std.Io.Writer,
    view: DhcpView,
    id: []const u8,
    title: []const u8,
    description: []const u8,
    action: []const u8,
    server_index: usize,
    reservation_index: ?usize,
    mac: []const u8,
    ip: []const u8,
    submit_label: []const u8,
) !void {
    try w.writeAll("<dialog id=\"");
    try html.writeEscaped(w, id);
    try w.writeAll("\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try html.writeEscaped(w, title);
    try w.writeAll("</h3><p>");
    try html.writeEscaped(w, description);
    try w.writeAll("</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/dhcp/rules\" hx-post=\"/dhcp/rules\" hx-target=\"#nat-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try html.writeEscaped(w, action);
    try w.writeAll("\"><input type=\"hidden\" name=\"index\" value=\"");
    try html.writeNumber(w, server_index);
    try w.writeAll("\">");
    if (reservation_index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"res_index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try w.writeAll("<label class=\"field\"><span>MAC address</span><input name=\"mac\" required placeholder=\"aa:bb:cc:dd:ee:ff\" value=\"");
    try html.writeEscaped(w, mac);
    try w.writeAll("\"></label><label class=\"field\"><span>IP address</span><input name=\"ip\" required placeholder=\"192.168.1.50\" value=\"");
    try html.writeEscaped(w, ip);
    try w.writeAll("\"></label><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary button-inline\" type=\"submit\">");
    try html.writeEscaped(w, submit_label);
    try w.writeAll("</button></footer></form></div></dialog>");
}

pub const DnsZoneRow = struct {
    suffix: []const u8 = "",
    upstreams: []const u8 = "",
};

pub const DnsView = struct {
    csrf: []const u8,
    draft_json: []const u8,
    upstreams: []const u8 = "",
    listen: []const u8 = "",
    cache: bool = true,
    max_entries: u32 = 1024,
    tcp: bool = true,
    zones: []const DnsZoneRow = &.{},
    pending: usize = 0,
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?ConfigReview = null,
};

pub fn dnsPage(gpa: std.mem.Allocator, w: *std.Io.Writer, view: DnsView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try writeDnsBody(&body.writer, view);
    try html.writePage(w, .{
        .title = "DNS",
        .subtitle = "Forwarder upstreams, listener and split-DNS zones. Saved changes take effect after vrouterd restarts.",
        .active = .dns,
        .csrf = view.csrf,
        .body = body.written(),
    });
}

fn writeDnsBody(w: *std.Io.Writer, view: DnsView) !void {
    try w.writeAll("<section class=\"page-head\"><div><p class=\"eyebrow\">Network services</p><h2>DNS</h2></div><div class=\"page-actions\">");
    if (view.draft_json.len > 0) {
        try w.writeAll("<button class=\"button\" type=\"button\" data-dialog-open=\"dns-add-zone\">Add zone</button>");
    }
    try w.writeAll("</div></section><div id=\"dns-live\">");
    try dnsFragment(w, view);
    try w.writeAll("</div>\n");
}

pub fn dnsFragment(w: *std.Io.Writer, view: DnsView) !void {
    if (view.review) |review| {
        try writeStagedReviewDialog(w, view.csrf, view.draft_json, "/dns/apply", "#dns-live", review, "Save changes", true);
    } else if (view.notice) |message| {
        try writeMessageDialog(w, "DNS result", message, false);
    } else if (view.err) |message| {
        try writeMessageDialog(w, "DNS change failed", message, true);
    }

    try w.writeAll("<section class=\"config-bar");
    if (view.pending > 0) try w.writeAll(" config-bar-pending");
    try w.writeAll("\"><div class=\"config-state\">");
    if (view.pending > 0) {
        try w.writeAll("<span class=\"badge badge-warn\">Pending</span><div><strong>");
        try html.writeNumber(w, view.pending);
        try w.writeAll(" pending change");
        if (view.pending != 1) try w.writeAll("s");
        try w.writeAll("</strong><p>DNS config is staged. Saving writes the config file; restart vrouterd to activate it.</p></div>");
    } else {
        try w.writeAll("<span class=\"badge badge-ok\">Running</span><div><strong>Running configuration</strong><p>Edit the resolver settings or add a zone to stage a draft. Nothing changes until Save.</p></div>");
    }
    try w.writeAll("</div><div class=\"config-actions\">");
    if (view.pending > 0) {
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/dns/review\" hx-post=\"/dns/review\" hx-target=\"#dns-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button\" type=\"submit\">Review changes</button></form><form class=\"inline-form\" method=\"post\" action=\"/dns/apply\" hx-post=\"/dns/apply\" hx-target=\"#dns-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button button-primary button-inline\" type=\"submit\">Save changes</button></form><button class=\"button button-ghost\" type=\"button\" hx-get=\"/partials/dns\" hx-target=\"#dns-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">Discard</button>");
    }
    try w.writeAll("</div></section>");

    try w.writeAll("<div class=\"stat-grid stat-grid-2\">");
    try statCard(w, "Upstreams", upstreamCount(view.upstreams), "Resolver servers", "ok");
    try statCard(w, "Zones", view.zones.len, "Split-DNS suffixes", "info");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Resolver</h3><p>Upstreams receive queries that no zone matches. The listener address must be assigned to a router interface.</p></div></header><form class=\"dialog-form\" method=\"post\" action=\"/dns/rules\" hx-post=\"/dns/rules\" hx-target=\"#dns-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"save_settings\"><label class=\"field\"><span>Upstream servers</span><textarea name=\"upstreams\" rows=\"3\" placeholder=\"1.1.1.1, 8.8.8.8\">");
    try html.writeEscaped(w, view.upstreams);
    try w.writeAll("</textarea><small>Comma or space separated IPv4 addresses.</small></label><div class=\"dialog-grid\"><label class=\"field\"><span>Listen address (optional)</span><input name=\"listen\" placeholder=\"192.168.1.1\" value=\"");
    try html.writeEscaped(w, view.listen);
    try w.writeAll("\"></label><label class=\"field\"><span>Cache entries</span><input name=\"max_entries\" type=\"number\" min=\"1\" max=\"1000000\" value=\"");
    try html.writeNumber(w, view.max_entries);
    try w.writeAll("\"></label></div><div class=\"checkbox-row\"><label class=\"checkbox-field\"><input type=\"checkbox\" name=\"cache\" value=\"1\"");
    if (view.cache) try w.writeAll(" checked");
    try w.writeAll("><span>Cache answers</span></label><label class=\"checkbox-field\"><input type=\"checkbox\" name=\"tcp\" value=\"1\"");
    if (view.tcp) try w.writeAll(" checked");
    try w.writeAll("><span>Accept TCP queries</span></label></div><footer class=\"dialog-actions\"><button class=\"button button-primary button-inline\" type=\"submit\">Stage settings</button></footer></form></section>");

    if (view.zones.len == 0) {
        try w.writeAll("<section class=\"card\">");
        try html.writeEmpty(w, "No DNS zones", "Use Add zone to route a suffix to a different upstream.");
        try w.writeAll("</section>");
    } else {
        try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Split-DNS zones</h3><p>Queries matching a suffix are forwarded to the zone upstreams instead of the global resolver.</p></div></header><div class=\"table-wrap\"><table><thead><tr><th>Suffix</th><th>Upstreams</th><th></th></tr></thead><tbody>");
        for (view.zones, 0..) |zone, index| {
            try w.writeAll("<tr><td class=\"mono\">");
            try html.writeEscaped(w, zone.suffix);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, zone.upstreams);
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-ghost button-small\" type=\"button\" data-dialog-open=\"dns-edit-zone-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><button class=\"button button-ghost button-small\" type=\"button\" data-confirm-open=\"dns-confirm\" data-action=\"remove_zone\" data-index=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\" data-resindex=\"\" data-label=\"zone ");
            try html.writeEscaped(w, zone.suffix);
            try w.writeAll("\">Remove</button></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div></section>");
    }

    for (view.zones, 0..) |zone, index| {
        var id_buf: [64]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "dns-edit-zone-{d}", .{index});
        try writeDnsZoneDialog(w, view, id, "Edit DNS zone", "Update the suffix or its resolver list.", "edit_zone", index, zone.suffix, zone.upstreams, "Stage change");
    }
    try writeDnsZoneDialog(w, view, "dns-add-zone", "Add DNS zone", "Route a suffix to one or more resolvers.", "add_zone", null, "", "", "Stage zone");
    try w.writeAll("<dialog id=\"dns-confirm\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Remove zone?</h3><p>This stages a removal. Nothing changes until Save.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/dns/rules\" hx-post=\"/dns/rules\" hx-target=\"#dns-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"\" data-confirm-field=\"action\"><input type=\"hidden\" name=\"index\" value=\"\" data-confirm-field=\"index\"><input type=\"hidden\" name=\"res_index\" value=\"\" data-confirm-field=\"resindex\"><p class=\"dialog-copy\" data-confirm-message>Remove this zone?</p><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-danger\" type=\"submit\">Stage removal</button></footer></form></div></dialog>");
    try w.writeAll("<p class=\"refresh-note\">DNS drafts live in this page. Reloading or signing out discards them.</p>");
}

fn writeDnsZoneDialog(
    w: *std.Io.Writer,
    view: DnsView,
    id: []const u8,
    title: []const u8,
    description: []const u8,
    action: []const u8,
    index: ?usize,
    suffix: []const u8,
    upstreams: []const u8,
    submit_label: []const u8,
) !void {
    try w.writeAll("<dialog id=\"");
    try html.writeEscaped(w, id);
    try w.writeAll("\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try html.writeEscaped(w, title);
    try w.writeAll("</h3><p>");
    try html.writeEscaped(w, description);
    try w.writeAll("</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/dns/rules\" hx-post=\"/dns/rules\" hx-target=\"#dns-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try html.writeEscaped(w, action);
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try w.writeAll("<label class=\"field\"><span>Suffix</span><input name=\"suffix\" required placeholder=\"lan\" value=\"");
    try html.writeEscaped(w, suffix);
    try w.writeAll("\"></label><label class=\"field\"><span>Zone upstreams</span><textarea name=\"zone_upstreams\" rows=\"3\" placeholder=\"10.0.0.53\">");
    try html.writeEscaped(w, upstreams);
    try w.writeAll("</textarea><small>Comma or space separated IPv4 addresses.</small></label><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary button-inline\" type=\"submit\">");
    try html.writeEscaped(w, submit_label);
    try w.writeAll("</button></footer></form></div></dialog>");
}

fn upstreamCount(upstreams: []const u8) usize {
    var count: usize = 0;
    var tokens = std.mem.tokenizeAny(u8, upstreams, ", \t\r\n");
    while (tokens.next()) |_| count += 1;
    return count;
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
    try w.writeAll("</div></section><section class=\"card\"><header class=\"card-head\"><div><h3>Local administration</h3><p>This console stages configuration changes and submits them through the daemon.</p></div></header><div class=\"prose\"><p>All state is read through the local Unix control socket. The web process never edits routes, addresses, NAT rules or firewall state directly.</p><p>The daemon owns validation, revisions, transactions and the journal.</p><p class=\"badge-row\"><span class=\"badge badge-ok\">loopback only</span><span class=\"badge badge-info\">session protected</span><span class=\"badge badge-muted\">staged apply</span></p></div></section></div>");
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
