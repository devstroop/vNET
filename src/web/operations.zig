//! Server-rendered operational pages: interfaces, clients, routes, firewall,
//! diagnostics, logs and the config editor.

const std = @import("std");
const vrouter = @import("vrouter");
const protocol = vrouter.control_protocol;
const html = @import("html.zig");
const pages = @import("pages.zig");

pub const PageData = struct {
    network: ?protocol.Network = null,
    status: ?protocol.Status = null,
    leases: ?protocol.DhcpLeases = null,
    counters: ?protocol.FirewallCounters = null,
    logs: ?protocol.LogTail = null,
    ports: ?std.json.Value = null,
    bridges: ?std.json.Value = null,
    interfaces: ?std.json.Value = null,
    routes: ?std.json.Value = null,
    dhcp: ?std.json.Value = null,
    firewall: ?std.json.Value = null,
    err: ?[]const u8 = null,
    notice: ?[]const u8 = null,
    csrf: []const u8 = "",
    now_ms: i64 = 0,
};

pub const PortRow = struct {
    name: []const u8 = "",
    kind: []const u8 = "l2",
    device: []const u8 = "",
    create: []const u8 = "",
    mtu: ?i64 = null,
    pvid: ?i64 = null,
    tagged: []const u8 = "",
    storm_control: i64 = 1000,
};

pub const BridgeRow = struct {
    name: []const u8 = "",
    ports: []const u8 = "",
    stp: bool = false,
    vlan_aware: bool = false,
    offload: []const u8 = "none",
    svi_count: i64 = 0,
};

pub const InterfaceRow = struct {
    name: []const u8 = "",
    bridge: []const u8 = "",
    port: []const u8 = "",
    address: []const u8 = "",
    addresses: []const u8 = "",
    vlan: ?i64 = null,
};

pub const InterfacesView = struct {
    csrf: []const u8,
    draft_json: []const u8 = "",
    network: ?protocol.Network = null,
    ports: []const PortRow = &.{},
    bridges: []const BridgeRow = &.{},
    interfaces: []const InterfaceRow = &.{},
    pending: usize = 0,
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?pages.ConfigReview = null,
    restart_pending: bool = false,
    restart_supported: bool = false,
    restart_token: ?[]const u8 = null,
};

pub fn interfacesPage(gpa: std.mem.Allocator, w: *std.Io.Writer, view: InterfacesView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try body.writer.writeAll("<div id=\"interfaces-live\">");
    try interfacesBody(&body.writer, view);
    try body.writer.writeAll("</div>");
    try html.writePage(w, .{
        .title = "Interfaces",
        .subtitle = "Physical ports, bridges, routed interfaces and live link state.",
        .active = .interfaces,
        .csrf = view.csrf,
        .body = body.written(),
    });
}

pub fn interfacesFragment(w: *std.Io.Writer, view: InterfacesView) !void {
    try interfacesBody(w, view);
}

fn interfacesBody(w: *std.Io.Writer, view: InterfacesView) !void {
    if (view.restart_pending) try writeRestartBanner(w, view.csrf, view.restart_token, view.restart_supported);
    if (view.notice) |notice| {
        try w.writeAll("<div class=\"alert alert-ok\" role=\"status\">");
        try html.writeEscaped(w, notice);
        try w.writeAll("</div>");
    }
    if (view.err) |message| {
        try w.writeAll("<div class=\"alert alert-error\" role=\"alert\"><strong>Interface change failed.</strong> ");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }

    var up: usize = 0;
    if (view.network) |network| {
        for (network.links) |link| {
            if (link.up) up += 1;
        }
    }
    try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
    try statCard(w, "Live links", if (view.network) |network| network.links.len else 0, "Kernel interfaces", "neutral");
    try statCard(w, "Links up", up, "Carrier and admin state", if (up > 0) "ok" else "warn");
    try statCard(w, "Configured ports", view.ports.len, "vRouter datapath ports", "info");
    try statCard(w, "Bridges", view.bridges.len, "L2 domains", "neutral");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"page-head\"><div><p class=\"eyebrow\">Network</p><h2>Ports and addressing</h2></div>");
    if (view.draft_json.len != 0) {
        try w.writeAll("<div class=\"page-actions\"><button class=\"button\" type=\"button\" data-dialog-open=\"port-add\">Add port</button><button class=\"button\" type=\"button\" data-dialog-open=\"bridge-add\">Add bridge</button><button class=\"button\" type=\"button\" data-dialog-open=\"interface-add\">Add interface</button><form class=\"inline-form\" method=\"post\" action=\"/interfaces/review\" hx-post=\"/interfaces/review\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button button-primary\" type=\"submit\">Review changes</button></form><form class=\"inline-form\" method=\"post\" action=\"/partials/interfaces\" hx-get=\"/partials/interfaces\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\"><button class=\"button button-ghost\" type=\"submit\">Discard</button></form></div>");
    }
    try w.writeAll("</section>");

    try w.writeAll("<section class=\"card card-wide\"><header class=\"card-head\"><div><h3>Interfaces and SVIs</h3><p>Configured routed interfaces, with the live state of the backing device.</p></div></header>");
    if (view.interfaces.len == 0) {
        try html.writeEmpty(w, "No routed interfaces", "Add an interface to configure an address or bridge SVI.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Addresses</th><th>Backing</th><th>VLAN</th><th>Link</th><th>Actions</th></tr></thead><tbody>");
        for (view.interfaces, 0..) |iface, index| {
            const link = findLink(view.network, iface.name);
            try w.writeAll("<tr><td class=\"mono strong\">");
            try html.writeEscaped(w, iface.name);
            try w.writeAll("</td><td class=\"mono small\">");
            var wrote = false;
            if (iface.address.len != 0) {
                try html.writeEscaped(w, iface.address);
                wrote = true;
            }
            if (iface.addresses.len != 0) {
                if (wrote) try w.writeAll("<br>");
                try html.writeEscaped(w, iface.addresses);
                wrote = true;
            }
            if (!wrote) try w.writeAll("—");
            try w.writeAll("</td><td class=\"mono\">");
            if (iface.bridge.len != 0) {
                try w.writeAll("bridge ");
                try html.writeEscaped(w, iface.bridge);
            } else if (iface.port.len != 0) {
                try w.writeAll("port ");
                try html.writeEscaped(w, iface.port);
            } else {
                try w.writeAll("—");
            }
            try w.writeAll("</td><td class=\"mono\">");
            if (iface.vlan) |vlan| try html.writeNumber(w, vlan) else try w.writeAll("—");
            try w.writeAll("</td><td>");
            if (link) |value| {
                try writeLinkState(w, value);
            } else {
                try html.writeEscaped(w, "—");
            }
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-small button-ghost\" type=\"button\" data-dialog-open=\"interface-edit-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><form class=\"inline-form\" method=\"post\" action=\"/interfaces/rules\" hx-post=\"/interfaces/rules\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
            try writeStagedFields(w, view.csrf, view.draft_json);
            try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"remove_interface\"><input type=\"hidden\" name=\"index\" value=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\"><button class=\"button button-small button-danger\" type=\"submit\">Remove</button></form></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section>");

    try w.writeAll("<div class=\"content-grid\"><section class=\"card\"><header class=\"card-head\"><div><h3>Ports</h3><p>Datapath members backed by kernel devices or TUN/TAP.</p></div></header>");
    if (view.ports.len == 0) {
        try html.writeEmpty(w, "No ports", "Add a port to attach a device to vRouter.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Kind</th><th>Device</th><th>MTU</th><th>PVID</th><th>Tagged</th><th>Storm</th><th></th></tr></thead><tbody>");
        for (view.ports, 0..) |port, index| {
            try w.writeAll("<tr><td class=\"mono strong\">");
            try html.writeEscaped(w, port.name);
            try w.writeAll("</td><td>");
            try writeBadge(w, port.kind, if (std.mem.eql(u8, port.kind, "l2")) "badge-info" else "badge-muted");
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, port.device);
            if (port.create.len != 0) {
                try w.writeAll(" <span class=\"muted small\">(");
                try html.writeEscaped(w, port.create);
                try w.writeAll(")</span>");
            }
            try w.writeAll("</td><td class=\"mono\">");
            if (port.mtu) |mtu| try html.writeNumber(w, mtu) else try w.writeAll("—");
            try w.writeAll("</td><td class=\"mono\">");
            if (port.pvid) |pvid| try html.writeNumber(w, pvid) else try w.writeAll("—");
            try w.writeAll("</td><td class=\"mono small\">");
            try html.writeEscaped(w, if (port.tagged.len == 0) "—" else port.tagged);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, port.storm_control);
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-small button-ghost\" type=\"button\" data-dialog-open=\"port-edit-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><form class=\"inline-form\" method=\"post\" action=\"/interfaces/rules\" hx-post=\"/interfaces/rules\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
            try writeStagedFields(w, view.csrf, view.draft_json);
            try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"remove_port\"><input type=\"hidden\" name=\"index\" value=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\"><button class=\"button button-small button-danger\" type=\"submit\">Remove</button></form></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section><section class=\"card\"><header class=\"card-head\"><div><h3>Bridges</h3><p>Layer-2 domains, VLAN awareness and kernel offload.</p></div></header>");
    if (view.bridges.len == 0) {
        try html.writeEmpty(w, "No bridges", "Add a bridge to connect L2 ports.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Ports</th><th>STP</th><th>VLAN-aware</th><th>Offload</th><th>SVIs</th><th></th></tr></thead><tbody>");
        for (view.bridges, 0..) |bridge, index| {
            try w.writeAll("<tr><td class=\"mono strong\">");
            try html.writeEscaped(w, bridge.name);
            try w.writeAll("</td><td class=\"mono small\">");
            try html.writeEscaped(w, if (bridge.ports.len == 0) "—" else bridge.ports);
            try w.writeAll("</td><td>");
            try writeBool(w, bridge.stp);
            try w.writeAll("</td><td>");
            try writeBool(w, bridge.vlan_aware);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, bridge.offload);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, bridge.svi_count);
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-small button-ghost\" type=\"button\" data-dialog-open=\"bridge-edit-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><form class=\"inline-form\" method=\"post\" action=\"/interfaces/rules\" hx-post=\"/interfaces/rules\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
            try writeStagedFields(w, view.csrf, view.draft_json);
            try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"remove_bridge\"><input type=\"hidden\" name=\"index\" value=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\"><button class=\"button button-small button-danger\" type=\"submit\">Remove</button></form></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section></div>");

    if (view.network) |network| {
        try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Live kernel links</h3><p>Interfaces reported by netlink, independent of vRouter configuration.</p></div></header>");
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Index</th><th>State</th><th>MTU</th><th>MAC</th><th>Master</th><th></th></tr></thead><tbody>");
        for (network.links, 0..) |link, index| {
            try w.writeAll("<tr><td class=\"mono strong\">");
            try html.writeEscaped(w, link.name);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, link.index);
            try w.writeAll("</td><td>");
            try writeLinkState(w, link);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, link.mtu);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, link.mac);
            try w.writeAll("</td><td class=\"mono\">");
            if (link.master == 0) try w.writeAll("—") else try html.writeNumber(w, link.master);
            try w.writeAll("</td><td class=\"right\"><button class=\"button button-small button-ghost\" type=\"button\" data-dialog-open=\"link-state-");
            try html.writeNumber(w, index);
            try w.writeAll("\">");
            if (link.up) try w.writeAll("Bring down") else try w.writeAll("Bring up");
            try w.writeAll("</button></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
        for (network.links, 0..) |link, index| {
            try w.writeAll("<dialog id=\"link-state-");
            try html.writeNumber(w, index);
            try w.writeAll("\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
            if (link.up) try w.writeAll("Bring link down?") else try w.writeAll("Bring link up?");
            try w.writeAll("</h3><p>This changes the host link immediately. The change is journaled so <code>vrouter down</code> can restore it.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/interfaces/link\" hx-post=\"/interfaces/link\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\"><input type=\"hidden\" name=\"csrf\" value=\"");
            try html.writeEscaped(w, view.csrf);
            try w.writeAll("\">");
            if (view.draft_json.len != 0) {
                try w.writeAll("<input type=\"hidden\" name=\"draft\" value=\"");
                try html.writeEscaped(w, view.draft_json);
                try w.writeAll("\">");
            }
            try w.writeAll("<input type=\"hidden\" name=\"dev\" value=\"");
            try html.writeEscaped(w, link.name);
            try w.writeAll("\"><input type=\"hidden\" name=\"up\" value=\"");
            if (link.up) try w.writeAll("false") else try w.writeAll("true");
            try w.writeAll("\"><label class=\"field\"><span>Type <code class=\"mono\">");
            try html.writeEscaped(w, link.name);
            try w.writeAll("</code> to confirm</span><input name=\"confirm\" required autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" placeholder=\"");
            try html.writeEscaped(w, link.name);
            try w.writeAll("\"></label><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button ");
            if (link.up) try w.writeAll("button-danger") else try w.writeAll("button-primary");
            try w.writeAll(" button-inline\" type=\"submit\">");
            if (link.up) try w.writeAll("Bring down") else try w.writeAll("Bring up");
            try w.writeAll("</button></footer></form></div></dialog>");
        }
        try w.writeAll("</section>");
    }

    if (view.draft_json.len != 0) {
        try writePortDialog(w, view, null, null);
        for (view.ports, 0..) |port, index| try writePortDialog(w, view, port, index);
        try writeBridgeDialog(w, view, null, null);
        for (view.bridges, 0..) |bridge, index| try writeBridgeDialog(w, view, bridge, index);
        try writeInterfaceDialog(w, view, null, null);
        for (view.interfaces, 0..) |iface, index| try writeInterfaceDialog(w, view, iface, index);
    }
    if (view.review) |review| try writeReviewDialog(w, view.csrf, view.draft_json, "/interfaces/apply", "#interfaces-live", review, "Apply interfaces");
    try w.writeAll("<p class=\"refresh-note\">Link state is read when this page loads. Interface changes take effect when vrouterd restarts.</p>");
}

fn writeBool(w: *std.Io.Writer, value: bool) !void {
    try writeBadge(w, if (value) "yes" else "no", if (value) "badge-ok" else "badge-muted");
}

const port_kinds = [_]SelectOption{
    .{ .value = "l2", .label = "L2 (bridged)" },
    .{ .value = "l3", .label = "L3 (routed)" },
};
const port_creates = [_]SelectOption{
    .{ .value = "", .label = "Existing device" },
    .{ .value = "tun", .label = "Create TUN" },
    .{ .value = "tap", .label = "Create TAP" },
};
const bridge_offloads = [_]SelectOption{
    .{ .value = "none", .label = "Userspace" },
    .{ .value = "kernel", .label = "Kernel bridge" },
};

fn writePortDialog(w: *std.Io.Writer, view: InterfacesView, port: ?PortRow, index: ?usize) !void {
    const editing = port != null;
    try w.writeAll("<dialog id=\"port-");
    if (editing) {
        try w.writeAll("edit-");
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"dialog\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try w.writeAll(if (editing) "Edit port" else "Add port");
    try w.writeAll("</h3><p>Ports attach a kernel device, TUN or TAP to the datapath.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\"><form id=\"port-form-");
    if (editing) {
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"form-grid\" method=\"post\" action=\"/interfaces/rules\" hx-post=\"/interfaces/rules\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try w.writeAll(if (editing) "edit_port" else "add_port");
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try writeField(w, "Name", "name", if (port) |value| value.name else "", "lan0", true);
    try writeSelectField(w, "Kind", "kind", if (port) |value| value.kind else "l2", &port_kinds);
    try writeField(w, "Device", "device", if (port) |value| value.device else "", "eth1", true);
    try writeSelectField(w, "Create", "create", if (port) |value| value.create else "", &port_creates);
    var mtu_buf: [24]u8 = undefined;
    var pvid_buf: [24]u8 = undefined;
    var storm_buf: [24]u8 = undefined;
    const mtu = if (port) |value| if (value.mtu) |number| std.fmt.bufPrint(&mtu_buf, "{d}", .{number}) catch "" else "" else "";
    const pvid = if (port) |value| if (value.pvid) |number| std.fmt.bufPrint(&pvid_buf, "{d}", .{number}) catch "" else "" else "";
    const storm = if (port) |value| std.fmt.bufPrint(&storm_buf, "{d}", .{value.storm_control}) catch "1000" else "1000";
    try writeField(w, "MTU", "mtu", mtu, "1500", false);
    try writeField(w, "PVID", "pvid", pvid, "1", false);
    try writeField(w, "Tagged VLANs", "tagged", if (port) |value| value.tagged else "", "10, 20", false);
    try writeField(w, "Storm limit", "storm_control", storm, "1000", false);
    try w.writeAll("</form></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary\" type=\"submit\" form=\"port-form-");
    if (editing) try html.writeNumber(w, index.?) else try w.writeAll("add");
    try w.writeAll("\">");
    try w.writeAll(if (editing) "Save port" else "Add port");
    try w.writeAll("</button></footer></div></dialog>");
}

fn writeBridgeDialog(w: *std.Io.Writer, view: InterfacesView, bridge: ?BridgeRow, index: ?usize) !void {
    const editing = bridge != null;
    try w.writeAll("<dialog id=\"bridge-");
    if (editing) {
        try w.writeAll("edit-");
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"dialog\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try w.writeAll(if (editing) "Edit bridge" else "Add bridge");
    try w.writeAll("</h3><p>Ports must already exist. VLAN-aware bridges enable access and trunk handling.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\"><form id=\"bridge-form-");
    if (editing) try html.writeNumber(w, index.?) else try w.writeAll("add");
    try w.writeAll("\" class=\"form-grid\" method=\"post\" action=\"/interfaces/rules\" hx-post=\"/interfaces/rules\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try w.writeAll(if (editing) "edit_bridge" else "add_bridge");
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try writeField(w, "Name", "name", if (bridge) |value| value.name else "", "br0", true);
    try writeField(w, "Ports", "ports", if (bridge) |value| value.ports else "", "lan0, lan1", false);
    try writeSelectField(w, "Offload", "offload", if (bridge) |value| value.offload else "none", &bridge_offloads);
    try writeCheckbox(w, "stp", "Spanning tree", if (bridge) |value| value.stp else false);
    try writeCheckbox(w, "vlan_aware", "VLAN aware", if (bridge) |value| value.vlan_aware else false);
    try w.writeAll("</form></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary\" type=\"submit\" form=\"bridge-form-");
    if (editing) try html.writeNumber(w, index.?) else try w.writeAll("add");
    try w.writeAll("\">");
    try w.writeAll(if (editing) "Save bridge" else "Add bridge");
    try w.writeAll("</button></footer></div></dialog>");
}

fn writeInterfaceDialog(w: *std.Io.Writer, view: InterfacesView, iface: ?InterfaceRow, index: ?usize) !void {
    const editing = iface != null;
    try w.writeAll("<dialog id=\"interface-");
    if (editing) {
        try w.writeAll("edit-");
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"dialog\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try w.writeAll(if (editing) "Edit interface" else "Add interface");
    try w.writeAll("</h3><p>Attach an address to a port, or create a routed SVI on a VLAN-aware bridge.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\"><form id=\"interface-form-");
    if (editing) try html.writeNumber(w, index.?) else try w.writeAll("add");
    try w.writeAll("\" class=\"form-grid\" method=\"post\" action=\"/interfaces/rules\" hx-post=\"/interfaces/rules\" hx-target=\"#interfaces-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try w.writeAll(if (editing) "edit_interface" else "add_interface");
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try writeField(w, "Name", "name", if (iface) |value| value.name else "", "lan", true);
    try writeField(w, "Bridge", "bridge", if (iface) |value| value.bridge else "", "br0", false);
    try writeField(w, "Port", "port", if (iface) |value| value.port else "", "wan0", false);
    try writeField(w, "Address", "address", if (iface) |value| value.address else "", "10.0.0.1/24", false);
    try writeField(w, "More addresses", "addresses", if (iface) |value| value.addresses else "", "2001:db8::1/64", false);
    var vlan_buf: [24]u8 = undefined;
    const vlan = if (iface) |value| if (value.vlan) |number| std.fmt.bufPrint(&vlan_buf, "{d}", .{number}) catch "" else "" else "";
    try writeField(w, "VLAN", "vlan", vlan, "10", false);
    try w.writeAll("</form></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary\" type=\"submit\" form=\"interface-form-");
    if (editing) try html.writeNumber(w, index.?) else try w.writeAll("add");
    try w.writeAll("\">");
    try w.writeAll(if (editing) "Save interface" else "Add interface");
    try w.writeAll("</button></footer></div></dialog>");
}

pub fn clientsPage(gpa: std.mem.Allocator, w: *std.Io.Writer, csrf: []const u8, data: PageData) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try body.writer.writeAll("<div id=\"clients-live\" hx-get=\"/partials/clients\" hx-trigger=\"every 10s\" hx-swap=\"innerHTML\">");
    try clientsBody(&body.writer, data);
    try body.writer.writeAll("</div>");
    try html.writePage(w, .{
        .title = "Clients",
        .subtitle = "DHCP leases, neighbour entries and static reservations.",
        .active = .clients,
        .csrf = csrf,
        .body = body.written(),
    });
}

pub fn clientsFragment(w: *std.Io.Writer, data: PageData) !void {
    try clientsBody(w, data);
}

fn clientsBody(w: *std.Io.Writer, data: PageData) !void {
    if (data.notice) |message| {
        try w.writeAll("<div class=\"alert alert-ok\" role=\"status\">");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }
    if (data.err) |message| {
        try w.writeAll("<div class=\"alert alert-warn\" role=\"status\">");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }
    const leases = if (data.leases) |value| value.leases else &.{};
    const total = if (data.leases) |value| value.total else 0;
    const neighbors = if (data.network) |value| value.neighbors.len else 0;
    var bound: usize = 0;
    for (leases) |lease| {
        if (std.mem.eql(u8, lease.state, "bound")) bound += 1;
    }
    try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
    try statCard(w, "DHCP leases", total, "Active lease records", "info");
    try statCard(w, "Bound", bound, "Addresses currently assigned", if (bound > 0) "ok" else "neutral");
    try statCard(w, "Neighbours", neighbors, "ARP + NDP entries", "neutral");
    try statCard(w, "Returned", if (data.leases) |value| value.returned else 0, "Rows in this snapshot", "neutral");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>DHCP leases</h3><p>Leases reported by the DHCP service, updated live.</p></div></header>");
    if (leases.len == 0) {
        try html.writeEmpty(w, "No DHCP leases", "No client currently holds a lease.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Interface</th><th>State</th><th>Address</th><th>MAC</th><th>Expires</th><th></th></tr></thead><tbody>");
        for (leases, 0..) |lease, index| {
            try w.writeAll("<tr><td class=\"mono\">");
            try html.writeEscaped(w, if (lease.iface.len == 0) "—" else lease.iface);
            try w.writeAll("</td><td>");
            try writeStateBadge(w, lease.state);
            try w.writeAll("</td><td class=\"mono strong\">");
            try html.writeEscaped(w, lease.ip);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, lease.mac);
            try w.writeAll("</td><td class=\"small\">");
            try writeExpiry(w, lease.expires_ms, data.now_ms);
            try w.writeAll("</td><td class=\"right\">");
            if (lease.iface.len != 0) {
                try w.writeAll("<button class=\"button button-small button-danger\" type=\"button\" data-dialog-open=\"lease-forget-");
                try html.writeNumber(w, index);
                try w.writeAll("\">Forget</button>");
            }
            try w.writeAll("</td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
        for (leases, 0..) |lease, index| {
            if (lease.iface.len == 0) continue;
            try w.writeAll("<dialog id=\"lease-forget-");
            try html.writeNumber(w, index);
            try w.writeAll("\" class=\"dialog dialog-sm\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Forget lease?</h3><p>This frees the address in the DHCP server. The client is not notified and may keep using the address until it renews.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><form class=\"dialog-form\" method=\"post\" action=\"/clients/lease\" hx-post=\"/clients/lease\" hx-target=\"#clients-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\"><input type=\"hidden\" name=\"csrf\" value=\"");
            try html.writeEscaped(w, data.csrf);
            try w.writeAll("\"><input type=\"hidden\" name=\"iface\" value=\"");
            try html.writeEscaped(w, lease.iface);
            try w.writeAll("\"><input type=\"hidden\" name=\"ip\" value=\"");
            try html.writeEscaped(w, lease.ip);
            try w.writeAll("\"><label class=\"field\"><span>Type <code class=\"mono\">");
            try html.writeEscaped(w, lease.ip);
            try w.writeAll("</code> to confirm</span><input name=\"confirm\" required autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" placeholder=\"");
            try html.writeEscaped(w, lease.ip);
            try w.writeAll("\"></label><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-danger\" type=\"submit\">Forget lease</button></footer></form></div></dialog>");
        }
    }
    try w.writeAll("</section>");

    try w.writeAll("<div class=\"content-grid\"><section class=\"card card-wide\"><header class=\"card-head\"><div><h3>Neighbours</h3><p>Devices visible in the kernel ARP and NDP tables.</p></div></header>");
    if (data.network) |network| {
        if (network.neighbors.len == 0) {
            try html.writeEmpty(w, "No neighbours", "No device has resolved an address yet.");
        } else {
            try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Device</th><th>Address</th><th>MAC</th><th>Family</th><th>State</th></tr></thead><tbody>");
            for (network.neighbors) |neigh| {
                try w.writeAll("<tr><td class=\"mono\">");
                try html.writeEscaped(w, neigh.dev);
                try w.writeAll("</td><td class=\"mono strong\">");
                try html.writeEscaped(w, neigh.address);
                try w.writeAll("</td><td class=\"mono\">");
                try html.writeEscaped(w, neigh.mac);
                try w.writeAll("</td><td>");
                try html.writeEscaped(w, neigh.family);
                try w.writeAll("</td><td>");
                try writeStateBadge(w, neigh.state);
                try w.writeAll("</td></tr>");
            }
            try w.writeAll("</tbody></table></div>");
        }
    } else {
        try html.writeEmpty(w, "Neighbour state unavailable", "The daemon did not return live network state.");
    }
    try w.writeAll("</section><section class=\"card\"><header class=\"card-head\"><div><h3>Reservations</h3><p>Static MAC-to-address bindings from DHCP configuration.</p></div></header>");
    try writeReservations(w, data.dhcp);
    try w.writeAll("</section></div><p class=\"refresh-note\">Auto-refreshes every 10 seconds.</p>");
}

test "client lease dialog posts the target and typed confirmation" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    const leases = [_]protocol.DhcpLease{
        .{ .iface = "lan0", .state = "bound", .ip = "10.0.0.100", .mac = "02:00:00:00:00:02" },
    };
    try clientsFragment(&out.writer, .{
        .csrf = "csrf-value",
        .leases = .{ .total = 1, .returned = 1, .leases = &leases },
    });
    const text = out.written();
    const action_at = std.mem.indexOf(u8, text, "action=\"/clients/lease\"") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOfPos(u8, text, action_at, "name=\"iface\" value=\"lan0\"") != null);
    try std.testing.expect(std.mem.indexOfPos(u8, text, action_at, "name=\"ip\" value=\"10.0.0.100\"") != null);
    try std.testing.expect(std.mem.indexOfPos(u8, text, action_at, "name=\"confirm\"") != null);
}

pub const RouteRow = struct {
    dst: []const u8 = "",
    via: []const u8 = "",
    dev: []const u8 = "",
    metric: i64 = 0,
    table: i64 = 0,
};

pub const RoutesView = struct {
    csrf: []const u8,
    draft_json: []const u8 = "",
    routes: []const RouteRow = &.{},
    pending: usize = 0,
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?pages.ConfigReview = null,
    restart_pending: bool = false,
    restart_supported: bool = false,
    restart_token: ?[]const u8 = null,
};

pub fn routesPage(gpa: std.mem.Allocator, w: *std.Io.Writer, view: RoutesView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try body.writer.writeAll("<div id=\"routes-live\">");
    try routesBody(&body.writer, view);
    try body.writer.writeAll("</div>");
    try html.writePage(w, .{
        .title = "Routes",
        .subtitle = "Static routes. Edits are staged, reviewed and applied as one config transaction.",
        .active = .routes,
        .csrf = view.csrf,
        .body = body.written(),
    });
}

pub fn routesFragment(w: *std.Io.Writer, view: RoutesView) !void {
    try routesBody(w, view);
}

fn routesBody(w: *std.Io.Writer, view: RoutesView) !void {
    if (view.restart_pending) try writeRestartBanner(w, view.csrf, view.restart_token, view.restart_supported);
    if (view.notice) |notice| {
        try w.writeAll("<div class=\"alert alert-ok\" role=\"status\">");
        try html.writeEscaped(w, notice);
        try w.writeAll("</div>");
    }
    if (view.err) |message| {
        try w.writeAll("<div class=\"alert alert-error\" role=\"alert\"><strong>Route edit failed.</strong> ");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }

    var v4: usize = 0;
    var v6: usize = 0;
    for (view.routes) |route| {
        if (std.mem.indexOfScalar(u8, route.dst, ':') != null) v6 += 1 else v4 += 1;
    }
    try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
    try statCard(w, "Routes", view.routes.len, "Configured entries", "info");
    try statCard(w, "IPv4", v4, "IPv4 destinations", "neutral");
    try statCard(w, "IPv6", v6, "IPv6 destinations", "neutral");
    try statCard(w, "Pending", view.pending, "Unapplied changes", if (view.pending > 0) "warn" else "ok");
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Routing table</h3><p>Routes are validated and written atomically. They take effect when vrouterd restarts.</p></div><div class=\"card-actions\">");
    if (view.draft_json.len != 0) {
        try w.writeAll("<button class=\"button\" type=\"button\" data-dialog-open=\"route-add\">Add route</button>");
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/routes/review\" hx-post=\"/routes/review\" hx-target=\"#routes-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button button-primary\" type=\"submit\">Review changes</button></form>");
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/partials/routes\" hx-get=\"/partials/routes\" hx-target=\"#routes-live\" hx-swap=\"innerHTML\"><button class=\"button button-ghost\" type=\"submit\">Discard</button></form>");
    }
    try w.writeAll("</div></header>");
    if (view.routes.len == 0) {
        try html.writeEmpty(w, "No routes", "Only directly connected networks are reachable.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Destination</th><th>Gateway</th><th>Device</th><th>Metric</th><th>Table</th><th>Family</th><th></th></tr></thead><tbody>");
        for (view.routes, 0..) |route, index| {
            const is_v6 = std.mem.indexOfScalar(u8, route.dst, ':') != null;
            try w.writeAll("<tr><td class=\"mono strong\">");
            try html.writeEscaped(w, route.dst);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (route.via.len == 0) "—" else route.via);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (route.dev.len == 0) "—" else route.dev);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, route.metric);
            try w.writeAll("</td><td class=\"mono\">");
            try writeTableName(w, route.table);
            try w.writeAll("</td><td>");
            try writeBadge(w, if (is_v6) "ipv6" else "ipv4", if (is_v6) "badge-info" else "badge-muted");
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-small button-ghost\" type=\"button\" data-dialog-open=\"route-edit-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><form class=\"inline-form\" method=\"post\" action=\"/routes/rules\" hx-post=\"/routes/rules\" hx-target=\"#routes-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
            try writeStagedFields(w, view.csrf, view.draft_json);
            try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"remove_route\"><input type=\"hidden\" name=\"index\" value=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\"><button class=\"button button-small button-danger\" type=\"submit\">Remove</button></form></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section>");

    if (view.draft_json.len != 0) {
        try writeRouteDialog(w, view, null, null);
        for (view.routes, 0..) |route, index| try writeRouteDialog(w, view, route, index);
    }
    if (view.review) |review| try writeReviewDialog(w, view.csrf, view.draft_json, "/routes/apply", "#routes-live", review, "Apply routes");
}

fn writeRouteDialog(w: *std.Io.Writer, view: RoutesView, route: ?RouteRow, index: ?usize) !void {
    const editing = route != null;
    try w.writeAll("<dialog id=\"route-");
    if (editing) {
        try w.writeAll("edit-");
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"dialog\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try w.writeAll(if (editing) "Edit route" else "Add route");
    try w.writeAll("</h3><p>Destination is a CIDR prefix; the gateway is a single address. Device is required.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\"><form id=\"route-form-");
    if (editing) {
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"form-grid\" method=\"post\" action=\"/routes/rules\" hx-post=\"/routes/rules\" hx-target=\"#routes-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try w.writeAll(if (editing) "edit_route" else "add_route");
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try writeField(w, "Destination", "dst", if (route) |value| value.dst else "", "0.0.0.0/0", true);
    try writeField(w, "Gateway", "via", if (route) |value| value.via else "", "203.0.113.1", false);
    try writeField(w, "Device", "dev", if (route) |value| value.dev else "", "wan0", true);
    var metric_buf: [24]u8 = undefined;
    var table_buf: [24]u8 = undefined;
    const metric = if (route) |value| std.fmt.bufPrint(&metric_buf, "{d}", .{value.metric}) catch "0" else "0";
    const table = if (route) |value| std.fmt.bufPrint(&table_buf, "{d}", .{value.table}) catch "0" else "0";
    try writeField(w, "Metric", "metric", metric, "0", false);
    try writeField(w, "Table", "table", table, "0", false);
    try w.writeAll("</form></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary\" type=\"submit\" form=\"route-form-");
    if (editing) {
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\">");
    try w.writeAll(if (editing) "Save route" else "Add route");
    try w.writeAll("</button></footer></div></dialog>");
}
pub const FirewallRuleRow = struct {
    action: []const u8 = "drop",
    family: []const u8 = "ipv4",
    proto: []const u8 = "",
    src: []const u8 = "",
    dst: []const u8 = "",
    sport: ?i64 = null,
    dport: ?i64 = null,
    iif: []const u8 = "",
    oif: []const u8 = "",
    ct_state: []const u8 = "",
};

pub const FirewallView = struct {
    csrf: []const u8,
    draft_json: []const u8 = "",
    default_in: []const u8 = "drop",
    default_forward: []const u8 = "drop",
    default_out: []const u8 = "accept",
    rp_filter: bool = false,
    rate_icmp: i64 = 100,
    rate_arp: i64 = 512,
    rate_dhcp: i64 = 100,
    rate_ndp: i64 = 256,
    rules: []const FirewallRuleRow = &.{},
    counters: ?protocol.FirewallCounters = null,
    pending: usize = 0,
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?pages.ConfigReview = null,
    restart_pending: bool = false,
    restart_supported: bool = false,
    restart_token: ?[]const u8 = null,
};

pub fn firewallPage(gpa: std.mem.Allocator, w: *std.Io.Writer, view: FirewallView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try body.writer.writeAll("<div id=\"firewall-live\">");
    try firewallBody(&body.writer, view);
    try body.writer.writeAll("</div>");
    try html.writePage(w, .{
        .title = "Firewall",
        .subtitle = "Default policy, ordered rules and rate limits. Edits are staged until you apply them.",
        .active = .firewall,
        .csrf = view.csrf,
        .body = body.written(),
    });
}

pub fn firewallFragment(w: *std.Io.Writer, view: FirewallView) !void {
    try firewallBody(w, view);
}

fn firewallBody(w: *std.Io.Writer, view: FirewallView) !void {
    if (view.restart_pending) try writeRestartBanner(w, view.csrf, view.restart_token, view.restart_supported);
    if (view.notice) |notice| {
        try w.writeAll("<div class=\"alert alert-ok\" role=\"status\">");
        try html.writeEscaped(w, notice);
        try w.writeAll("</div>");
    }
    if (view.err) |message| {
        try w.writeAll("<div class=\"alert alert-error\" role=\"alert\"><strong>Firewall edit failed.</strong> ");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }

    var accepted: usize = 0;
    var dropped: usize = 0;
    for (view.rules) |rule| {
        if (std.mem.eql(u8, rule.action, "accept")) accepted += 1;
        if (std.mem.eql(u8, rule.action, "drop") or std.mem.eql(u8, rule.action, "reject")) dropped += 1;
    }
    try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
    try statCard(w, "Rules", view.rules.len, "Ordered first-match", "info");
    try statCard(w, "Accept", accepted, "Allow rules", "ok");
    try statCard(w, "Drop / reject", dropped, "Block rules", if (dropped > 0) "warn" else "neutral");
    try statCardText(w, "Default forward", view.default_forward, "Unmatched forwarded traffic", if (std.mem.eql(u8, view.default_forward, "drop")) "ok" else "warn");
    try w.writeAll("</div>");

    if (view.counters) |counters| {
        try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
        try statCard(w, "Dropped", counters.firewall_dropped, "Firewall drops since boot", if (counters.firewall_dropped > 0) "warn" else "ok");
        try statCard(w, "Spoofed", counters.firewall_spoofed, "uRPF drops", if (counters.firewall_spoofed > 0) "warn" else "neutral");
        try statCard(w, "Rate limited", counters.icmp_rate_limited + counters.arp_rate_limited + counters.dhcp_rate_limited + counters.ndp_rate_limited, "ICMP, ARP, DHCP and NDP", "info");
        try statCard(w, "Rules counted", counters.rules.len, "Per-rule counters", "neutral");
        try w.writeAll("</div>");
    }

    try w.writeAll("<div class=\"content-grid\"><section class=\"card card-wide\"><header class=\"card-head\"><div><h3>Ordered rules</h3><p>First matching rule wins. Established and related flows are accepted before this list.</p></div>");
    if (view.draft_json.len != 0) {
        try w.writeAll("<div class=\"card-actions\"><button class=\"button\" type=\"button\" data-dialog-open=\"firewall-rule-add\">Add rule</button><form class=\"inline-form\" method=\"post\" action=\"/firewall/review\" hx-post=\"/firewall/review\" hx-target=\"#firewall-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
        try writeStagedFields(w, view.csrf, view.draft_json);
        try w.writeAll("<button class=\"button button-primary\" type=\"submit\">Review changes</button></form><form class=\"inline-form\" method=\"post\" action=\"/partials/firewall\" hx-get=\"/partials/firewall\" hx-target=\"#firewall-live\" hx-swap=\"innerHTML\"><button class=\"button button-ghost\" type=\"submit\">Discard</button></form></div>");
    }
    try w.writeAll("</header>");
    if (view.rules.len == 0) {
        try html.writeEmpty(w, "No explicit rules", "Only the default policy and established-flow shortcut apply.");
    } else {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>#</th><th>Action</th><th>Family</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Ports</th><th>Interfaces</th><th>State</th><th class=\"right\">Packets</th><th></th></tr></thead><tbody>");
        for (view.rules, 0..) |rule, index| {
            const action_class = if (std.mem.eql(u8, rule.action, "accept")) "badge-ok" else "badge-warn";
            try w.writeAll("<tr><td class=\"mono\">");
            try html.writeNumber(w, index + 1);
            try w.writeAll("</td><td>");
            try writeBadge(w, rule.action, action_class);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, rule.family);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (rule.proto.len == 0) "any" else rule.proto);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (rule.src.len == 0) "any" else rule.src);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (rule.dst.len == 0) "any" else rule.dst);
            try w.writeAll("</td><td class=\"mono\">");
            try writePortRange(w, rule.sport, rule.dport);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (rule.iif.len == 0) "*" else rule.iif);
            try w.writeAll(" → ");
            try html.writeEscaped(w, if (rule.oif.len == 0) "*" else rule.oif);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, if (rule.ct_state.len == 0) "—" else rule.ct_state);
            try w.writeAll("</td><td class=\"right mono\">");
            if (view.counters) |counters| {
                if (index < counters.rules.len) try html.writeNumber(w, counters.rules[index]) else try w.writeAll("0");
            } else {
                try w.writeAll("—");
            }
            try w.writeAll("</td><td class=\"right\"><div class=\"row-actions\"><button class=\"button button-small button-ghost\" type=\"button\" data-dialog-open=\"firewall-rule-edit-");
            try html.writeNumber(w, index);
            try w.writeAll("\">Edit</button><form class=\"inline-form\" method=\"post\" action=\"/firewall/rules\" hx-post=\"/firewall/rules\" hx-target=\"#firewall-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
            try writeStagedFields(w, view.csrf, view.draft_json);
            try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"remove_rule\"><input type=\"hidden\" name=\"index\" value=\"");
            try html.writeNumber(w, index);
            try w.writeAll("\"><button class=\"button button-small button-danger\" type=\"submit\">Remove</button></form></div></td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    }
    try w.writeAll("</section><div class=\"stack\">");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Policy</h3><p>Default verdicts for unmatched traffic.</p></div></header><form class=\"form-stack\" method=\"post\" action=\"/firewall/rules\" hx-post=\"/firewall/rules\" hx-target=\"#firewall-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"save_policy\">");
    try writeSelectField(w, "Input", "default_in", view.default_in, &firewall_actions);
    try writeSelectField(w, "Forward", "default_forward", view.default_forward, &firewall_actions);
    try writeSelectField(w, "Output", "default_out", view.default_out, &firewall_out_actions);
    try writeCheckbox(w, "rp_filter", "Reverse-path filter", view.rp_filter);
    try w.writeAll("<button class=\"button button-primary\" type=\"submit\">Save policy</button></form></section>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Rate limits</h3><p>Packets per second; zero disables a limit.</p></div></header><form class=\"form-stack\" method=\"post\" action=\"/firewall/rules\" hx-post=\"/firewall/rules\" hx-target=\"#firewall-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"save_limits\">");
    var icmp_buf: [24]u8 = undefined;
    var arp_buf: [24]u8 = undefined;
    var dhcp_buf: [24]u8 = undefined;
    var ndp_buf: [24]u8 = undefined;
    try writeField(w, "ICMP", "rate_icmp", std.fmt.bufPrint(&icmp_buf, "{d}", .{view.rate_icmp}) catch "0", "100", true);
    try writeField(w, "ARP", "rate_arp", std.fmt.bufPrint(&arp_buf, "{d}", .{view.rate_arp}) catch "0", "512", true);
    try writeField(w, "DHCP", "rate_dhcp", std.fmt.bufPrint(&dhcp_buf, "{d}", .{view.rate_dhcp}) catch "0", "100", true);
    try writeField(w, "NDP", "rate_ndp", std.fmt.bufPrint(&ndp_buf, "{d}", .{view.rate_ndp}) catch "0", "256", true);
    try w.writeAll("<button class=\"button button-primary\" type=\"submit\">Save limits</button></form></section>");
    try w.writeAll("</div></div>");

    if (view.draft_json.len != 0) {
        try writeFirewallRuleDialog(w, view, null, null);
        for (view.rules, 0..) |rule, index| try writeFirewallRuleDialog(w, view, rule, index);
    }
    if (view.review) |review| try writeReviewDialog(w, view.csrf, view.draft_json, "/firewall/apply", "#firewall-live", review, "Apply firewall");
    try w.writeAll("<p class=\"refresh-note\">Counters are read when this page loads. Rule changes take effect when vrouterd restarts.</p>");
}

const SelectOption = struct { value: []const u8, label: []const u8 };
const firewall_actions = [_]SelectOption{
    .{ .value = "accept", .label = "accept" },
    .{ .value = "drop", .label = "drop" },
    .{ .value = "reject", .label = "reject" },
};
const firewall_out_actions = [_]SelectOption{
    .{ .value = "accept", .label = "accept" },
};
const firewall_families = [_]SelectOption{
    .{ .value = "ipv4", .label = "IPv4" },
    .{ .value = "ipv6", .label = "IPv6" },
    .{ .value = "any", .label = "Any" },
};
const firewall_protocols = [_]SelectOption{
    .{ .value = "", .label = "Any" },
    .{ .value = "tcp", .label = "TCP" },
    .{ .value = "udp", .label = "UDP" },
    .{ .value = "icmp", .label = "ICMP" },
    .{ .value = "icmpv6", .label = "ICMPv6" },
};

fn writeSelectField(w: *std.Io.Writer, label: []const u8, name: []const u8, value: []const u8, options: []const SelectOption) !void {
    try w.writeAll("<label class=\"field\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><select class=\"input\" name=\"");
    try html.writeEscaped(w, name);
    try w.writeAll("\">");
    for (options) |option| {
        try w.writeAll("<option value=\"");
        try html.writeEscaped(w, option.value);
        try w.writeAll("\"");
        if (std.mem.eql(u8, option.value, value)) try w.writeAll(" selected");
        try w.writeAll(">");
        try html.writeEscaped(w, option.label);
        try w.writeAll("</option>");
    }
    try w.writeAll("</select></label>");
}

fn writeCheckbox(w: *std.Io.Writer, name: []const u8, label: []const u8, checked: bool) !void {
    try w.writeAll("<label class=\"check\"><input type=\"checkbox\" name=\"");
    try html.writeEscaped(w, name);
    try w.writeAll("\" value=\"1\"");
    if (checked) try w.writeAll(" checked");
    try w.writeAll("><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span></label>");
}

fn writeFirewallRuleDialog(w: *std.Io.Writer, view: FirewallView, rule: ?FirewallRuleRow, index: ?usize) !void {
    const editing = rule != null;
    try w.writeAll("<dialog id=\"firewall-rule-");
    if (editing) {
        try w.writeAll("edit-");
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"dialog dialog-wide\"><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>");
    try w.writeAll(if (editing) "Edit firewall rule" else "Add firewall rule");
    try w.writeAll("</h3><p>Rules are evaluated in order. Leave a field empty to match anything.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\"><form id=\"firewall-form-");
    if (editing) {
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\" class=\"form-grid\" method=\"post\" action=\"/firewall/rules\" hx-post=\"/firewall/rules\" hx-target=\"#firewall-live\" hx-swap=\"innerHTML\" hx-indicator=\"#refresh-indicator\">");
    try writeStagedFields(w, view.csrf, view.draft_json);
    try w.writeAll("<input type=\"hidden\" name=\"action\" value=\"");
    try w.writeAll(if (editing) "edit_rule" else "add_rule");
    try w.writeAll("\">");
    if (index) |value| {
        try w.writeAll("<input type=\"hidden\" name=\"index\" value=\"");
        try html.writeNumber(w, value);
        try w.writeAll("\">");
    }
    try writeSelectField(w, "Action", "rule_action", if (rule) |value| value.action else "drop", &firewall_actions);
    try writeSelectField(w, "Family", "family", if (rule) |value| value.family else "ipv4", &firewall_families);
    try writeSelectField(w, "Protocol", "proto", if (rule) |value| value.proto else "", &firewall_protocols);
    try writeField(w, "Source", "src", if (rule) |value| value.src else "", "10.0.0.0/24", false);
    try writeField(w, "Destination", "dst", if (rule) |value| value.dst else "", "203.0.113.10/32", false);
    var sport_buf: [24]u8 = undefined;
    var dport_buf: [24]u8 = undefined;
    const sport = if (rule) |value| if (value.sport) |port| std.fmt.bufPrint(&sport_buf, "{d}", .{port}) catch "" else "" else "";
    const dport = if (rule) |value| if (value.dport) |port| std.fmt.bufPrint(&dport_buf, "{d}", .{port}) catch "" else "" else "";
    try writeField(w, "Source port", "sport", sport, "1024", false);
    try writeField(w, "Destination port", "dport", dport, "443", false);
    try writeField(w, "Ingress", "iif", if (rule) |value| value.iif else "", "wan0", false);
    try writeField(w, "Egress", "oif", if (rule) |value| value.oif else "", "lan0", false);
    try writeField(w, "Connection states", "ct_state", if (rule) |value| value.ct_state else "", "new, established", false);
    try w.writeAll("</form></div><footer class=\"dialog-actions\"><button class=\"button\" type=\"button\" data-dialog-close>Cancel</button><button class=\"button button-primary\" type=\"submit\" form=\"firewall-form-");
    if (editing) {
        try html.writeNumber(w, index.?);
    } else {
        try w.writeAll("add");
    }
    try w.writeAll("\">");
    try w.writeAll(if (editing) "Save rule" else "Add rule");
    try w.writeAll("</button></footer></div></dialog>");
}
pub fn diagnosticsPage(gpa: std.mem.Allocator, w: *std.Io.Writer, csrf: []const u8, data: PageData) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try body.writer.writeAll("<div id=\"diagnostics-live\" hx-get=\"/partials/diagnostics\" hx-trigger=\"every 10s\" hx-swap=\"innerHTML\">");
    try diagnosticsBody(&body.writer, data);
    try body.writer.writeAll("</div>");
    try html.writePage(w, .{
        .title = "Diagnostics",
        .subtitle = "Live link, address, neighbour and datapath health.",
        .active = .diagnostics,
        .csrf = csrf,
        .body = body.written(),
    });
}

pub fn diagnosticsFragment(w: *std.Io.Writer, data: PageData) !void {
    try diagnosticsBody(w, data);
}

fn diagnosticsBody(w: *std.Io.Writer, data: PageData) !void {
    if (data.err) |message| {
        try w.writeAll("<div class=\"alert alert-warn\" role=\"status\">");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }
    const network = data.network;
    var up: usize = 0;
    if (network) |value| {
        for (value.links) |link| {
            if (link.up) up += 1;
        }
    }
    try w.writeAll("<div class=\"stat-grid stat-grid-4\">");
    try statCard(w, "Links up", up, "Carrier present", if (up > 0) "ok" else "warn");
    try statCard(w, "Addresses", if (network) |value| value.addresses.len else 0, "IPv4 + IPv6", "info");
    try statCard(w, "Neighbours", if (network) |value| value.neighbors.len else 0, "ARP + NDP entries", "neutral");
    if (data.status) |status| {
        try statCard(w, "Conntrack", status.counters.conntrack_hits, "Flow table hits", "neutral");
    } else {
        try statCard(w, "Conntrack", 0, "Flow table hits", "neutral");
    }
    try w.writeAll("</div>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Links</h3><p>Kernel interface state and driver-reported MTU.</p></div></header>");
    if (network) |value| {
        try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Index</th><th>State</th><th>MTU</th><th>MAC</th><th>Master</th></tr></thead><tbody>");
        for (value.links) |link| {
            try w.writeAll("<tr><td class=\"mono strong\">");
            try html.writeEscaped(w, link.name);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, link.index);
            try w.writeAll("</td><td>");
            try writeLinkState(w, link);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeNumber(w, link.mtu);
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, link.mac);
            try w.writeAll("</td><td class=\"mono\">");
            if (link.master == 0) try w.writeAll("—") else try html.writeNumber(w, link.master);
            try w.writeAll("</td></tr>");
        }
        try w.writeAll("</tbody></table></div>");
    } else {
        try html.writeEmpty(w, "Link state unavailable", "The daemon did not return live network state.");
    }
    try w.writeAll("</section>");

    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Offline recovery</h3><p>Journal repair is intentionally CLI-only; the web never edits the journal or config on disk.</p></div></header><div class=\"card-body\"><p>If <code>doctor.status</code> reports a malformed journal or a pending transaction, stop the daemon and repair it offline:</p><pre class=\"log-tail\"><code>sudo vrouter down\nsudo vrouter doctor --repair</code></pre></div></section>");

    try w.writeAll("<div class=\"content-grid\"><section class=\"card card-wide\"><header class=\"card-head\"><div><h3>Address table</h3><p>Addresses currently assigned in the kernel.</p></div></header>");
    if (network) |value| {
        if (value.addresses.len == 0) {
            try html.writeEmpty(w, "No addresses", "No address is currently assigned.");
        } else {
            try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Device</th><th>Address</th><th>Family</th><th>Scope</th></tr></thead><tbody>");
            for (value.addresses) |addr| {
                try w.writeAll("<tr><td class=\"mono\">");
                try html.writeEscaped(w, addr.dev);
                try w.writeAll("</td><td class=\"mono\">");
                try html.writeEscaped(w, addr.address);
                try w.print("/{d}</td><td>", .{addr.prefix_len});
                try html.writeEscaped(w, addr.family);
                try w.writeAll("</td><td class=\"mono\">");
                try writeScope(w, addr.scope);
                try w.writeAll("</td></tr>");
            }
            try w.writeAll("</tbody></table></div>");
        }
    } else {
        try html.writeEmpty(w, "Address state unavailable", "The daemon did not return live network state.");
    }
    try w.writeAll("</section><section class=\"card\"><header class=\"card-head\"><div><h3>Neighbour table</h3><p>Resolved ARP and NDP entries.</p></div></header>");
    if (network) |value| {
        if (value.neighbors.len == 0) {
            try html.writeEmpty(w, "No neighbours", "No entry is populated yet.");
        } else {
            try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>Address</th><th>MAC</th><th>Device</th><th>State</th></tr></thead><tbody>");
            for (value.neighbors) |neigh| {
                try w.writeAll("<tr><td class=\"mono strong\">");
                try html.writeEscaped(w, neigh.address);
                try w.writeAll("</td><td class=\"mono\">");
                try html.writeEscaped(w, neigh.mac);
                try w.writeAll("</td><td class=\"mono\">");
                try html.writeEscaped(w, neigh.dev);
                try w.writeAll("</td><td>");
                try writeStateBadge(w, neigh.state);
                try w.writeAll("</td></tr>");
            }
            try w.writeAll("</tbody></table></div>");
        }
    } else {
        try html.writeEmpty(w, "Neighbour state unavailable", "The daemon did not return live network state.");
    }
    try w.writeAll("</section></div><p class=\"refresh-note\">Auto-refreshes every 10 seconds.</p>");
}

pub fn logsPage(gpa: std.mem.Allocator, w: *std.Io.Writer, csrf: []const u8, data: PageData) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try body.writer.writeAll("<div id=\"logs-live\" hx-get=\"/partials/logs\" hx-trigger=\"every 10s\" hx-swap=\"innerHTML\">");
    try logsBody(&body.writer, data);
    try body.writer.writeAll("</div>");
    try html.writePage(w, .{
        .title = "Logs",
        .subtitle = "Bounded tail of the daemon log file.",
        .active = .logs,
        .csrf = csrf,
        .body = body.written(),
    });
}

pub fn logsFragment(w: *std.Io.Writer, data: PageData) !void {
    try logsBody(w, data);
}

fn logsBody(w: *std.Io.Writer, data: PageData) !void {
    if (data.err) |message| {
        try html.writeError(w, message);
        return;
    }
    const logs = data.logs orelse {
        try html.writeEmpty(w, "No log file", "The daemon log file is not available for this instance.");
        return;
    };
    try w.writeAll("<div class=\"stat-grid stat-grid-3\">");
    try statCard(w, "Lines", logs.lines, "Lines in the returned tail", "neutral");
    try statCard(w, "Size", logs.text.len, "Bytes returned", "info");
    try statCardText(w, "File", logs.path, "Daemon log path", "neutral");
    try w.writeAll("</div>");
    if (logs.truncated) {
        try w.writeAll("<div class=\"alert alert-warn\" role=\"status\"><strong>Tail truncated.</strong> Showing the most recent 48 KiB.</div>");
    }
    if (logs.text.len == 0) {
        try html.writeEmpty(w, "Log is empty", "The daemon has not written to this file yet.");
    } else {
        try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Log tail</h3><p>Read-only, newest content at the end.</p></div></header><pre class=\"log-tail\">");
        try html.writeEscaped(w, logs.text);
        try w.writeAll("</pre></section>");
    }
    try w.writeAll("<p class=\"refresh-note\">Auto-refreshes every 10 seconds.</p>");
}

pub const LoggingView = struct {
    csrf: []const u8,
    level: []const u8 = "info",
    format: []const u8 = "text",
    revision: []const u8 = "",
    draft_json: []const u8 = "",
    notice: ?[]const u8 = null,
    err: ?[]const u8 = null,
    review: ?pages.ConfigReview = null,
    restart_pending: bool = false,
    restart_supported: bool = false,
    restart_token: []const u8 = "",
};

pub fn configPage(gpa: std.mem.Allocator, w: *std.Io.Writer, csrf: []const u8, config: ?std.json.Value, revision: ?[]const u8, source_path: ?[]const u8, writable: ?bool, err: ?[]const u8, logging: ?LoggingView) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    try configBody(&body.writer, gpa, config, revision, source_path, writable, err, logging);
    try html.writePage(w, .{
        .title = "Config",
        .subtitle = "Running configuration with staged logging changes.",
        .active = .config,
        .csrf = csrf,
        .body = body.written(),
    });
}

fn configBody(w: *std.Io.Writer, gpa: std.mem.Allocator, config: ?std.json.Value, revision: ?[]const u8, source_path: ?[]const u8, writable: ?bool, err: ?[]const u8, logging: ?LoggingView) !void {
    if (err) |message| {
        try html.writeError(w, message);
        return;
    }
    try w.writeAll("<div class=\"stat-grid stat-grid-3\">");
    try statCardText(w, "Revision", revision orelse "—", "Current config hash", "info");
    try statCardText(w, "Source", source_path orelse "—", "Config store path", "neutral");
    try statCardText(w, "Writable", if (writable orelse false) "yes" else "no", "Daemon write access", if (writable orelse false) "ok" else "warn");
    try w.writeAll("</div>");
    if (logging) |log_view| try loggingCard(w, log_view);
    const value = config orelse {
        try html.writeEmpty(w, "No config", "The daemon did not return a configuration document.");
        return;
    };
    var pretty: std.Io.Writer.Allocating = .init(gpa);
    defer pretty.deinit();
    std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, &pretty.writer) catch {
        try html.writeEmpty(w, "Config unavailable", "The configuration could not be rendered.");
        return;
    };
    try w.writeAll("<section class=\"card\"><header class=\"card-head\"><div><h3>Running configuration</h3><p>Read-only. Use the resource pages for staged edits.</p></div></header><pre class=\"log-tail config-json\">");
    try html.writeEscaped(w, pretty.written());
    try w.writeAll("</pre></section>");
}

const logging_levels = [_]SelectOption{
    .{ .value = "err", .label = "error" },
    .{ .value = "warn", .label = "warn" },
    .{ .value = "info", .label = "info" },
    .{ .value = "debug", .label = "debug" },
};

const logging_formats = [_]SelectOption{
    .{ .value = "text", .label = "text" },
    .{ .value = "json", .label = "json" },
};

fn loggingCard(w: *std.Io.Writer, view: LoggingView) !void {
    try w.writeAll("<section class=\"card\" id=\"config-logging\"><header class=\"card-head\"><div><h3>Logging</h3><p>Daemon log level and output format. Changes are staged, diffed and applied through the control socket.</p></div></header><div class=\"card-body\">");
    if (view.notice) |notice| {
        try w.writeAll("<div class=\"alert alert-ok\" role=\"status\">");
        try html.writeEscaped(w, notice);
        try w.writeAll("</div>");
    }
    if (view.err) |message| {
        try w.writeAll("<div class=\"alert alert-err\" role=\"alert\">");
        try html.writeEscaped(w, message);
        try w.writeAll("</div>");
    }
    if (view.restart_pending) try writeRestartBanner(w, view.csrf, if (view.restart_token.len == 0) null else view.restart_token, view.restart_supported);
    try w.writeAll("<form class=\"form-grid\" method=\"post\" action=\"/config/logging\"><input type=\"hidden\" name=\"csrf\" value=\"");
    try html.writeEscaped(w, view.csrf);
    try w.writeAll("\"><input type=\"hidden\" name=\"revision\" value=\"");
    try html.writeEscaped(w, view.revision);
    try w.writeAll("\">");
    try writeSelectField(w, "Level", "level", view.level, &logging_levels);
    try writeSelectField(w, "Format", "format", view.format, &logging_formats);
    try w.writeAll("<div class=\"form-actions\"><button class=\"button button-primary\" type=\"submit\">Review logging</button></div></form>");
    try w.writeAll("</div></section>");
    if (view.review) |review| try loggingReviewDialog(w, view, review);
}

fn loggingReviewDialog(w: *std.Io.Writer, view: LoggingView, review: pages.ConfigReview) !void {
    try w.writeAll("<dialog class=\"dialog dialog-wide\" data-auto-open><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Review logging changes</h3><p>This is the proposed diff from the running configuration. Nothing has been applied yet.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\">");
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
    if (review.diff.len > 0) {
        try w.writeAll("<form class=\"inline-form\" method=\"post\" action=\"/config/apply\"><input type=\"hidden\" name=\"csrf\" value=\"");
        try html.writeEscaped(w, view.csrf);
        try w.writeAll("\"><input type=\"hidden\" name=\"draft\" value=\"");
        try html.writeEscaped(w, view.draft_json);
        try w.writeAll("\"><button class=\"button button-primary button-inline\" type=\"submit\">Apply logging</button></form>");
    }
    try w.writeAll("</footer></div></dialog>");
}

fn statCard(w: *std.Io.Writer, label: []const u8, value: anytype, hint: []const u8, tone: []const u8) !void {
    try w.writeAll("<article class=\"stat-card tone-");
    try w.writeAll(tone);
    try w.writeAll("\"><p class=\"stat-label\">");
    try html.writeEscaped(w, label);
    try w.writeAll("</p><p class=\"stat-value\">");
    try html.writeNumber(w, value);
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

fn metaRow(w: *std.Io.Writer, label: []const u8, value: []const u8) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong>");
    try html.writeEscaped(w, value);
    try w.writeAll("</strong></div>");
}

fn metaRowInt(w: *std.Io.Writer, label: []const u8, value: i64) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong class=\"mono\">");
    try html.writeNumber(w, value);
    try w.writeAll("</strong></div>");
}

fn metaRowBool(w: *std.Io.Writer, label: []const u8, value: bool) !void {
    try w.writeAll("<div class=\"meta-row\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><strong>");
    try writeBoolBadge(w, value);
    try w.writeAll("</strong></div>");
}

fn writeBoolBadge(w: *std.Io.Writer, value: bool) !void {
    try writeBadge(w, if (value) "enabled" else "disabled", if (value) "badge-ok" else "badge-muted");
}

fn writeBadge(w: *std.Io.Writer, text: []const u8, class: []const u8) !void {
    try w.writeAll("<span class=\"badge ");
    try w.writeAll(class);
    try w.writeAll("\">");
    try html.writeEscaped(w, text);
    try w.writeAll("</span>");
}

fn writeStateBadge(w: *std.Io.Writer, state: []const u8) !void {
    const class = if (std.mem.eql(u8, state, "bound") or std.mem.eql(u8, state, "reachable") or std.mem.eql(u8, state, "permanent"))
        "badge-ok"
    else if (std.mem.eql(u8, state, "offered") or std.mem.eql(u8, state, "stale") or std.mem.eql(u8, state, "delay"))
        "badge-warn"
    else if (std.mem.eql(u8, state, "declined") or std.mem.eql(u8, state, "failed"))
        "badge-danger"
    else
        "badge-muted";
    try writeBadge(w, state, class);
}

fn findLink(network: ?protocol.Network, name: []const u8) ?protocol.NetworkLink {
    const value = network orelse return null;
    for (value.links) |link| {
        if (std.mem.eql(u8, link.name, name)) return link;
    }
    return null;
}

fn writeLinkState(w: *std.Io.Writer, link: ?protocol.NetworkLink) !void {
    const value = link orelse {
        try writeBadge(w, "config only", "badge-muted");
        return;
    };
    if (value.up) {
        try writeBadge(w, "up", "badge-ok");
    } else {
        try writeBadge(w, "down", "badge-danger");
    }
    try w.print(" <span class=\"small muted mono\">MTU {d}</span>", .{value.mtu});
}

fn writeInterfaceAddresses(w: *std.Io.Writer, iface_value: std.json.Value) !void {
    const iface = asObject(iface_value) orelse {
        try w.writeAll("—");
        return;
    };
    var wrote = false;
    if (objectString(iface, "address")) |address| {
        if (address.len != 0) {
            try w.writeAll("<span class=\"badge badge-info mono\">");
            try html.writeEscaped(w, address);
            try w.writeAll("</span> ");
            wrote = true;
        }
    }
    if (objectArray(iface, "addresses")) |addresses| {
        for (addresses) |value| {
            const address = switch (value) {
                .string => |text| text,
                else => continue,
            };
            if (address.len == 0) continue;
            try w.writeAll("<span class=\"badge badge-muted mono\">");
            try html.writeEscaped(w, address);
            try w.writeAll("</span> ");
            wrote = true;
        }
    }
    if (!wrote) try w.writeAll("—");
}

fn writeNumberArray(w: *std.Io.Writer, values: ?[]const std.json.Value) !void {
    const items = values orelse {
        try w.writeAll("—");
        return;
    };
    if (items.len == 0) {
        try w.writeAll("—");
        return;
    }
    for (items, 0..) |item, index| {
        if (index != 0) try w.writeAll(", ");
        switch (item) {
            .integer => |value| try html.writeNumber(w, value),
            .string => |text| try html.writeEscaped(w, text),
            else => try w.writeAll("?"),
        }
    }
}

fn writeStringArray(w: *std.Io.Writer, values: ?[]const std.json.Value) !void {
    const items = values orelse {
        try w.writeAll("—");
        return;
    };
    if (items.len == 0) {
        try w.writeAll("—");
        return;
    }
    for (items, 0..) |item, index| {
        if (index != 0) try w.writeAll(", ");
        switch (item) {
            .string => |text| try html.writeEscaped(w, text),
            else => try w.writeAll("?"),
        }
    }
}

fn writePortRange(w: *std.Io.Writer, sport: ?i64, dport: ?i64) !void {
    if (sport) |value| try html.writeNumber(w, value) else try w.writeAll("*");
    try w.writeAll(" → ");
    if (dport) |value| try html.writeNumber(w, value) else try w.writeAll("*");
}

fn writeStagedFields(w: *std.Io.Writer, csrf: []const u8, draft_json: []const u8) !void {
    try w.writeAll("<input type=\"hidden\" name=\"csrf\" value=\"");
    try html.writeEscaped(w, csrf);
    try w.writeAll("\"><input type=\"hidden\" name=\"draft\" value=\"");
    try html.writeEscaped(w, draft_json);
    try w.writeAll("\">");
}

fn writeField(w: *std.Io.Writer, label: []const u8, name: []const u8, value: []const u8, placeholder: []const u8, required: bool) !void {
    try w.writeAll("<label class=\"field\"><span>");
    try html.writeEscaped(w, label);
    try w.writeAll("</span><input class=\"input\" type=\"text\" name=\"");
    try html.writeEscaped(w, name);
    try w.writeAll("\" value=\"");
    try html.writeEscaped(w, value);
    try w.writeAll("\" placeholder=\"");
    try html.writeEscaped(w, placeholder);
    try w.writeAll("\"");
    if (required) try w.writeAll(" required");
    try w.writeAll("></label>");
}

fn writeReviewDialog(
    w: *std.Io.Writer,
    csrf: []const u8,
    draft_json: []const u8,
    action: []const u8,
    target: []const u8,
    review: pages.ConfigReview,
    apply_label: []const u8,
) !void {
    try w.writeAll("<dialog id=\"config-review\" class=\"dialog dialog-wide\" data-auto-open><div class=\"dialog-card\"><header class=\"dialog-head\"><div><h3>Review changes</h3><p>This is the proposed diff from the running configuration. Nothing has been applied yet.</p></div><button class=\"icon-button\" type=\"button\" data-dialog-close aria-label=\"Close\">×</button></header><div class=\"dialog-body\">");
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
    if (review.diff.len > 0) {
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

fn writeRestartBanner(w: *std.Io.Writer, csrf: []const u8, token: ?[]const u8, supported: bool) !void {
    try w.writeAll("<div class=\"alert alert-warn\" role=\"alert\"><strong>Restart required.</strong> Configuration changes are saved and activate when vrouterd restarts.");
    if (supported) {
        try w.writeAll("<form class=\"inline-form restart-form\" method=\"post\" action=\"/restart\" hx-post=\"/restart\" hx-target=\"#restart-result\" hx-swap=\"innerHTML\"><input type=\"hidden\" name=\"csrf\" value=\"");
        try html.writeEscaped(w, csrf);
        try w.writeAll("\">");
        if (token) |value| {
            try w.writeAll("<input type=\"hidden\" name=\"restart_token\" value=\"");
            try html.writeEscaped(w, value);
            try w.writeAll("\"><button class=\"button button-small\" type=\"submit\">Restart daemon</button>");
        } else {
            try w.writeAll("<button class=\"button button-small\" type=\"submit\" disabled>Restart unavailable</button>");
        }
        try w.writeAll("</form><div id=\"restart-result\"></div>");
    }
    try w.writeAll("</div>");
}

fn writeTableName(w: *std.Io.Writer, table: i64) !void {
    if (table == 0 or table == 254) {
        try w.writeAll("main");
    } else {
        try html.writeNumber(w, table);
    }
}

fn writeScope(w: *std.Io.Writer, scope: u8) !void {
    switch (scope) {
        0 => try w.writeAll("global"),
        200 => try w.writeAll("site"),
        253 => try w.writeAll("link"),
        254 => try w.writeAll("host"),
        else => try html.writeNumber(w, scope),
    }
}

fn writeExpiry(w: *std.Io.Writer, expires_ms: i64, now_ms: i64) !void {
    if (expires_ms <= 0) {
        try w.writeAll("—");
        return;
    }
    const remaining = expires_ms - now_ms;
    if (remaining <= 0) {
        try w.writeAll("expired");
    } else {
        try html.writeDuration(w, remaining);
    }
}

fn writeReservations(w: *std.Io.Writer, value: ?std.json.Value) !void {
    const servers = jsonObjects(value);
    if (servers.len == 0) {
        try html.writeEmpty(w, "No DHCP configuration", "No DHCP server is configured.");
        return;
    }
    var wrote = false;
    for (servers) |server| {
        const object = switch (server) {
            .object => |map| map,
            else => continue,
        };
        const iface = objectString(object, "iface") orelse "—";
        const reservations = objectArray(object, "reservations") orelse &.{};
        for (reservations) |reservation| {
            const entry = switch (reservation) {
                .object => |map| map,
                else => continue,
            };
            if (!wrote) {
                try w.writeAll("<div class=\"table-wrap\"><table><thead><tr><th>MAC</th><th>Address</th><th>Interface</th></tr></thead><tbody>");
                wrote = true;
            }
            try w.writeAll("<tr><td class=\"mono\">");
            try html.writeEscaped(w, objectString(entry, "mac") orelse "—");
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, objectString(entry, "ip") orelse "—");
            try w.writeAll("</td><td class=\"mono\">");
            try html.writeEscaped(w, iface);
            try w.writeAll("</td></tr>");
        }
    }
    if (wrote) {
        try w.writeAll("</tbody></table></div>");
    } else {
        try html.writeEmpty(w, "No reservations", "Every DHCP client is allocated from the pool.");
    }
}

fn asObject(value: std.json.Value) ?std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => null,
    };
}

fn objectString(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

fn objectInt(object: std.json.ObjectMap, name: []const u8) ?i64 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .integer => |number| number,
        else => null,
    };
}

fn objectBool(object: std.json.ObjectMap, name: []const u8) ?bool {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .bool => |flag| flag,
        else => null,
    };
}

fn objectArray(object: std.json.ObjectMap, name: []const u8) ?[]const std.json.Value {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .array => |array| array.items,
        else => null,
    };
}

fn objectObject(object: std.json.ObjectMap, name: []const u8) ?std.json.ObjectMap {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .object => |map| map,
        else => null,
    };
}

fn jsonObjects(value: ?std.json.Value) []const std.json.Value {
    const actual = value orelse return &.{};
    return switch (actual) {
        .array => |array| array.items,
        else => &.{},
    };
}

fn jsonLen(value: ?std.json.Value) usize {
    return jsonObjects(value).len;
}

test "operations helpers render escaped values" {
    var buf: [128]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buf);
    try writeStringArray(&out, &.{});
    try std.testing.expectEqualStrings("—", out.buffered());
}

test "restart banner posts the restart token under the control field name" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeRestartBanner(&out.writer, "csrf-value", "token-value", true);
    const text = out.written();
    try std.testing.expect(std.mem.indexOf(u8, text, "name=\"restart_token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "value=\"token-value\"") != null);
}

fn expectLiveRegionInsidePage(text: []const u8, id: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, text, "<!doctype html>"));
    const body_at = std.mem.indexOf(u8, text, "<body>") orelse return error.TestUnexpectedResult;
    const marker = try std.fmt.allocPrint(std.testing.allocator, "<div id=\"{s}\">", .{id});
    defer std.testing.allocator.free(marker);
    const live_at = std.mem.indexOf(u8, text, marker) orelse return error.TestUnexpectedResult;
    try std.testing.expect(live_at > body_at);
}

test "staged editor pages keep their live regions inside the document body" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try interfacesPage(std.testing.allocator, &out.writer, .{ .csrf = "" });
    try expectLiveRegionInsidePage(out.written(), "interfaces-live");

    var routes: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer routes.deinit();
    try routesPage(std.testing.allocator, &routes.writer, .{ .csrf = "" });
    try expectLiveRegionInsidePage(routes.written(), "routes-live");

    var firewall: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer firewall.deinit();
    try firewallPage(std.testing.allocator, &firewall.writer, .{ .csrf = "" });
    try expectLiveRegionInsidePage(firewall.written(), "firewall-live");
}

test "link dialog posts the target and keeps the staged draft" {
    const links = [_]protocol.NetworkLink{.{ .name = "eth0", .index = 2, .up = true }};
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try interfacesFragment(&out.writer, .{
        .csrf = "csrf-value",
        .draft_json = "{\"ports\":[]}",
        .network = .{ .links = &links },
    });
    const text = out.written();
    const dialog_at = std.mem.indexOf(u8, text, "id=\"link-state-0\"") orelse return error.TestUnexpectedResult;
    const action_at = std.mem.indexOfPos(u8, text, dialog_at, "action=\"/interfaces/link\"") orelse return error.TestUnexpectedResult;
    const draft_at = std.mem.indexOfPos(u8, text, action_at, "name=\"draft\"") orelse return error.TestUnexpectedResult;
    const dev_at = std.mem.indexOfPos(u8, text, action_at, "name=\"dev\"") orelse return error.TestUnexpectedResult;
    try std.testing.expect(draft_at < dev_at);
    const confirm_at = std.mem.indexOfPos(u8, text, action_at, "name=\"confirm\"") orelse return error.TestUnexpectedResult;
    try std.testing.expect(dev_at < confirm_at);
}

test "review dialog uses a page-neutral identifier" {
    var review = pages.ConfigReview{ .diff = "+ one line", .affected = &.{}, .restart_required = false };
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeReviewDialog(&out.writer, "csrf", "{}", "/interfaces/apply", "#interfaces-live", review, "Apply interfaces");
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "id=\"config-review\"") != null);
    review.diff = "";
}
