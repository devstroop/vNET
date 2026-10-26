//! Config-backed read models for protocol v3 list operations. The daemon
//! parses the current config document on the config worker; these functions
//! only serialize, they never touch live datapath state.

const std = @import("std");
const schema = @import("vnet-core").config_schema;

pub fn isListOp(op: []const u8) bool {
    return std.mem.eql(u8, op, "ports.list") or
        std.mem.eql(u8, op, "bridges.list") or
        std.mem.eql(u8, op, "interfaces.list") or
        std.mem.eql(u8, op, "routes.list") or
        std.mem.eql(u8, op, "dhcp.list") or
        std.mem.eql(u8, op, "dns.list") or
        std.mem.eql(u8, op, "firewall.list");
}

pub fn writeSection(
    json: *std.json.Stringify,
    op: []const u8,
    cfg: *const schema.Config,
) !bool {
    if (std.mem.eql(u8, op, "ports.list")) {
        try json.objectField("ports");
        try writePorts(json, cfg);
    } else if (std.mem.eql(u8, op, "bridges.list")) {
        try json.objectField("bridges");
        try writeBridges(json, cfg);
    } else if (std.mem.eql(u8, op, "interfaces.list")) {
        try json.objectField("interfaces");
        try writeInterfaces(json, cfg);
    } else if (std.mem.eql(u8, op, "routes.list")) {
        try json.objectField("routes");
        try writeRoutes(json, cfg);
    } else if (std.mem.eql(u8, op, "dhcp.list")) {
        try json.objectField("dhcp");
        try writeDhcp(json, cfg);
    } else if (std.mem.eql(u8, op, "dns.list")) {
        try json.objectField("dns");
        try writeDns(json, cfg);
    } else if (std.mem.eql(u8, op, "firewall.list")) {
        try json.objectField("firewall");
        try writeFirewall(json, cfg);
    } else {
        return false;
    }
    return true;
}

fn writePorts(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    try json.beginArray();
    var it = cfg.ports.iterator();
    while (it.next()) |entry| {
        const port = entry.value_ptr.*;
        try json.beginObject();
        try field(json, "name", entry.key_ptr.*);
        try field(json, "kind", @tagName(port.kind));
        try field(json, "device", port.device);
        try optional(json, "create", if (port.create) |value| @tagName(value) else null);
        try optional(json, "mtu", port.mtu);
        try optional(json, "pvid", port.pvid);
        try json.objectField("tagged");
        try json.beginArray();
        for (port.tagged) |vlan| try json.write(vlan);
        try json.endArray();
        try field(json, "storm_control", port.storm_control);
        try json.endObject();
    }
    try json.endArray();
}

fn writeBridges(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    try json.beginArray();
    var it = cfg.bridges.iterator();
    while (it.next()) |entry| {
        const bridge = entry.value_ptr.*;
        try json.beginObject();
        try field(json, "name", entry.key_ptr.*);
        try json.objectField("ports");
        try json.beginArray();
        for (bridge.ports) |port| try json.write(port);
        try json.endArray();
        try field(json, "stp", bridge.stp);
        try field(json, "vlan_aware", bridge.vlan_aware);
        try field(json, "offload", @tagName(bridge.offload));
        var svi_count: u32 = 0;
        var interfaces = cfg.interfaces.iterator();
        while (interfaces.next()) |iface| {
            if (iface.value_ptr.bridge) |name| {
                if (std.mem.eql(u8, name, entry.key_ptr.*)) svi_count += 1;
            }
        }
        try field(json, "svi_count", svi_count);
        try json.endObject();
    }
    try json.endArray();
}

fn writeInterfaces(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    try json.beginArray();
    var it = cfg.interfaces.iterator();
    while (it.next()) |entry| {
        const iface = entry.value_ptr.*;
        try json.beginObject();
        try field(json, "name", entry.key_ptr.*);
        try optional(json, "bridge", iface.bridge);
        try optional(json, "port", iface.port);
        try optional(json, "address", iface.address);
        try json.objectField("addresses");
        try json.beginArray();
        for (iface.addresses) |address| try json.write(address);
        try json.endArray();
        try optional(json, "vlan", iface.vlan);
        try json.endObject();
    }
    try json.endArray();
}

fn writeRoutes(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    try json.beginArray();
    for (cfg.routes) |route| {
        try json.beginObject();
        try field(json, "dst", route.dst);
        try optional(json, "via", route.via);
        try optional(json, "dev", route.dev);
        try field(json, "metric", route.metric);
        try field(json, "table", route.table);
        try json.endObject();
    }
    try json.endArray();
}

fn writeDhcp(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    try json.beginArray();
    for (cfg.dhcp) |server| {
        try json.beginObject();
        try field(json, "iface", server.iface);
        try field(json, "pool", server.pool);
        try field(json, "lease", server.lease);
        try optional(json, "dns", server.dns);
        try optional(json, "domain", server.domain);
        try optional(json, "mtu", server.mtu);
        try optional(json, "ntp", server.ntp);
        try json.objectField("reservations");
        try json.beginArray();
        for (server.reservations) |reservation| {
            try json.beginObject();
            try field(json, "mac", reservation.mac);
            try field(json, "ip", reservation.ip);
            try json.endObject();
        }
        try json.endArray();
        try json.endObject();
    }
    try json.endArray();
}

fn writeDns(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    const dns = cfg.dns;
    try json.beginObject();
    try json.objectField("upstreams");
    try json.beginArray();
    for (dns.upstreams) |upstream| try json.write(upstream);
    try json.endArray();
    try field(json, "cache", dns.cache);
    try optional(json, "listen", dns.listen);
    try field(json, "max_entries", dns.max_entries);
    try field(json, "tcp", dns.tcp);
    try json.objectField("zones");
    try json.beginArray();
    for (dns.zones) |zone| {
        try json.beginObject();
        try field(json, "suffix", zone.suffix);
        try json.objectField("upstreams");
        try json.beginArray();
        for (zone.upstreams) |upstream| try json.write(upstream);
        try json.endArray();
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
}

fn writeFirewall(json: *std.json.Stringify, cfg: *const schema.Config) !void {
    const firewall = cfg.firewall;
    try json.beginObject();
    try field(json, "default_in", @tagName(firewall.default_in));
    try field(json, "default_forward", @tagName(firewall.default_forward));
    try field(json, "default_out", @tagName(firewall.default_out));
    try field(json, "rp_filter", firewall.rp_filter);
    try json.objectField("rate_limit");
    try json.beginObject();
    try field(json, "icmp", firewall.rate_limit.icmp);
    try field(json, "arp", firewall.rate_limit.arp);
    try field(json, "dhcp", firewall.rate_limit.dhcp);
    try field(json, "ndp", firewall.rate_limit.ndp);
    try json.endObject();
    try json.objectField("rules");
    try json.beginArray();
    for (firewall.rules) |rule| {
        try json.beginObject();
        try field(json, "action", @tagName(rule.action));
        try field(json, "family", @tagName(rule.family));
        try optional(json, "proto", if (rule.proto) |proto| @tagName(proto) else null);
        try optional(json, "src", rule.src);
        try optional(json, "dst", rule.dst);
        try optional(json, "sport", rule.sport);
        try optional(json, "dport", rule.dport);
        try optional(json, "iif", rule.iif);
        try optional(json, "oif", rule.oif);
        try json.objectField("ct_state");
        try json.beginArray();
        for (rule.ct_state) |state| try json.write(@tagName(state));
        try json.endArray();
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
}

fn field(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
}

fn optional(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
}

test "config-backed read models serialize" {
    const testing = std.testing;
    const config_parse = @import("vnet-core").config_parse;
    const source =
        \\{
        \\  "version": 1,
        \\  "instance": "test",
        \\  "ports": {"lan": {"kind": "l2", "device": "eth0", "mtu": 1500, "tagged": [10, 20]}},
        \\  "bridges": {"br0": {"ports": ["lan"], "stp": true, "vlan_aware": true}},
        \\  "interfaces": {"br0": {"bridge": "br0", "address": "10.0.0.1/24", "addresses": ["2001:db8::1/64"], "vlan": 10}},
        \\  "routes": [{"dst": "0.0.0.0/0", "via": "10.0.0.254", "metric": 100}],
        \\  "dhcp": [{"iface": "br0", "pool": "10.0.0.100/24", "lease": "1h", "reservations": [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.50"}]}],
        \\  "dns": {"upstreams": ["1.1.1.1"], "listen": "10.0.0.1", "zones": [{"suffix": "lan", "upstreams": ["1.1.1.1"]}]},
        \\  "firewall": {"default_in": "drop", "rules": [{"action": "accept", "proto": "tcp", "dport": 22, "ct_state": ["new"]}]}
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, source);
    defer parsed.deinit();

    var buf: [16 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    var json: std.json.Stringify = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "ports.list", &parsed.config));
    try json.endObject();
    var ports = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer ports.deinit();
    const port_items = ports.value.object.get("ports").?.array.items;
    try testing.expectEqualStrings("lan", port_items[0].object.get("name").?.string);
    try testing.expectEqual(@as(i64, 1500), port_items[0].object.get("mtu").?.integer);

    writer = .fixed(&buf);
    json = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "bridges.list", &parsed.config));
    try json.endObject();
    var bridges = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer bridges.deinit();
    try testing.expectEqual(@as(i64, 1), bridges.value.object.get("bridges").?.array.items[0].object.get("svi_count").?.integer);

    writer = .fixed(&buf);
    json = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "interfaces.list", &parsed.config));
    try json.endObject();
    var interfaces = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer interfaces.deinit();
    try testing.expectEqualStrings(
        "2001:db8::1/64",
        interfaces.value.object.get("interfaces").?.array.items[0].object.get("addresses").?.array.items[0].string,
    );

    writer = .fixed(&buf);
    json = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "routes.list", &parsed.config));
    try json.endObject();
    var routes = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer routes.deinit();
    try testing.expectEqualStrings(
        "10.0.0.254",
        routes.value.object.get("routes").?.array.items[0].object.get("via").?.string,
    );

    writer = .fixed(&buf);
    json = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "dhcp.list", &parsed.config));
    try json.endObject();
    var dhcp = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer dhcp.deinit();
    try testing.expectEqualStrings(
        "aa:bb:cc:dd:ee:ff",
        dhcp.value.object.get("dhcp").?.array.items[0].object.get("reservations").?.array.items[0].object.get("mac").?.string,
    );

    writer = .fixed(&buf);
    json = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "dns.list", &parsed.config));
    try json.endObject();
    var dns = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer dns.deinit();
    try testing.expectEqualStrings(
        "lan",
        dns.value.object.get("dns").?.object.get("zones").?.array.items[0].object.get("suffix").?.string,
    );

    writer = .fixed(&buf);
    json = .{ .writer = &writer };
    try json.beginObject();
    try testing.expect(try writeSection(&json, "firewall.list", &parsed.config));
    try json.endObject();
    var firewall = try std.json.parseFromSlice(std.json.Value, testing.allocator, writer.buffered(), .{});
    defer firewall.deinit();
    try testing.expectEqualStrings(
        "tcp",
        firewall.value.object.get("firewall").?.object.get("rules").?.array.items[0].object.get("proto").?.string,
    );
}
