//! vNET public Zig API.
//!
//! This is the composition root: it re-exports the shard surfaces and wires the
//! forwarding engine and runtime that are not separate shards yet.

const builtin = @import("builtin");

const core = @import("vnet-core");
const port_shard = @import("vnet-port");
const l2_shard = @import("vnet-l2");
const l3_shard = @import("vnet-l3");
const conntrack_shard = @import("vnet-conntrack");
const nat_shard = @import("vnet-nat");
const dhcp_shard = @import("vnet-dhcp");
const dns_shard = @import("vnet-dns");
const ctl_shard = @import("vnet-ctl");

pub const version = core.version;

pub const types = core.types;
pub const errors = core.errors;
pub const io = core.io;
pub const log = core.log;

pub const config_schema = core.config_schema;
pub const config_parse = core.config_parse;
pub const config_validate = core.config_validate;
pub const config_write = core.config_write;
pub const config_store = core.config_store;

pub const port = port_shard.port;
pub const memory_port = port_shard.memory;
pub const fd_port = port_shard.fd;
pub const buffer_pool = port_shard.pool;
pub const manager = port_shard.manager;
pub const linux_ports = port_shard.linux;

pub const ethernet = l2_shard.ethernet;
pub const stp = l2_shard.stp;

pub const ipv4 = l3_shard.ipv4;
pub const ipv6 = l3_shard.ipv6;
pub const arp = l3_shard.arp;
pub const ndp = l3_shard.ndp;
pub const fib = l3_shard.fib;
pub const fib6 = l3_shard.fib6;
pub const rate = l3_shard.rate;
pub const icmp = l3_shard.icmp;
pub const icmpv6 = l3_shard.icmpv6;

pub const conntrack = conntrack_shard.conntrack;
pub const nat = nat_shard.nat;

pub const dhcp_message = dhcp_shard.message;
pub const dhcp_server = dhcp_shard.server;
pub const dhcp_leases = dhcp_shard.leases;

pub const dns_message = dns_shard.message;
pub const dns_probe = dns_shard.probe;
pub const dns_cache = dns_shard.cache;
pub const dns_service = dns_shard.service;

pub const journal = ctl_shard.journal;
pub const firewall_counters = ctl_shard.firewall_counters;
pub const control_state = ctl_shard.state;
pub const control_protocol = ctl_shard.protocol;
pub const config_apply = ctl_shard.config_apply;
pub const control_transaction = ctl_shard.transaction;
pub const control_client = ctl_shard.client;
pub const control_server = ctl_shard.server;
pub const control_offload = ctl_shard.offload;
pub const control_host = ctl_shard.host;

pub const forward = @import("l3/forward.zig");
pub const app_service = if (builtin.os.tag == .linux)
    @import("app/service.zig")
else
    struct {};

pub const Config = core.Config;
pub const Port = port.Port;
pub const PortId = core.PortId;
pub const MemoryPort = memory_port.MemoryPort;

test {
    _ = @import("l3/forward.zig");
    if (builtin.os.tag == .linux) _ = @import("app/service.zig");
}
