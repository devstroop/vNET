//! Port abstraction.
//!
//! A port is a source/sink of frames (L2) or packets (L3). The datapath holds
//! ports behind this vtable so the forwarding pipeline is independent of
//! AF_PACKET, TUN/TAP, VpnService fds and in-memory test ports.

const std = @import("std");
const types = @import("vnet-core").types;
const PortError = @import("vnet-core").PortError;

pub const PortId = types.PortId;

pub const PortKind = enum {
    ethernet,
    wifi,
    cellular,
    usb,
    tun,
    tap,
    bridge,
    memory,
};

pub const Capabilities = struct {
    l2: bool = false,
    l3: bool = false,
    promiscuous: bool = false,
    multicast: bool = false,
    vlan_filter: bool = false,
    checksum_offload: bool = false,
    gso: bool = false,
    can_set_mtu: bool = false,
};

pub const LinkState = enum { unknown, down, up };

pub const PortInfo = struct {
    id: PortId,
    name: []const u8,
    ifindex: u32 = 0,
    kind: PortKind,
    mac: types.Mac = .{},
    mtu: u16 = 1500,
    link: LinkState = .unknown,
    capabilities: Capabilities = .{},
};

pub const Stats = struct {
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
    drops: u64 = 0,
};

pub const BatchFrame = struct {
    data: []u8,
    len: usize = 0,
};

/// A port handle. The concrete implementation owns `ctx`; `Port` is copied by
/// value and is only valid while the implementation is alive.
pub const Port = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, io: std.Io, buf: []u8) PortError!?usize,
        write: *const fn (ctx: *anyopaque, io: std.Io, frame: []const u8) PortError!void,
        pollFd: *const fn (ctx: *anyopaque) ?std.posix.fd_t,
        info: *const fn (ctx: *anyopaque) PortInfo,
        stats: *const fn (ctx: *anyopaque) Stats,
        refresh: *const fn (ctx: *anyopaque, io: std.Io) PortError!void,
        setUp: *const fn (ctx: *anyopaque, io: std.Io, up: bool) PortError!void,
        setMtu: *const fn (ctx: *anyopaque, io: std.Io, mtu: u16) PortError!void,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
        /// Optional bulk receive. Implementations that can amortize the
        /// syscall fill `frames[0..n]` and return `n`; the default loops over
        /// `read`. Each `data` buffer belongs to the caller. Slots with
        /// `len == 0` are holes and must be skipped by the caller.
        read_batch: ?*const fn (ctx: *anyopaque, io: std.Io, frames: []BatchFrame) PortError!usize = null,
        /// Optional queued write for ports that batch `write_queued` calls.
        write_queued: ?*const fn (ctx: *anyopaque, io: std.Io, frame: []const u8) PortError!void = null,
        /// Optional flush for ports that batch `write_queued` calls.
        flush: ?*const fn (ctx: *anyopaque, io: std.Io) PortError!void = null,
    };

    /// Returns null when no frame is currently available. Implementations must
    /// not block the caller indefinitely; use `io` for any required waits.
    pub fn read(self: Port, io: std.Io, buf: []u8) PortError!?usize {
        return self.vtable.read(self.ctx, io, buf);
    }

    pub fn write(self: Port, io: std.Io, frame: []const u8) PortError!void {
        return self.vtable.write(self.ctx, io, frame);
    }

    /// Writes a frame without necessarily pushing it to the device. Call
    /// `flush` before waiting for input or shutting down.
    pub fn writeQueued(self: Port, io: std.Io, frame: []const u8) PortError!void {
        if (self.vtable.write_queued) |write_queued| return write_queued(self.ctx, io, frame);
        return self.vtable.write(self.ctx, io, frame);
    }

    /// Receives up to `frames.len` descriptors. Returns the number of slots
    /// filled, including holes with `len == 0` for frames dropped by the
    /// implementation; callers must skip those slots. Implementations may cap
    /// the batch below `frames.len`.
    pub fn readBatch(self: Port, io: std.Io, frames: []BatchFrame) PortError!usize {
        if (self.vtable.read_batch) |read_batch| {
            return read_batch(self.ctx, io, frames);
        }
        var count: usize = 0;
        for (frames) |*frame| {
            const maybe_len = self.read(io, frame.data) catch |err| {
                if (count > 0) return count;
                return err;
            };
            const len = maybe_len orelse break;
            frame.len = len;
            count += 1;
        }
        return count;
    }

    /// Pushes any frames held by a batching implementation.
    pub fn flush(self: Port, io: std.Io) PortError!void {
        if (self.vtable.flush) |flush_fn| return flush_fn(self.ctx, io);
    }

    /// Returns a descriptor that becomes readable when `read` may return a
    /// frame, or null for ports without a pollable fd (in-memory tests).
    pub fn pollFd(self: Port) ?std.posix.fd_t {
        return self.vtable.pollFd(self.ctx);
    }

    pub fn info(self: Port) PortInfo {
        return self.vtable.info(self.ctx);
    }

    pub fn stats(self: Port) Stats {
        return self.vtable.stats(self.ctx);
    }

    /// Re-reads link state, MTU and MAC from the OS. Used after hotplug events.
    pub fn refresh(self: Port, io: std.Io) PortError!void {
        return self.vtable.refresh(self.ctx, io);
    }

    pub fn setUp(self: Port, io: std.Io, up: bool) PortError!void {
        return self.vtable.setUp(self.ctx, io, up);
    }

    pub fn setMtu(self: Port, io: std.Io, mtu: u16) PortError!void {
        return self.vtable.setMtu(self.ctx, io, mtu);
    }

    pub fn deinit(self: Port, io: std.Io) void {
        self.vtable.close(self.ctx, io);
    }
};
