//! Fixed-capacity bridge forwarding database.
//!
//! The table is allocated once at startup. MAC learning never allocates:
//! entries live in a preallocated slot array, and a FIFO list supplies the
//! oldest slot when the table is full. FIFO order is insertion order; a
//! source-MAC refresh updates the timestamp but does not move the slot.

const std = @import("std");
const types = @import("vnet-core").types;

const none: u16 = std.math.maxInt(u16);

pub const Value = struct {
    port: types.PortId,
    updated_ms: i64,
};

pub const Fdb = struct {
    entries: []Entry = &.{},
    index: std.AutoHashMapUnmanaged(u128, u16) = .empty,
    free_head: u16 = none,
    fifo_head: u16 = none,
    fifo_tail: u16 = none,
    len: usize = 0,

    const Entry = struct {
        key: u128 = 0,
        value: Value = undefined,
        prev: u16 = none,
        next: u16 = none,
        used: bool = false,
    };

    /// Allocate `capacity` slots and the key index. `capacity` must be at
    /// least one and small enough for `u16` slot indices.
    pub fn init(gpa: std.mem.Allocator, max_entries: usize) !Fdb {
        if (max_entries == 0 or max_entries >= none) return error.InvalidCapacity;

        const entries = try gpa.alloc(Entry, max_entries);
        errdefer gpa.free(entries);
        for (entries, 0..) |*entry, i| {
            entry.* = .{};
            entry.next = if (i + 1 < max_entries) @intCast(i + 1) else none;
        }

        var index: std.AutoHashMapUnmanaged(u128, u16) = .empty;
        errdefer index.deinit(gpa);
        try index.ensureTotalCapacity(gpa, @intCast(max_entries));

        return .{
            .entries = entries,
            .index = index,
            .free_head = 0,
        };
    }

    pub fn deinit(self: *Fdb, gpa: std.mem.Allocator) void {
        self.index.deinit(gpa);
        if (self.entries.len != 0) gpa.free(self.entries);
        self.* = .{};
    }

    pub fn count(self: *const Fdb) usize {
        return self.len;
    }

    pub fn capacity(self: *const Fdb) usize {
        return self.entries.len;
    }

    pub fn get(self: *const Fdb, key: u128) ?Value {
        const index = self.index.get(key) orelse return null;
        return self.entries[index].value;
    }

    /// Insert a new key or refresh an existing one. When the table is full,
    /// the oldest inserted key is evicted. A refresh does not change FIFO
    /// order.
    pub fn learn(self: *Fdb, key: u128, new_value: Value) void {
        if (self.index.get(key)) |index| {
            self.entries[index].value = new_value;
            return;
        }
        if (self.len == self.entries.len and !self.evictOldest()) return;

        const index = self.free_head;
        if (index == none) return;
        const entry = &self.entries[index];
        self.free_head = entry.next;

        entry.* = .{
            .key = key,
            .value = new_value,
            .prev = self.fifo_tail,
            .next = none,
            .used = true,
        };
        if (self.fifo_tail != none) {
            self.entries[self.fifo_tail].next = index;
        } else {
            self.fifo_head = index;
        }
        self.fifo_tail = index;
        self.len += 1;
        self.index.putAssumeCapacityNoClobber(key, index);
    }

    pub fn remove(self: *Fdb, key: u128) bool {
        const index = self.index.get(key) orelse return false;
        self.removeIndex(index);
        return true;
    }

    pub fn evictOldest(self: *Fdb) bool {
        if (self.fifo_head == none) return false;
        self.removeIndex(self.fifo_head);
        return true;
    }

    /// Remove entries whose timestamp is older than `ttl_ms`.
    pub fn prune(self: *Fdb, now_ms: i64, ttl_ms: i64) usize {
        var removed: usize = 0;
        for (self.entries, 0..) |*entry, i| {
            if (!entry.used) continue;
            if (now_ms - entry.value.updated_ms <= ttl_ms) continue;
            self.removeIndex(@intCast(i));
            removed += 1;
        }
        return removed;
    }

    fn removeIndex(self: *Fdb, index: u16) void {
        const entry = &self.entries[index];
        if (!entry.used) return;

        _ = self.index.remove(entry.key);
        if (entry.prev != none) {
            self.entries[entry.prev].next = entry.next;
        } else {
            self.fifo_head = entry.next;
        }
        if (entry.next != none) {
            self.entries[entry.next].prev = entry.prev;
        } else {
            self.fifo_tail = entry.prev;
        }

        entry.used = false;
        entry.prev = none;
        entry.next = self.free_head;
        self.free_head = index;
        self.len -= 1;
    }
};

const testing = std.testing;

fn value(port: u32, updated_ms: i64) Value {
    return .{ .port = .{ .value = port }, .updated_ms = updated_ms };
}

test "fdb learns looks up and refreshes without growing" {
    var fdb = try Fdb.init(testing.allocator, 4);
    defer fdb.deinit(testing.allocator);

    fdb.learn(1, value(10, 100));
    fdb.learn(2, value(20, 200));
    try testing.expectEqual(@as(usize, 2), fdb.count());
    try testing.expectEqual(@as(u32, 10), fdb.get(1).?.port.value);

    fdb.learn(1, value(11, 300));
    try testing.expectEqual(@as(usize, 2), fdb.count());
    try testing.expectEqual(@as(u32, 11), fdb.get(1).?.port.value);
    try testing.expectEqual(@as(i64, 300), fdb.get(1).?.updated_ms);
}

test "fdb evicts oldest inserted entry when full" {
    var fdb = try Fdb.init(testing.allocator, 2);
    defer fdb.deinit(testing.allocator);

    fdb.learn(1, value(10, 100));
    fdb.learn(2, value(20, 200));
    fdb.learn(1, value(11, 300));
    fdb.learn(3, value(30, 400));

    try testing.expect(fdb.get(1) == null);
    try testing.expectEqual(@as(u32, 20), fdb.get(2).?.port.value);
    try testing.expectEqual(@as(u32, 30), fdb.get(3).?.port.value);
    try testing.expectEqual(@as(usize, 2), fdb.count());
}

test "fdb removes entries and reuses slots" {
    var fdb = try Fdb.init(testing.allocator, 3);
    defer fdb.deinit(testing.allocator);

    fdb.learn(1, value(10, 100));
    fdb.learn(2, value(20, 200));
    fdb.learn(3, value(30, 300));
    try testing.expect(fdb.remove(2));

    fdb.learn(4, value(40, 400));
    try testing.expectEqual(@as(usize, 3), fdb.count());
    try testing.expect(fdb.get(2) == null);
    try testing.expect(fdb.get(4) != null);

    fdb.learn(5, value(50, 500));
    try testing.expect(fdb.get(1) == null);
    try testing.expect(fdb.get(3) != null);
    try testing.expect(fdb.get(4) != null);
    try testing.expect(fdb.get(5) != null);
}

test "fdb prunes expired entries and refills freed slots" {
    var fdb = try Fdb.init(testing.allocator, 2);
    defer fdb.deinit(testing.allocator);

    fdb.learn(1, value(10, 100));
    fdb.learn(2, value(20, 300));
    try testing.expectEqual(@as(usize, 1), fdb.prune(350, 100));
    try testing.expect(fdb.get(1) == null);
    try testing.expect(fdb.get(2) != null);

    fdb.learn(3, value(30, 350));
    fdb.learn(4, value(40, 400));
    try testing.expectEqual(@as(usize, 2), fdb.count());
    try testing.expect(fdb.get(2) == null);
    try testing.expect(fdb.get(3) != null);
    try testing.expect(fdb.get(4) != null);
}
