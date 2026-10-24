const std = @import("std");

pub const token_hex_len = 64;
pub const default_session_ttl_ms: i64 = 12 * 60 * 60 * 1000;
pub const max_sessions = 32;

pub const Session = struct {
    token: [token_hex_len]u8,
    csrf: [token_hex_len]u8,
    expires_ms: i64,
};

pub const Created = struct {
    token: [token_hex_len]u8,
    csrf: [token_hex_len]u8,
};

/// In-memory session store for the web admin preview.
///
/// Sessions are bearer tokens held in a bounded list. Restarting the process
/// invalidates every session; this is intentional until a persistent session
/// store and explicit revocation policy are designed.
pub const Store = struct {
    gpa: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    sessions: std.ArrayListUnmanaged(Session) = .empty,

    pub fn init(gpa: std.mem.Allocator) Store {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Store) void {
        self.sessions.deinit(self.gpa);
        self.* = undefined;
    }

    /// Creates a session and returns its bearer token and CSRF token.
    pub fn create(self: *Store, io: std.Io, now_ms: i64, ttl_ms: i64) !Created {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        self.pruneLocked(now_ms);
        while (self.sessions.items.len >= max_sessions) {
            _ = self.sessions.orderedRemove(0);
        }

        var raw_token: [32]u8 = undefined;
        var raw_csrf: [32]u8 = undefined;
        try io.randomSecure(&raw_token);
        try io.randomSecure(&raw_csrf);
        const token = std.fmt.bytesToHex(raw_token, .lower);
        const csrf = std.fmt.bytesToHex(raw_csrf, .lower);

        try self.sessions.append(self.gpa, .{
            .token = token,
            .csrf = csrf,
            .expires_ms = now_ms + @max(ttl_ms, 1),
        });
        return .{ .token = token, .csrf = csrf };
    }

    /// Returns true and refreshes nothing when `token` names a live session.
    pub fn validate(self: *Store, io: std.Io, token: []const u8, now_ms: i64) bool {
        if (token.len != token_hex_len) return false;
        var candidate: [token_hex_len]u8 = undefined;
        @memcpy(&candidate, token);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        self.pruneLocked(now_ms);
        for (self.sessions.items) |session| {
            if (std.crypto.timing_safe.eql([token_hex_len]u8, session.token, candidate)) {
                return true;
            }
        }
        return false;
    }

    /// Returns the CSRF token for a live session.
    pub fn csrfFor(self: *Store, io: std.Io, token: []const u8, now_ms: i64) ?[token_hex_len]u8 {
        if (token.len != token_hex_len) return null;
        var candidate: [token_hex_len]u8 = undefined;
        @memcpy(&candidate, token);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        self.pruneLocked(now_ms);
        for (self.sessions.items) |session| {
            if (std.crypto.timing_safe.eql([token_hex_len]u8, session.token, candidate)) {
                return session.csrf;
            }
        }
        return null;
    }

    pub fn remove(self: *Store, io: std.Io, token: []const u8) void {
        if (token.len != token_hex_len) return;
        var candidate: [token_hex_len]u8 = undefined;
        @memcpy(&candidate, token);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        for (self.sessions.items, 0..) |session, i| {
            if (std.crypto.timing_safe.eql([token_hex_len]u8, session.token, candidate)) {
                _ = self.sessions.orderedRemove(i);
                return;
            }
        }
    }

    fn pruneLocked(self: *Store, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.sessions.items.len) {
            if (self.sessions.items[i].expires_ms <= now_ms) {
                _ = self.sessions.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

pub fn hashPassword(
    io: std.Io,
    gpa: std.mem.Allocator,
    password: []const u8,
    params: std.crypto.pwhash.argon2.Params,
    out: []u8,
) ![]const u8 {
    return std.crypto.pwhash.argon2.strHash(password, .{
        .allocator = gpa,
        .params = params,
    }, out, io);
}

pub fn verifyPassword(
    io: std.Io,
    gpa: std.mem.Allocator,
    phc: []const u8,
    password: []const u8,
) bool {
    std.crypto.pwhash.argon2.strVerify(phc, password, .{
        .allocator = gpa,
    }, io) catch return false;
    return true;
}

test "session lifecycle" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const created = try store.create(std.testing.io, 1_000, 500);
    try std.testing.expect(store.validate(std.testing.io, &created.token, 1_400));
    try std.testing.expect(store.csrfFor(std.testing.io, &created.token, 1_400) != null);
    try std.testing.expect(!store.validate(std.testing.io, &created.token, 1_600));

    const created2 = try store.create(std.testing.io, 1_700, 500);
    store.remove(std.testing.io, &created2.token);
    try std.testing.expect(!store.validate(std.testing.io, &created2.token, 1_800));
}

test "session store is bounded" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    for (0..max_sessions + 8) |i| {
        _ = try store.create(std.testing.io, @intCast(i), 1_000);
        try std.testing.expect(store.sessions.items.len <= max_sessions);
    }
}

test "argon2 password round trip" {
    var out: [256]u8 = undefined;
    const phc = try hashPassword(std.testing.io, std.testing.allocator, "correct horse", .{
        .t = 1,
        .m = 8,
        .p = 1,
    }, &out);

    try std.testing.expect(verifyPassword(std.testing.io, std.testing.allocator, phc, "correct horse"));
    try std.testing.expect(!verifyPassword(std.testing.io, std.testing.allocator, phc, "wrong"));
}
