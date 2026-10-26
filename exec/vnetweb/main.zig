const std = @import("std");
const web = @import("web");

const default_password_file = "/etc/vnet/web-password";
const max_password_bytes = 1024;

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var buf: [256]u8 = undefined;
        const message = std.fmt.bufPrint(&buf, "vnetweb: {s}\n", .{@errorName(err)}) catch "vnetweb: error\n";
        std.Io.File.stderr().writeStreamingAll(init.io, message) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var listen: []const u8 = "127.0.0.1:8080";
    var control_path: ?[]const u8 = null;
    var password_file: []const u8 = default_password_file;
    var hash_password = false;
    var ttl_ms: i64 = web.auth.default_session_ttl_ms;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return usage(io);
        }
        if (std.mem.eql(u8, arg, "--version")) {
            try std.Io.File.stdout().writeStreamingAll(io, "vnetweb " ++ @import("build_options").version ++ "\n");
            return;
        }
        if (std.mem.eql(u8, arg, "--hash-password")) {
            hash_password = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--listen")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            listen = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--control")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            control_path = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--password-hash-file")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            password_file = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--session-ttl-hours")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            const hours = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidArgument;
            if (hours == 0 or hours > 24 * 7) return error.InvalidArgument;
            ttl_ms = @as(i64, hours) * 60 * 60 * 1000;
            continue;
        }
        return error.InvalidArgument;
    }

    if (hash_password) {
        var password_buf: [max_password_bytes]u8 = undefined;
        var reader = std.Io.File.stdin().reader(io, &password_buf);
        const password = try reader.interface.takeDelimiterExclusive('\n');
        if (password.len == 0) return error.MissingPassword;
        var hash_buf: [256]u8 = undefined;
        const phc = try web.auth.hashPassword(io, gpa, password, .owasp_2id, &hash_buf);
        try std.Io.File.stdout().writeStreamingAll(io, phc);
        try std.Io.File.stdout().writeStreamingAll(io, "\n");
        return;
    }

    const run_dir = init.environ_map.get("VNET_RUN_DIR") orelse "/run/vnet";
    var control_buf: [512]u8 = undefined;
    const control = control_path orelse try std.fmt.bufPrint(&control_buf, "{s}/control.sock", .{run_dir});

    const phc_raw = try std.Io.Dir.cwd().readFileAlloc(io, password_file, gpa, .limited(4096));
    defer gpa.free(phc_raw);
    const phc = std.mem.trim(u8, phc_raw, " \t\r\n");
    if (phc.len == 0) return error.EmptyPasswordHash;

    try web.server.run(.{
        .io = io,
        .gpa = gpa,
        .listen = listen,
        .control_path = control,
        .password_phc = phc,
        .session_ttl_ms = ttl_ms,
    });
}

fn usage(io: std.Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io,
        \\vnetweb — vNET web admin
        \\
        \\Usage:
        \\  vnetweb [options]
        \\  vnetweb --hash-password < password.txt
        \\
        \\Options:
        \\  --listen <addr:port>          Default 127.0.0.1:8080; loopback only.
        \\  --control <path>              Default $VNET_RUN_DIR/control.sock.
        \\  --password-hash-file <path>   Default /etc/vnet/web-password.
        \\  --session-ttl-hours <n>       Default 12, maximum 168.
        \\  --version                     Print version.
        \\  -h, --help                    Print this help.
        \\
        \\The password hash is an Argon2id PHC string produced by --hash-password.
        \\The server serves embedded HTMX assets and obtains all state over the
        \\control socket. Writes are staged and sent to the daemon as control
        \\requests; the web process never mutates host state directly.
        \\
    );
}
