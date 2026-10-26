const std = @import("std");
const vnet = @import("vnet");

const default_config = "/etc/vnet/vnet.json";

var stop = std.atomic.Value(bool).init(false);

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    stop.store(true, .release);
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        if (err == error.RestartRequested) {
            const args = init.minimal.args.toSlice(init.arena.allocator()) catch {
                std.Io.File.stderr().writeStreamingAll(init.io, "vnetd: restart: argument copy failed\n") catch {};
                std.process.exit(1);
            };
            const replace_error = std.process.replace(init.io, .{ .argv = args });
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "vnetd: restart: {s}\n", .{@errorName(replace_error)}) catch
                "vnetd: restart failed\n";
            std.Io.File.stderr().writeStreamingAll(init.io, msg) catch {};
            std.process.exit(1);
        }
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "vnetd: {s}\n", .{@errorName(err)}) catch "vnetd: error\n";
        std.Io.File.stderr().writeStreamingAll(init.io, msg) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var path: []const u8 = default_config;
    var enable_restart = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try usage(io);
            return;
        }
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            path = args[i];
            continue;
        }
        if (std.mem.eql(u8, arg, "--enable-restart")) {
            enable_restart = true;
            continue;
        }
        return error.InvalidArgument;
    }

    const run_dir = init.environ_map.get("VNET_RUN_DIR") orelse "/run/vnet";

    var store = try vnet.config_store.Store.open(io, gpa, path);
    defer store.deinit();
    if (try vnet.control_transaction.loadPending(io, gpa, run_dir)) |pending_value| {
        var pending = pending_value;
        defer pending.deinit();
        _ = try vnet.control_transaction.resolvePending(
            io,
            gpa,
            run_dir,
            store.revisionCopy(),
            &pending,
        );
    }
    const source = try store.readAlloc();
    defer gpa.free(source);

    var parsed = try vnet.config_parse.parse(gpa, source);
    defer parsed.deinit();
    try vnet.config_validate.validate(&parsed.config);

    const action = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);

    try vnet.app_service.run(io, gpa, &parsed.config, &stop, .{
        .state_dir = run_dir,
        .config_store = &store,
        .restart_supported = enable_restart,
    });
}

fn usage(io: std.Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io,
        \\vnetd — vNET daemon
        \\
        \\Usage:
        \\  vnetd [-c <config.json>] [--enable-restart]
        \\
        \\Defaults to /etc/vnet/vnet.json. Stops on SIGINT or SIGTERM.
        \\--enable-restart allows an authenticated control client to restart or
        \\stop this process. Restart re-execs after a clean teardown; stop exits.
        \\Without this flag both control lifecycle calls are refused.
        \\
    );
}
