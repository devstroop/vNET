const std = @import("std");
const build_zon = @import("build.zig.zon");

fn createModule(
    b: *std.Build,
    root: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const target_os = target.result.os.tag;
    const target_abi = target.result.abi;
    const is_linux = target_os == .linux;
    const is_android = is_linux and
        (target_abi == .android or target_abi == .androideabi);

    const version = build_zon.version;
    const semantic_version = comptime std.SemanticVersion.parse(version) catch
        @compileError("build.zig.zon version is not semantic");

    // CLI shards use std.Thread; the C ABI must use the host pthread backend.
    const cli_options = b.addOptions();
    cli_options.addOption([]const u8, "version", version);
    cli_options.addOption(bool, "pthread_threads", false);
    const cli_options_mod = cli_options.createModule();

    const ffi_options = b.addOptions();
    ffi_options.addOption([]const u8, "version", version);
    ffi_options.addOption(bool, "pthread_threads", true);
    const ffi_options_mod = ffi_options.createModule();

    const core_mod = createModule(b, "src/shard_core.zig", target, optimize);
    core_mod.addImport("build_options", cli_options_mod);

    const thread_cli = createModule(b, "src/thread.zig", target, optimize);
    thread_cli.addImport("build_options", cli_options_mod);
    const thread_ffi = createModule(b, "src/thread.zig", target, optimize);
    thread_ffi.addImport("build_options", ffi_options_mod);

    const port_mod = createModule(b, "src/shard_port.zig", target, optimize);
    port_mod.addImport("vnet-core", core_mod);

    const l2_mod = createModule(b, "src/shard_l2.zig", target, optimize);
    l2_mod.addImport("vnet-core", core_mod);

    const l3_mod = createModule(b, "src/shard_l3.zig", target, optimize);
    l3_mod.addImport("vnet-core", core_mod);

    const conntrack_mod = createModule(b, "src/shard_conntrack.zig", target, optimize);
    conntrack_mod.addImport("vnet-core", core_mod);

    const nat_mod = createModule(b, "src/shard_nat.zig", target, optimize);
    nat_mod.addImport("vnet-core", core_mod);
    nat_mod.addImport("vnet-l3", l3_mod);
    nat_mod.addImport("vnet-conntrack", conntrack_mod);

    const dhcp_mod = createModule(b, "src/shard_dhcp.zig", target, optimize);
    dhcp_mod.addImport("vnet-core", core_mod);

    const dns_cli = createModule(b, "src/shard_dns.zig", target, optimize);
    dns_cli.addImport("vnet-core", core_mod);
    dns_cli.addImport("vnet-thread", thread_cli);
    const dns_ffi = createModule(b, "src/shard_dns.zig", target, optimize);
    dns_ffi.addImport("vnet-core", core_mod);
    dns_ffi.addImport("vnet-thread", thread_ffi);

    const ctl_cli = createModule(b, "src/shard_ctl.zig", target, optimize);
    ctl_cli.addImport("vnet-core", core_mod);
    ctl_cli.addImport("vnet-port", port_mod);
    ctl_cli.addImport("vnet-dns", dns_cli);
    ctl_cli.addImport("vnet-thread", thread_cli);
    const ctl_ffi = createModule(b, "src/shard_ctl.zig", target, optimize);
    ctl_ffi.addImport("vnet-core", core_mod);
    ctl_ffi.addImport("vnet-port", port_mod);
    ctl_ffi.addImport("vnet-dns", dns_ffi);
    ctl_ffi.addImport("vnet-thread", thread_ffi);

    const vnet_mod = createModule(b, "src/lib.zig", target, optimize);
    vnet_mod.addImport("vnet-core", core_mod);
    vnet_mod.addImport("vnet-port", port_mod);
    vnet_mod.addImport("vnet-l2", l2_mod);
    vnet_mod.addImport("vnet-l3", l3_mod);
    vnet_mod.addImport("vnet-conntrack", conntrack_mod);
    vnet_mod.addImport("vnet-nat", nat_mod);
    vnet_mod.addImport("vnet-dhcp", dhcp_mod);
    vnet_mod.addImport("vnet-dns", dns_cli);
    vnet_mod.addImport("vnet-ctl", ctl_cli);

    const ffi_mod = createModule(b, "src/ffi.zig", target, optimize);
    ffi_mod.addImport("vnet-core", core_mod);
    ffi_mod.addImport("vnet-port", port_mod);
    ffi_mod.addImport("vnet-l2", l2_mod);
    ffi_mod.addImport("vnet-l3", l3_mod);
    ffi_mod.addImport("vnet-conntrack", conntrack_mod);
    ffi_mod.addImport("vnet-nat", nat_mod);
    ffi_mod.addImport("vnet-dhcp", dhcp_mod);
    ffi_mod.addImport("vnet-dns", dns_ffi);
    ffi_mod.addImport("vnet-ctl", ctl_ffi);
    ffi_mod.addImport("vnet-thread", thread_ffi);

    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "vnet",
        .root_module = ffi_mod,
    });
    b.installArtifact(static_lib);
    static_lib.installHeader(b.path("include/vnet.h"), "vnet.h");
    const static_lib_step = b.step("static-lib", "Build the static library");
    static_lib_step.dependOn(&b.addInstallArtifact(static_lib, .{}).step);

    const shared_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "vnet",
        .root_module = ffi_mod,
        .version = semantic_version,
    });
    shared_lib.linker_allow_shlib_undefined = true;
    b.installArtifact(shared_lib);
    const shared_lib_step = b.step("shared-lib", "Build the shared library");
    shared_lib_step.dependOn(&b.addInstallArtifact(shared_lib, .{}).step);

    if (is_linux and !is_android) {
        const exe_mod = createModule(b, "exec/vnet/main.zig", target, optimize);
        exe_mod.addImport("vnet", vnet_mod);

        const exe = b.addExecutable(.{
            .name = "vnet",
            .root_module = exe_mod,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (@hasField(std.Build, "args")) {
            if (b.args) |args| run_cmd.addArgs(args);
        } else {
            run_cmd.addPassthruArgs();
        }

        const run_step = b.step("run", "Run vNET");
        run_step.dependOn(&run_cmd.step);

        const daemon_mod = createModule(b, "exec/vnetd/main.zig", target, optimize);
        daemon_mod.addImport("vnet", vnet_mod);

        const daemon = b.addExecutable(.{
            .name = "vnetd",
            .root_module = daemon_mod,
        });
        b.installArtifact(daemon);

        const web_mod = createModule(b, "src/web/root.zig", target, optimize);
        web_mod.addImport("vnet-core", core_mod);
        web_mod.addImport("vnet-ctl", ctl_cli);

        const web_exe_mod = createModule(b, "exec/vnetweb/main.zig", target, optimize);
        web_exe_mod.addImport("web", web_mod);
        web_exe_mod.addImport("build_options", cli_options_mod);
        const web_exe = b.addExecutable(.{
            .name = "vnetweb",
            .root_module = web_exe_mod,
        });
        const web_step = b.step("web", "Build the HTMX web admin");
        web_step.dependOn(&b.addInstallArtifact(web_exe, .{}).step);

        const web_tests = b.addTest(.{
            .root_module = web_mod,
        });
        const run_web_tests = b.addRunArtifact(web_tests);
        const web_test_step = b.step("web-test", "Run web admin tests");
        web_test_step.dependOn(&run_web_tests.step);
    }

    const test_mod = createModule(b, "test.zig", target, optimize);
    test_mod.addImport("vnet-core", core_mod);
    test_mod.addImport("vnet-port", port_mod);
    test_mod.addImport("vnet-l2", l2_mod);
    test_mod.addImport("vnet-l3", l3_mod);
    test_mod.addImport("vnet-conntrack", conntrack_mod);
    test_mod.addImport("vnet-nat", nat_mod);
    test_mod.addImport("vnet-dhcp", dhcp_mod);
    test_mod.addImport("vnet-dns", dns_cli);
    test_mod.addImport("vnet-ctl", ctl_cli);
    test_mod.addImport("vnet-thread", thread_cli);

    const test_filter = b.option([]const u8, "test-filter", "Only run tests containing this substring");
    const test_filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
        .filters = test_filters,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const shards = [_]*std.Build.Module{
        core_mod,
        port_mod,
        l2_mod,
        l3_mod,
        conntrack_mod,
        nat_mod,
        dhcp_mod,
        dns_cli,
        ctl_cli,
    };
    for (shards) |module| {
        const shard_tests = b.addTest(.{
            .root_module = module,
            .filters = test_filters,
        });
        test_step.dependOn(&b.addRunArtifact(shard_tests).step);
    }

    // Fuzz tests live in their own artifact so `-fno-error-tracing` can work
    // around the Zig 0.16 fuzz test runner's StackTrace type mismatch without
    // weakening diagnostics for the normal unit suite.
    const fuzz_mod = createModule(b, "fuzz.zig", target, optimize);
    fuzz_mod.error_tracing = false;
    fuzz_mod.addImport("vnet-core", core_mod);
    fuzz_mod.addImport("vnet-port", port_mod);
    fuzz_mod.addImport("vnet-l2", l2_mod);
    fuzz_mod.addImport("vnet-l3", l3_mod);
    fuzz_mod.addImport("vnet-conntrack", conntrack_mod);
    fuzz_mod.addImport("vnet-nat", nat_mod);
    fuzz_mod.addImport("vnet-dhcp", dhcp_mod);
    fuzz_mod.addImport("vnet-dns", dns_cli);
    fuzz_mod.addImport("vnet-ctl", ctl_cli);

    // The self-hosted backend used by Debug emits no coverage counters, which
    // makes `--fuzz` abort with "pcs_len was zero". LLVM provides the counters.
    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        .filters = test_filters,
        .use_llvm = true,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    test_step.dependOn(&run_fuzz_tests.step);

    const fuzz_step = b.step("fuzz", "Run parser fuzz targets (pass --fuzz=N)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    const ffi_smoke_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ffi_smoke_mod.addCSourceFile(.{
        .file = b.path("test/ffi_smoke.c"),
        .flags = &.{"-std=c11"},
    });
    ffi_smoke_mod.addIncludePath(b.path("include"));
    ffi_smoke_mod.linkLibrary(shared_lib);

    const ffi_smoke = b.addExecutable(.{
        .name = "ffi-smoke",
        .root_module = ffi_smoke_mod,
    });
    const run_ffi_smoke = b.addRunArtifact(ffi_smoke);
    test_step.dependOn(&run_ffi_smoke.step);
}
