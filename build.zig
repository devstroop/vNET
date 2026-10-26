const std = @import("std");
const build_zon = @import("build.zig.zon");

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

    const core_options = b.addOptions();
    core_options.addOption([]const u8, "version", version);
    core_options.addOption(bool, "pthread_threads", false);
    const core_options_mod = core_options.createModule();

    const ffi_options = b.addOptions();
    ffi_options.addOption([]const u8, "version", version);
    ffi_options.addOption(bool, "pthread_threads", true);
    const ffi_options_mod = ffi_options.createModule();

    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    core_mod.addImport("build_options", core_options_mod);

    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ffi_mod.addImport("build_options", ffi_options_mod);

    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "vnet",
        .root_module = ffi_mod,
    });
    b.installArtifact(static_lib);
    static_lib.installHeader(b.path("include/vnet.h"), "vnet.h");

    const shared_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "vnet",
        .root_module = ffi_mod,
        .version = semantic_version,
    });
    shared_lib.linker_allow_shlib_undefined = true;
    b.installArtifact(shared_lib);

    if (is_linux and !is_android) {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path("exec/vnet/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vnet", .module = core_mod },
            },
        });

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

        const daemon_mod = b.createModule(.{
            .root_source_file = b.path("exec/vnetd/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vnet", .module = core_mod },
            },
        });

        const daemon = b.addExecutable(.{
            .name = "vnetd",
            .root_module = daemon_mod,
        });
        b.installArtifact(daemon);

        const web_mod = b.createModule(.{
            .root_source_file = b.path("src/web/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vnet", .module = core_mod },
            },
        });
        web_mod.addImport("build_options", core_options_mod);

        const web_exe_mod = b.createModule(.{
            .root_source_file = b.path("exec/vnetweb/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "web", .module = web_mod },
                .{ .name = "build_options", .module = core_options_mod },
            },
        });
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

    const test_mod = b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("build_options", core_options_mod);

    const test_filter = b.option([]const u8, "test-filter", "Only run tests containing this substring");
    const test_filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
        .filters = test_filters,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Fuzz tests live in their own artifact so `-fno-error-tracing` can work
    // around the Zig 0.16 fuzz test runner's StackTrace type mismatch without
    // weakening diagnostics for the normal unit suite.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .error_tracing = false,
    });
    fuzz_mod.addImport("build_options", core_options_mod);

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
