const std = @import("std");

/// The package manifest. Its version names the release files.
const manifest: struct {
    name: @TypeOf(.enum_literal),
    version: []const u8,
    minimum_zig_version: []const u8,
    fingerprint: u64,
    dependencies: struct {},
    paths: []const []const u8,
} = @import("build.zig.zon");

comptime {
    // `blackice version` prints the constant in src/main.zig, so it must match the release file names.
    const declared = "pub const version = \"" ++ manifest.version ++ "\";";
    if (std.mem.find(u8, @embedFile("src/main.zig"), declared) == null)
        @compileError("src/main.zig must declare " ++ declared ++ " to match build.zig.zon");
}

/// The targets of `zig build release`. Linux binaries are static (std only, no libc); macOS binaries link only
/// libSystem.
const release_targets = [_][]const u8{ "x86_64-linux", "aarch64-linux", "aarch64-macos", "x86_64-macos" };

/// The Linux helper's release targets. A privileged binary ships only after it has run once on a real machine
/// of its architecture, so aarch64 stays out until an arm64 run exists (its own step builds it meanwhile).
const helper_targets = [_][]const u8{"x86_64-linux"};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "blackice",
        .root_module = root,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run blackice");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{ .root_module = root });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    if (target.result.os.tag == .linux) {
        // Match linux-build-helper.sh even when the main executable targets the native CPU.
        const helper_target = b.resolveTargetQuery(.{
            .cpu_arch = target.result.cpu.arch,
            .cpu_model = .baseline,
            .os_tag = .linux,
        });
        const helper_root = b.createModule(.{
            .root_source_file = b.path("src/linux/helper.zig"),
            .target = helper_target,
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        const helper = b.addExecutable(.{ .name = "blackice-linux-helper", .root_module = helper_root });
        b.installArtifact(helper);
        const helper_tests = b.addTest(.{ .root_module = helper_root });
        test_step.dependOn(&b.addRunArtifact(helper_tests).step);

        const launch_io_tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path("src/linux/launch_io.zig"),
            .target = target,
            .optimize = optimize,
        }) });
        test_step.dependOn(&b.addRunArtifact(launch_io_tests).step);

        const probe_root = b.createModule(.{
            .root_source_file = b.path("src/linux/probe.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "blackice_core", .module = root }},
        });
        const probe = b.addExecutable(.{ .name = "blackice-linux-probe", .root_module = probe_root });
        const probe_step = b.step("linux-probe", "Build the explicit Linux backend test harness");
        probe_step.dependOn(&b.addInstallArtifact(probe, .{}).step);
        const probe_tests = b.addTest(.{ .root_module = probe_root });
        test_step.dependOn(&b.addRunArtifact(probe_tests).step);
    }

    // Separate, opt-in build: never loads or attaches anything.
    const apps_target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .cpu_model = .baseline, .os_tag = .linux });
    const apps_root = b.createModule(.{ .root_source_file = b.path("src/linux_appfilter.zig"), .target = apps_target, .optimize = .ReleaseSafe, .strip = true });
    const apps_options = b.addOptions();
    apps_options.addOption(bool, "vm_faults", b.option(bool, "appfilter-vm-faults", "VM3-only reload fault build; NEVER use for a host install") orelse false);
    apps_root.addOptions("appfilter_build", apps_options);
    const apps = b.addExecutable(.{ .name = "blackice-linux-appfilter", .root_module = apps_root });
    b.step("linux-appfilter", "Build the kernel-pinned Linux application filter (no install to host)").dependOn(&b.addInstallArtifact(apps, .{}).step);
    const apps_tests = b.addTest(.{ .root_module = apps_root, .filters = &.{"appfilter"} });
    b.step("linux-appfilter-test", "Run pure application-filter unit tests; no BPF or network activity").dependOn(&b.addRunArtifact(apps_tests).step);

    addRelease(b);
}

/// `zig build release`: in zig-out/release/,
/// - blackice-<version>-<target> for every release target,
/// - blackice-linux-helper-<version>-<arch>-linux for each helper target,
/// - SHA256SUMS, covering every file above.
///
/// All are ReleaseSafe, stripped and built for the baseline CPU of their architecture. Stripping drops the
/// debug info, which holds absolute build paths, so the same commit built with the same Zig gives the same
/// bytes in any directory, and the helper matches scripts/linux-build-helper.sh.
///
/// -Dmacos-min sets the oldest macOS the binaries start on. Without it, Zig would write its own default (15.0).
/// It also decides which system interfaces the standard library may use, so test with the same minimum.
///
/// `zig build helper-aarch64` builds the aarch64 helper the same way, into zig-out/unreleased/. It is not a
/// release file and is not in SHA256SUMS.
fn addRelease(b: *std.Build) void {
    const macos_min = b.option([]const u8, "macos-min", "Oldest macOS the release binaries run on (default 13.0)") orelse "13.0";
    const release_step = b.step("release", "Build stripped, reproducible release files and their SHA256SUMS");

    const sums_tool = b.addExecutable(.{
        .name = "sha256sums",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/sha256sums.zig"),
            .target = b.graph.host,
        }),
    });
    const sums = b.addRunArtifact(sums_tool);
    const sums_file = sums.addOutputFileArg("SHA256SUMS");

    for (release_targets) |name| {
        const triple = if (std.mem.endsWith(u8, name, "-macos")) b.fmt("{s}.{s}", .{ name, macos_min }) else name;
        const query = std.Target.Query.parse(.{ .arch_os_abi = triple, .cpu_features = "baseline" }) catch |err| {
            // Only the release step fails; the other steps still work with a bad -Dmacos-min.
            const fail = b.addFail(b.fmt("release target {s}: {s} (check -Dmacos-min)", .{ triple, @errorName(err) }));
            release_step.dependOn(&fail.step);
            continue;
        };
        const exe = b.addExecutable(.{
            .name = "blackice",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = b.resolveTargetQuery(query),
                .optimize = .ReleaseSafe,
                .strip = true,
            }),
        });
        addReleaseFile(b, release_step, sums, exe, b.fmt("blackice-{s}-{s}", .{ manifest.version, name }));
    }
    for (helper_targets) |name| {
        addReleaseFile(b, release_step, sums, linuxHelper(b, name), b.fmt("blackice-linux-helper-{s}-{s}", .{ manifest.version, name }));
    }

    const install_sums = b.addInstallFileWithDir(sums_file, .{ .custom = "release" }, "SHA256SUMS");
    release_step.dependOn(&install_sums.step);

    const arm_step = b.step("helper-aarch64", "Build the aarch64 Linux helper into zig-out/unreleased (not a release file until an arm64 run exists)");
    const arm_install = b.addInstallArtifact(linuxHelper(b, "aarch64-linux"), .{
        .dest_dir = .{ .override = .{ .custom = "unreleased" } },
        .dest_sub_path = b.fmt("blackice-linux-helper-{s}-aarch64-linux", .{manifest.version}),
    });
    arm_step.dependOn(&arm_install.step);
}

/// The Linux helper for one `<arch>-linux` target, with the flags scripts/linux-build-helper.sh uses:
/// baseline CPU, ReleaseSafe, stripped.
fn linuxHelper(b: *std.Build, arch_os: []const u8) *std.Build.Step.Compile {
    const query = std.Target.Query.parse(.{ .arch_os_abi = arch_os, .cpu_features = "baseline" }) catch unreachable;
    return b.addExecutable(.{
        .name = "blackice-linux-helper",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/linux/helper.zig"),
            .target = b.resolveTargetQuery(query),
            .optimize = .ReleaseSafe,
            .strip = true,
        }),
    });
}

/// Installs one release file under its release name and lists it in SHA256SUMS.
fn addReleaseFile(b: *std.Build, release_step: *std.Build.Step, sums: *std.Build.Step.Run, exe: *std.Build.Step.Compile, file_name: []const u8) void {
    const install = b.addInstallArtifact(exe, .{
        .dest_dir = .{ .override = .{ .custom = "release" } },
        .dest_sub_path = file_name,
    });
    release_step.dependOn(&install.step);
    sums.addArg(file_name);
    sums.addFileArg(exe.getEmittedBin());
}
