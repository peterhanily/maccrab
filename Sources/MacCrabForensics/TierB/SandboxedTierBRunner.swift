// SandboxedTierBRunner — spawns a verified UNTRUSTED third-party / sideload
// Tier-B plugin under a deny-default sandbox, via the signed
// `maccrab-tierb-sandbox-host` trampoline. The disjoint twin of
// FirstPartyTierBRunner: same proven spawn/reap/cap machinery (own process group
// + kill(-pgid) reap, env scrubbed to PATH+HOME, F_SETNOSIGPIPE stdin,
// background-capped stdout, WNOWAIT-then-reap, wall-clock timeout), but:
//   - hard-requires VerifiedPlugin.isSandboxed AND refuses isFirstParty (only
//     resolveForSandboxedExecution sets isSandboxed; the lanes never cross);
//   - launches the TRAMPOLINE, not the plugin: the trampoline sets rlimits,
//     applies the manifest-derived deny-default SBPL to itself via sandbox_init,
//     then execv's the verified plugin — so the plugin runs contained;
//   - writes that SBPL to a fresh 0o400 temp (sibling of the 0o500 verified
//     binary temp) and passes its path to the trampoline;
//   - fail-closed: if the trampoline is missing / not executable, or the profile
//     can't be written, it throws BEFORE spawning — third-party code is
//     contained-or-nothing, never run uncontained.
//
// The TierBIPC stdin/stdout contract is UNCHANGED and survives the trampoline
// (the trampoline inherits fds 0/1/2 across execv). Output maps through
// TierBArtifactBridge exactly as the first-party lane.
//
// LIVE: this runner is reached via TierBCollectorExecutor (CLI `plugin run`, the
// dashboard "Run on this Mac", and MCP forensics.run_collector). It attaches the
// per-invocation SCM_RIGHTS file broker on fd 3 (O_NOFOLLOW safe-open beneath the
// allowed roots + brokered-TCC snapshots; the served-path TCC guard keeps live
// stores out) and tears it down after reap. Containment is PROVEN on-device by
// ContainmentCorpus (`make test-corpus`) for both C and Swift fixtures. The
// runnable lane is still TRUST-gated (FirstPartyTrustRoot / signed catalog /
// sideload TOFU) and GA-gated on the keyholder ceremony + external pentest.
//
// REMAINING DEVICE / HARDENING ITEMS (operator/tracked, NOT fail-open):
//   - Re-validate the SBPL runtime base + rlimits against the corpus on the EXACT
//     signed release build (the defaults here are corpus-proven on the dev host;
//     widen SandboxProfileBuilder.runtimeBaseMachServices if a heavier plugin
//     SIGABRTs — never restore a global mach-lookup).
//   - The check->spawn TOCTOU on the trampoline (an fd-pinned/fexecve-style spawn)
//     and a runtime fetch of a fresh signed revocation list are tracked hardenings.

import Foundation
import Darwin
import Security

public struct SandboxedTierBRunner: Sendable {

    /// Resource bounds applied by the trampoline (setrlimit) before sandbox_init
    /// + execv, on top of the runner's existing stdout/artifact/time caps. 0 ==
    /// "leave the inherited limit alone". DEVICE-TUNE: these are conservative
    /// starting points; the corpus client-test sets the proven values.
    public struct ResourceLimits: Sendable, Equatable {
        public var cpuSeconds: UInt64
        public var addressSpaceBytes: UInt64
        public var maxProcesses: UInt64
        public var maxOpenFiles: UInt64
        public var maxFileSizeBytes: UInt64

        public init(
            cpuSeconds: UInt64 = 300,
            // RLIMIT_AS is unreliable on macOS — the dyld shared-cache mapping
            // needs a large address space, so a finite cap aborts startup (the
            // corpus confirmed setrlimit(RLIMIT_AS, 2GB) fails). 0 = don't set;
            // tune on device if a hard AS bound is ever needed.
            addressSpaceBytes: UInt64 = 0,
            // Per-real-uid soft cap, applied while running as the operator uid —
            // so =1 is a backstop, NOT the real fork-deny. Actual fork-deny is the
            // SBPL `(deny default)` (no process-fork unless the manifest declares
            // it). The corpus-proven value is set on device. DEVICE-TUNE.
            maxProcesses: UInt64 = 1,
            maxOpenFiles: UInt64 = 256,
            maxFileSizeBytes: UInt64 = 256 * 1024 * 1024           // 256 MB
        ) {
            self.cpuSeconds = cpuSeconds
            self.addressSpaceBytes = addressSpaceBytes
            self.maxProcesses = maxProcesses
            self.maxOpenFiles = maxOpenFiles
            self.maxFileSizeBytes = maxFileSizeBytes
        }

        public static let `default` = ResourceLimits()
    }

    public enum RunnerError: Error, CustomStringConvertible {
        case notSandboxed(pluginID: String)
        case isFirstParty(pluginID: String)
        case sandboxRuntimeUnavailable(pluginID: String, message: String)
        case profileWriteFailed(pluginID: String, message: String)
        case spawnFailed(pluginID: String, message: String)

        public var description: String {
            switch self {
            case .notSandboxed(let id):
                return "SandboxedTierBRunner: refusing to spawn \(id) — not sandbox-gated (only resolveForSandboxedExecution may produce a runnable sandboxed plugin)"
            case .isFirstParty(let id):
                return "SandboxedTierBRunner: refusing to spawn \(id) — it is first-party (use the unsandboxed FirstPartyTierBRunner; the lanes never cross)"
            case .sandboxRuntimeUnavailable(let id, let m):
                return "SandboxedTierBRunner: refusing to spawn \(id) uncontained — sandbox runtime unavailable: \(m)"
            case .profileWriteFailed(let id, let m):
                return "SandboxedTierBRunner: failed to write sandbox profile for \(id): \(m)"
            case .spawnFailed(let id, let m):
                return "SandboxedTierBRunner: failed to spawn \(id): \(m)"
            }
        }
    }

    /// Path to the signed `maccrab-tierb-sandbox-host` trampoline binary.
    public let trampolinePath: String
    public let limits: ResourceLimits
    /// Explicitly allow an unsigned (dev) trampoline — for `maccrabctl plugin
    /// test` only. Threaded as a value, NOT via a process-wide env var, so it
    /// can't leak to other code paths or children. Ignored unless DEBUG-honored.
    public let allowUnsignedTrampoline: Bool

    /// `trampolinePath` defaults to a binary named `maccrab-tierb-sandbox-host`
    /// next to the running executable (dev/test: `.build/<config>/`; release: the
    /// app bundle's helper dir, wired by build-release.sh). Pass an explicit path
    /// in tests.
    public init(trampolinePath: String? = nil, limits: ResourceLimits = .default,
                allowUnsignedTrampoline: Bool = false) {
        self.trampolinePath = trampolinePath ?? Self.defaultTrampolinePath()
        self.limits = limits
        self.allowUnsignedTrampoline = allowUnsignedTrampoline
    }

    /// Best-effort default location of the trampoline: a sibling of the current
    /// executable. Returns the path even if it does not exist — `isRuntimeAvailable`
    /// is the gate; this just computes the candidate.
    public static func defaultTrampolinePath() -> String {
        // Resolve ONLY from Bundle.main (the real executable image), never argv[0]
        // — a launching parent controls argv[0] and could steer the sibling
        // candidate to an attacker-writable dir (S3). If Bundle.main has no
        // executable URL, return a non-existent path so isRuntimeAvailable
        // fail-closes rather than trusting parent-supplied input.
        guard let exe = Bundle.main.executableURL else {
            return "/nonexistent/maccrab-tierb-sandbox-host"
        }
        let dir = exe.deletingLastPathComponent()
        let name = "maccrab-tierb-sandbox-host"
        let candidates = [
            dir.appendingPathComponent(name),                                                // sibling: CLI/MCP in Resources/bin, dev .build
            dir.deletingLastPathComponent().appendingPathComponent("Resources/bin/\(name)"), // app: Contents/MacOS → ../Resources/bin
        ]
        let fm = FileManager.default
        for c in candidates where fm.isExecutableFile(atPath: c.path) { return c.path }
        return candidates[0].path   // fall back to the sibling path; isRuntimeAvailable rejects if absent
    }

    /// Whether the sandbox runtime can be established: the trampoline exists and
    /// is executable. The ThirdPartyExecutionGate consumes this (FALSE →
    /// fail-closed). Pure filesystem check, safe to call before resolve.
    ///
    /// The trampoline is the signed binary that enforces containment, so in
    /// RELEASE this requires a valid Developer-ID signature anchored to Apple AND
    /// the host's team (`isTrampolineSignatureTrusted`). It must ALSO be
    /// tamper-resistant on disk (`trampolinePathIsTamperResistant`): opened
    /// `O_NOFOLLOW`, a single-link regular file, and neither the binary NOR its
    /// parent dir group/other-writable — so a same-uid attacker cannot swap it
    /// between this check and the spawn. macOS has neither `fexecve` nor exec of
    /// `/dev/fd/N` (both refused), so the spawn cannot be inode-pinned; in the
    /// canonical root-owned, non-user-writable app bundle the non-writable check
    /// makes the trampoline unswappable by a same-uid non-root process. The
    /// residual (a same-uid-root or writable-install swap) carries no privilege
    /// crossing — this lane is uid-501 CLI/MCP/app only, never the root sysext.
    public var isRuntimeAvailable: Bool {
        Self.isRuntimeAvailable(
            trampolinePath: trampolinePath,
            allowUnsigned: Self.devOverrideAllowed(explicit: allowUnsignedTrampoline))
    }

    public static func isRuntimeAvailable(trampolinePath: String) -> Bool {
        isRuntimeAvailable(trampolinePath: trampolinePath, allowUnsigned: devOverrideAllowed(explicit: false))
    }

    /// Whether an UNSIGNED (dev) trampoline is permitted. The env overrides are
    /// honored ONLY in DEBUG builds (M1) — a RELEASE binary literally cannot be
    /// tricked into running an unsigned/swapped trampoline via an inherited env
    /// var (the MCP server inherits its parent's full env). The explicit flag is
    /// the in-process channel for `maccrabctl plugin test`, also DEBUG-only.
    static func devOverrideAllowed(explicit: Bool) -> Bool {
        #if DEBUG
        if explicit { return true }
        let env = ProcessInfo.processInfo.environment
        return env["MACCRAB_TIERB_DEV_TRAMPOLINE"] == "1" || env["MACCRAB_CORPUS"] != nil
        #else
        _ = explicit
        return false
        #endif
    }

    /// Testable core. `allowUnsigned` skips the release signature requirement.
    static func isRuntimeAvailable(trampolinePath: String, allowUnsigned: Bool) -> Bool {
        var isDir: ObjCBool = false
        let fm = FileManager.default
        guard fm.fileExists(atPath: trampolinePath, isDirectory: &isDir), !isDir.boolValue,
              fm.isExecutableFile(atPath: trampolinePath) else { return false }
        // S3: the trampoline + its install dir must be non-(group/other)-writable so
        // a same-uid attacker can't swap the binary between this check and the
        // spawn. Applied in dev too (the .build bin dir is 0755). See the doc above
        // for why macOS leaves a same-uid-root residual (no fexecve / no /dev/fd exec).
        guard trampolinePathIsTamperResistant(trampolinePath) else { return false }
        if allowUnsigned { return true }
        // Release: the trampoline is the signed binary that enforces containment.
        // Require a valid signature anchored to Apple AND the SAME team as the
        // host, so a swapped/user-planted trampoline is refused before any
        // untrusted code runs.
        return isTrampolineSignatureTrusted(trampolinePath)
    }

    /// True iff `path` opens cleanly under `O_NOFOLLOW`, is a single-link regular
    /// file, and neither the file NOR its parent dir is group/other-writable — i.e.
    /// a same-uid non-root process cannot swap or replace it in place. The
    /// load-bearing S3 control given macOS cannot inode-pin the spawn (no fexecve /
    /// no /dev/fd exec). Pure filesystem check.
    static func trampolinePathIsTamperResistant(_ path: String) -> Bool {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return false }      // ELOOP if the final component is a symlink
        defer { close(fd) }
        var st = Darwin.stat()
        guard fstat(fd, &st) == 0 else { return false }
        let mode = UInt32(st.st_mode)
        guard (mode & UInt32(S_IFMT)) == UInt32(S_IFREG), st.st_nlink == 1 else { return false }
        let groupOtherWrite = UInt32(S_IWGRP) | UInt32(S_IWOTH)
        guard (mode & groupOtherWrite) == 0 else { return false }   // binary not group/other-writable
        // The parent dir must not be writable either — a writable dir lets an
        // attacker replace the file via rename even if the file itself is read-only.
        let parent = (path as NSString).deletingLastPathComponent
        var pst = Darwin.stat()
        guard stat(parent.isEmpty ? "/" : parent, &pst) == 0 else { return false }
        return (UInt32(pst.st_mode) & groupOtherWrite) == 0
    }

    static func isTrampolineSignatureTrusted(_ path: String) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        let reqStr: String
        if let team = hostTeamIdentifier() {
            reqStr = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        } else {
            // Host team unknown (a Sec failure, or the host is ad-hoc/unsigned).
            // In RELEASE this means a signed-app Sec failure → FAIL CLOSED (M2):
            // never accept ANY Apple-Developer-ID binary as the trampoline. The
            // bare anchor-apple-generic fallback is DEBUG-only (dev host).
            #if DEBUG
            reqStr = "anchor apple generic"
            #else
            return false
            #endif
        }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(reqStr as CFString, [], &req) == errSecSuccess,
              let requirement = req else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    /// The Developer-ID team identifier of the running host, or nil if the host
    /// is ad-hoc / unsigned (dev).
    static func hostTeamIdentifier() -> String? {
        var selfCode: SecCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let sc = selfCode else { return nil }
        var staticSelf: SecStaticCode?
        guard SecCodeCopyStaticCode(sc, [], &staticSelf) == errSecSuccess, let ssc = staticSelf else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(ssc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }

    /// realpath(3) — resolves all symlinks (esp. /var → /private/var) so the SBPL
    /// self-exec literal matches the path the kernel checks at exec time. Falls
    /// back to the input if realpath fails (the verified temp always exists).
    static func canonicalPath(_ p: String) -> String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        return p.withCString { cstr in
            realpath(cstr, &buf) != nil ? String(cString: buf) : p
        }
    }

    /// Build the trampoline argv (pure + testable). The host owns every value —
    /// none is plugin-named except the verified-temp paths the host generated.
    public static func trampolineArguments(
        trampolinePath: String,
        profilePath: String,
        execPath: String,
        limits: ResourceLimits
    ) -> [String] {
        var argv = [trampolinePath, "--profile", profilePath, "--exec", execPath]
        if limits.cpuSeconds > 0 { argv += ["--rlimit-cpu", String(limits.cpuSeconds)] }
        if limits.addressSpaceBytes > 0 { argv += ["--rlimit-as", String(limits.addressSpaceBytes)] }
        if limits.maxFileSizeBytes > 0 { argv += ["--rlimit-fsize", String(limits.maxFileSizeBytes)] }
        if limits.maxOpenFiles > 0 { argv += ["--rlimit-nofile", String(limits.maxOpenFiles)] }
        if limits.maxProcesses > 0 { argv += ["--rlimit-nproc", String(limits.maxProcesses)] }
        return argv
    }

    /// Spawn the verified third-party plugin UNDER THE SANDBOX (via the
    /// trampoline), deliver the request on stdin, and stream + parse its TierBIPC
    /// stdout. SYNCHRONOUS — call it off any actor/main thread. Fail-closed at
    /// every precondition.
    public func run(
        verified: TierBRegistry.VerifiedPlugin,
        scratchDir: String,
        windowStartUnix: Int64? = nil,
        windowEndUnix: Int64? = nil,
        timeout: TimeInterval = TierBIPC.defaultTimeoutSeconds
    ) throws -> TierBRunOutcome {
        // Disjoint lanes: this runner is ONLY for sandbox-gated, non-first-party
        // plugins. Defense in depth on top of the gate.
        guard verified.isSandboxed else {
            throw RunnerError.notSandboxed(pluginID: verified.pluginID)
        }
        guard !verified.isFirstParty else {
            throw RunnerError.isFirstParty(pluginID: verified.pluginID)
        }
        // Contained-or-nothing: never spawn without the trampoline. Use the
        // INSTANCE gate so it honors `allowUnsignedTrampoline` (DEBUG-only, the
        // in-process channel for `maccrabctl plugin test`); the static overload
        // hardcodes explicit:false and silently dropped the flag, fail-closing the
        // documented one-command contributor test on a `swift build` binary (audit
        // #7). RELEASE is unchanged: devOverrideAllowed is false regardless there.
        guard isRuntimeAvailable else {
            throw RunnerError.sandboxRuntimeUnavailable(
                pluginID: verified.pluginID,
                message: "trampoline not found or not executable at \(trampolinePath)")
        }

        // Brokered file access (Model B): the SBPL grants NO manifest reads. The
        // host snapshots manifest-declared TCC sources into a host-owned,
        // plugin-UNWRITABLE dir and the broker serves read-fds over fd 3, so the
        // plugin can only reach a declared, broker-opened path (a symlink/TOCTOU
        // race or an undeclared path can never be opened directly). A TCC source
        // that can't be snapshotted is fail-closed (denied).
        let snapshotDir = URL(fileURLWithPath: NSTemporaryDirectory() + "maccrab-tier-b-tccsnap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: snapshotDir) }
        let readPlan = BrokeredTCC.prepare(
            manifestReadPaths: verified.manifest.fileReadSubpaths,
            snapshotDir: snapshotDir,
            home: NSHomeDirectory())
        let brokerPolicy = readPlan.brokerPolicy(scratchDir: scratchDir)

        // Canonicalize the verified-binary path: NSTemporaryDirectory() lives
        // under /var/folders, but /var is a symlink to /private/var, and the
        // kernel checks the sandbox process-exec rule against the RESOLVED path.
        // The SBPL self-exec literal + the execv target must both use the
        // canonical /private/var path or exec is denied. (Corpus finding.)
        let canonicalExec = Self.canonicalPath(verified.binaryPath)

        // Build + write the Model-B deny-default SBPL the trampoline applies to
        // itself (reads brokered, not in the profile). 0o400 owner-read-only temp.
        let spec = verified.manifest.toBrokeredSandboxProfileSpec(scratchDir: scratchDir)
        let profile = SandboxProfileBuilder.compileTrampolineDenyDefault(spec, selfExecPath: canonicalExec)
        let profilePath = NSTemporaryDirectory() + "maccrab-tier-b-profile-\(UUID().uuidString).sb"
        do {
            try profile.write(toFile: profilePath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: profilePath)
        } catch {
            throw RunnerError.profileWriteFailed(pluginID: verified.pluginID, message: "\(error)")
        }
        defer { try? FileManager.default.removeItem(atPath: profilePath) }

        // Per-invocation broker socketpair: the child inherits the broker end on
        // fd 3 (the fd-3 dup below clears CLOEXEC so it survives the trampoline's
        // execv to the plugin); the host end is CLOEXEC and closes at exec, so the
        // plugin never sees it.
        var brokerFds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &brokerFds) == 0 else {
            throw RunnerError.spawnFailed(pluginID: verified.pluginID, message: "socketpair() failed")
        }
        let brokerHostFd = brokerFds[0], brokerChildFd = brokerFds[1]
        _ = fcntl(brokerHostFd, F_SETFD, FD_CLOEXEC)
        _ = fcntl(brokerChildFd, F_SETFD, FD_CLOEXEC)

        let argvStrings = Self.trampolineArguments(
            trampolinePath: trampolinePath,
            profilePath: profilePath,
            execPath: canonicalExec,
            limits: limits
        )

        // Spawn the TRAMPOLINE (not the plugin) under the SHARED hardened machinery
        // (TierBSubprocess — audit #9, one source of truth across both lanes). The
        // lane-specific extras attach the broker: dup the child end onto fd 3 (dup2
        // clears CLOEXEC so it survives the trampoline's execv to the plugin), serve
        // it on a dedicated thread after spawn, and tear it down after reap (close
        // the host end → EOF the serve loop → bounded join) so no blocked broker
        // thread leaks into the long-lived host.
        let broker = TierBFileBroker()
        let brokerDone = DispatchSemaphore(value: 0)
        let extras = TierBSubprocess.Extras(
            fileActions: { fa in posix_spawn_file_actions_adddup2(fa, brokerChildFd, 3) },
            parentCloseAfterSpawn: [brokerChildFd],   // child inherited it; parent's copy closes
            parentCloseOnFailure: [brokerHostFd],     // spawn failed → host end never served
            afterSpawn: { _ in
                Thread { broker.serve(hostSocket: brokerHostFd, policy: brokerPolicy); brokerDone.signal() }.start()
            },
            afterReap: {
                close(brokerHostFd)
                _ = brokerDone.wait(timeout: .now() + 3.0)
            },
            // Tell the plugin (via MacCrabPluginKit) that it is on the sandboxed
            // lane and where the broker socket is, so its declared reads go over
            // the broker (fd 3) instead of a deny-default open(). The first-party
            // lane sets nothing → the plugin reads directly.
            extraEnv: ["MACCRAB_TIERB_BROKER_FD": "3"])

        do {
            return try TierBSubprocess.spawnAndStream(
                executable: trampolinePath,
                argv: argvStrings,
                request: TierBCollectRequest(
                    pluginID: verified.pluginID,
                    pluginVersion: verified.manifest.version,
                    scratchDir: scratchDir,
                    windowStartUnix: windowStartUnix,
                    windowEndUnix: windowEndUnix),
                timeout: timeout,
                extras: extras)
        } catch let e as TierBSubprocessError {
            // A failure BEFORE spawn (pipe()) never consumed the broker fds → close
            // them so they don't leak. A spawn() failure already closed brokerChildFd
            // (unconditional) + brokerHostFd (parentCloseOnFailure), so only the
            // pre-spawn case needs cleanup here.
            if case .pipeFailed = e { close(brokerHostFd); close(brokerChildFd) }
            throw RunnerError.spawnFailed(pluginID: verified.pluginID, message: e.description)
        }
    }
}
