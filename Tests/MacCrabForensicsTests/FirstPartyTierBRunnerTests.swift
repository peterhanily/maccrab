// FirstPartyTierBRunner (Shape 2 Phase 2b) — the trusted first-party subprocess
// runtime. Pure parse/cap tests pin the attack-pass mitigations (line/depth caps,
// missing-result), and real-subprocess tests (shell-script fixtures, spawned the
// same way the host spawns a verified plugin) prove the happy path, env-scrub
// (no MACCRAB_* leak), and the wall-clock timeout.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("FirstPartyTierBRunner (Shape 2 Phase 2b)")
struct FirstPartyTierBRunnerTests {

    // MARK: - Pure parse / caps (no spawn)

    @Test("parseOutputLines: artifacts + terminal result")
    func parseHappy() {
        let buf = Data(("""
        {"kind":"artifact","artifact":{"contentType":"a","privacyClass":"metadata","data":{"n":1}}}
        {"kind":"artifact","artifact":{"contentType":"b","privacyClass":"metadata","data":{}}}
        {"kind":"result","result":{"status":"ok","notes":["done"]}}
        """ + "\n").utf8)
        let p = FirstPartyTierBRunner.parseOutputLines(buf)
        #expect(p.artifacts.count == 2)
        #expect(p.artifacts.first?.contentType == "a")
        #expect(p.result?.status == "ok")
        #expect(p.decodeErrors == 0)
    }

    @Test("parseOutputLines: an over-long line is skipped + flagged, not parsed")
    func parseLongLine() {
        let huge = String(repeating: "x", count: TierBIPC.maxLineBytes + 16)
        let line = "{\"kind\":\"artifact\",\"artifact\":{\"contentType\":\"\(huge)\",\"privacyClass\":\"metadata\",\"data\":{}}}"
        let buf = Data((line + "\n{\"kind\":\"result\",\"result\":{\"status\":\"ok\"}}\n").utf8)
        let p = FirstPartyTierBRunner.parseOutputLines(buf)
        #expect(p.artifacts.isEmpty)
        #expect(p.truncated)
        #expect(p.decodeErrors >= 1)
        #expect(p.result?.status == "ok")   // the well-formed result line still parses
    }

    @Test("parseOutputLines: a deeply-nested line is rejected before decode (nesting DoS guard)")
    func parseDeepLine() {
        var s = "{\"kind\":\"artifact\",\"artifact\":{\"contentType\":\"x\",\"privacyClass\":\"metadata\",\"data\":"
        let depth = TierBIPC.maxJSONDepth + 10
        s += String(repeating: "[", count: depth) + "1" + String(repeating: "]", count: depth) + "}}"
        let p = FirstPartyTierBRunner.parseOutputLines(Data((s + "\n").utf8))
        #expect(p.artifacts.isEmpty)
        #expect(p.decodeErrors >= 1)
    }

    @Test("parseOutputLines: garbage + missing-result")
    func parseGarbageNoResult() {
        let buf = Data(("not json\n{\"kind\":\"artifact\",\"artifact\":{\"contentType\":\"a\",\"privacyClass\":\"metadata\",\"data\":{}}}\n").utf8)
        let p = FirstPartyTierBRunner.parseOutputLines(buf)
        #expect(p.artifacts.count == 1)
        #expect(p.result == nil)            // host treats a missing result as not-ok in the bridge
        #expect(p.decodeErrors == 1)
    }

    @Test("jsonDepthExceeds is string-aware (braces inside strings don't count)")
    func depthStringAware() {
        #expect(FirstPartyTierBRunner.jsonDepthExceeds(Data("{\"a\":{\"a\":1}}".utf8), max: 64) == false)
        #expect(FirstPartyTierBRunner.jsonDepthExceeds(Data("{\"k\":\"[[[[[[[[\"}".utf8), max: 5) == false)
        var deep = String(repeating: "[", count: 70) + "1" + String(repeating: "]", count: 70)
        #expect(FirstPartyTierBRunner.jsonDepthExceeds(Data(deep.utf8), max: 64) == true)
        deep = ""  // silence unused-mutability
    }

    // MARK: - Load-tolerant timing bounds (full-suite-load flake fix)
    //
    // The real-subprocess tests below spawn actual processes, so under full-suite
    // saturation (~2000 concurrent tests) wall-clock time balloons — ~27s observed
    // for work that completes in <1s in isolation. These bounds are widened so a
    // scheduling delay under load can't fail them, while STILL catching a genuine
    // hang. Every SEMANTIC assertion (secret ABSENT, PATH pinned, reap kills the
    // group, timedOut flagged) is unchanged; only the wall-clock/timeout numbers move.

    /// Runner wall-clock timeout for the happy / env-scrub / reap / no-stdin spawn
    /// tests (was 20s). The child work is trivial JSONL printf; this is pure
    /// headroom so the runner doesn't SIGKILL the child before it emits under load.
    /// A genuine hang is still caught — the child just gets flagged `timedOut` at
    /// this bound instead of finishing.
    static let spawnRunnerTimeout: TimeInterval = 120

    /// "run() returns promptly" bound for the reap test (was 12s). Must sit ABOVE
    /// the worst under-load delay (~27s) so a saturated machine can't flake it, and
    /// BELOW `spawnRunnerTimeout` so a hung child (which only returns once the
    /// runner timeout fires at ~120s) still trips it. Reap CORRECTNESS itself is
    /// proven by the kill(pid,0) poll loop, not by this wall-clock number.
    static let returnsPromptlyBound: TimeInterval = 60

    @Test("timing bounds stay load-tolerant yet still catch a genuine hang (parity: semantics unchanged)")
    func timingBoundsRemainMeaningful() {
        // Above the worst observed under-load scheduling delay → won't flake.
        let observedUnderLoadDelay: TimeInterval = 27
        #expect(Self.returnsPromptlyBound > observedUnderLoadDelay)
        // Below the runner-timeout return path → a child that returns only because
        // the runner timeout fired (~spawnRunnerTimeout) still exceeds the bound, so
        // the reap test's `elapsed < returnsPromptlyBound` check is never vacuous.
        #expect(Self.returnsPromptlyBound < Self.spawnRunnerTimeout)
    }

    // MARK: - Real subprocess (script fixtures, spawned via the verified path)

    /// Install a script as a first-party bundle binary, gate it for execution with
    /// an injected matching fingerprint, and run it through FirstPartyTierBRunner.
    ///
    /// `allowUnsignedPayload` defaults TRUE so the unsigned shell-script fixtures
    /// clear the A1-05 Developer-ID gate (the DEBUG-only dev override); the A1-05
    /// negative test passes `false` to prove the gate refuses an unsigned payload.
    static func runScript(id: String, script: String, timeout: TimeInterval,
                          allowUnsignedPayload: Bool = true) async throws -> TierBRunOutcome {
        let scriptPath = NSTemporaryDirectory() + "tierb-script-\(UUID().uuidString).sh"
        try script.write(toFile: scriptPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptPath)
        defer { try? FileManager.default.removeItem(atPath: scriptPath) }

        let m = TierBManifest(id: id, displayName: "x", version: "1.0", schemaVersion: 1, description: "x")
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: m, binaryPath: scriptPath)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)

        let registry = TierBRegistry(installer: installer)
        let base = try await registry.resolve(pluginID: id)
        let fp = base.publicKeySHA256
        registry.cleanupVerifiedBinary(base)
        let verified = try await registry.resolveForFirstPartyExecution(
            pluginID: id, officialSource: true, catalogOverrideActive: false,
            expectedPublisherFingerprint: fp, anchorConfigured: true)
        defer { registry.cleanupVerifiedBinary(verified) }

        let scratch = NSTemporaryDirectory() + "tierb-scratch-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: scratch) }

        return try FirstPartyTierBRunner(allowUnsignedPayload: allowUnsignedPayload)
            .run(verified: verified, scratchDir: scratch, timeout: timeout)
    }

    @Test("happy path: a verified first-party plugin emits artifacts + result over stdin/stdout")
    func spawnHappy() async throws {
        let script = """
        #!/bin/sh
        cat >/dev/null
        printf '%s\\n' '{"kind":"artifact","artifact":{"contentType":"echo.item","privacyClass":"metadata","data":{"n":1}}}'
        printf '%s\\n' '{"kind":"result","result":{"status":"ok","notes":["echoed"]}}'
        """
        let out = try await Self.runScript(id: "com.test.run.happy", script: script, timeout: Self.spawnRunnerTimeout)
        #expect(out.artifacts.count == 1)
        #expect(out.artifacts.first?.contentType == "echo.item")
        #expect(out.result?.status == "ok")
        #expect(out.exitCode == 0)
        #expect(!out.timedOut)
        #expect(!out.stdoutTruncated)
        #expect(out.decodeErrors == 0)
    }

    @Test("env is scrubbed: a planted MACCRAB_SECRET never reaches the child; PATH is pinned")
    func spawnEnvScrub() async throws {
        setenv("MACCRAB_SECRET", "leak-me", 1)
        defer { unsetenv("MACCRAB_SECRET") }
        let script = """
        #!/bin/sh
        cat >/dev/null
        printf '{"kind":"artifact","artifact":{"contentType":"env","privacyClass":"metadata","data":{"secret":"%s","path":"%s"}}}\\n' "${MACCRAB_SECRET:-ABSENT}" "${PATH}"
        printf '%s\\n' '{"kind":"result","result":{"status":"ok"}}'
        """
        let out = try await Self.runScript(id: "com.test.run.env", script: script, timeout: Self.spawnRunnerTimeout)
        #expect(out.artifacts.first?.data["secret"] == .string("ABSENT"))
        #expect(out.artifacts.first?.data["path"] == .string("/usr/bin:/bin"))
    }

    @Test("timeout: a hanging plugin is terminated and flagged timedOut")
    func spawnTimeout() async throws {
        let script = """
        #!/bin/sh
        cat >/dev/null
        sleep 30
        """
        let out = try await Self.runScript(id: "com.test.run.hang", script: script, timeout: 1)
        #expect(out.timedOut)
    }

    @Test("audit HIGH#1: F_SETNOSIGPIPE makes a write to a closed-read-end pipe throw, not crash")
    func sigpipeIsThrowableNotFatal() throws {
        // The mechanism the runner relies on: with F_SETNOSIGPIPE on the write fd,
        // writing to a pipe whose read end is closed surfaces EPIPE as a throwable
        // (try? can swallow it) instead of raising SIGPIPE (which would kill the host).
        let pipe = Pipe()
        #expect(fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0)
        try pipe.fileHandleForReading.close()
        var threw = false
        do { try pipe.fileHandleForWriting.write(contentsOf: Data([0x41, 0x42, 0x43])) }
        catch { threw = true }
        #expect(threw)
    }

    @Test("a plugin that exits without reading stdin does not crash the host (SIGPIPE-safe write)")
    func spawnPluginIgnoresStdin() async throws {
        let script = """
        #!/bin/sh
        printf '%s\\n' '{"kind":"result","result":{"status":"ok"}}'
        """  // exits immediately; the host's request write may hit a closed stdin
        let out = try await Self.runScript(id: "com.test.run.nostdin", script: script, timeout: Self.spawnRunnerTimeout)
        #expect(out.result?.status == "ok")
    }

    @Test("audit HIGH#2 reap: a forked descendant is KILLED with the process group, not orphaned, and run() returns promptly")
    func spawnForkedDescendantReaped() async throws {
        // The plugin backgrounds `sleep 30` (which inherits + holds stdout) and
        // records its pid. With the process-group spawn, run()'s kill(-pgid) must
        // reap that descendant; without it the descendant would orphan + survive.
        let marker = NSTemporaryDirectory() + "desc-pid-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: marker) }
        let script = """
        #!/bin/sh
        cat >/dev/null
        sleep 30 &
        echo $! > \(marker)
        printf '%s\\n' '{"kind":"result","result":{"status":"ok"}}'
        """
        let start = Date()
        let out = try await Self.runScript(id: "com.test.run.reap", script: script, timeout: Self.spawnRunnerTimeout)
        let elapsed = Date().timeIntervalSince(start)
        #expect(out.result?.status == "ok")
        #expect(elapsed < Self.returnsPromptlyBound)   // returns promptly, not a genuine hang; reap correctness is the poll loop below

        let pidStr = (try? String(contentsOfFile: marker, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard let descPid = Int32(pidStr) else {
            Issue.record("no descendant pid recorded (got \(pidStr.debugDescription))"); return
        }
        // Poll briefly: kill(pid, 0) returns -1/ESRCH once the descendant is gone.
        var alive = true
        for _ in 0..<40 {
            if kill(descPid, 0) != 0 { alive = false; break }
            usleep(100_000)
        }
        #expect(!alive, "forked descendant pid \(descPid) should be reaped by the process-group kill")
    }

    // MARK: - A1-01 exec-guard: TOCTOU hardening on the unsandboxed exec target
    //
    // The first-party lane runs UNSANDBOXED with the host's full FDA, so the bytes
    // it spawns must be provably the verified bytes. These pin the guard that
    // closes the write→spawn TOCTOU the runner previously had no defense against.

    /// Write `bytes` to a fresh temp path as an owner-r-x (0o500) regular file.
    static func writePayload(_ bytes: Data) throws -> String {
        let path = NSTemporaryDirectory() + "fp-guard-\(UUID().uuidString)"
        try bytes.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: path)
        return path
    }

    @Test("A1-01: revalidateBeforeSpawn refuses a symlink at the exec-target path (O_NOFOLLOW — no swap runs)")
    func guardRefusesSymlinkExecTarget() throws {
        let payload = Data("#!/bin/sh\necho verified\n".utf8)
        let real = try Self.writePayload(payload)
        defer { try? FileManager.default.removeItem(atPath: real) }
        let digest = TierBFirstPartyExecGuard.sha256Hex(payload)
        // Sanity: the real regular file re-validates cleanly.
        try TierBFirstPartyExecGuard.revalidateBeforeSpawn(execPath: real, expectedSHA256: digest)

        // A same-uid attacker swaps the exec target for a symlink to the real bytes
        // (a symlink swap is the minimal TOCTOU; posix_spawn would follow it).
        let link = NSTemporaryDirectory() + "fp-guard-link-\(UUID().uuidString)"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        defer { try? FileManager.default.removeItem(atPath: link) }
        #expect(throws: TierBFirstPartyExecGuard.GuardError.self) {
            try TierBFirstPartyExecGuard.revalidateBeforeSpawn(execPath: link, expectedSHA256: digest)
        }
    }

    @Test("A1-01: revalidateBeforeSpawn refuses a re-hash mismatch (substituted bytes)")
    func guardRefusesHashMismatch() throws {
        let payload = Data("#!/bin/sh\necho verified\n".utf8)
        let path = try Self.writePayload(payload)
        defer { try? FileManager.default.removeItem(atPath: path) }
        // Correct digest passes; a wrong digest (as if the inode was swapped) is refused.
        try TierBFirstPartyExecGuard.revalidateBeforeSpawn(
            execPath: path, expectedSHA256: TierBFirstPartyExecGuard.sha256Hex(payload))
        #expect(throws: TierBFirstPartyExecGuard.GuardError.self) {
            try TierBFirstPartyExecGuard.revalidateBeforeSpawn(
                execPath: path, expectedSHA256: String(repeating: "a", count: 64))
        }
    }

    @Test("A1-01: stage refuses a symlinked verified source (O_NOFOLLOW read of the source)")
    func guardStageRefusesSymlinkedSource() throws {
        let payload = Data("#!/bin/sh\necho verified\n".utf8)
        let real = try Self.writePayload(payload)
        defer { try? FileManager.default.removeItem(atPath: real) }
        let digest = TierBFirstPartyExecGuard.sha256Hex(payload)

        let link = NSTemporaryDirectory() + "fp-guard-srclink-\(UUID().uuidString)"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        defer { try? FileManager.default.removeItem(atPath: link) }

        let dir = NSTemporaryDirectory() + "fp-guard-dir-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(throws: TierBFirstPartyExecGuard.GuardError.self) {
            _ = try TierBFirstPartyExecGuard.stage(verifiedPath: link, expectedSHA256: digest, into: dir)
        }
    }

    @Test("A1-01: stage copies the verified bytes into a fresh 0o700 dir as a 0o500 target that re-validates")
    func guardStageHappy() throws {
        let payload = Data("#!/bin/sh\necho verified\n".utf8)
        let real = try Self.writePayload(payload)
        defer { try? FileManager.default.removeItem(atPath: real) }
        let digest = TierBFirstPartyExecGuard.sha256Hex(payload)

        let dir = NSTemporaryDirectory() + "fp-guard-dir-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let execPath = try TierBFirstPartyExecGuard.stage(verifiedPath: real, expectedSHA256: digest, into: dir)
        // The staged copy re-validates against the same digest…
        try TierBFirstPartyExecGuard.revalidateBeforeSpawn(execPath: execPath, expectedSHA256: digest)
        // …is 0o500 (owner r-x, not group/other-writable)…
        let fileMode = (try FileManager.default.attributesOfItem(atPath: execPath)[.posixPermissions] as? NSNumber)?.intValue
        #expect(fileMode == 0o500)
        // …and lives in the fresh 0o700 dir.
        let dirMode = (try FileManager.default.attributesOfItem(atPath: dir)[.posixPermissions] as? NSNumber)?.intValue
        #expect(dirMode == 0o700)
    }

    @Test("A1-01: stage refuses a source whose bytes do not match the verified digest")
    func guardStageRefusesDigestMismatch() throws {
        let real = try Self.writePayload(Data("#!/bin/sh\necho tampered\n".utf8))
        defer { try? FileManager.default.removeItem(atPath: real) }
        let dir = NSTemporaryDirectory() + "fp-guard-dir-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(throws: TierBFirstPartyExecGuard.GuardError.self) {
            _ = try TierBFirstPartyExecGuard.stage(
                verifiedPath: real, expectedSHA256: String(repeating: "b", count: 64), into: dir)
        }
    }

    // MARK: - A1-05 exec-guard: Developer-ID gate on the unsandboxed payload

    @Test("A1-05: an unsigned / non-Developer-ID payload is refused (allowUnsigned=false); the dev override lets it through")
    func guardRefusesUnsignedPayload() throws {
        // A bare unsigned file carries no Developer-ID signature, so the gate must
        // refuse it. (Deterministic regardless of host team: even the DEBUG
        // anchor-apple-generic fallback fails on a non-Apple-anchored file.)
        let path = try Self.writePayload(Data("#!/bin/sh\necho hi\n".utf8))
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(TierBFirstPartyExecGuard.developerIDTrusted(path: path, allowUnsigned: false) == false)
        // The DEBUG-only dev/test override is the ONLY bypass.
        #expect(TierBFirstPartyExecGuard.developerIDTrusted(path: path, allowUnsigned: true) == true)
    }

    @Test("A1-05 end-to-end: the first-party runner with NO dev override refuses an unsigned payload before spawning")
    func runnerRefusesUnsignedPayloadEndToEnd() async throws {
        // Skip if a corpus/dev env override is ambiently active (it would legitimately
        // bypass the gate); the guard-level test above covers the enforcement.
        guard !TierBFirstPartyExecGuard.devOverrideAllowed(explicit: false) else { return }
        let script = """
        #!/bin/sh
        cat >/dev/null
        printf '%s\\n' '{"kind":"result","result":{"status":"ok"}}'
        """
        await #expect(throws: FirstPartyTierBRunnerError.self) {
            _ = try await Self.runScript(id: "com.test.run.unsigned", script: script,
                                         timeout: 20, allowUnsignedPayload: false)
        }
    }
}
