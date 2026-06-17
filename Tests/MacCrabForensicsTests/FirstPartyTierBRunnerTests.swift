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

    // MARK: - Real subprocess (script fixtures, spawned via the verified path)

    /// Install a script as a first-party bundle binary, gate it for execution with
    /// an injected matching fingerprint, and run it through FirstPartyTierBRunner.
    static func runScript(id: String, script: String, timeout: TimeInterval) async throws -> TierBRunOutcome {
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

        return try FirstPartyTierBRunner().run(verified: verified, scratchDir: scratch, timeout: timeout)
    }

    @Test("happy path: a verified first-party plugin emits artifacts + result over stdin/stdout")
    func spawnHappy() async throws {
        let script = """
        #!/bin/sh
        cat >/dev/null
        printf '%s\\n' '{"kind":"artifact","artifact":{"contentType":"echo.item","privacyClass":"metadata","data":{"n":1}}}'
        printf '%s\\n' '{"kind":"result","result":{"status":"ok","notes":["echoed"]}}'
        """
        let out = try await Self.runScript(id: "com.test.run.happy", script: script, timeout: 20)
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
        let out = try await Self.runScript(id: "com.test.run.env", script: script, timeout: 20)
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
        let out = try await Self.runScript(id: "com.test.run.nostdin", script: script, timeout: 20)
        #expect(out.result?.status == "ok")
    }

    @Test("audit HIGH#2: a forked descendant holding stdout doesn't hang run() (bounded drain)")
    func spawnForkedFdHolderBounded() async throws {
        let script = """
        #!/bin/sh
        cat >/dev/null
        ( sleep 30 & )
        printf '%s\\n' '{"kind":"result","result":{"status":"ok"}}'
        """  // parent exits; the backgrounded descendant keeps stdout open
        let start = Date()
        let out = try await Self.runScript(id: "com.test.run.fork", script: script, timeout: 20)
        let elapsed = Date().timeIntervalSince(start)
        #expect(out.result?.status == "ok")
        #expect(elapsed < 12)   // bounded ~3s drain, not the 30s descendant lifetime
    }
}
