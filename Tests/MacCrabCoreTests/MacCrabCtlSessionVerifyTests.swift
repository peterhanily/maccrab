// MacCrabCtlSessionVerifyTests.swift
// MacCrabCoreTests
//
// Pre-GA audit (MEDIUM): `maccrabctl session verify` must have a TRUSTWORTHY
// exit code so a caller can gate on authenticated evidence. Before the fix it
// exited 0 for an UNSIGNED (forgeable) bundle — indistinguishable from a
// genuinely signed+verified one. This drives the REAL built `maccrabctl`
// binary over an unsigned bundle and asserts a NON-ZERO exit.
//
// maccrabctl is an executable target (not importable), so — like
// MCPProtocolHarnessTests — this spawns the built binary. The bundle is built
// via MacCrabCore's AgentSessionBundle export (importable), and `session verify`
// takes an explicit path arg, so the test does not depend on the machine's
// MacCrab data dir.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("maccrabctl session verify exit code", .serialized)
struct MacCrabCtlSessionVerifyTests {

    /// Locate the built maccrabctl binary, building it once if absent
    /// (mirrors MCPProtocolHarnessTests.binaryURL()).
    static func binaryURL() -> URL? {
        if let directory = ProcessInfo.processInfo.environment["MACCRAB_BIN_DIR"],
           !directory.isEmpty {
            let binary = URL(fileURLWithPath: directory).appendingPathComponent("maccrabctl")
            return FileManager.default.isExecutableFile(atPath: binary.path) ? binary : nil
        }
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
        let fm = FileManager.default
        for c in [root.appendingPathComponent(".build/debug/maccrabctl"),
                  root.appendingPathComponent(".build/release/maccrabctl")]
            where fm.isExecutableFile(atPath: c.path) { return c }
        let build = Process()
        build.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        build.arguments = ["swift", "build", "--product", "maccrabctl"]
        build.currentDirectoryURL = root
        build.standardOutput = FileHandle.nullDevice
        build.standardError = FileHandle.nullDevice
        try? build.run()
        build.waitUntilExit()
        let debug = root.appendingPathComponent(".build/debug/maccrabctl")
        return fm.isExecutableFile(atPath: debug.path) ? debug : nil
    }

    /// Run maccrabctl with a hermetic HOME (so it never reads/writes the real
    /// user MacCrab tree) and a 60s watchdog. Returns (exit status, stdout).
    private func run(_ args: [String], home: URL) -> (status: Int32, stdout: String)? {
        guard let bin = Self.binaryURL() else { return nil }
        let proc = Process()
        proc.executableURL = bin
        proc.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["HOME"] = home.path
        // FileManager's user-domain Application Support lookup is based on
        // getpwuid on macOS, not HOME. This Foundation test override keeps the
        // spawned verifier's session key out of the developer's real profile.
        env["CFFIXED_USER_HOME"] = home.path
        proc.environment = env
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.nullDevice
        do { try proc.run() } catch { return nil }

        var outData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        if group.wait(timeout: .now() + 60) == .timedOut {
            proc.terminate()
            _ = group.wait(timeout: .now() + 2)
        }
        proc.waitUntilExit()
        return (proc.terminationStatus, String(data: outData, encoding: .utf8) ?? "")
    }

    @Test("a valid foreign self-signature exits 3 as UNTRUSTED, while an explicit pin authenticates it")
    func foreignSignerNeedsTrustAnchor() async throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-foreign-home-\(UUID().uuidString)", isDirectory: true)
        let bundleDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("foreign-\(UUID().uuidString).maccrabsession")
        let foreignKeys = FileManager.default.temporaryDirectory
            .appendingPathComponent("foreign-keys-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: bundleDir)
            try? FileManager.default.removeItem(at: foreignKeys)
        }
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let foreign = TrustSubstrate(
            storage: FilesystemTrustSubstrateStorage(baseDirectory: foreignKeys),
            modeOverride: .filesystemDegraded
        )
        _ = try await AgentSessionBundle.export(
            sessionId: "S-foreign-cli", eventsJsonl: ["{\"seq\":1}"], alertsJson: "[]",
            mutationsJson: "[]", metadataJson: "{}", to: bundleDir,
            trustSubstrate: foreign
        )

        guard let untrusted = run(["session", "verify", bundleDir.path], home: home) else {
            Issue.record("could not locate/build the maccrabctl binary (spawn/build failure)")
            return
        }
        #expect(untrusted.status == 3,
                "valid foreign self-signature must exit 3 (untrusted), got \(untrusted.status)")
        #expect(untrusted.stdout.contains("signer_trusted: false"))
        #expect(untrusted.stdout.contains("authenticated:  false"))
        #expect(untrusted.stdout.contains("UNTRUSTED signer"))
        #expect(!untrusted.stdout.contains("verdict:      verified"),
                "an unknown embedded key must never receive a verified verdict")

        let fingerprint = try await foreign.publicKeyFingerprint()
        guard let pinned = run([
            "session", "verify", bundleDir.path, "--expect-key", fingerprint,
        ], home: home) else {
            Issue.record("could not run maccrabctl with an expected signer pin")
            return
        }
        #expect(pinned.status == 0,
                "an explicitly pinned foreign signer should authenticate, got \(pinned.status)")
        #expect(pinned.stdout.contains("signer_trusted: true"))
        #expect(pinned.stdout.contains("authenticated:  true"))
        #expect(pinned.stdout.contains("expected signing-key fingerprint"))
    }

    @Test("an unsigned (forgeable) bundle exits NON-ZERO — not mistakable for authenticated evidence")
    func unsignedBundleExitsNonZero() async throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-verify-home-\(UUID().uuidString)", isDirectory: true)
        let bundleDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("unsigned-\(UUID().uuidString).maccrabsession")
        defer {
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: bundleDir)
        }
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)

        // Build a well-formed but UNSIGNED bundle (no trust substrate → signed=false).
        // Merkle recomputes cleanly, so this is exactly the "well-formed file that
        // is NOT authenticated" case the exit code must not bless with 0.
        let res = try await AgentSessionBundle.export(
            sessionId: "S-audit", eventsJsonl: ["{\"seq\":1}"], alertsJson: "[]",
            mutationsJson: "[]", metadataJson: "{}", to: bundleDir, trustSubstrate: nil
        )
        #expect(!res.signed)

        guard let out = run(["session", "verify", bundleDir.path], home: home) else {
            Issue.record("could not locate/build the maccrabctl binary (spawn/build failure)")
            return
        }
        // The load-bearing assertion: exit code is NON-ZERO for an unsigned bundle.
        #expect(out.status != 0,
                "unsigned bundle must exit non-zero (got \(out.status)); exit-code gating cannot trust a 0 here")
        // Human-readable output is retained + names the unsigned verdict.
        #expect(out.stdout.contains("unsigned"),
                "verify output should still explain the unsigned verdict; got:\n\(out.stdout)")
    }

    @Test("session verify gates exit 0 on authentication (source guard, robust to a stale binary)")
    func verifyExitGateIsInSource() throws {
        // Defense-in-depth for the spawn test above (which could run a stale
        // binary under bare `swift test`): assert the exit-code gate is in the
        // source — exit 0 ONLY when integrity AND signer trust authenticate.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl/SessionCommands.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        #expect(src.contains("if !v.authenticated"),
                "sessionVerify must gate exit 0 on AgentSessionBundle's trust-aware authentication result")
        #expect(src.contains("v.merkleOk && v.signed && v.signatureOk { exit(3)"),
                "a cryptographically valid but untrusted signer must exit non-zero with code 3")
        #expect(src.contains("signer_trusted:"),
                "human-readable output must expose signer trust separately from signature validity")
        // The old bug: exit was gated ONLY on the TAMPERED verdict, so unsigned
        // fell through to exit 0. That predicate must be gone.
        #expect(!src.contains("if verdict.hasPrefix(\"TAMPERED\") { exit(1) }"),
                "the old exit gate (only TAMPERED → non-zero; unsigned → 0) must be replaced")
    }

    @Test("MCP session verification exposes integrity and authentication as separate facts")
    func mcpVerificationTrustFieldsAreInSource() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrab-mcp/main.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        #expect(src.contains("\"signer_trusted\": v.signerTrusted"))
        #expect(src.contains("\"authenticated\": v.authenticated"))
        #expect(src.contains("UNTRUSTED signer (signature is self-consistent"),
                "a foreign self-signer must receive an explicitly untrusted verdict")
        #expect(src.contains("pinnedKeyFingerprint: args[\"expected_signer_fingerprint\"] as? String"),
                "MCP's optional trust anchor must come from explicit caller input")
    }
}
