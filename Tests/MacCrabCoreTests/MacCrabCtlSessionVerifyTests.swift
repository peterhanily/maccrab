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
        // source — exit 0 ONLY when merkle+signed+signatureOk, non-zero otherwise.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl/SessionCommands.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        #expect(src.contains("v.merkleOk && v.signed && v.signatureOk"),
                "sessionVerify must gate exit 0 on the authenticated (signed+verified) condition")
        #expect(src.contains("if !authenticated"),
                "sessionVerify must exit non-zero when the bundle is not authenticated")
        // The old bug: exit was gated ONLY on the TAMPERED verdict, so unsigned
        // fell through to exit 0. That predicate must be gone.
        #expect(!src.contains("if verdict.hasPrefix(\"TAMPERED\") { exit(1) }"),
                "the old exit gate (only TAMPERED → non-zero; unsigned → 0) must be replaced")
    }
}
