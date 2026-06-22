// ContainmentCorpusTests — the adversarial containment corpus as a CLIENT
// integration test against the EXACT shipped SandboxedTierBRunner + broker +
// trampoline (never a prototype). It proves, on a real macOS host, that:
//   - a benign plugin runs and emits under the deny-default sandbox (ALLOW);
//   - a DECLARED read is served through the broker over fd 3 (ALLOW);
//   - an undeclared file open, undeclared network egress, fork, a stat() of a
//     metadata-denied crown-jewel, and an undeclared com.apple Mach-service
//     lookup are all DENIED by the OS (DENY) — the host commits ZERO leak.*
//     artifacts (audit #4 added the metadata + mach-escape probes).
//
// GATED: the live-spawn tests run only when MACCRAB_CORPUS is set in the env AND
// the signed trampoline + fixtures are present — so normal `swift test`/CI stays
// green and the OPERATOR runs the real containment proof on macOS 26 with:
//     MACCRAB_CORPUS=1 swift test --filter ContainmentCorpus
// This is the launch gate the plan binds: assurance that "the OS denied the
// read" is provable only by running it. The SBPL runtime base for a full Swift
// plugin is still being tuned on device (TierB tuning); these C fixtures are the
// minimal proof that the runner+broker+trampoline chain contains.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("Containment corpus (client integration; gated on MACCRAB_CORPUS)")
struct ContainmentCorpusTests {

    /// The build bin dir holding the trampoline + fixtures. In a test run
    /// Bundle.main points inside the .xctest bundle, so prefer the explicit
    /// MACCRAB_BIN_DIR (operator: `MACCRAB_BIN_DIR=$(swift build --show-bin-path)`),
    /// else derive `.build/<arch>/debug` from the xctest executable path.
    static var binDir: String {
        if let d = ProcessInfo.processInfo.environment["MACCRAB_BIN_DIR"], !d.isEmpty { return d }
        var url = Bundle.main.executableURL ?? URL(fileURLWithPath: "/")
        for _ in 0..<4 { url.deleteLastPathComponent() }   // runner → MacOS → Contents → X.xctest → debug
        return url.path
    }
    static var trampoline: String { binDir + "/maccrab-tierb-sandbox-host" }
    static var exampleBin: String { binDir + "/maccrab-tierb-example" }
    static var probeBin: String { binDir + "/maccrab-tierb-corpus-probe" }
    static var swiftProbeBin: String { binDir + "/maccrab-tierb-corpus-probe-swift" }

    /// True only when the operator opts in AND the runtime is genuinely present.
    static var corpusEnabled: Bool {
        ProcessInfo.processInfo.environment["MACCRAB_CORPUS"] != nil
            && SandboxedTierBRunner.isRuntimeAvailable(trampolinePath: trampoline)
            && FileManager.default.isExecutableFile(atPath: probeBin)
            && FileManager.default.isExecutableFile(atPath: exampleBin)
    }

    /// The Swift-fixture proof additionally needs the Swift probe built — it is the
    /// real-workload gate (Swift runtime + Foundation under the SBPL base).
    static var swiftCorpusEnabled: Bool {
        corpusEnabled && FileManager.default.isExecutableFile(atPath: swiftProbeBin)
    }

    /// Install + sign `binaryPath` as a Tier-B bundle, resolve it into the
    /// SANDBOXED lane (anchor configured but DIFFERENT, so it is not first-party),
    /// and run it under the real trampoline.
    static func run(binaryPath: String, id: String, reads: [String], scratch: String) async throws -> TierBRunOutcome {
        let m = TierBManifest(id: id, displayName: "x", version: "1.0", schemaVersion: 1, description: "x",
                              fileReadSubpaths: reads)
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: m, binaryPath: binaryPath)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)
        let verified = try await registry.resolveForSandboxedExecution(
            pluginID: id, sandboxRuntimeAvailable: true,
            hasValidCuratedReceipt: false, catalogOverrideActive: false,
            firstPartyAnchorFingerprint: String(repeating: "f", count: 64),  // != bundle key → sandboxed lane
            firstPartyAnchorConfigured: true)
        defer { registry.cleanupVerifiedBinary(verified) }
        let runner = SandboxedTierBRunner(trampolinePath: trampoline)
        return try runner.run(verified: verified, scratchDir: scratch, timeout: 30)
    }

    static func tempDir() throws -> String {
        let d = NSTemporaryDirectory() + "corpus-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        return d
    }

    @Test("ALLOW F1: a benign plugin runs + emits its result under the sandbox", .enabled(if: ContainmentCorpusTests.corpusEnabled))
    func benignRuns() async throws {
        let scratch = try Self.tempDir(); defer { try? FileManager.default.removeItem(atPath: scratch) }
        let out = try await Self.run(binaryPath: Self.exampleBin, id: "corpus.example", reads: [], scratch: scratch)
        #expect(out.exitCode == 0, "stderr: \(out.stderrTail)")
        #expect(out.result?.status == "ok")
        #expect(out.artifacts.contains { $0.contentType == "example.heartbeat" })
    }

    @Test("ALLOW F2 + DENY F4/F9/F11/META/MACH: brokered read works; file/network/fork/metadata/mach denied", .enabled(if: ContainmentCorpusTests.corpusEnabled))
    func containment() async throws {
        let scratch = try Self.tempDir(); defer { try? FileManager.default.removeItem(atPath: scratch) }
        try "BROKER-OK".write(toFile: scratch + "/allowed.txt", atomically: true, encoding: .utf8)
        try "TOP-SECRET".write(toFile: "/tmp/maccrab-corpus-secret", atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: "/tmp/maccrab-corpus-secret") }

        let out = try await Self.run(binaryPath: Self.probeBin, id: "corpus.probe", reads: [], scratch: scratch)

        // ALLOW: the declared (scratch) read came back through the broker.
        #expect(out.artifacts.contains { $0.contentType == "broker.read.ok" },
                "no broker.read.ok — exit=\(out.exitCode) result=\(out.result?.status ?? "nil") artifacts=\(out.artifacts.map { "\($0.contentType):\($0.summary ?? "")" }) stderr=\(out.stderrTail)")
        // DENY: the OS denied every boundary probe → no leak.* artifacts.
        let leaks = out.artifacts.filter { $0.contentType.hasPrefix("leak.") }.map { $0.contentType }
        #expect(leaks.isEmpty, "containment FAILED — leaks: \(leaks)")
    }

    @Test("ALLOW + DENY (SWIFT): the Swift runtime starts contained; brokered read works; boundary denied",
          .enabled(if: ContainmentCorpusTests.swiftCorpusEnabled))
    func swiftContainment() async throws {
        // The real shipped workload is Swift (Swift runtime + Foundation + dyld
        // shared cache) — a far broader SBPL surface than the C fixtures. If the
        // base is too tight the binary SIGABRTs at startup and this test fails,
        // which is the exact signal to widen runtimeBaseMachServices. (audit #3)
        let scratch = try Self.tempDir(); defer { try? FileManager.default.removeItem(atPath: scratch) }
        try "BROKER-OK".write(toFile: scratch + "/allowed.txt", atomically: true, encoding: .utf8)
        try "TOP-SECRET".write(toFile: "/tmp/maccrab-corpus-secret", atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: "/tmp/maccrab-corpus-secret") }

        let out = try await Self.run(binaryPath: Self.swiftProbeBin, id: "corpus.probe.swift", reads: [], scratch: scratch)

        // ALLOW: the Swift runtime STARTED under the deny-default sandbox and emitted.
        #expect(out.result?.status == "ok",
                "swift plugin did not emit a terminal result (SBPL base may be too tight) — exit=\(out.exitCode) stderr=\(out.stderrTail)")
        // ALLOW: the declared (scratch) read came back through the broker from Swift.
        #expect(out.artifacts.contains { $0.contentType == "broker.read.ok" },
                "no broker.read.ok — exit=\(out.exitCode) artifacts=\(out.artifacts.map { $0.contentType }) stderr=\(out.stderrTail)")
        // DENY: file/network/fork+exec/metadata all denied → no leak.* artifacts.
        let leaks = out.artifacts.filter { $0.contentType.hasPrefix("leak.") }.map { $0.contentType }
        #expect(leaks.isEmpty, "Swift containment FAILED — leaks: \(leaks)")
    }
}
