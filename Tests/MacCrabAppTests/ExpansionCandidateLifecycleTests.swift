import Testing
import Foundation
import CryptoKit
import Darwin
@testable import MacCrabForensics
@testable import MacCrabApp

@Suite("Ten expansion candidate lifecycle")
struct ExpansionCandidateLifecycleTests {
    // Fixture inputs are admitted from their exact unsigned archives by
    // qualify-ten-plugins.py. Only the test publisher key is trusted in
    // these disposable directories; production trust is never changed.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["RAVE_TEN_FIXTURE_ROOT"] != nil),
          arguments: ExpansionFinding.slugs)
    func candidateLifecycle(slug: String) async throws {
        let base = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["RAVE_TEN_FIXTURE_ROOT"]))
        let input = base.appendingPathComponent(slug)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let binary = try Data(contentsOf: input.appendingPathComponent("binary"))
        let manifestBytes = try Data(contentsOf: input.appendingPathComponent("manifest.json"))
        let manifest = try JSONDecoder().decode(TierBManifest.self, from: manifestBytes)
        let key = Curve25519.Signing.PrivateKey()
        let signature = try key.signature(for: PluginSignatureVerifier.canonicalSignedPayload(manifestData: manifestBytes, binaryData: binary))
        let bundle = try PluginBundleSnapshot(files: ["manifest.json": manifestBytes, "binary": binary,
            "signature": signature, "signing.key.pub": key.publicKey.rawRepresentation])
        let installer = PluginInstaller(pluginsRoot: root.appendingPathComponent("plugins"))
        await #expect(throws: (any Error).self) { try await installer.install(snapshot: bundle) }
        let installed = try await installer.install(snapshot: bundle, trustOnInstall: true)
        let location = URL(fileURLWithPath: installed.installRoot)
        #expect(try Data(contentsOf: location.appendingPathComponent("binary")) == binary)
        await #expect(throws: (any Error).self) { try await installer.install(snapshot: bundle) }
        _ = try await installer.install(snapshot: bundle, force: true)
        #expect(try PluginBundleSnapshot.capture(sourceDirectory: location) == bundle)
        // Test the actual signature gate without enabling the unsigned override.
        let expectedSigned = ProcessInfo.processInfo.environment["RAVE_TEN_EXPECT_SIGNED"] == "1"
        #expect(TierBFirstPartyExecGuard.developerIDTrusted(path: location.appendingPathComponent("binary").path, allowUnsigned: false) == expectedSigned)

        // Deliberate development invocation, with only fictional selected inputs.
        let output = try run(binary: location.appendingPathComponent("binary"), home: input.appendingPathComponent("home"),
                             manifest: manifest, directory: root)
        let manager = CaseManager(casesRoot: root.appendingPathComponent("cases"), dekVault: InMemoryDEKVault())
        let handle = try await manager.createCase(name: "Candidate qualification")
        var count = 0, terminals = 0
        for line in String(decoding: output, as: UTF8.self).split(separator: "\n") {
            switch try JSONDecoder().decode(TierBOutputLine.self, from: Data(line.utf8)) {
            case .artifact(let artifact):
                #expect(terminals == 0)
                if case .record(let record) = TierBArtifactBridge.map(dto: artifact, caseID: handle.caseID, manifest: manifest, caseAllowsSensitive: true) {
                    try await handle.store.commit(record); count += 1
                } else { Issue.record("Actual candidate artifact rejected by native bridge") }
                if artifact.privacyClass != "metadata" {
                    if case .rejected = TierBArtifactBridge.map(dto: artifact, caseID: handle.caseID, manifest: manifest, caseAllowsSensitive: false) {} else {
                        Issue.record("Sensitive candidate artifact accepted in plaintext case")
                    }
                }
            case .result(let result):
                #expect(["ok", "partial"].contains(result.status)); terminals += 1
            }
        }
        #expect(terminals == 1); #expect(count > 0)
        let reopened = try await manager.openCase(id: handle.caseID)
        let records = try await reopened.store.query(.init(caseID: reopened.caseID, limit: 5000))
        #expect(records.count == count)
        let findings = records.filter { $0.record.contentType.hasSuffix(".finding") }
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { ExpansionFinding($0) != nil })
        try await installer.uninstall(pluginID: manifest.id)
        #expect(try await installer.list().isEmpty)
    }

    private func run(binary: URL, home: URL, manifest: TierBManifest, directory: URL) throws -> Data {
        let stdout = directory.appendingPathComponent("stdout"), stderr = directory.appendingPathComponent("stderr")
        FileManager.default.createFile(atPath: stdout.path, contents: nil)
        FileManager.default.createFile(atPath: stderr.path, contents: nil)
        let out = try FileHandle(forWritingTo: stdout), err = try FileHandle(forWritingTo: stderr)
        defer { try? out.close(); try? err.close() }
        let input = Pipe(), process = Process()
        process.executableURL = binary; process.arguments = ["--dev-run", "--home", home.path]
        process.standardInput = input; process.standardOutput = out; process.standardError = err
        try process.run()
        let request = try JSONSerialization.data(withJSONObject: ["protocolVersion": 1, "pluginID": manifest.id, "pluginVersion": manifest.version])
        try input.fileHandleForWriting.write(contentsOf: request); try input.fileHandleForWriting.close()
        let deadline = Date().addingTimeInterval(20)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw RaveReviewError.invalid }
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        let size = try FileManager.default.attributesOfItem(atPath: stdout.path)[.size] as? NSNumber
        guard let size, size.intValue <= 4 * RaveReviewEngine.maxBytes else { throw RaveReviewError.oversized }
        return try Data(contentsOf: stdout)
    }
}
