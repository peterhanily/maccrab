// TierBSubprocessLoader IPC round-trip tests.
//
// These exercise the JSON-RPC-over-stdio contract end-to-end by
// spawning the tier-b-fixture-plugin binary (an SPM executable
// target) and verifying responses parse correctly.
//
// Tests are skipped when the fixture binary is missing — the
// tests run from the build root only.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("TierBSubprocessLoader IPC round-trip")
struct TierBSubprocessLoaderTests {

    static var fixtureBinaryPath: String? {
        let candidates = [
            ".build/debug/tier-b-fixture-plugin",
            ".build/release/tier-b-fixture-plugin",
        ]
        let fm = FileManager.default
        for c in candidates where fm.isExecutableFile(atPath: c) {
            return c
        }
        return nil
    }

    @Test("collect returns the requested number of heartbeats")
    func collectReturnsRequestedTickCount() async throws {
        guard let binary = Self.fixtureBinaryPath else {
            // Skip when not built — early-iteration TaskScheduler
            // scenarios don't always build executables first.
            return
        }
        let loader = TierBSubprocessLoader()
        let result = try await loader.runCollect(
            binaryPath: binary,
            caseID: "test-case-1",
            caseName: "ipc round trip",
            encryptionState: "plaintext",
            tickCount: 4
        )
        #expect(result.artifacts.count == 4)
        #expect(result.status == "ok")
        #expect(result.subprocessExitCode == 0)
        for (idx, artifact) in result.artifacts.enumerated() {
            #expect(artifact.contentType == "tier_b_fixture.heartbeat")
            #expect(artifact.confidence == "observed")
            #expect(artifact.privacyClass == "metadata")
            #expect(artifact.summary.contains("tick \(idx)"))
            // SHA-256 hex = 64 chars.
            #expect(artifact.sha256.count == 64)
        }
    }

    @Test("missing binary raises binaryMissing")
    func missingBinaryRaisesBinaryMissing() async throws {
        let loader = TierBSubprocessLoader()
        do {
            _ = try await loader.runCollect(
                binaryPath: "/tmp/this-binary-definitely-does-not-exist-\(UUID().uuidString)",
                caseID: "x",
                caseName: "x",
                encryptionState: "plaintext"
            )
            Issue.record("expected binaryMissing error")
        } catch TierBSubprocessLoader.LoaderError.binaryMissing {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("runCollectAndCommit commits to the supplied ArtifactStore")
    func runCollectAndCommitWritesToStore() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let tmpRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tierb-loader-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: tmpRoot,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: tmpRoot) }

        let layout = CaseDirectoryLayout(
            casesRoot: tmpRoot,
            caseID: "tier-b-test-case"
        )
        try FileManager.default.createDirectory(
            at: layout.caseDirectory,
            withIntermediateDirectories: true
        )
        let store = try await ArtifactStore(
            path: layout.sqliteFile.path,
            dek: nil,
            encryptionState: .plaintext
        )
        // commit() requires the case row to exist for the FK.
        try await store.insertCase(CaseRecord(
            id: "tier-b-test-case",
            name: "tier-b-test-case",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        let loader = TierBSubprocessLoader()
        let (committed, rejected, _) = try await loader.runCollectAndCommit(
            binaryPath: binary,
            pluginID: "tier-b-fixture",
            pluginVersion: "research",
            schemaVersion: 1,
            caseID: "tier-b-test-case",
            caseName: "tier-b-test-case",
            encryptionState: .plaintext,
            store: store,
            tickCount: 2
        )
        #expect(committed == 2)
        #expect(rejected == 0)
        let listed = try await store.query(ArtifactQuery(
            caseID: "tier-b-test-case",
            contentType: "tier_b_fixture.heartbeat",
            limit: 10
        ))
        #expect(listed.count == 2)
    }
}
