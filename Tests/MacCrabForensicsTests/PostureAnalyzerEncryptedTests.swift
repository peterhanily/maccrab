// PostureAnalyzerEncryptedTests.swift
//
// FIQ-8: on an encrypted case the posture analyzer can't yet read the
// store, but it must surface that gap as ONE honest informational
// finding rather than returning [] (which is indistinguishable from
// "analyzed, found nothing" and silently hides the limitation).

import Testing
import Foundation
import MacCrabCore
@testable import MacCrabForensics

@Suite("PostureAnalyzer — encrypted case")
struct PostureAnalyzerEncryptedTests {

    @Test("encrypted case yields one 'analysis unavailable' finding, not a silent empty array")
    func encryptedCaseSurfacesGap() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("posture-enc-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "enc")   // encrypted by default
        #expect(handle.encryptionState == .encryptedKeychain)

        let ctx = CaseContext(
            caseID: handle.caseID,
            caseName: "enc",
            aiContentAllowed: false,
            scheduledTrusted: false,
            directory: handle.layout.caseDirectory,
            encryptionState: handle.encryptionState
        )

        let findings = try await PostureAnalyzer().analyze(case: ctx, scope: .wholeCase)
        #expect(findings.count == 1)
        #expect(findings.first?.findingType == "posture.analysis_unavailable_encrypted")
        #expect(findings.first?.severity == .informational)
        #expect(findings.first?.explanation.isEmpty == false)
    }
}
