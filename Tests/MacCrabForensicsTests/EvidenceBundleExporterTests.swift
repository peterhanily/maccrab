// EvidenceBundleExporterTests — privacy-class redaction on export.
//
// Regression for the leak where the exporter serialized every artifact's
// full data payload with NO privacy-class filtering, writing secret /
// personalComms / credential content into the exported bundle. A default
// export must redact non-metadata payloads (and summaries, which routinely
// embed the same content); an explicit includeSensitive:true opts back in.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("EvidenceBundleExporter privacy-class redaction")
struct EvidenceBundleExporterTests {

    private func secretArtifact() -> CommittedArtifact {
        let rec = ArtifactRecord(
            caseID: "case-1",
            pluginID: "com.test.secret",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "keychain.secret",
            sha256: String(repeating: "a", count: 64),
            observedAt: Date(timeIntervalSince1970: 1_700_000_000),
            summary: "decrypted password for bank.example",
            privacyClass: .secret,
            data: ["password": .string("hunter2")]
        )
        return CommittedArtifact(id: 1, record: rec)
    }

    private func metadataArtifact() -> CommittedArtifact {
        let rec = ArtifactRecord(
            caseID: "case-1",
            pluginID: "com.test.meta",
            pluginVersion: "1.0.0",
            schemaVersion: 1,
            contentType: "tcc.grant",
            sha256: String(repeating: "b", count: 64),
            observedAt: Date(timeIntervalSince1970: 1_700_000_000),
            summary: "camera allowed for com.test.app",
            privacyClass: .metadata,
            data: ["service": .string("camera")]
        )
        return CommittedArtifact(id: 2, record: rec)
    }

    private func artifactObjs(_ data: Data) throws -> [[String: Any]] {
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        return obj["artifacts"] as! [[String: Any]]
    }

    @Test("Default export redacts a secret-class artifact's payload + summary")
    func defaultExportRedactsSecret() throws {
        let data = try EvidenceBundleExporter.render(
            caseID: "case-1",
            artifacts: [secretArtifact(), metadataArtifact()],
            exportedAt: Date(timeIntervalSince1970: 1_700_000_100),
            appVersion: "test"
        )
        let objs = try artifactObjs(data)

        let secret = objs.first { ($0["content_type"] as? String) == "keychain.secret" }!
        #expect(secret["data"] == nil)
        #expect(secret["summary"] == nil)
        #expect((secret["redacted"] as? Bool) == true)
        // Envelope is retained so the export still attests the artifact exists.
        #expect((secret["privacy_class"] as? String) == "secret")
        #expect((secret["sha256"] as? String) == String(repeating: "a", count: 64))

        // A metadata artifact is untouched.
        let meta = objs.first { ($0["content_type"] as? String) == "tcc.grant" }!
        #expect(meta["data"] != nil)
        #expect(meta["summary"] != nil)
        #expect(meta["redacted"] == nil)
    }

    @Test("includeSensitive:true exports the secret payload verbatim")
    func includeSensitiveExportsSecret() throws {
        let data = try EvidenceBundleExporter.render(
            caseID: "case-1",
            artifacts: [secretArtifact()],
            exportedAt: Date(timeIntervalSince1970: 1_700_000_100),
            appVersion: "test",
            includeSensitive: true
        )
        let objs = try artifactObjs(data)
        let secret = objs[0]
        let payload = secret["data"] as? [String: Any]
        #expect(payload?["password"] as? String == "hunter2")
        #expect(secret["summary"] as? String == "decrypted password for bank.example")
        #expect(secret["redacted"] == nil)
    }
}
