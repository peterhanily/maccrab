// CaseEvidence (S2-08/09) tests — evidence-integrity chain.
//
// Coverage:
//   * manifest provenance present (every collected artifact's sha256
//     appears under signature; Merkle root commits to the set)
//   * custody log append-only + tamper-evident (hash chain breaks on
//     mutate / reorder / delete / insert)
//   * sign + verify roundtrip (offline, embedded-key)
//   * cross-form determinism (canonical bytes identical regardless of
//     TZ / key order / Date precision wobble → court-defensible
//     pre-encryption canonical form)
//
// Uses a filesystem-degraded TrustSubstrate over in-memory storage so CI
// runs without Secure Enclave; InMemoryDEKVault so no Keychain UI fires.

import Testing
import Foundation
import CryptoKit
import MacCrabCore
@testable import MacCrabForensics

@Suite("Custody log (S2-08 append-only chain of custody)")
struct CustodyLogTests {

    private func append(
        _ log: inout CustodyLog,
        collector: String,
        at date: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) throws {
        try log.append(
            engineVersion: "1.19.0",
            rulePackHash: String(repeating: "a", count: 64),
            pluginID: "com.maccrab.\(collector)",
            pluginVersion: "1.0.0",
            pluginHash: String(repeating: "b", count: 64),
            collector: collector,
            timestamp: date
        )
    }

    @Test("empty log head is the genesis sentinel")
    func emptyHeadGenesis() throws {
        let log = CustodyLog()
        #expect(log.head == CustodyLog.genesis)
        #expect(try log.verifyChain() == CustodyLog.genesis)
    }

    @Test("appended entries chain prev_hash → entry_hash")
    func chainLinks() throws {
        var log = CustodyLog()
        try append(&log, collector: "tcc-lite")
        try append(&log, collector: "launchd-lite")
        try append(&log, collector: "safari-lite")

        #expect(log.entries.count == 3)
        // First entry chains onto genesis.
        #expect(log.entries[0].payload.prevHash == CustodyLog.genesis)
        // Each subsequent entry chains onto its predecessor's entryHash.
        #expect(log.entries[1].payload.prevHash == log.entries[0].entryHash)
        #expect(log.entries[2].payload.prevHash == log.entries[1].entryHash)
        // Head is the last entryHash.
        #expect(log.head == log.entries[2].entryHash)
        // Full chain verifies.
        #expect(try log.verifyChain() == log.head)
    }

    @Test("captures the trust context at collection time")
    func capturesContext() throws {
        var log = CustodyLog()
        try append(&log, collector: "tcc-lite")
        let p = log.entries[0].payload
        #expect(p.engineVersion == "1.19.0")
        #expect(p.rulePackHash == String(repeating: "a", count: 64))
        #expect(p.pluginID == "com.maccrab.tcc-lite")
        #expect(p.pluginHash == String(repeating: "b", count: 64))
        #expect(p.collector == "tcc-lite")
        // Timestamp is canonical UTC ISO-8601 with fractional seconds.
        #expect(p.timestamp.hasSuffix("Z"))
        #expect(p.timestamp.contains("."))
    }

    @Test("mutating a payload field breaks the chain")
    func tamperMutateDetected() throws {
        var log = CustodyLog()
        try append(&log, collector: "tcc-lite")
        try append(&log, collector: "launchd-lite")

        // Forge a manifest where entry 0's collector was swapped but its
        // stored entry_hash kept — entry_hash recompute must fail.
        let forgedPayload = CustodyEntryPayload(
            engineVersion: log.entries[0].payload.engineVersion,
            rulePackHash: log.entries[0].payload.rulePackHash,
            pluginID: log.entries[0].payload.pluginID,
            pluginVersion: log.entries[0].payload.pluginVersion,
            pluginHash: log.entries[0].payload.pluginHash,
            collector: "EVIL-COLLECTOR",
            timestamp: log.entries[0].payload.timestamp,
            prevHash: log.entries[0].payload.prevHash
        )
        let forged = CustodyLog(entries: [
            CustodyEntry(payload: forgedPayload, entryHash: log.entries[0].entryHash),
            log.entries[1],
        ])
        #expect(throws: CustodyLogError.self) { try forged.verifyChain() }
    }

    @Test("reordering entries breaks the chain")
    func tamperReorderDetected() throws {
        var log = CustodyLog()
        try append(&log, collector: "tcc-lite")
        try append(&log, collector: "launchd-lite")
        let reordered = CustodyLog(entries: [log.entries[1], log.entries[0]])
        #expect(throws: CustodyLogError.self) { try reordered.verifyChain() }
    }

    @Test("deleting an entry breaks the chain")
    func tamperDeleteDetected() throws {
        var log = CustodyLog()
        try append(&log, collector: "tcc-lite")
        try append(&log, collector: "launchd-lite")
        try append(&log, collector: "safari-lite")
        // Drop the middle entry: entry[2].prevHash no longer matches.
        let truncated = CustodyLog(entries: [log.entries[0], log.entries[2]])
        #expect(throws: CustodyLogError.self) { try truncated.verifyChain() }
    }
}

@Suite("CaseEvidenceSigner (S2-09 signed evidence manifest)")
struct CaseEvidenceSignerTests {

    private func makeSubstrate() -> TrustSubstrate {
        TrustSubstrate(storage: InMemoryTrustSubstrateStorage(), modeOverride: .filesystemDegraded)
    }

    private func tempRoot() -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-evidence-\(UUID().uuidString)")
    }

    private func sampleProvenance() -> [ArtifactProvenance] {
        [
            ArtifactProvenance(sha256: String(repeating: "c", count: 64), contentType: "tcc.grant", pluginID: "tcc", sizeBytes: 100),
            ArtifactProvenance(sha256: String(repeating: "a", count: 64), contentType: "launchd.entry", pluginID: "launchd", sizeBytes: 200),
            ArtifactProvenance(sha256: String(repeating: "b", count: 64), contentType: "safari.download", pluginID: "safari", sizeBytes: 300),
        ]
    }

    private func sampleCustody() throws -> CustodyLog {
        var log = CustodyLog()
        try log.append(
            engineVersion: "1.19.0", rulePackHash: String(repeating: "f", count: 64),
            pluginID: "tcc", pluginVersion: "1.0", pluginHash: "",
            collector: "tcc-lite", timestamp: Date(timeIntervalSince1970: 1_700_000_000)
        )
        try log.append(
            engineVersion: "1.19.0", rulePackHash: String(repeating: "f", count: 64),
            pluginID: "launchd", pluginVersion: "1.0", pluginHash: "",
            collector: "launchd-lite", timestamp: Date(timeIntervalSince1970: 1_700_000_500)
        )
        return log
    }

    @Test("buildBody enumerates provenance + a Merkle root over sorted sha256s")
    func bodyProvenancePresent() throws {
        let prov = sampleProvenance()
        let body = CaseEvidenceSigner.buildBody(
            caseID: "case-1", caseName: "audit", engineVersion: "1.19.0",
            sealedAt: Date(timeIntervalSince1970: 1_700_000_000),
            provenance: prov, custodyHead: CustodyLog.genesis, custodyEntryCount: 0
        )
        // Every artifact's sha256 is present, count matches.
        #expect(body.artifactCount == 3)
        let shas = Set(body.artifacts.map { $0.sha256 })
        #expect(shas == Set(prov.map { $0.sha256 }))
        // Artifacts are canonically sorted by sha256 (a < b < c).
        #expect(body.artifacts.map { $0.sha256 } == [
            String(repeating: "a", count: 64),
            String(repeating: "b", count: 64),
            String(repeating: "c", count: 64),
        ])
        // Merkle root matches an independent reduction over the sorted leaves.
        let expectedRoot = BundleMerkle.reduce(body.artifacts.map { $0.sha256 })
        #expect(body.artifactsMerkleRoot == expectedRoot)
        #expect(!body.artifactsMerkleRoot.isEmpty)
    }

    @Test("sign + verify roundtrips offline using the embedded key")
    func signVerifyRoundTrip() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: UUID().uuidString.lowercased())
        try layout.createDirectoryStructure()

        let custody = try sampleCustody()
        let body = CaseEvidenceSigner.buildBody(
            caseID: layout.caseID, caseName: "roundtrip",
            sealedAt: Date(timeIntervalSince1970: 1_700_000_000),
            provenance: sampleProvenance(),
            custodyHead: custody.head, custodyEntryCount: custody.entries.count
        )
        let signer = CaseEvidenceSigner(substrate: makeSubstrate())
        let url = try await signer.writeEnvelope(body: body, custodyLog: custody, to: layout.evidenceManifestFile)
        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(url.lastPathComponent == "evidence_manifest.json")

        let verified = try CaseEvidenceSigner.verify(at: url, expectedCaseID: layout.caseID)
        #expect(verified.body == body)
        #expect(verified.body.artifactCount == 3)
        #expect(verified.custodyLog.entries.count == 2)
        #expect(verified.body.custodyHead == custody.head)
    }

    @Test("seal over a live store collects ALL artifacts as provenance")
    func sealOverLiveStore() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "live seal")

        // Commit two artifacts (metadata class — plaintext-safe + encrypted-safe).
        for (i, ct) in ["tcc.grant", "launchd.entry"].enumerated() {
            _ = try await handle.store.commit(ArtifactRecord(
                caseID: handle.caseID, pluginID: "p\(i)", pluginVersion: "1.0",
                schemaVersion: 1, contentType: ct,
                sha256: String(repeating: String(i), count: 64),
                observedAt: Date(timeIntervalSince1970: 1_700_000_000),
                sizeBytes: 10, privacyClass: .metadata
            ))
        }

        var custody = CustodyLog()
        try custody.append(
            engineVersion: MacCrabVersion.current, rulePackHash: "",
            pluginID: "p0", pluginVersion: "1.0", pluginHash: "",
            collector: "tcc-lite", timestamp: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let signer = CaseEvidenceSigner(substrate: makeSubstrate())
        let url = try await signer.seal(
            caseID: handle.caseID, caseName: "live seal",
            store: handle.store, custodyLog: custody, layout: handle.layout
        )
        let verified = try CaseEvidenceSigner.verify(at: url, expectedCaseID: handle.caseID)
        #expect(verified.body.artifactCount == 2)
        #expect(verified.custodyLog.entries.count == 1)
    }

    @Test("tampering with a signed body field breaks verification")
    func tamperBodyDetected() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: UUID().uuidString.lowercased())
        try layout.createDirectoryStructure()
        let custody = try sampleCustody()
        let body = CaseEvidenceSigner.buildBody(
            caseID: layout.caseID, caseName: "t",
            provenance: sampleProvenance(),
            custodyHead: custody.head, custodyEntryCount: custody.entries.count
        )
        let signer = CaseEvidenceSigner(substrate: makeSubstrate())
        let url = try await signer.writeEnvelope(body: body, custodyLog: custody, to: layout.evidenceManifestFile)

        // Swap one artifact's sha256 inside the signed body.
        let data = try Data(contentsOf: url)
        var top = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var bodyDict = try #require(top["body"] as? [String: Any])
        var arts = try #require(bodyDict["artifacts"] as? [[String: Any]])
        arts[0]["sha256"] = String(repeating: "9", count: 64)
        bodyDict["artifacts"] = arts
        top["body"] = bodyDict
        let tampered = try JSONSerialization.data(withJSONObject: top)
        #expect(throws: CaseEvidenceError.self) {
            try CaseEvidenceSigner.verify(data: tampered)
        }
    }

    @Test("swapping the bundled custody log for a different valid chain is rejected")
    func tamperCustodySwapDetected() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: UUID().uuidString.lowercased())
        try layout.createDirectoryStructure()
        let custody = try sampleCustody()
        let body = CaseEvidenceSigner.buildBody(
            caseID: layout.caseID, caseName: "t",
            provenance: sampleProvenance(),
            custodyHead: custody.head, custodyEntryCount: custody.entries.count
        )
        let signer = CaseEvidenceSigner(substrate: makeSubstrate())
        let url = try await signer.writeEnvelope(body: body, custodyLog: custody, to: layout.evidenceManifestFile)

        // Build a DIFFERENT internally-valid custody log and splice it in.
        var other = CustodyLog()
        try other.append(
            engineVersion: "9.9.9", rulePackHash: "", pluginID: "x",
            pluginVersion: "9", pluginHash: "", collector: "rogue",
            timestamp: Date(timeIntervalSince1970: 1)
        )
        let otherData = try JSONEncoder().encode(other)
        let otherObj = try JSONSerialization.jsonObject(with: otherData)

        let data = try Data(contentsOf: url)
        var top = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        top["custody_log"] = otherObj  // valid chain, but head ≠ signed custody_head
        let tampered = try JSONSerialization.data(withJSONObject: top)
        #expect(throws: CaseEvidenceError.self) {
            try CaseEvidenceSigner.verify(data: tampered)
        }
    }

    @Test("verify rejects a manifest lifted onto a different case id")
    func caseIDCrossBinding() async throws {
        let root = tempRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: UUID().uuidString.lowercased())
        try layout.createDirectoryStructure()
        let custody = try sampleCustody()
        let body = CaseEvidenceSigner.buildBody(
            caseID: layout.caseID, caseName: "t",
            provenance: sampleProvenance(),
            custodyHead: custody.head, custodyEntryCount: custody.entries.count
        )
        let signer = CaseEvidenceSigner(substrate: makeSubstrate())
        let url = try await signer.writeEnvelope(body: body, custodyLog: custody, to: layout.evidenceManifestFile)

        #expect(throws: CaseEvidenceError.self) {
            try CaseEvidenceSigner.verify(at: url, expectedCaseID: "some-other-case")
        }
        // But the genuine case id still verifies.
        _ = try CaseEvidenceSigner.verify(at: url, expectedCaseID: layout.caseID)
    }

    @Test("malformed input → malformed error, not a crash")
    func malformedDetected() {
        let notAManifest = Data(#"{"hello":"world"}"#.utf8)
        #expect(throws: CaseEvidenceError.self) {
            try CaseEvidenceSigner.verify(data: notAManifest)
        }
    }
}

@Suite("Evidence cross-form determinism (court-defensible canonical form)")
struct EvidenceDeterminismTests {

    /// Two bodies built from the SAME logical artifact set but supplied
    /// in different row order must canonicalize to byte-identical bytes —
    /// the property that makes encrypted-at-rest cases verifiable across
    /// machines regardless of SQLCipher page/row layout.
    @Test("artifact row order does not affect canonical bytes")
    func rowOrderIndependent() throws {
        let a = ArtifactProvenance(sha256: String(repeating: "a", count: 64), contentType: "x", pluginID: "p", sizeBytes: 1)
        let b = ArtifactProvenance(sha256: String(repeating: "b", count: 64), contentType: "y", pluginID: "q", sizeBytes: 2)
        let c = ArtifactProvenance(sha256: String(repeating: "c", count: 64), contentType: "z", pluginID: "r", sizeBytes: 3)

        let sealed = Date(timeIntervalSince1970: 1_700_000_000)
        let body1 = CaseEvidenceSigner.buildBody(
            caseID: "case", caseName: "n", engineVersion: "1.19.0",
            sealedAt: sealed, provenance: [a, b, c],
            custodyHead: CustodyLog.genesis, custodyEntryCount: 0
        )
        let body2 = CaseEvidenceSigner.buildBody(
            caseID: "case", caseName: "n", engineVersion: "1.19.0",
            sealedAt: sealed, provenance: [c, a, b],   // shuffled
            custodyHead: CustodyLog.genesis, custodyEntryCount: 0
        )
        #expect(try body1.canonicalBytes() == body2.canonicalBytes())
        #expect(body1.artifactsMerkleRoot == body2.artifactsMerkleRoot)
    }

    /// The canonical timestamp pins millisecond precision + UTC, so two
    /// Dates representing the same instant render identically regardless
    /// of the host timezone the test process happens to carry.
    @Test("canonical timestamp is UTC + fixed precision")
    func timestampCanonical() {
        let date = Date(timeIntervalSince1970: 1_700_000_000.123)
        let s = CanonicalTimestamp.string(from: date)
        #expect(s == "2023-11-14T22:13:20.123Z")
        // Re-rendering the same instant is stable.
        #expect(CanonicalTimestamp.string(from: Date(timeIntervalSince1970: 1_700_000_000.123)) == s)
    }

    /// JSON key order in the encoded body must be deterministic (sorted),
    /// so the signed digest is reproducible across encoder runs.
    @Test("canonical bytes are stable across repeated encodes")
    func encodeStable() throws {
        let body = CaseEvidenceSigner.buildBody(
            caseID: "case", caseName: "n", engineVersion: "1.19.0",
            sealedAt: Date(timeIntervalSince1970: 1_700_000_000),
            provenance: [
                ArtifactProvenance(sha256: String(repeating: "a", count: 64), contentType: "x", pluginID: "p", sizeBytes: 1),
            ],
            custodyHead: CustodyLog.genesis, custodyEntryCount: 0
        )
        let first = try body.canonicalBytes()
        for _ in 0..<5 {
            #expect(try body.canonicalBytes() == first)
        }
        // And a decode→re-encode round-trip reproduces the same bytes,
        // which is exactly what the offline verifier relies on.
        let decoded = try JSONDecoder().decode(EvidenceManifestBody.self, from: first)
        #expect(try decoded.canonicalBytes() == first)
    }
}
