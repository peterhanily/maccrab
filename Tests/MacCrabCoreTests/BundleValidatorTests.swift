// BundleValidatorTests.swift
// v1.10 TraceGraph (PR-10a) — exercises every published exit code
// from §18.9 against synthetic bundle directories.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: BundleValidator (§18.9 exit codes)")
struct BundleValidatorTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Bundle builder

    /// Build a minimal valid bundle directory in a temp location.
    /// Returns the directory URL; caller is responsible for cleanup.
    private func buildValidBundle(
        manifestOverrides: ((inout BundleManifest) -> Void)? = nil,
        graphOverrides: ((inout GraphArtifact) -> Void)? = nil,
        eventsLines: [String]? = nil,
        provJsonOverride: String? = nil,
        otelJsonOverride: String? = nil,
        sigMerkleOverride: String? = nil,
        sigKeyModeOverride: String? = nil
    ) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabtrace-\(UUID().uuidString)")

        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        for sub in ["replay", "integrity", "prov", "otel", "schema", "rules", "evidence", "baseline", "report", "attribution", "llm"] {
            try FileManager.default.createDirectory(
                at: dir.appendingPathComponent(sub),
                withIntermediateDirectories: true
            )
        }

        var manifest = BundleManifest(
            maccrabVersion: "1.10.0",
            rulesetVersion: "1.10.0",
            normalizationVersion: "1",
            createdAt: now,
            hostRedacted: true,
            traceId: "trace-1",
            title: "Test trace",
            severity: "high",
            confidence: 0.9,
            provCompliant: true,
            otelAligned: true,
            otelConventionVersion: "gen_ai_mcp_current_at_build",
            processIdentityVersion: "maccrab.process_identity.v1",
            traceSigningKeyMode: sigKeyModeOverride ?? "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
        manifestOverrides?(&manifest)

        let trace = Trace(
            id: manifest.traceId,
            title: manifest.title,
            anchorEventId: "ev-1",
            rootEntityId: "process:root",
            severity: manifest.severity,
            confidence: manifest.confidence,
            createdAt: now, updatedAt: now,
            daemonVersion: manifest.maccrabVersion,
            rulesetVersion: manifest.rulesetVersion,
            policyId: "default", policyVersion: "1",
            policySha256: "x", policySnapshotJson: "{}",
            traceSigningKeyMode: manifest.traceSigningKeyMode,
            replayScope: manifest.replayScope,
            attributionOverridePolicy: manifest.attributionOverridePolicy
        )

        let entityRoot = TraceEntity(
            id: "process:root", entityType: "process",
            stableKey: "root", displayName: "root",
            firstSeen: now, lastSeen: now,
            attributesJson: "{}", source: "test"
        )
        let entityAnchor = TraceEntity(
            id: "process:anchor", entityType: "process",
            stableKey: "anchor", displayName: "anchor",
            firstSeen: now, lastSeen: now,
            attributesJson: "{}", source: "test"
        )
        let edge = TraceEdge(
            id: EdgeBuilder.edgeId(
                sourceEntityId: "process:root",
                targetEntityId: "process:anchor",
                relation: .spawned
            ),
            sourceEntityId: "process:root",
            targetEntityId: "process:anchor",
            relation: "spawned",
            firstSeen: now, lastSeen: now,
            confidence: 0.95, confidenceTier: "direct",
            evidenceJson: "{}", eventIdsJson: "[]"
        )

        var graph = GraphArtifact(
            trace: trace,
            entities: [entityRoot, entityAnchor],
            edges: [edge],
            memberships: [
                TraceMembership(traceId: trace.id, entityId: "process:anchor", role: "anchor", layer: "core", addedAt: now),
            ],
            rootCauseEntityId: "process:root",
            anchorEntityId: "process:anchor"
        )
        graphOverrides?(&graph)

        let encoder = canonicalJSONEncoder()
        try encoder.encode(manifest).write(to: dir.appendingPathComponent("manifest.json"))
        try encoder.encode(graph).write(to: dir.appendingPathComponent("graph.json"))

        // events.jsonl
        let lines = eventsLines ?? [#"{"id":"ev-1","ts":1700000000,"type":"exec","host":"~/..."}"#]
        try lines.joined(separator: "\n").write(
            to: dir.appendingPathComponent("events.jsonl"),
            atomically: true, encoding: .utf8
        )

        // replay_manifest
        let replay = ReplayManifestArtifact(
            daemonVersion: manifest.maccrabVersion,
            rulesetVersion: manifest.rulesetVersion,
            normalizationVersion: manifest.normalizationVersion,
            replayScope: manifest.replayScope,
            policySnapshotJson: "{}"
        )
        try encoder.encode(replay).write(to: dir.appendingPathComponent("replay/replay_manifest.json"))

        // hash_chain + signature
        let chain = HashChainArtifact(
            artifacts: [
                .init(path: "manifest.json", sha256: "deadbeef"),
                .init(path: "graph.json", sha256: "cafebabe"),
            ],
            merkleRoot: "ROOT_DEADBEEF"
        )
        try encoder.encode(chain).write(to: dir.appendingPathComponent("integrity/hash_chain.json"))

        let signature = ChainHeadSignatureArtifact(
            merkleRoot: sigMerkleOverride ?? "ROOT_DEADBEEF",
            signatureBase64: "AAAA",
            signingKeyMode: manifest.traceSigningKeyMode,
            signingKeyFingerprint: "fpfp",
            signedAt: now
        )
        try encoder.encode(signature).write(to: dir.appendingPathComponent("integrity/chain_head_signature.json"))

        // prov + otel (basic shapes that satisfy the claim validators)
        let provDefault = """
        {"@context":{"prov":"http://www.w3.org/ns/prov#"},"@graph":[{"@id":"ex:trace1","@type":"prov:Activity"}]}
        """
        try (provJsonOverride ?? provDefault).write(
            to: dir.appendingPathComponent("prov/prov.jsonld"),
            atomically: true, encoding: .utf8
        )

        let otelDefault = """
        {"resourceSpans":[{"resource":{"attributes":[{"key":"otel.semconv.version","value":{"stringValue":"gen_ai_mcp_current_at_build"}}]},"scopeSpans":[]}]}
        """
        try (otelJsonOverride ?? otelDefault).write(
            to: dir.appendingPathComponent("otel/spans.json"),
            atomically: true, encoding: .utf8
        )

        return dir
    }

    private func cleanup(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - Tests

    @Test("Exit 0: valid bundle")
    func validBundle() throws {
        let dir = try buildValidBundle()
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 0)
        #expect(outcome.kind == .valid)
    }

    @Test("Exit 1: missing manifest.json")
    func missingManifest() throws {
        let dir = try buildValidBundle()
        defer { cleanup(dir) }
        try FileManager.default.removeItem(at: dir.appendingPathComponent("manifest.json"))
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
        if case .schemaInvalid = outcome.kind {} else { Issue.record("Expected schemaInvalid, got \(outcome.kind)") }
    }

    @Test("Exit 1: malformed manifest JSON")
    func malformedManifestJson() throws {
        let dir = try buildValidBundle()
        defer { cleanup(dir) }
        try "not json".write(
            to: dir.appendingPathComponent("manifest.json"),
            atomically: true, encoding: .utf8
        )
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
    }

    @Test("Exit 5: incompatible bundle major version (v2)")
    func incompatibleMajor() throws {
        let dir = try buildValidBundle(manifestOverrides: { manifest in
            manifest = BundleManifest(
                format: "maccrab.tracebundle.v2",
                maccrabVersion: manifest.maccrabVersion,
                rulesetVersion: manifest.rulesetVersion,
                normalizationVersion: manifest.normalizationVersion,
                createdAt: manifest.createdAt,
                hostRedacted: manifest.hostRedacted,
                traceId: manifest.traceId,
                title: manifest.title,
                severity: manifest.severity,
                confidence: manifest.confidence,
                provCompliant: manifest.provCompliant,
                otelAligned: manifest.otelAligned,
                otelConventionVersion: manifest.otelConventionVersion,
                processIdentityVersion: manifest.processIdentityVersion,
                traceSigningKeyMode: manifest.traceSigningKeyMode,
                replayScope: manifest.replayScope,
                attributionOverridePolicy: manifest.attributionOverridePolicy
            )
        })
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 5)
        if case .incompatibleMajorVersion = outcome.kind {} else {
            Issue.record("Expected incompatibleMajorVersion, got \(outcome.kind)")
        }
    }

    @Test("Exit 1: graph.json trace_id mismatches manifest")
    func graphTraceIdMismatch() throws {
        let dir = try buildValidBundle(graphOverrides: { graph in
            // Replace trace with one carrying a different id.
            let mismatchTrace = Trace(
                id: "DIFFERENT-trace-id",
                title: graph.trace.title,
                anchorEventId: graph.trace.anchorEventId,
                rootEntityId: graph.trace.rootEntityId,
                severity: graph.trace.severity,
                confidence: graph.trace.confidence,
                createdAt: graph.trace.createdAt,
                updatedAt: graph.trace.updatedAt,
                daemonVersion: graph.trace.daemonVersion,
                rulesetVersion: graph.trace.rulesetVersion,
                policyId: graph.trace.policyId,
                policyVersion: graph.trace.policyVersion,
                policySha256: graph.trace.policySha256,
                policySnapshotJson: graph.trace.policySnapshotJson,
                traceSigningKeyMode: graph.trace.traceSigningKeyMode,
                replayScope: graph.trace.replayScope,
                attributionOverridePolicy: graph.trace.attributionOverridePolicy
            )
            graph = GraphArtifact(
                trace: mismatchTrace,
                entities: graph.entities,
                edges: graph.edges,
                memberships: graph.memberships,
                rootCauseEntityId: graph.rootCauseEntityId,
                anchorEntityId: graph.anchorEntityId
            )
        })
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
    }

    @Test("Exit 1: graph.json edge references unknown entity")
    func edgeReferencesUnknown() throws {
        let dir = try buildValidBundle(graphOverrides: { graph in
            let badEdge = TraceEdge(
                id: "bad-edge",
                sourceEntityId: "process:nonexistent",
                targetEntityId: graph.anchorEntityId,
                relation: "spawned",
                firstSeen: graph.trace.createdAt,
                lastSeen: graph.trace.createdAt,
                confidence: 0.5,
                confidenceTier: "weak_inferred",
                evidenceJson: "{}",
                eventIdsJson: "[]"
            )
            graph = GraphArtifact(
                trace: graph.trace,
                entities: graph.entities,
                edges: graph.edges + [badEdge],
                memberships: graph.memberships,
                rootCauseEntityId: graph.rootCauseEntityId,
                anchorEntityId: graph.anchorEntityId
            )
        })
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
    }

    @Test("Exit 1: events.jsonl contains an invalid line")
    func eventsJsonlInvalid() throws {
        let dir = try buildValidBundle(eventsLines: [
            #"{"id":"ev-1","ts":1700000000}"#,
            "this is not json",
        ])
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
    }

    @Test("Exit 1: signature merkle root does not match hash_chain merkle root")
    func merkleMismatch() throws {
        let dir = try buildValidBundle(sigMerkleOverride: "DIFFERENT_ROOT")
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
    }

    @Test("Exit 1: signature key mode does not match manifest claim")
    func signingKeyModeMismatch() throws {
        let dir = try buildValidBundle(sigKeyModeOverride: "secure_enclave")
        defer { cleanup(dir) }
        // This produces a bundle where the manifest's
        // trace_signing_key_mode is filesystem_degraded (default)
        // but the signature carries secure_enclave. Cross-check fails.
        // Need to override only the signature side, not the manifest.
        let sigPath = dir.appendingPathComponent("integrity/chain_head_signature.json")
        let sigData = try Data(contentsOf: sigPath)
        var sig = try canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: sigData)
        // Reconstruct the artifact with a mismatched mode.
        sig = ChainHeadSignatureArtifact(
            merkleRoot: sig.merkleRoot,
            signatureBase64: sig.signatureBase64,
            signingKeyMode: "secure_enclave",   // mismatch (manifest says filesystem_degraded)
            signingKeyFingerprint: sig.signingKeyFingerprint,
            signedAt: sig.signedAt
        )
        try canonicalJSONEncoder().encode(sig).write(to: sigPath)
        // Also revert the manifest's mode if buildValidBundle propagated the override;
        // re-read the manifest to confirm.
        let manifestData = try Data(contentsOf: dir.appendingPathComponent("manifest.json"))
        let manifest = try canonicalJSONDecoder().decode(BundleManifest.self, from: manifestData)
        if manifest.traceSigningKeyMode != "filesystem_degraded" {
            // Force the manifest to filesystem_degraded so the cross-check fails predictably.
            let fixed = BundleManifest(
                format: manifest.format,
                maccrabVersion: manifest.maccrabVersion,
                rulesetVersion: manifest.rulesetVersion,
                normalizationVersion: manifest.normalizationVersion,
                createdAt: manifest.createdAt,
                hostRedacted: manifest.hostRedacted,
                traceId: manifest.traceId,
                title: manifest.title,
                severity: manifest.severity,
                confidence: manifest.confidence,
                provCompliant: manifest.provCompliant,
                otelAligned: manifest.otelAligned,
                otelConventionVersion: manifest.otelConventionVersion,
                processIdentityVersion: manifest.processIdentityVersion,
                traceSigningKeyMode: "filesystem_degraded",
                replayScope: manifest.replayScope,
                attributionOverridePolicy: manifest.attributionOverridePolicy
            )
            try canonicalJSONEncoder().encode(fixed).write(to: dir.appendingPathComponent("manifest.json"))
        }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 1)
    }

    @Test("Exit 7: redaction policy violation when host_redacted=true but /Users/<name>/ leaks through")
    func redactionViolation() throws {
        let dir = try buildValidBundle(eventsLines: [
            #"{"id":"ev-1","path":"/Users/alice/Downloads/foo"}"#,
        ])
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 7)
    }

    @Test("Redaction check is skipped when host_redacted=false")
    func redactionSkippedWhenHostNotRedacted() throws {
        let dir = try buildValidBundle(
            manifestOverrides: { manifest in
                manifest = BundleManifest(
                    format: manifest.format,
                    maccrabVersion: manifest.maccrabVersion,
                    rulesetVersion: manifest.rulesetVersion,
                    normalizationVersion: manifest.normalizationVersion,
                    createdAt: manifest.createdAt,
                    hostRedacted: false,
                    traceId: manifest.traceId,
                    title: manifest.title,
                    severity: manifest.severity,
                    confidence: manifest.confidence,
                    provCompliant: manifest.provCompliant,
                    otelAligned: manifest.otelAligned,
                    otelConventionVersion: manifest.otelConventionVersion,
                    processIdentityVersion: manifest.processIdentityVersion,
                    traceSigningKeyMode: manifest.traceSigningKeyMode,
                    replayScope: manifest.replayScope,
                    attributionOverridePolicy: manifest.attributionOverridePolicy
                )
            },
            eventsLines: [#"{"id":"ev-1","path":"/Users/alice/Downloads/foo"}"#]
        )
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 0)
    }

    @Test("Exit 10: prov_compliant=true but prov.jsonld is invalid JSON")
    func provInvalidJson() throws {
        let dir = try buildValidBundle(provJsonOverride: "{not valid json")
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 10)
    }

    @Test("Exit 10: prov_compliant=true but no recognizable PROV-O context or types")
    func provMissingContext() throws {
        let dir = try buildValidBundle(provJsonOverride: #"{"hello":"world"}"#)
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 10)
    }

    @Test("Exit 10: otel_aligned=true but missing resourceSpans")
    func otelMissingResourceSpans() throws {
        let dir = try buildValidBundle(otelJsonOverride: #"{"empty":true}"#)
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 10)
    }

    @Test("Exit 10: otel_aligned=true but missing otel.semconv.version attribute")
    func otelMissingSemconv() throws {
        let dir = try buildValidBundle(otelJsonOverride: #"{"resourceSpans":[{"resource":{"attributes":[]},"scopeSpans":[]}]}"#)
        defer { cleanup(dir) }
        let outcome = BundleValidator.validate(at: dir)
        #expect(outcome.exitCode == 10)
    }

    @Test("Format major version parsing handles edge cases")
    func formatMajorVersionParsing() {
        #expect(BundleManifest.formatMajorVersion(of: "maccrab.tracebundle.v1") == 1)
        #expect(BundleManifest.formatMajorVersion(of: "maccrab.tracebundle.v1.2") == 1)
        #expect(BundleManifest.formatMajorVersion(of: "maccrab.tracebundle.v2") == 2)
        #expect(BundleManifest.formatMajorVersion(of: "maccrab.tracebundle.v10") == 10)
        #expect(BundleManifest.formatMajorVersion(of: "garbage") == nil)
        #expect(BundleManifest.formatMajorVersion(of: "maccrab.tracebundle.vBAD") == nil)
    }
}
