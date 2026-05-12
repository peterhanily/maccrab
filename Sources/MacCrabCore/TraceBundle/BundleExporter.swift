// BundleExporter.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10b) — turns a materialized `Trace` plus its
// graph contents into a `.maccrabtrace` directory tree validatable by
// `BundleValidator`.
//
// Pipeline:
//   1. Materialize the manifest, graph artifact, replay manifest,
//      attribution split, PROV-O JSON-LD, OTel spans, events.jsonl,
//      and integrity skeleton.
//   2. Apply the redaction sweep over text artifacts.
//   3. Compute SHA-256 over each file in canonical sorted-path order.
//   4. Build the Merkle root over the artifact hashes.
//   5. Write `integrity/hash_chain.json` and a placeholder
//      `integrity/chain_head_signature.json`.
//   6. Caller can subsequently sign the Merkle root via TrustSubstrate
//      (PR-10c) and replace the placeholder signature.
//
// Tar-gz packaging is the caller's job — `maccrabctl trace export`
// (PR-9) wraps the directory in `tar.gz` after this exporter returns.

import Foundation
import CryptoKit

public actor BundleExporter {

    // MARK: - Errors

    public enum ExportError: Error, LocalizedError {
        case directoryAlreadyExists(URL)
        case writeFailed(String)
        case encodeFailed(String)

        public var errorDescription: String? {
            switch self {
            case .directoryAlreadyExists(let u): return "BundleExporter: directory already exists: \(u.path)"
            case .writeFailed(let m):           return "BundleExporter: write failed: \(m)"
            case .encodeFailed(let m):          return "BundleExporter: encode failed: \(m)"
            }
        }
    }

    // MARK: - Inputs

    public struct Inputs: Sendable {
        public let trace: Trace
        public let entities: [TraceEntity]
        public let edges: [TraceEdge]
        public let memberships: [TraceMembership]
        public let eventsJsonl: [String]                    // pre-sanitized JSON lines
        public let machineAttributions: [MachineAttributionArtifact.MachineAttribution]
        public let humanOverrides: [HumanOverridesArtifact.Verdict]
        public let policySnapshotJson: String
        public let otelConventionVersion: String
        public let matchedRules: MatchedRulesArtifact

        public init(
            trace: Trace,
            entities: [TraceEntity],
            edges: [TraceEdge],
            memberships: [TraceMembership],
            eventsJsonl: [String] = [],
            machineAttributions: [MachineAttributionArtifact.MachineAttribution] = [],
            humanOverrides: [HumanOverridesArtifact.Verdict] = [],
            policySnapshotJson: String = "{}",
            otelConventionVersion: String = "gen_ai_mcp_current_at_build",
            matchedRules: MatchedRulesArtifact = MatchedRulesArtifact(rules: [])
        ) {
            self.trace = trace
            self.entities = entities
            self.edges = edges
            self.memberships = memberships
            self.eventsJsonl = eventsJsonl
            self.machineAttributions = machineAttributions
            self.humanOverrides = humanOverrides
            self.policySnapshotJson = policySnapshotJson
            self.otelConventionVersion = otelConventionVersion
            self.matchedRules = matchedRules
        }
    }

    public struct Options: Sendable {
        public var includeRawPaths: Bool = false
        public var includeHostname: Bool = false
        public var includeLLMSummary: Bool = false
        public var rootEntityId: String?
        public var anchorEntityId: String?
        public var title: String?
        public var severity: String?
        public var maccrabVersion: String = MacCrabVersion.current

        public init() {}
    }

    private let redactor: BundleRedactor
    private let trustSubstrate: TrustSubstrate?
    private let unifiedLogAnchor: UnifiedLogAnchor?

    public init(
        redactor: BundleRedactor = .systemDefault(),
        trustSubstrate: TrustSubstrate? = nil,
        unifiedLogAnchor: UnifiedLogAnchor? = nil
    ) {
        self.redactor = redactor
        self.trustSubstrate = trustSubstrate
        self.unifiedLogAnchor = unifiedLogAnchor
    }

    // MARK: - Export

    @discardableResult
    public func export(
        inputs: Inputs,
        to bundleRoot: URL,
        options: Options = Options()
    ) async throws -> URL {
        if FileManager.default.fileExists(atPath: bundleRoot.path) {
            throw ExportError.directoryAlreadyExists(bundleRoot)
        }

        try createSkeleton(at: bundleRoot)

        let anchor = options.anchorEntityId
            ?? inputs.memberships.first(where: { $0.role == "anchor" })?.entityId
            ?? inputs.trace.anchorEventId
        let root = options.rootEntityId
            ?? inputs.trace.rootEntityId
            ?? anchor

        let manifest = buildManifest(
            inputs: inputs,
            options: options
        )

        let encoder = canonicalJSONEncoder()
        let manifestData = try encoder.encode(manifest)
        try manifestData.write(to: bundleRoot.appendingPathComponent("manifest.json"))

        // graph.json
        let graph = GraphArtifact(
            trace: inputs.trace,
            entities: inputs.entities,
            edges: inputs.edges,
            memberships: inputs.memberships,
            rootCauseEntityId: root,
            anchorEntityId: anchor
        )
        try encoder.encode(graph).write(to: bundleRoot.appendingPathComponent("graph.json"))

        // events.jsonl
        try writeEventsJsonl(inputs.eventsJsonl, to: bundleRoot.appendingPathComponent("events.jsonl"))

        // replay/replay_manifest.json
        let replay = ReplayManifestArtifact(
            daemonVersion: options.maccrabVersion,
            rulesetVersion: inputs.trace.rulesetVersion,
            normalizationVersion: manifest.normalizationVersion,
            replayScope: inputs.trace.replayScope,
            policySnapshotJson: inputs.policySnapshotJson
        )
        try encoder.encode(replay).write(to: bundleRoot.appendingPathComponent("replay/replay_manifest.json"))

        // attribution/{machine,human}.json
        try encoder.encode(MachineAttributionArtifact(entries: inputs.machineAttributions))
            .write(to: bundleRoot.appendingPathComponent("attribution/machine_attribution.json"))
        try encoder.encode(HumanOverridesArtifact(verdicts: inputs.humanOverrides))
            .write(to: bundleRoot.appendingPathComponent("attribution/human_overrides.json"))

        // rules/matched_rules.json — drives ReplayEngine's
        // state-requirement check (§17.1.1). Empty when the trace
        // didn't fire any rules (e.g. user-requested traces).
        try encoder.encode(inputs.matchedRules)
            .write(to: bundleRoot.appendingPathComponent("rules/matched_rules.json"))

        // prov/prov.jsonld
        let provData = try ProvOEncoder.encodeToData(
            trace: inputs.trace,
            entities: inputs.entities,
            edges: inputs.edges
        )
        try provData.write(to: bundleRoot.appendingPathComponent("prov/prov.jsonld"))

        // otel/spans.json
        let otelData = try OtelEncoder.encodeToData(
            trace: inputs.trace,
            entities: inputs.entities,
            edges: inputs.edges,
            otelConventionVersion: inputs.otelConventionVersion
        )
        try otelData.write(to: bundleRoot.appendingPathComponent("otel/spans.json"))

        // baseline (placeholder)
        try "reset".write(
            to: bundleRoot.appendingPathComponent("baseline/baseline_mode.txt"),
            atomically: true, encoding: .utf8
        )
        try "{\"mode\":\"reset\"}".write(
            to: bundleRoot.appendingPathComponent("baseline/baseline_snapshot.json"),
            atomically: true, encoding: .utf8
        )

        // 2. Redaction sweep — applies before integrity hashing so the
        // hash chain commits to the redacted bytes.
        let activeRedactor = redactorFor(options: options)
        try activeRedactor.redactDirectory(bundleRoot)

        // 3-5. Integrity: per-artifact SHA-256 → Merkle root → write artifacts.
        // Use the shared BundleMerkle helper so the verifier recomputes
        // an identical canonical reduction.
        let computation = try BundleMerkle.compute(forBundleAt: bundleRoot)
        let chain = HashChainArtifact(
            artifacts: computation.artifacts,
            merkleRoot: computation.merkleRoot
        )
        try encoder.encode(chain).write(to: bundleRoot.appendingPathComponent("integrity/hash_chain.json"))

        // Real signature when a TrustSubstrate is wired; UNSIGNED placeholder otherwise.
        let signedAt = Date()
        let signatureArtifact: ChainHeadSignatureArtifact
        if let trustSubstrate {
            let payload = Data(computation.merkleRoot.utf8)
            let sigBytes = try await trustSubstrate.sign(payload)
            let publicKey = try await trustSubstrate.publicKey()
            // Bundle the public key DER so verifiers are self-contained.
            try publicKey.derBytes.write(to: bundleRoot.appendingPathComponent("integrity/trace-signing.pub"))
            // Manifest's signing key mode must reflect the actual mode used.
            let actualMode = try await trustSubstrate.activeMode()
            let modeString = actualMode.rawValue
            // If the manifest claimed a different mode, rewrite manifest
            // to keep the cross-check honest.
            let manifestPath = bundleRoot.appendingPathComponent("manifest.json")
            if manifest.traceSigningKeyMode != modeString {
                let updated = BundleManifest(
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
                    traceSigningKeyMode: modeString,
                    replayScope: manifest.replayScope,
                    attributionOverridePolicy: manifest.attributionOverridePolicy
                )
                try encoder.encode(updated).write(to: manifestPath)
                // Recompute the Merkle root since manifest.json content changed.
                let recomputed = try BundleMerkle.compute(forBundleAt: bundleRoot)
                let updatedChain = HashChainArtifact(
                    artifacts: recomputed.artifacts,
                    merkleRoot: recomputed.merkleRoot
                )
                try encoder.encode(updatedChain).write(
                    to: bundleRoot.appendingPathComponent("integrity/hash_chain.json")
                )
                let updatedPayload = Data(recomputed.merkleRoot.utf8)
                let updatedSig = try await trustSubstrate.sign(updatedPayload)
                signatureArtifact = ChainHeadSignatureArtifact(
                    merkleRoot: recomputed.merkleRoot,
                    signatureBase64: updatedSig.base64EncodedString(),
                    signingKeyMode: modeString,
                    signingKeyFingerprint: publicKey.fingerprint,
                    signedAt: signedAt
                )
            } else {
                signatureArtifact = ChainHeadSignatureArtifact(
                    merkleRoot: computation.merkleRoot,
                    signatureBase64: sigBytes.base64EncodedString(),
                    signingKeyMode: modeString,
                    signingKeyFingerprint: publicKey.fingerprint,
                    signedAt: signedAt
                )
            }
        } else {
            // UNSIGNED placeholder — produces a bundle that passes
            // BundleValidator structurally but is correctly rejected
            // with exit 3 by BundleVerifier.
            signatureArtifact = ChainHeadSignatureArtifact(
                merkleRoot: computation.merkleRoot,
                signatureBase64: "UNSIGNED",
                signingKeyMode: manifest.traceSigningKeyMode,
                signingKeyFingerprint: "PLACEHOLDER",
                signedAt: signedAt
            )
        }
        try encoder.encode(signatureArtifact).write(to: bundleRoot.appendingPathComponent("integrity/chain_head_signature.json"))

        // Outer-archive sha256 placeholder — only meaningful after tar.gz packaging.
        try "PLACEHOLDER\n".write(
            to: bundleRoot.appendingPathComponent("integrity/bundle_sha256.txt"),
            atomically: true, encoding: .utf8
        )

        // Step 6: emit chain head to the unified-log anchor when wired.
        if let unifiedLogAnchor, signatureArtifact.signatureBase64 != "UNSIGNED" {
            let record = UnifiedLogChainHeadRecord(
                merkleRoot: signatureArtifact.merkleRoot,
                signatureBase64: signatureArtifact.signatureBase64,
                signingKeyMode: signatureArtifact.signingKeyMode,
                signingKeyFingerprint: signatureArtifact.signingKeyFingerprint,
                traceId: inputs.trace.id,
                emittedAt: signedAt
            )
            try await unifiedLogAnchor.emit(record)
        }

        return bundleRoot
    }

    // MARK: - Helpers

    private func createSkeleton(at bundleRoot: URL) throws {
        try FileManager.default.createDirectory(at: bundleRoot, withIntermediateDirectories: true)
        let subdirs = ["replay", "integrity", "prov", "otel", "schema", "rules", "evidence", "baseline", "report", "attribution", "llm"]
        for sub in subdirs {
            try FileManager.default.createDirectory(
                at: bundleRoot.appendingPathComponent(sub),
                withIntermediateDirectories: true
            )
        }
    }

    private func buildManifest(inputs: Inputs, options: Options) -> BundleManifest {
        BundleManifest(
            maccrabVersion: options.maccrabVersion,
            rulesetVersion: inputs.trace.rulesetVersion,
            normalizationVersion: "1",
            createdAt: Date(),
            hostRedacted: !options.includeHostname,
            traceId: inputs.trace.id,
            title: options.title ?? inputs.trace.title,
            severity: options.severity ?? inputs.trace.severity,
            confidence: inputs.trace.confidence,
            provCompliant: true,
            otelAligned: true,
            otelConventionVersion: inputs.otelConventionVersion,
            processIdentityVersion: "maccrab.process_identity.v1",
            traceSigningKeyMode: inputs.trace.traceSigningKeyMode,
            replayScope: inputs.trace.replayScope,
            attributionOverridePolicy: inputs.trace.attributionOverridePolicy
        )
    }

    private func writeEventsJsonl(_ lines: [String], to url: URL) throws {
        let body = lines.joined(separator: "\n")
        // Always append a trailing newline so the file is line-correct.
        let withNewline = body.isEmpty ? "" : body + "\n"
        try withNewline.write(to: url, atomically: true, encoding: .utf8)
    }

    private func redactorFor(options: Options) -> BundleRedactor {
        // When the operator opts in to including paths/hostname, swap
        // the redactor for a no-op variant so the bundle preserves
        // those values for forensic investigation.
        if options.includeRawPaths || options.includeHostname {
            return BundleRedactor(
                redactHomePaths: !options.includeRawPaths,
                redactHostname: !options.includeHostname,
                redactPrivateIPs: redactor.redactPrivateIPs,
                hostname: redactor.hostname,
                userName: redactor.userName
            )
        }
        return redactor
    }

    private func buildArtifactHashList(at bundleRoot: URL) throws -> [HashChainArtifact.ArtifactHash] {
        var artifacts: [HashChainArtifact.ArtifactHash] = []
        guard let enumerator = FileManager.default.enumerator(
            at: bundleRoot,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        for case let url as URL in enumerator {
            let resources = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard resources.isRegularFile == true else { continue }
            // Skip integrity/ files that don't exist yet; they're
            // emitted after this list is built. (The enumerator will
            // simply not see them on the first pass.)
            // Skip integrity/hash_chain.json + chain_head_signature.json
            // even if they happen to exist — they're computed FROM this list.
            let relative = relativePath(of: url, under: bundleRoot)
            if relative.hasPrefix("integrity/") {
                continue
            }
            let data = try Data(contentsOf: url)
            let digest = SHA256.hash(data: data)
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            artifacts.append(HashChainArtifact.ArtifactHash(path: relative, sha256: hex))
        }
        // Canonical sorted-path order for the Merkle reduction.
        artifacts.sort { $0.path < $1.path }
        return artifacts
    }

    private func relativePath(of url: URL, under root: URL) -> String {
        let rootPath = root.path.hasSuffix("/") ? root.path : root.path + "/"
        if url.path.hasPrefix(rootPath) {
            return String(url.path.dropFirst(rootPath.count))
        }
        return url.lastPathComponent
    }

    /// Pairwise SHA-256 reduction over the artifact hashes. Single-leaf
    /// trees return the leaf itself; odd levels duplicate the last
    /// element (per the standard Merkle convention used by Bitcoin and
    /// many other protocols).
    private func computeMerkleRoot(_ leaves: [String]) -> String {
        var current = leaves.compactMap { hex -> Data? in
            return Data(hex: hex)
        }
        if current.isEmpty {
            return SHA256.hash(data: Data()).map { String(format: "%02x", $0) }.joined()
        }
        while current.count > 1 {
            var next: [Data] = []
            var i = 0
            while i < current.count {
                let left = current[i]
                let right = (i + 1 < current.count) ? current[i + 1] : current[i]
                let combined = SHA256.hash(data: left + right)
                next.append(Data(combined))
                i += 2
            }
            current = next
        }
        return current[0].map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Hex helper

private extension Data {
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        self = data
    }
}
