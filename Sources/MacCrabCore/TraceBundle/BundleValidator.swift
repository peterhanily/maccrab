// BundleValidator.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10a) — directory-based validator for the
// .maccrabtrace bundle format. Implements the stable exit-code
// contract from §18.9.
//
// Validation contract:
//
//   exit 0  — valid
//   exit 1  — schema invalid
//   exit 2  — hash-chain invalid (deferred to BundleVerifier in PR-10c)
//   exit 3  — signature invalid (deferred)
//   exit 4  — unified-log anchor missing (deferred)
//   exit 5  — incompatible bundle major version
//   exit 6  — replay or normalization version incompatible
//   exit 7  — redaction policy violation
//   exit 8  — bundle archive malformed (caller's responsibility)
//   exit 9  — internal validation error
//   exit 10 — manifest claim does not match artifact content
//   exit 11 — replay scope exceeded (replay-side, not validate-side)
//
// PR-10a covers exits 1, 5, 7, 9, 10 (the validator's domain).
// Exits 2/3/4 belong to the verifier in PR-10c. Exit 8 is the
// archive layer (the caller extracted the .tar.gz and now points
// us at a directory). Exit 11 is the replay engine (PR-11).

import Foundation

public enum BundleValidator {

    // MARK: - Result

    public struct Outcome: Sendable, Equatable {
        public let exitCode: Int32
        public let kind: Kind
        public let messages: [String]

        public init(exitCode: Int32, kind: Kind, messages: [String] = []) {
            self.exitCode = exitCode
            self.kind = kind
            self.messages = messages
        }

        public var isValid: Bool { exitCode == 0 }
    }

    public enum Kind: Sendable, Equatable {
        case valid
        case schemaInvalid(String)              // exit 1
        case incompatibleMajorVersion(found: String, supported: String)  // exit 5
        case redactionPolicyViolation(String)   // exit 7
        case internalError(String)              // exit 9
        case manifestClaimMismatch(String)      // exit 10
    }

    // MARK: - Required artifacts (§18.1)

    private static let requiredArtifactPaths: [String] = [
        "manifest.json",
        "graph.json",
        "events.jsonl",
        "replay/replay_manifest.json",
        "integrity/hash_chain.json",
        "integrity/chain_head_signature.json",
        "prov/prov.jsonld",
        "otel/spans.json",
    ]

    private static let supportedMajorVersion = 1

    // MARK: - Public entry point

    public static func validate(at directory: URL) -> Outcome {
        // Step 1: structural — directory exists and contains required artifacts
        if let result = validateStructure(at: directory) {
            return result
        }

        // Step 2: parse manifest
        let manifestURL = directory.appendingPathComponent("manifest.json")
        let manifest: BundleManifest
        do {
            let data = try Data(contentsOf: manifestURL)
            manifest = try canonicalJSONDecoder().decode(BundleManifest.self, from: data)
        } catch {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("manifest.json failed to decode: \(error)"),
                messages: ["manifest.json: \(error)"]
            )
        }

        // Step 3: format major-version check (exit 5)
        guard let major = manifest.formatMajorVersion else {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("manifest.format is malformed: \(manifest.format)")
            )
        }
        if major > supportedMajorVersion {
            return Outcome(
                exitCode: 5,
                kind: .incompatibleMajorVersion(
                    found: manifest.format,
                    supported: BundleManifest.currentFormat
                ),
                messages: ["unknown bundle major version: \(manifest.format)"]
            )
        }

        // Step 4: parse graph.json
        if let result = validateGraph(at: directory, manifest: manifest) { return result }

        // Step 5: parse events.jsonl (line-delimited JSON)
        if let result = validateEventsJsonl(at: directory) { return result }

        // Step 6: parse replay manifest
        if let result = validateReplayManifest(at: directory) { return result }

        // Step 7: parse integrity artifacts (structural only — Merkle
        // verification is in BundleVerifier / PR-10c)
        if let result = validateIntegrityArtifacts(at: directory, manifest: manifest) { return result }

        // Step 8: redaction policy check (basic)
        if let result = validateRedactionPolicy(at: directory, manifest: manifest) { return result }

        // Step 9: manifest-claim verification (exit 10)
        if manifest.provCompliant {
            if let result = validateProvOClaim(at: directory) { return result }
        }
        if manifest.otelAligned {
            if let result = validateOtelClaim(at: directory) { return result }
        }

        // All checks passed.
        return Outcome(exitCode: 0, kind: .valid)
    }

    // MARK: - Step helpers

    private static func validateStructure(at directory: URL) -> Outcome? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDir) else {
            return Outcome(
                exitCode: 9,
                kind: .internalError("directory does not exist: \(directory.path)")
            )
        }
        guard isDir.boolValue else {
            return Outcome(
                exitCode: 9,
                kind: .internalError("path is not a directory: \(directory.path)")
            )
        }
        for path in requiredArtifactPaths {
            let url = directory.appendingPathComponent(path)
            if !FileManager.default.fileExists(atPath: url.path) {
                return Outcome(
                    exitCode: 1,
                    kind: .schemaInvalid("required artifact missing: \(path)")
                )
            }
        }
        return nil
    }

    private static func validateGraph(at directory: URL, manifest: BundleManifest) -> Outcome? {
        let url = directory.appendingPathComponent("graph.json")
        do {
            let data = try Data(contentsOf: url)
            let graph = try canonicalJSONDecoder().decode(GraphArtifact.self, from: data)
            if graph.trace.id != manifest.traceId {
                return Outcome(
                    exitCode: 1,
                    kind: .schemaInvalid(
                        "graph.json trace.id (\(graph.trace.id)) does not match manifest.trace_id (\(manifest.traceId))"
                    )
                )
            }
            // Spot-check: anchor entity must exist in the entities list.
            let entityIds = Set(graph.entities.map { $0.id })
            if !entityIds.contains(graph.anchorEntityId) {
                return Outcome(
                    exitCode: 1,
                    kind: .schemaInvalid(
                        "graph.json anchorEntityId (\(graph.anchorEntityId)) missing from entities[]"
                    )
                )
            }
            // Edges must reference existing entities.
            for edge in graph.edges {
                if !entityIds.contains(edge.sourceEntityId) || !entityIds.contains(edge.targetEntityId) {
                    return Outcome(
                        exitCode: 1,
                        kind: .schemaInvalid(
                            "graph.json edge \(edge.id) references unknown entity (source=\(edge.sourceEntityId) target=\(edge.targetEntityId))"
                        )
                    )
                }
            }
            return nil
        } catch {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("graph.json failed to decode: \(error)")
            )
        }
    }

    private static func validateEventsJsonl(at directory: URL) -> Outcome? {
        let url = directory.appendingPathComponent("events.jsonl")
        do {
            let data = try Data(contentsOf: url)
            guard let text = String(data: data, encoding: .utf8) else {
                return Outcome(exitCode: 1, kind: .schemaInvalid("events.jsonl is not valid UTF-8"))
            }
            // Each non-empty line must be a valid JSON object.
            let lines = text.split(omittingEmptySubsequences: true, whereSeparator: { $0.isNewline })
            for (index, line) in lines.enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.isEmpty { continue }
                guard let lineData = trimmed.data(using: .utf8) else {
                    return Outcome(
                        exitCode: 1,
                        kind: .schemaInvalid("events.jsonl line \(index + 1) is not valid UTF-8")
                    )
                }
                do {
                    _ = try JSONSerialization.jsonObject(with: lineData, options: [])
                } catch {
                    return Outcome(
                        exitCode: 1,
                        kind: .schemaInvalid("events.jsonl line \(index + 1): invalid JSON: \(error)")
                    )
                }
            }
            return nil
        } catch {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("events.jsonl could not be read: \(error)")
            )
        }
    }

    private static func validateReplayManifest(at directory: URL) -> Outcome? {
        let url = directory.appendingPathComponent("replay/replay_manifest.json")
        do {
            let data = try Data(contentsOf: url)
            _ = try canonicalJSONDecoder().decode(ReplayManifestArtifact.self, from: data)
            return nil
        } catch {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("replay/replay_manifest.json failed to decode: \(error)")
            )
        }
    }

    private static func validateIntegrityArtifacts(
        at directory: URL,
        manifest: BundleManifest
    ) -> Outcome? {
        // hash_chain.json
        let chainURL = directory.appendingPathComponent("integrity/hash_chain.json")
        let chain: HashChainArtifact
        do {
            let data = try Data(contentsOf: chainURL)
            chain = try canonicalJSONDecoder().decode(HashChainArtifact.self, from: data)
        } catch {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("integrity/hash_chain.json failed to decode: \(error)")
            )
        }

        // chain_head_signature.json
        let sigURL = directory.appendingPathComponent("integrity/chain_head_signature.json")
        let signature: ChainHeadSignatureArtifact
        do {
            let data = try Data(contentsOf: sigURL)
            signature = try canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: data)
        } catch {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid("integrity/chain_head_signature.json failed to decode: \(error)")
            )
        }

        // Cross-check: signature.merkleRoot == chain.merkleRoot
        if signature.merkleRoot != chain.merkleRoot {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid(
                    "chain_head_signature.merkleRoot does not match hash_chain.merkleRoot"
                )
            )
        }

        // Cross-check: signature.signingKeyMode matches manifest claim
        if signature.signingKeyMode != manifest.traceSigningKeyMode {
            return Outcome(
                exitCode: 1,
                kind: .schemaInvalid(
                    "chain_head_signature.signingKeyMode (\(signature.signingKeyMode)) does not match manifest.trace_signing_key_mode (\(manifest.traceSigningKeyMode))"
                )
            )
        }

        return nil
    }

    private static func validateRedactionPolicy(
        at directory: URL,
        manifest: BundleManifest
    ) -> Outcome? {
        // PR-10a baseline check: when manifest claims `host_redacted: true`,
        // the events.jsonl payloads must not contain the local hostname.
        // We can't know the local hostname inside the validator (it might
        // be running on a different machine), so we instead spot-check
        // for obvious markers like /Users/<name>/ patterns where the
        // user has not been redacted.
        guard manifest.hostRedacted else { return nil }
        let url = directory.appendingPathComponent("events.jsonl")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        // §18.4 redacts user paths to ~/...
        // A residual /Users/<actual_name>/ in the bundle is a violation.
        // The redacted form has /Users/[REDACTED]/ or ~/...
        let pattern = #"/Users/(?!\[REDACTED\])[A-Za-z0-9_-]+/"#
        if let regex = try? NSRegularExpression(pattern: pattern),
           regex.firstMatch(
               in: text,
               range: NSRange(text.startIndex..., in: text)
           ) != nil {
            return Outcome(
                exitCode: 7,
                kind: .redactionPolicyViolation(
                    "events.jsonl contains unredacted /Users/<name>/ paths despite manifest.host_redacted=true"
                )
            )
        }
        return nil
    }

    /// Manifest-claim verification for PROV-O. Per §18.9 exit 10:
    /// when manifest.prov_compliant is true, the artifact must
    /// exist as valid JSON-LD with a recognizable PROV-O context
    /// and at least one prov:Activity, prov:Entity, or prov:Agent.
    private static func validateProvOClaim(at directory: URL) -> Outcome? {
        let url = directory.appendingPathComponent("prov/prov.jsonld")
        guard let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data, options: []) else {
            return Outcome(
                exitCode: 10,
                kind: .manifestClaimMismatch(
                    "manifest.prov_compliant=true but prov/prov.jsonld is not valid JSON"
                )
            )
        }
        // PROV-O JSON-LD has either "@context" pointing at a PROV
        // context or @type tags using "prov:" prefix.
        guard let dict = json as? [String: Any] else {
            return Outcome(
                exitCode: 10,
                kind: .manifestClaimMismatch(
                    "prov/prov.jsonld root is not a JSON object"
                )
            )
        }
        let contextHasProv = (dict["@context"] as? String)?.contains("prov") ?? false
            || (dict["@context"] as? [String: Any])?.values.contains(where: {
                ($0 as? String)?.contains("prov") ?? false
            }) ?? false
        let graph = (dict["@graph"] as? [[String: Any]]) ?? []
        let hasProvType = graph.contains { item in
            if let type = item["@type"] as? String {
                return type.contains("prov:") || type.contains("Activity") || type.contains("Entity") || type.contains("Agent")
            }
            if let types = item["@type"] as? [String] {
                return types.contains { $0.contains("prov:") }
            }
            return false
        }
        if !contextHasProv && !hasProvType {
            return Outcome(
                exitCode: 10,
                kind: .manifestClaimMismatch(
                    "prov/prov.jsonld has no recognizable PROV-O context or types"
                )
            )
        }
        return nil
    }

    /// Manifest-claim verification for OTel. Per §18.9 exit 10: when
    /// manifest.otel_aligned is true, the artifact must be valid
    /// JSON in the OTel `resourceSpans` shape and carry an
    /// `otel.semconv.version` resource attribute.
    private static func validateOtelClaim(at directory: URL) -> Outcome? {
        let url = directory.appendingPathComponent("otel/spans.json")
        guard let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data, options: []),
              let dict = json as? [String: Any] else {
            return Outcome(
                exitCode: 10,
                kind: .manifestClaimMismatch(
                    "manifest.otel_aligned=true but otel/spans.json is not valid JSON"
                )
            )
        }
        guard let resourceSpans = dict["resourceSpans"] as? [[String: Any]], !resourceSpans.isEmpty else {
            return Outcome(
                exitCode: 10,
                kind: .manifestClaimMismatch(
                    "otel/spans.json missing resourceSpans[] (OTLP JSON shape)"
                )
            )
        }
        // Look for otel.semconv.version somewhere in the resource attributes.
        let semconvFound = resourceSpans.contains { rs in
            guard let resource = rs["resource"] as? [String: Any] else { return false }
            guard let attrs = resource["attributes"] as? [[String: Any]] else { return false }
            return attrs.contains { kv in
                let key = (kv["key"] as? String) ?? ""
                return key == "otel.semconv.version"
            }
        }
        if !semconvFound {
            return Outcome(
                exitCode: 10,
                kind: .manifestClaimMismatch(
                    "otel/spans.json missing otel.semconv.version resource attribute"
                )
            )
        }
        return nil
    }
}
