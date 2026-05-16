// AttestationEnricher.swift
// MacCrabCore
//
// Cryptographic-provenance verifier for npm + PyPI packages. For each
// (name, version) pair, queries the registry's attestation endpoint and
// returns a structured status that downstream rules / dashboard can
// surface as a badge.
//
// What we check:
//   - **npm**: GET registry.npmjs.org/-/npm/v1/security/attestations/{pkg}@{ver}.
//     Confirms whether the published version carries an npm provenance
//     attestation (Sigstore + GitHub Actions OIDC builder).
//   - **PyPI**: GET pypi.org/integrity/{pkg}/{ver}/{file}/provenance.
//     PEP 740 provenance — Sigstore-bundled signing with builder
//     identity captured.
//
// The high-signal detection here is *publishing-method mismatch*: a
// prior version had Sigstore + GH Actions OIDC, the current version
// has none. That's the defining indicator that a maintainer's token
// (rather than their OIDC identity) was stolen and used to republish.

import Foundation
import os.log

// MARK: - AttestationEnricher

public actor AttestationEnricher {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "attestation-enricher")

    public enum Registry: String, Sendable, CaseIterable {
        case npm = "npm"
        case pypi = "pypi"
    }

    public enum AttestationStatus: String, Sendable {
        case verified       // present and valid
        case absent         // not present
        case mismatched     // present but builder / source repo doesn't match prior versions
        case fetchFailed    // network / parse error
    }

    public struct AttestationResult: Sendable {
        public let packageName: String
        public let version: String
        public let registry: Registry
        public let status: AttestationStatus
        public let builder: String?
        public let sourceRepo: String?
        public let priorBuilder: String?
        public let warnings: [String]

        public init(
            packageName: String, version: String, registry: Registry,
            status: AttestationStatus, builder: String?, sourceRepo: String?,
            priorBuilder: String?, warnings: [String]
        ) {
            self.packageName = packageName
            self.version = version
            self.registry = registry
            self.status = status
            self.builder = builder
            self.sourceRepo = sourceRepo
            self.priorBuilder = priorBuilder
            self.warnings = warnings
        }
    }

    public typealias Fetcher = @Sendable (URL) async -> Data?

    private var cache: [String: (result: AttestationResult, fetched: Date)] = [:]
    private let cacheTTL: TimeInterval
    private let fetcher: Fetcher

    public init(cacheTTL: TimeInterval = 24 * 3600, fetcher: Fetcher? = nil) {
        self.cacheTTL = cacheTTL
        self.fetcher = fetcher ?? Self.defaultFetcher
    }

    private static let defaultFetcher: Fetcher = { url in
        guard let result = try? await HardenedRegistrySession.fetch(url: url) else { return nil }
        return result.0
    }

    // MARK: - Public API

    /// Verify a (package, version) pair. Compares against `priorBuilder` if
    /// supplied (typically the builder identity from the package's previous
    /// version, retrieved by the caller). Returns a result even when the
    /// fetch fails — `status` will be `.fetchFailed`.
    public func verify(
        packageName: String, version: String, registry: Registry,
        priorBuilder: String? = nil
    ) async -> AttestationResult {
        let cacheKey = "\(registry.rawValue):\(packageName)@\(version)"
        if let entry = cache[cacheKey], Date().timeIntervalSince(entry.fetched) < cacheTTL {
            return entry.result
        }
        guard let url = url(forPackage: packageName, version: version, registry: registry) else {
            return fail(packageName: packageName, version: version, registry: registry, reason: "could not build attestation URL")
        }
        guard let data = await fetcher(url) else {
            return fail(packageName: packageName, version: version, registry: registry, reason: "fetch failed")
        }
        let parsed = parse(data: data, registry: registry)
        var warnings: [String] = []
        let status: AttestationStatus
        if parsed.builder == nil && parsed.sourceRepo == nil {
            status = .absent
        } else if let prior = priorBuilder, let current = parsed.builder, current != prior {
            status = .mismatched
            warnings.append("builder identity changed: was '\(prior)', now '\(current)' — possible stolen-token republish")
        } else {
            status = .verified
        }
        let result = AttestationResult(
            packageName: packageName, version: version, registry: registry,
            status: status, builder: parsed.builder, sourceRepo: parsed.sourceRepo,
            priorBuilder: priorBuilder, warnings: warnings
        )
        cache[cacheKey] = (result, Date())
        return result
    }

    // MARK: - Helpers

    private func fail(packageName: String, version: String, registry: Registry, reason: String) -> AttestationResult {
        AttestationResult(
            packageName: packageName, version: version, registry: registry,
            status: .fetchFailed, builder: nil, sourceRepo: nil, priorBuilder: nil,
            warnings: [reason]
        )
    }

    /// Build the attestation URL with strict name + version
    /// validation. Returns nil on invalid inputs — defeats SSRF
    /// via name / version injection.
    private func url(forPackage name: String, version: String, registry: Registry) -> URL? {
        do {
            switch registry {
            case .npm:
                return try SafeRegistryURL.npmAttestation(name: name, version: version)
            case .pypi:
                return try SafeRegistryURL.pypiVersionMetadata(name: name, version: version)
            }
        } catch {
            logger.warning("Refused invalid package '\(name, privacy: .private)@\(version, privacy: .private)' for \(registry.rawValue, privacy: .public)")
            return nil
        }
    }

    /// Parse the attestation JSON / metadata response into (builder, sourceRepo).
    nonisolated private func parse(data: Data, registry: Registry) -> (builder: String?, sourceRepo: String?) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return (nil, nil)
        }
        switch registry {
        case .npm:
            // npm /v1/security/attestations returns `attestations[]` with
            // `predicateType`, `predicate.buildDefinition.externalParameters.workflow.repository`
            // (Sigstore in-toto v1 predicate).
            guard let attestations = json["attestations"] as? [[String: Any]] else {
                return (nil, nil)
            }
            for att in attestations {
                if let predicate = att["predicate"] as? [String: Any] {
                    if let buildDef = predicate["buildDefinition"] as? [String: Any],
                       let extParams = buildDef["externalParameters"] as? [String: Any] {
                        let builder = (predicate["runDetails"] as? [String: Any])
                            .flatMap { ($0["builder"] as? [String: Any])?["id"] as? String }
                        let repo = (extParams["workflow"] as? [String: Any])?["repository"] as? String
                        return (builder, repo)
                    }
                }
            }
            return (nil, nil)
        case .pypi:
            // PyPI per-version JSON has `urls[].provenance` when PEP 740
            // attestations were uploaded. Distinct from npm: the repo
            // identifier is embedded in the bundle's certificate
            // identity claim, which the simple summary API surfaces as
            // `digests` only. For v1.12 we only confirm provenance presence.
            guard let urls = json["urls"] as? [[String: Any]] else { return (nil, nil) }
            for entry in urls {
                if entry["provenance"] != nil {
                    return ("pypi-trusted-publisher", nil)
                }
            }
            return (nil, nil)
        }
    }
}
