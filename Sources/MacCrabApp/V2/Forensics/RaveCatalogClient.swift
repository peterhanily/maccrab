// RaveCatalogClient.swift
//
// rc.7 — dashboard-side fetch + Ed25519-verify of the rave
// plugin catalog at maccrab.com/rave/. Mirrors the maccrabctl
// PluginCatalogFetch path the parallel rave session wired in:
//   1. GET <base>/catalog.json + .sig
//   2. Verify against bundled catalog.pub
//   3. Return parsed plugin list
//
// Install action stays in the CLI side for now; the dashboard
// is browse-only in rc.7. Click-through "Install" copies the
// matching `maccrabctl plugin install <plugin-id>` command to
// the clipboard with a hint, until the in-dashboard install
// flow lands in v1.18.

import Foundation
import CryptoKit

public struct RaveCatalogEntry: Identifiable, Hashable, Sendable {
    public let id: String           // plugin id, e.g. com.maccrab.hosts-collector
    public let currentVersion: String
    public let channel: String      // "official" / "contrib"
    public let trustTier: String    // "first-party" / "verified-community" / "unverified"
    public let signerIdentity: String
    public let category: String?
    public let tags: [String]
    public let minMaccrabVersion: String?
}

public enum RaveCatalogError: Error, CustomStringConvertible {
    case noBaseURL
    case noCatalogKey
    case fetchFailed(url: URL, status: Int)
    case signatureMismatch
    case parseFailed(reason: String)

    public var description: String {
        switch self {
        case .noBaseURL:            return "No catalog base URL configured (MACCRAB_RAVE_BASE_URL or default)."
        case .noCatalogKey:         return "Bundled catalog signing key (catalog.pub) is missing."
        case .fetchFailed(let url, let s): return "HTTP \(s) fetching \(url.absoluteString)"
        case .signatureMismatch:    return "Catalog signature does not verify against the bundled key. The catalog may be corrupted or the signing key has rotated."
        case .parseFailed(let r):   return "Catalog parse failed: \(r)"
        }
    }
}

public actor RaveCatalogClient {

    public init() {}

    /// Default base — maccrab.com/rave/, can be overridden by
    /// MACCRAB_RAVE_BASE_URL for staging / local-rehearsal use.
    public var baseURL: URL {
        let env = ProcessInfo.processInfo.environment["MACCRAB_RAVE_BASE_URL"]
        let raw = env ?? "https://maccrab.com/rave/"
        let trimmed = raw.hasSuffix("/") ? raw : raw + "/"
        return URL(string: trimmed) ?? URL(string: "https://maccrab.com/rave/")!
    }

    /// Fetch + verify + parse the catalog index.
    public func fetchEntries() async throws -> [RaveCatalogEntry] {
        let key = try loadCatalogPublicKey()
        let base = baseURL
        let catalogURL = base.appendingPathComponent("catalog.json")
        let sigURL = base.appendingPathComponent("catalog.json.sig")

        async let dataF = fetch(url: catalogURL)
        async let sigF = fetch(url: sigURL)
        let data = try await dataF
        let sig = try await sigF
        guard key.isValidSignature(sig, for: data) else {
            throw RaveCatalogError.signatureMismatch
        }
        return try parseCatalog(data: data)
    }

    private func fetch(url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse else {
            throw RaveCatalogError.fetchFailed(url: url, status: -1)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw RaveCatalogError.fetchFailed(url: url, status: http.statusCode)
        }
        return data
    }

    private func loadCatalogPublicKey() throws -> Curve25519.Signing.PublicKey {
        // Local-dev override.
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_CATALOG_PUB_PATH"], !path.isEmpty,
           let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           data.count == 32,
           let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) {
            return key
        }
        // Bundle key — shipped via Sources/MacCrabApp/Resources/rave-keys/catalog.pub
        let candidates: [URL?] = [
            Bundle.main.url(forResource: "catalog", withExtension: "pub"),
            Bundle.main.resourceURL?
                .appendingPathComponent("MacCrab_MacCrabApp.bundle")
                .appendingPathComponent("catalog.pub"),
            Bundle.main.resourceURL?
                .appendingPathComponent("rave-keys")
                .appendingPathComponent("catalog.pub"),
        ]
        for url in candidates.compactMap({ $0 }) {
            guard let data = try? Data(contentsOf: url), data.count == 32 else { continue }
            if let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) {
                return key
            }
        }
        throw RaveCatalogError.noCatalogKey
    }

    private func parseCatalog(data: Data) throws -> [RaveCatalogEntry] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let plugins = json["plugins"] as? [String: [String: Any]] else {
            throw RaveCatalogError.parseFailed(reason: "missing top-level plugins map")
        }
        var entries: [RaveCatalogEntry] = []
        for (id, raw) in plugins {
            guard let current = raw["current_version"] as? String else { continue }
            let metadata = (raw["metadata"] as? [String: Any]) ?? [:]
            entries.append(RaveCatalogEntry(
                id: id,
                currentVersion: current,
                channel: (raw["channel"] as? String) ?? "official",
                trustTier: (raw["trust_tier"] as? String) ?? "unverified",
                signerIdentity: (raw["signer_identity"] as? String) ?? "",
                category: metadata["category"] as? String,
                tags: (metadata["tags"] as? [String]) ?? [],
                minMaccrabVersion: metadata["min_maccrab_version"] as? String
            ))
        }
        return entries.sorted { $0.id < $1.id }
    }
}
