// PluginCatalogFetch — HTTP fetch path for `maccrabctl plugin install <plugin-id>`.
//
// Resolves a plugin-id against the maccrab.com/rave/ catalog and downloads the
// signed bundle into a temp dir, then delegates to PluginInstaller for the
// existing verify + install path. The chain is:
//
//   1. GET <base>/catalog.json + .sig → verify against rave catalog Ed25519 key
//   2. Look up plugin entry from index
//   3. GET <base>/catalog/<plugin-id>.json + .sig → verify against same key
//   4. Resolve binary URL from release_url_template (RFC6570 {tag} {file})
//   5. GET binary URL → verify artifact_sha256
//   6. Extract via /usr/bin/unzip into temp dir
//   7. Hand to PluginInstaller.install(sourceDir:) — existing verified path
//
// The catalog public key is the rave project's signing key (the one used to
// sign /rave/catalog.json + /rave/catalog/*.json on the maccrab-site repo).
// Production: hardcoded. Local-dev override: MACCRAB_RAVE_CATALOG_PUB_PATH.
//
// URL rewriting for local testing: MACCRAB_RAVE_URL_REWRITE_FROM +
// MACCRAB_RAVE_URL_REWRITE_TO replace a prefix in release URLs. This lets the
// production catalog's GitHub-Releases URLs be redirected to a localhost
// http.server for the launch-rehearsal flow.

import Foundation
import CryptoKit
import MacCrabForensics

enum PluginCatalogFetchError: Error, CustomStringConvertible {
    case noCatalogPublicKey
    case catalogPublicKeyInvalid(reason: String)
    case httpFetchFailed(url: URL, status: Int)
    case signatureVerifyFailed(url: URL)
    case catalogParseFailed(reason: String)
    case pluginNotInCatalog(id: String)
    case versionNotFound(id: String, version: String)
    case artifactHashMismatch(expected: String, actual: String)
    case unzipFailed(status: Int32)
    case extractedBundleNotFound(extractDir: String)

    var description: String {
        switch self {
        case .noCatalogPublicKey:
            return "No rave catalog public key configured. Set MACCRAB_RAVE_CATALOG_PUB_PATH or rebuild with a bundled key."
        case .catalogPublicKeyInvalid(let reason):
            return "Rave catalog public key invalid: \(reason)"
        case .httpFetchFailed(let url, let status):
            return "HTTP fetch failed: \(url.absoluteString) → HTTP \(status)"
        case .signatureVerifyFailed(let url):
            return "Ed25519 signature verification failed for \(url.absoluteString)"
        case .catalogParseFailed(let reason):
            return "Catalog parse failed: \(reason)"
        case .pluginNotInCatalog(let id):
            return "Plugin id not found in rave catalog: \(id)"
        case .versionNotFound(let id, let version):
            return "Plugin \(id) has no version entry for \(version) in the catalog."
        case .artifactHashMismatch(let expected, let actual):
            return "Artifact SHA-256 mismatch — expected \(expected), got \(actual)"
        case .unzipFailed(let status):
            return "/usr/bin/unzip exited with status \(status)"
        case .extractedBundleNotFound(let extractDir):
            return "Extracted archive did not contain a plugin bundle directory at \(extractDir)"
        }
    }
}

struct PluginCatalogFetcher {
    let catalogBase: URL
    let catalogPublicKey: Curve25519.Signing.PublicKey

    init(catalogBase: String) throws {
        var trimmed = catalogBase
        if !trimmed.hasSuffix("/") { trimmed += "/" }
        guard let url = URL(string: trimmed) else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "bad catalog base URL: \(catalogBase)")
        }
        self.catalogBase = url
        self.catalogPublicKey = try Self.loadCatalogPublicKey()
    }

    private static func loadCatalogPublicKey() throws -> Curve25519.Signing.PublicKey {
        // Local-dev override — explicit file path wins.
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_CATALOG_PUB_PATH"], !path.isEmpty {
            return try loadFromFile(path: path)
        }
        // Production fallback: bundled rave catalog key sourced
        // from maccrab-site/rave/keys/catalog.pub at build time.
        // For maccrabctl this comes from the MacCrab.app's
        // Resources/ when shipped via DMG, OR from candidate
        // dev paths when running via `swift run`.
        let candidates: [String] = [
            "/Applications/MacCrab.app/Contents/Resources/MacCrab_MacCrabApp.bundle/catalog.pub",
            "/Applications/MacCrab.app/Contents/Resources/rave-keys/catalog.pub",
            // SPM dev — Sources/MacCrabApp/Resources/rave-keys/catalog.pub
            FileManager.default.currentDirectoryPath + "/Sources/MacCrabApp/Resources/rave-keys/catalog.pub",
            FileManager.default.currentDirectoryPath + "/Sources/MacCrabApp/Resources/MacCrab_MacCrabApp.bundle/catalog.pub",
        ]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            return try loadFromFile(path: path)
        }
        throw PluginCatalogFetchError.noCatalogPublicKey
    }

    private static func loadFromFile(path: String) throws -> Curve25519.Signing.PublicKey {
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) }
        catch { throw PluginCatalogFetchError.catalogPublicKeyInvalid(reason: "cannot read \(path): \(error)") }
        guard data.count == 32 else {
            throw PluginCatalogFetchError.catalogPublicKeyInvalid(reason: "expected 32 bytes, got \(data.count) at \(path)")
        }
        do { return try Curve25519.Signing.PublicKey(rawRepresentation: data) }
        catch { throw PluginCatalogFetchError.catalogPublicKeyInvalid(reason: "Curve25519 rejected key: \(error)") }
    }

    func installPluginByID(
        pluginID: String,
        version: String? = nil,
        trustOnInstall: Bool,
        force: Bool
    ) async throws -> InstalledPlugin {
        // Step 1: catalog index + signature.
        let catalogURL = catalogBase.appendingPathComponent("catalog.json")
        let catalogSigURL = catalogBase.appendingPathComponent("catalog.json.sig")
        let catalogData = try await fetch(url: catalogURL)
        let catalogSig = try await fetch(url: catalogSigURL)
        try verify(data: catalogData, signature: catalogSig, url: catalogURL)

        // Step 2: locate plugin in index.
        let catalog = try parseCatalogIndex(data: catalogData)
        guard let entry = catalog.plugins[pluginID] else {
            throw PluginCatalogFetchError.pluginNotInCatalog(id: pluginID)
        }
        let resolvedVersion = version ?? entry.currentVersion

        // Step 3: per-plugin catalog entry + signature.
        let entryPath = "catalog/\(pluginID).json"
        let entryURL = catalogBase.appendingPathComponent(entryPath)
        let entrySigURL = catalogBase.appendingPathComponent(entryPath + ".sig")
        let entryData = try await fetch(url: entryURL)
        let entrySig = try await fetch(url: entrySigURL)
        try verify(data: entryData, signature: entrySig, url: entryURL)

        let parsed = try parseCatalogEntry(data: entryData)
        guard let versionEntry = parsed.versions[resolvedVersion] else {
            throw PluginCatalogFetchError.versionNotFound(id: pluginID, version: resolvedVersion)
        }

        // Step 4: resolve binary URL (RFC6570-ish; {tag} {file} only).
        let zipFile = "\(pluginID).zip"
        var rendered = parsed.releaseURLTemplate
            .replacingOccurrences(of: "{tag}", with: versionEntry.tag)
            .replacingOccurrences(of: "{file}", with: zipFile)
        if let from = ProcessInfo.processInfo.environment["MACCRAB_RAVE_URL_REWRITE_FROM"],
           let to = ProcessInfo.processInfo.environment["MACCRAB_RAVE_URL_REWRITE_TO"],
           rendered.hasPrefix(from) {
            rendered = to + rendered.dropFirst(from.count)
        }
        guard let binaryURL = URL(string: rendered) else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "bad rendered URL: \(rendered)")
        }

        // Step 5: download bundle, verify artifact SHA-256.
        let zipData = try await fetch(url: binaryURL)
        let actualHash = SHA256.hash(data: zipData).hexLower
        guard actualHash == versionEntry.artifactSHA256 else {
            throw PluginCatalogFetchError.artifactHashMismatch(
                expected: versionEntry.artifactSHA256,
                actual: actualHash
            )
        }

        // Step 6: stage in temp + unzip.
        let fm = FileManager.default
        let workDir = fm.temporaryDirectory.appendingPathComponent("maccrabctl-fetch-\(UUID().uuidString)")
        try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: workDir) }

        let zipPath = workDir.appendingPathComponent("bundle.zip")
        try zipData.write(to: zipPath)
        let extractDir = workDir.appendingPathComponent("extract")
        try fm.createDirectory(at: extractDir, withIntermediateDirectories: true)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        proc.arguments = ["-q", zipPath.path, "-d", extractDir.path]
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            throw PluginCatalogFetchError.unzipFailed(status: proc.terminationStatus)
        }

        let bundleDir = extractDir.appendingPathComponent(pluginID)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: bundleDir.path, isDirectory: &isDir), isDir.boolValue else {
            throw PluginCatalogFetchError.extractedBundleNotFound(extractDir: extractDir.path)
        }

        // Step 7: delegate to existing verified install path.
        let installer = PluginInstaller()
        return try await installer.install(
            sourceDir: bundleDir,
            trustOnInstall: trustOnInstall,
            force: force
        )
    }

    // MARK: - HTTP

    private func fetch(url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse else {
            throw PluginCatalogFetchError.httpFetchFailed(url: url, status: -1)
        }
        guard (200..<300).contains(http.statusCode) else {
            throw PluginCatalogFetchError.httpFetchFailed(url: url, status: http.statusCode)
        }
        return data
    }

    private func verify(data: Data, signature: Data, url: URL) throws {
        guard catalogPublicKey.isValidSignature(signature, for: data) else {
            throw PluginCatalogFetchError.signatureVerifyFailed(url: url)
        }
    }

    // MARK: - Catalog parsing

    private struct CatalogIndex {
        let plugins: [String: CatalogIndexEntry]
    }
    private struct CatalogIndexEntry {
        let currentVersion: String
    }
    private struct ParsedEntry {
        let releaseURLTemplate: String
        let versions: [String: ParsedVersion]
    }
    private struct ParsedVersion {
        let tag: String
        let artifactSHA256: String
    }

    private func parseCatalogIndex(data: Data) throws -> CatalogIndex {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "catalog.json is not a JSON object")
        }
        guard let plugins = json["plugins"] as? [String: [String: Any]] else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "catalog.json missing 'plugins' map")
        }
        var out: [String: CatalogIndexEntry] = [:]
        for (id, entry) in plugins {
            guard let v = entry["current_version"] as? String else {
                throw PluginCatalogFetchError.catalogParseFailed(reason: "plugin \(id) missing current_version")
            }
            out[id] = CatalogIndexEntry(currentVersion: v)
        }
        return CatalogIndex(plugins: out)
    }

    private func parseCatalogEntry(data: Data) throws -> ParsedEntry {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "catalog entry is not a JSON object")
        }
        guard let urlTemplate = json["release_url_template"] as? String else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "catalog entry missing release_url_template")
        }
        guard let versionsDict = json["versions"] as? [String: [String: Any]] else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "catalog entry missing versions map")
        }
        var versions: [String: ParsedVersion] = [:]
        for (v, fields) in versionsDict {
            guard let tag = fields["tag"] as? String,
                  let artifactHash = fields["artifact_sha256"] as? String else {
                throw PluginCatalogFetchError.catalogParseFailed(reason: "version \(v) missing tag or artifact_sha256")
            }
            versions[v] = ParsedVersion(tag: tag, artifactSHA256: artifactHash)
        }
        return ParsedEntry(releaseURLTemplate: urlTemplate, versions: versions)
    }
}

private extension Sequence where Element == UInt8 {
    var hexLower: String { map { String(format: "%02x", $0) }.joined() }
}
