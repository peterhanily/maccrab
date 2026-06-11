// PluginCatalogFetch — HTTP fetch path for `maccrabctl plugin install <plugin-id>`.
//
// Resolves a plugin-id against the rave.maccrab.com catalog and downloads the
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
    case signerKeyMismatch(expected: String, actual: String)
    case signerKeyAbsentOnOfficial(id: String)
    case catalogRollback(stored: Int, incoming: Int)

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
        case .signerKeyMismatch(let expected, let actual):
            return "Publisher-key pin mismatch — catalog endorses signer key sha256 \(expected), but the bundle's signing.key.pub hashes to \(actual). Refusing to install."
        case .signerKeyAbsentOnOfficial(let id):
            return "Catalog entry for \(id) has no signer_public_key_sha256 on an official (non-pre-release) channel. Refusing to install (fail-closed). Set --allow-unpinned-prerelease only for pre-release entries."
        case .catalogRollback(let stored, let incoming):
            return "Catalog rollback rejected — signed catalog_serial \(incoming) is older than the last-accepted serial \(stored). Keeping the prior trusted catalog (stale/replay)."
        }
    }
}

struct PluginCatalogFetcher {
    let catalogBase: URL
    let catalogPublicKey: Curve25519.Signing.PublicKey
    /// S2-AR anti-rollback high-water-mark store. Defaults to
    /// <maccrabDataDir>/rave_trust_state.json; overridable for tests.
    let trustState: RaveTrustStateStore

    init(catalogBase: String, trustState: RaveTrustStateStore? = nil) throws {
        var trimmed = catalogBase
        if !trimmed.hasSuffix("/") { trimmed += "/" }
        guard let url = URL(string: trimmed) else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "bad catalog base URL: \(catalogBase)")
        }
        self.catalogBase = url
        self.catalogPublicKey = try Self.loadCatalogPublicKey()
        self.trustState = trustState ?? RaveTrustStateStore.default(supportDir: maccrabDataDir())
    }

    private static func loadCatalogPublicKey() throws -> Curve25519.Signing.PublicKey {
        // Local-dev override — explicit file path wins.
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_CATALOG_PUB_PATH"], !path.isEmpty {
            return try loadFromFile(path: path)
        }
        // S2-13 debug-only staging-key seam: a debug build with
        // MACCRAB_RAVE_STAGING_PUB set verifies against the staging signing
        // key instead of the bundled production key. Compiled out / always nil
        // on release builds (see RaveStagingPubOverride).
        if let raw = RaveStagingPubOverride.rawKeyData() {
            do { return try Curve25519.Signing.PublicKey(rawRepresentation: raw) }
            catch { throw PluginCatalogFetchError.catalogPublicKeyInvalid(reason: "staging override key rejected: \(error)") }
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
        force: Bool,
        allowUnpinnedPrerelease: Bool = false
    ) async throws -> InstalledPlugin {
        // Step 1: catalog index + signature.
        let catalogURL = catalogBase.appendingPathComponent("catalog.json")
        let catalogSigURL = catalogBase.appendingPathComponent("catalog.json.sig")
        let catalogData = try await fetch(url: catalogURL)
        let catalogSig = try await fetch(url: catalogSigURL)
        try verify(data: catalogData, signature: catalogSig, url: catalogURL)

        // Step 2: locate plugin in index.
        let catalog = try parseCatalogIndex(data: catalogData)

        // Step 1.5 (S2-AR): anti-rollback gate on the now signature-verified
        // catalog. A validly-signed-but-older catalog_serial is a stale/replay
        // and is rejected; the prior trusted catalog (and its high-water mark)
        // is kept untouched. A missing serial is treated as first-seen so
        // pre-ceremony catalogs (serial not yet signed in) still install.
        if let serial = catalog.catalogSerial {
            switch trustState.evaluateCatalog(incoming: serial) {
            case .rollback(let stored, let incoming):
                throw PluginCatalogFetchError.catalogRollback(stored: stored, incoming: incoming)
            case .firstSeen, .accepted:
                break
            }
        }

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

        // Step 6.5 (O1b): publisher-key pin. Bind *which* signer key the
        // catalog endorsed to *which* key the bundle actually carries —
        // independent of artifact_sha256 (transport) and the bundle's own
        // self-signature. Replaces TOFU-via-trust-on-install on official
        // channels. Fail-closed: an official (non-"pre-release") entry with
        // no signer_public_key_sha256 is refused.
        try enforceSignerPin(
            entry: parsed,
            pluginID: pluginID,
            bundleDir: bundleDir,
            allowUnpinnedPrerelease: allowUnpinnedPrerelease
        )

        // Step 7: delegate to existing verified install path.
        let installer = PluginInstaller()
        let result = try await installer.install(
            sourceDir: bundleDir,
            trustOnInstall: trustOnInstall,
            force: force
        )
        // Install succeeded — advance the anti-rollback high-water mark so a
        // later stale catalog is rejected. Best-effort: a write failure must
        // not unwind a completed install.
        if let serial = catalog.catalogSerial {
            try? trustState.recordCatalog(serial: serial)
        }
        return result
    }

    /// O1b signer-key pin enforcement. Delegates to the shared
    /// `RaveSignerPin.enforce` policy (single source of truth across both
    /// clients) and maps its errors onto `PluginCatalogFetchError`.
    private func enforceSignerPin(
        entry: ParsedEntry,
        pluginID: String,
        bundleDir: URL,
        allowUnpinnedPrerelease: Bool
    ) throws {
        let pubURL = bundleDir.appendingPathComponent("signing.key.pub")
        let bundleKeyData = try? Data(contentsOf: pubURL)
        do {
            try RaveSignerPin.enforce(
                expectedPin: entry.signerPublicKeySHA256,
                status: entry.status,
                pluginID: pluginID,
                bundleKeyData: bundleKeyData,
                allowUnpinnedPrerelease: allowUnpinnedPrerelease
            )
        } catch let e as RaveSignerPinError {
            switch e {
            case .mismatch(let expected, let actual):
                throw PluginCatalogFetchError.signerKeyMismatch(expected: expected, actual: actual)
            case .missingBundleKey(let expected):
                throw PluginCatalogFetchError.signerKeyMismatch(expected: expected, actual: "<missing signing.key.pub>")
            case .absentOnOfficial(let id):
                throw PluginCatalogFetchError.signerKeyAbsentOnOfficial(id: id)
            }
        }
        // Loud diagnostic when a pre-release entry was installed unpinned.
        if entry.signerPublicKeySHA256 == nil && entry.status == "pre-release" && allowUnpinnedPrerelease {
            FileHandle.standardError.write(Data(
                "MacCrab: WARNING — installing pre-release plugin '\(pluginID)' WITHOUT a publisher-key pin (--allow-unpinned-prerelease).\n".utf8
            ))
        }
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
        /// Top-level monotonic freshness counter (S2-AR). nil when the catalog
        /// predates the field (pre-ceremony signed bytes keep it optional).
        let catalogSerial: Int?
    }
    private struct CatalogIndexEntry {
        let currentVersion: String
    }
    private struct ParsedEntry {
        let releaseURLTemplate: String
        let versions: [String: ParsedVersion]
        /// sha256 (hex-lower) of the publisher's bundle signing.key.pub, as
        /// endorsed by the (signature-verified) catalog. nil when absent.
        let signerPublicKeySHA256: String?
        /// Entry maturity. "pre-release" entries may install without the
        /// signer pin behind an explicit opt-in; anything else is treated as
        /// an official channel and fails closed when the pin is absent.
        let status: String?
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
        // Top-level monotonic freshness counter. JSONSerialization decodes
        // JSON integers as NSNumber; reject a non-integer serial rather than
        // silently treating it as absent (a string "0" would otherwise slip
        // past the rollback gate).
        let catalogSerial = (json["catalog_serial"] as? NSNumber)?.intValue
        return CatalogIndex(plugins: out, catalogSerial: catalogSerial)
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
        // O1b publisher-key pin. Validate shape (^[0-9a-f]{64}$) so a
        // malformed value can't masquerade as a valid pin; a present-but-bad
        // hash is a parse failure, an *absent* hash is handled fail-closed at
        // install time depending on the entry's maturity.
        var signerKey: String? = nil
        if let raw = json["signer_public_key_sha256"] as? String {
            let lowered = raw.lowercased()
            guard RaveSignerPin.isSHA256Hex(lowered) else {
                throw PluginCatalogFetchError.catalogParseFailed(
                    reason: "signer_public_key_sha256 is not a 64-char lowercase hex string"
                )
            }
            signerKey = lowered
        }
        let status = json["status"] as? String
        return ParsedEntry(
            releaseURLTemplate: urlTemplate,
            versions: versions,
            signerPublicKeySHA256: signerKey,
            status: status
        )
    }
}

private extension Sequence where Element == UInt8 {
    var hexLower: String { map { String(format: "%02x", $0) }.joined() }
}
