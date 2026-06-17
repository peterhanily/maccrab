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
import MacCrabCore
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
    case bundleComponentHashMismatch(component: String, expected: String, actual: String)
    case kindMismatch(catalog: String, manifest: String)
    case unzipFailed(status: Int32)
    case extractedBundleNotFound(extractDir: String)
    case signerKeyMismatch(expected: String, actual: String)
    case signerKeyAbsentOnOfficial(id: String)
    case catalogRollback(stored: Int, incoming: Int)
    case revocationsRollback(stored: Int, incoming: Int)
    case catalogSerialMissing
    case revocationsSerialMissing
    case revocationsParseFailed(reason: String)
    case pluginRevoked(id: String, version: String, reason: String, code: String)
    case versionFloor(reason: String)

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
        case .bundleComponentHashMismatch(let component, let expected, let actual):
            return "Bundle \(component) SHA-256 mismatch — catalog pins \(expected), extracted bundle has \(actual). Refusing to install (O3)."
        case .kindMismatch(let catalog, let manifest):
            return "Plugin kind mismatch — catalog declares kind=\(catalog) but the bundle manifest declares kind=\(manifest). Refusing to install."
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
        case .revocationsRollback(let stored, let incoming):
            return "Revocations rollback rejected — signed revocations serial \(incoming) is older than the last-accepted serial \(stored). Keeping the prior revocation state (un-revoke replay)."
        case .catalogSerialMissing:
            return "Refusing to install — the signature-verified catalog carries no catalog_serial. Post-launch every official rave catalog is serial-stamped; an absent serial is a pre-ceremony or replayed catalog and is rejected (fail-closed anti-rollback)."
        case .revocationsSerialMissing:
            return "Refusing to install — the signature-verified revocation list carries no serial. An absent serial is a pre-ceremony or replayed list that could silently un-revoke a plugin; rejected (fail-closed anti-rollback)."
        case .revocationsParseFailed(let reason):
            return "Revocations list parse failed: \(reason). Refusing to proceed without a valid revocation list (fail-closed)."
        case .pluginRevoked(let id, let version, let reason, let code):
            return "Refusing to install \(id)@\(version): revoked by the signed revocation list [\(code)] — \(reason)."
        case .versionFloor(let reason):
            return reason
        }
    }
}

struct PluginCatalogFetcher {
    let catalogBase: URL
    let catalogPublicKey: Curve25519.Signing.PublicKey
    /// S2-AR anti-rollback high-water-mark store. Defaults to
    /// <maccrabDataDir>/rave_trust_state.json; overridable for tests.
    let trustState: RaveTrustStateStore
    /// O3b (S2-06) signed install-receipt store. Defaults to a
    /// filesystem-substrate-backed store under <maccrabDataDir>; injectable
    /// for tests. A receipt is emitted best-effort after each successful
    /// install — a write/sign failure never unwinds a completed install.
    let receiptStore: PluginInstallReceiptStore

    init(
        catalogBase: String,
        trustState: RaveTrustStateStore? = nil,
        receiptStore: PluginInstallReceiptStore? = nil
    ) throws {
        var trimmed = catalogBase
        if !trimmed.hasSuffix("/") { trimmed += "/" }
        guard let url = URL(string: trimmed) else {
            throw PluginCatalogFetchError.catalogParseFailed(reason: "bad catalog base URL: \(catalogBase)")
        }
        self.catalogBase = url
        self.catalogPublicKey = try Self.loadCatalogPublicKey()
        // Client-owned WRITABLE trust artifacts (anti-rollback high-water mark +
        // signed receipts) go in the user-domain dir, NOT maccrabDataDir() (which
        // prefers the root-owned dir the non-root CLI can't write — v1.19 dry-run
        // Finding 2). Installs land in the same user-domain tree.
        let writableDir = maccrabUserWritableDataDir()
        self.trustState = trustState ?? RaveTrustStateStore.default(supportDir: writableDir)
        self.receiptStore = receiptStore ?? Self.defaultReceiptStore(dataDir: writableDir)
    }

    /// Default receipt store: receipts under <dataDir>/plugin_receipts/, signed
    /// by the same P256 TrustSubstrate key that signs trace/evidence bundles
    /// (keys under <dataDir>/keys/).
    private static func defaultReceiptStore(dataDir: String) -> PluginInstallReceiptStore {
        let keysDir = URL(fileURLWithPath: dataDir).appendingPathComponent("keys")
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: keysDir)
        let substrate = TrustSubstrate(storage: storage)
        let receiptsDir = URL(fileURLWithPath: dataDir).appendingPathComponent("plugin_receipts")
        return PluginInstallReceiptStore(receiptsDir: receiptsDir, substrate: substrate)
    }

    private static func loadCatalogPublicKey() throws -> Curve25519.Signing.PublicKey {
        #if DEBUG
        // Local-dev override — explicit file path wins. DEBUG-ONLY (matches the
        // S2-13 staging seam below): a RELEASE build must trust ONLY the bundled
        // production key. Honoring an env path on release would let a local
        // foothold swap the catalog trust root and forge a catalog/signer pin.
        if let path = ProcessInfo.processInfo.environment["MACCRAB_RAVE_CATALOG_PUB_PATH"], !path.isEmpty {
            return try loadFromFile(path: path)
        }
        #endif
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
        // v1.19.0: REQUIRE the serial on the install path (fail-closed). A
        // signature-verified catalog with no catalog_serial post-launch is a
        // pre-ceremony or replayed catalog — refuse rather than accept-as-
        // first-seen, which would let an old serial-less signed catalog defeat
        // anti-rollback.
        guard let serial = catalog.catalogSerial else {
            throw PluginCatalogFetchError.catalogSerialMissing
        }
        switch trustState.evaluateCatalog(incoming: serial) {
        case .rollback(let stored, let incoming):
            throw PluginCatalogFetchError.catalogRollback(stored: stored, incoming: incoming)
        case .firstSeen, .accepted:
            break
        }

        guard let entry = catalog.plugins[pluginID] else {
            throw PluginCatalogFetchError.pluginNotInCatalog(id: pluginID)
        }
        let resolvedVersion = version ?? entry.currentVersion

        // Step 2.5 (O2): fetch + verify + anti-rollback the signed revocation
        // list, then refuse the install if THIS id@version is revoked —
        // before download. The list is also reconciled against everything
        // already installed (quarantine) so a `plugin install` doubles as a
        // revocation sync. Fail-closed: a bad signature / malformed list /
        // older serial aborts the install.
        let revocations = try await fetchVerifiedRevocations()
        // Reconcile quarantine FIRST — before the per-install refusal — so that
        // re-running `plugin install <id>` for an ALREADY-INSTALLED, now-revoked
        // plugin quarantines the on-disk copy instead of just refusing while the
        // stale copy keeps loading. (v1.19 dry-run Finding 1: the refusal `throw`
        // short-circuited the reconcile, so quarantine-on-revoke only self-healed
        // when the operator happened to install some OTHER plugin.) Best-effort:
        // a reconcile write failure must not block a non-revoked install.
        try? await Self.reconcileInstalledQuarantine(against: revocations)
        if case .refused(let hit) = RevocationEnforcer.evaluateInstall(
            pluginID: pluginID, version: resolvedVersion, against: revocations
        ) {
            throw PluginCatalogFetchError.pluginRevoked(
                id: pluginID, version: resolvedVersion, reason: hit.reason, code: hit.code
            )
        }

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

        // Step 3.5 (O3a): version-floor gate. Refuse the install when the
        // running build is older than the entry's declared
        // metadata.min_maccrab_version — before download. Fail-closed: an
        // unparseable floor (or running version) is a refusal, never a silent
        // pass. Shared policy with the dashboard path (RaveVersionFloor).
        do {
            try RaveVersionFloor.enforce(
                pluginID: pluginID,
                floor: parsed.minMaccrabVersion,
                running: MacCrabVersion.current
            )
        } catch let e as RaveVersionFloorError {
            throw PluginCatalogFetchError.versionFloor(reason: e.description)
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

        // O3 (granular, defense-in-depth): when the catalog pins real (non-zero)
        // per-component hashes, the extracted bundle's signature + manifest bytes
        // must match. artifact_sha256 (the whole zip) already gates these
        // transitively; this catches a per-file swap explicitly. Skipped on
        // placeholder-zero (pre-ceremony) values.
        let zeroHash = String(repeating: "0", count: 64)
        if let sigHash = versionEntry.signatureSHA256, sigHash != zeroHash, RaveSignerPin.isSHA256Hex(sigHash) {
            let actual = (try? Data(contentsOf: bundleDir.appendingPathComponent("signature")))
                .map { SHA256.hash(data: $0).hexLower }
            guard actual == sigHash else {
                throw PluginCatalogFetchError.bundleComponentHashMismatch(
                    component: "signature", expected: sigHash, actual: actual ?? "<missing>")
            }
        }
        if let manHash = versionEntry.manifestSHA256, manHash != zeroHash, RaveSignerPin.isSHA256Hex(manHash) {
            let actual = (try? Data(contentsOf: bundleDir.appendingPathComponent("manifest.json")))
                .map { SHA256.hash(data: $0).hexLower }
            guard actual == manHash else {
                throw PluginCatalogFetchError.bundleComponentHashMismatch(
                    component: "manifest.json", expected: manHash, actual: actual ?? "<missing>")
            }
        }
        // #7: the catalog-declared kind must match the bundle manifest's kind when
        // both declare one (catches a kind-spoof between catalog and bundle).
        if let catalogKind = parsed.kind,
           let manifestKind = (try? TierBManifest.load(fromBundlePath: bundleDir.path))?.kind?.rawValue,
           catalogKind != manifestKind {
            throw PluginCatalogFetchError.kindMismatch(catalog: catalogKind, manifest: manifestKind)
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

        // O3b: emit a signed, offline-verifiable install receipt recording
        // exactly what was installed against which trust state. Best-effort —
        // a sign/write failure must not unwind a completed install.
        let receiptBody = PluginInstallReceiptBody(
            pluginID: pluginID,
            version: resolvedVersion,
            artifactSHA256: versionEntry.artifactSHA256,
            signerPublicKeySHA256: parsed.signerPublicKeySHA256 ?? "",
            catalogSerial: catalog.catalogSerial,
            revocationSerial: revocations.serial,
            appVersion: MacCrabVersion.current,
            timestamp: ISO8601DateFormatter().string(from: Date())
        )
        if let url = try? await receiptStore.emit(receiptBody) {
            FileHandle.standardError.write(Data(
                "MacCrab: wrote signed install receipt → \(url.path)\n".utf8
            ))
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

    // MARK: - Revocations (O2)

    /// Fetch revocations.json + .sig, Ed25519-verify against the pinned
    /// catalog.pub (same key path as the catalog), parse, and enforce the
    /// monotonic-serial anti-rollback high-water mark. Returns the verified
    /// list. Throws on bad signature (signatureVerifyFailed), malformed body
    /// (revocationsParseFailed), or an older serial (revocationsRollback).
    /// Advances the persisted revocations high-water mark on accept.
    func fetchVerifiedRevocations() async throws -> RaveRevocationList {
        let revURL = catalogBase.appendingPathComponent("revocations.json")
        let revSigURL = catalogBase.appendingPathComponent("revocations.json.sig")
        let revData = try await fetch(url: revURL)
        let revSig = try await fetch(url: revSigURL)
        try verify(data: revData, signature: revSig, url: revURL)

        let list: RaveRevocationList
        do {
            list = try RaveRevocationList.parse(data: revData)
        } catch {
            throw PluginCatalogFetchError.revocationsParseFailed(reason: "\(error)")
        }

        // Anti-rollback on the now signature-verified list. A validly-signed-
        // but-older serial is an un-revoke replay; reject it and keep the
        // prior revocation state. Missing serial = first-seen.
        guard let serial = list.serial else {
            throw PluginCatalogFetchError.revocationsSerialMissing
        }
        switch trustState.evaluateRevocations(incoming: serial) {
        case .rollback(let stored, let incoming):
            throw PluginCatalogFetchError.revocationsRollback(stored: stored, incoming: incoming)
        case .firstSeen, .accepted:
            try? trustState.recordRevocations(serial: serial)
        }
        return list
    }

    /// Reconcile the on-disk quarantine set against a verified revocation
    /// list: quarantine every installed plugin the list now revokes (by
    /// id+manifest-version), and un-quarantine any that have escaped (e.g. a
    /// version that no longer matches a range). Non-destructive — only marks.
    static func reconcileInstalledQuarantine(against list: RaveRevocationList) async throws {
        let installer = PluginInstaller()
        let installed = try await installer.list()
        var refs: [RevocationEnforcer.InstalledRef] = []
        refs.reserveCapacity(installed.count)
        for p in installed {
            // Resolve the installed version from the bundle manifest; a bundle
            // with no readable manifest gets an empty version (matched only by
            // all_versions — the safe fail-closed default).
            let version = (try? TierBManifest.load(fromBundlePath: p.installRoot))?.version ?? ""
            refs.append(.init(pluginID: p.pluginID, version: version))
        }
        let records = RevocationEnforcer.reconcileQuarantine(installed: refs, against: list)
        try await installer.applyQuarantine(records)
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
        /// O3a (S2-05) version floor: `metadata.min_maccrab_version`. nil when
        /// the (pre-ceremony) entry omits it. Enforced against the running
        /// build before download.
        let minMaccrabVersion: String?
        /// Plugin role from the catalog ("collector"/"analyzer"). #7: must match
        /// the installed bundle manifest's kind when both declare one. nil when absent.
        let kind: String?
    }
    private struct ParsedVersion {
        let tag: String
        let artifactSHA256: String
        /// O3 granular per-component anchors (hex-lower). nil/placeholder-zero on
        /// pre-ceremony entries; asserted against the extracted bundle when real.
        let signatureSHA256: String?
        let manifestSHA256: String?
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
            versions[v] = ParsedVersion(
                tag: tag,
                artifactSHA256: artifactHash,
                signatureSHA256: (fields["signature_sha256"] as? String)?.lowercased(),
                manifestSHA256: (fields["manifest_sha256"] as? String)?.lowercased()
            )
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
        // O3a version floor: metadata.min_maccrab_version (catalog-entry
        // schema). Optional only so pre-ceremony entries parse; an absent
        // floor means "no version gate" (the signer pin remains the trust
        // gate). A present-but-non-string value is treated as absent here and
        // the floor policy fails closed downstream if it can't parse.
        let metadata = json["metadata"] as? [String: Any]
        let minMaccrabVersion = metadata?["min_maccrab_version"] as? String
        let kind = json["kind"] as? String
        return ParsedEntry(
            releaseURLTemplate: urlTemplate,
            versions: versions,
            signerPublicKeySHA256: signerKey,
            status: status,
            minMaccrabVersion: minMaccrabVersion,
            kind: kind
        )
    }
}

private extension Sequence where Element == UInt8 {
    var hexLower: String { map { String(format: "%02x", $0) }.joined() }
}
