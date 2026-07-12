// PluginInstaller — copies a signed Tier B bundle into the
// operator's plugin directory, verifies its signature, and
// updates the trust store. Plus a JSON-on-disk revocation list
// that future PluginRegistry.load() consults.
//
// Plan §3.6 + §12 + plan §3.9 trust model.
//
// Layout the installer manages:
//   ~/Library/Application Support/MacCrab/plugins/tier-b/
//     <plugin-id>/
//       manifest.json
//       binary
//       signature
//       signing.key.pub
//     trusted-keys.json   {"keys": ["<hex>", ...]}
//     revoked-keys.json   {"keys": ["<hex>", ...]}
//
// Research-grade. Network-based plugin store + signed appcast is
// a release chapter (plan §12). For now: installs from a local
// directory and trust-keys are operator-managed via maccrabctl.

import Foundation
import CryptoKit

public actor PluginInstaller {

    public enum InstallError: Error, CustomStringConvertible {
        case sourceNotADirectory(path: String)
        case destinationAlreadyExists(path: String)
        case manifestUnreadable(message: String)
        case missingPluginID
        case invalidPluginID(message: String)
        case symlinkInSourceBundle(path: String)
        case verifyFailed(reason: String)
        case ioError(message: String)

        public var description: String {
            switch self {
            case .sourceNotADirectory(let p): return "PluginInstaller: source is not a directory: \(p)"
            case .destinationAlreadyExists(let p): return "PluginInstaller: destination already exists: \(p) (use --force to overwrite)"
            case .manifestUnreadable(let m): return "PluginInstaller: manifest unreadable: \(m)"
            case .missingPluginID: return "PluginInstaller: manifest has no 'id' field"
            case .invalidPluginID(let m): return "PluginInstaller: invalid plugin id: \(m)"
            case .symlinkInSourceBundle(let p): return "PluginInstaller: source bundle contains symlink (refused): \(p)"
            case .verifyFailed(let r): return "PluginInstaller: signature verification failed: \(r)"
            case .ioError(let m): return "PluginInstaller: I/O error: \(m)"
            }
        }
    }

    /// Reject any plugin id containing path separators, traversal
    /// sequences, leading dots, control characters, or characters
    /// outside the allowed RFC-1035-ish set. The id ends up as a
    /// directory name under pluginsRoot/, so its shape is part of
    /// the security boundary.
    ///
    /// Accepted pattern: `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`
    /// — starts with alphanumeric, contains only alphanumerics,
    /// dots, underscores, hyphens; at most 128 chars total.
    public static func validatePluginID(_ id: String) throws {
        guard !id.isEmpty else {
            throw InstallError.invalidPluginID(message: "id is empty")
        }
        guard id.count <= 128 else {
            throw InstallError.invalidPluginID(message: "id exceeds 128 characters")
        }
        // No path separator.
        if id.contains("/") || id.contains("\\") {
            throw InstallError.invalidPluginID(message: "id contains path separator: \(id)")
        }
        // No traversal sequence.
        if id == ".." || id == "." || id.contains("/..") || id.contains("../") {
            throw InstallError.invalidPluginID(message: "id contains traversal sequence: \(id)")
        }
        // Must start with alphanumeric (rejects leading dot/dash
        // which could mask the bundle on listing, or be parsed as
        // a flag by some tools).
        guard let first = id.first, first.isLetter || first.isNumber else {
            throw InstallError.invalidPluginID(message: "id must start with letter or digit: \(id)")
        }
        // Body charset.
        for ch in id {
            let ok = ch.isLetter || ch.isNumber || ch == "." || ch == "_" || ch == "-"
            if !ok {
                throw InstallError.invalidPluginID(message: "id contains disallowed character '\(ch)' in: \(id)")
            }
        }
        // No null bytes (defense in depth — Swift Strings can't
        // contain them per current Foundation, but the byte-level
        // check survives future Foundation changes).
        if id.utf8.contains(0) {
            throw InstallError.invalidPluginID(message: "id contains null byte")
        }
    }

    /// Validate a free-form display string (displayName, version,
    /// description). Rejects ANSI escape sequences + control
    /// characters that would let a hostile manifest hijack the
    /// operator's terminal when `installed-list` renders it.
    ///
    /// Allowed: printable Unicode (letters, digits, punctuation,
    /// whitespace = space + tab). Disallowed: ASCII control 0x00-
    /// 0x1F (except 0x20 + 0x09), 0x7F. Caps length at `maxChars`.
    public static func validateDisplayString(
        _ value: String,
        field: String,
        maxChars: Int = 256
    ) throws {
        guard value.count <= maxChars else {
            throw InstallError.invalidPluginID(
                message: "\(field) exceeds \(maxChars) chars"
            )
        }
        for scalar in value.unicodeScalars {
            let v = scalar.value
            // Allow space (0x20) and tab (0x09). Reject everything
            // else under 0x20, plus DEL (0x7F). Range 0x80-0x9F
            // contains "C1" control codes (less commonly weaponized
            // but still control). Strict mode: reject those too.
            let isAsciiPrintable = v >= 0x20 && v != 0x7F
            let isTab = v == 0x09
            // C1 controls (Unicode 0x80-0x9F): reject.
            let isC1Control = v >= 0x80 && v <= 0x9F
            if isC1Control {
                throw InstallError.invalidPluginID(
                    message: "\(field) contains C1 control char U+\(String(v, radix: 16, uppercase: true))"
                )
            }
            if !(isAsciiPrintable || isTab || v > 0x9F) {
                throw InstallError.invalidPluginID(
                    message: "\(field) contains control char U+\(String(v, radix: 16, uppercase: true))"
                )
            }
        }
    }

    /// Validate a manifest-declared path entry (member of fileReadSubpaths /
    /// fileWriteSubpaths / processExecPaths). Rejects control chars
    /// (newlines/tabs) and double-quotes that could break out of an SBPL string
    /// literal, '..' traversal segments, and relative paths; caps length.
    /// (Parens are legal in real paths and are neutralized by the SBPL quoter at
    /// profile-build time, not rejected here.)
    public static func validateSandboxPath(
        _ path: String,
        field: String,
        maxChars: Int = 1024
    ) throws {
        guard !path.isEmpty else {
            throw InstallError.invalidPluginID(
                message: "\(field) entry is empty"
            )
        }
        guard path.count <= maxChars else {
            throw InstallError.invalidPluginID(
                message: "\(field) entry exceeds \(maxChars) chars"
            )
        }
        guard path.hasPrefix("/") else {
            throw InstallError.invalidPluginID(
                message: "\(field) entry must be absolute path (starts with /): \(path)"
            )
        }
        // Reject `..` segments (path traversal in deny/allow rules).
        let segments = path.split(separator: "/", omittingEmptySubsequences: true)
        for seg in segments where seg == ".." {
            throw InstallError.invalidPluginID(
                message: "\(field) entry contains '..' segment: \(path)"
            )
        }
        // No control chars (newlines, tabs, etc.) or double-quotes — these can
        // close out the SBPL string literal in the profile. (Parens are legal in
        // paths; the SBPL quoter neutralizes them at build time.)
        for scalar in path.unicodeScalars {
            let v = scalar.value
            if v < 0x20 || v == 0x7F || (v >= 0x80 && v <= 0x9F) || v == 0x22 {
                throw InstallError.invalidPluginID(
                    message: "\(field) entry contains control/quote char U+\(String(v, radix: 16, uppercase: true)): \(path)"
                )
            }
        }
    }

    /// Validate the full manifest payload as parsed from
    /// manifest.json. Runs validatePluginID + validateDisplayString
    /// + validateSandboxPath across every field. Called before
    /// signature verification so an attacker can't supply a
    /// manifest with a hostile name + dummy binary + wait for the
    /// installer to render the name in installed-list before the
    /// signature mismatch is caught.
    public static func validateManifest(_ json: [String: Any]) throws {
        guard let id = json["id"] as? String else {
            throw InstallError.missingPluginID
        }
        try validatePluginID(id)
        if let s = json["displayName"] as? String {
            try validateDisplayString(s, field: "displayName")
        }
        if let s = json["version"] as? String {
            try validateDisplayString(s, field: "version", maxChars: 64)
        }
        if let s = json["description"] as? String {
            try validateDisplayString(s, field: "description", maxChars: 1024)
        }
        if let arr = json["fileReadSubpaths"] as? [String] {
            for p in arr { try validateSandboxPath(p, field: "fileReadSubpaths") }
        }
        if let arr = json["fileWriteSubpaths"] as? [String] {
            for p in arr { try validateSandboxPath(p, field: "fileWriteSubpaths") }
        }
        if let arr = json["networkConnectAllowlist"] as? [String] {
            for endpoint in arr {
                // Looser shape — just reject control chars + cap
                // length. Allowlist entries are host:port-style;
                // can't enforce more without a parser.
                try validateDisplayString(endpoint, field: "networkConnectAllowlist", maxChars: 256)
            }
        }
        // The three capability fields the deny-default profile also consumes are
        // validated here too (previously unvalidated — quoting was the sole
        // defense). processExecPaths are absolute exec paths; machServiceConnects
        // are service names (not paths), so they get the looser control/length
        // check. allowProcessFork is a Bool — nothing to validate.
        if let arr = json["processExecPaths"] as? [String] {
            for p in arr { try validateSandboxPath(p, field: "processExecPaths") }
        }
        if let arr = json["machServiceConnects"] as? [String] {
            for s in arr { try validateDisplayString(s, field: "machServiceConnects", maxChars: 256) }
        }
    }

    private let pluginsRoot: URL

    public init(pluginsRoot: URL? = nil) {
        if let r = pluginsRoot {
            self.pluginsRoot = r
        } else {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support")
            self.pluginsRoot = support
                .appendingPathComponent("MacCrab")
                .appendingPathComponent("plugins")
            // v1.17 rc.7 — one-time migration from the rc.20-era
            // engineering-named subdir to the operator-shaped path.
            // Old: ~/Library/Application Support/MacCrab/plugins/tier-b/
            // New: ~/Library/Application Support/MacCrab/plugins/
            // If old exists + new is missing, move it. Idempotent.
            Self.migrateLegacyTierBDirIfNeeded(newRoot: self.pluginsRoot, support: support)
        }
    }

    /// One-shot migration of the rc.20-era `plugins/tier-b/`
    /// subdirectory contents into `plugins/`. Runs on every
    /// PluginInstaller init but cheap: a single fileExists check.
    /// If the legacy dir exists and the new root contains no
    /// plugin entries yet, contents are moved + the legacy
    /// directory is removed. Existing installations gain the
    /// rename without any operator action.
    private static func migrateLegacyTierBDirIfNeeded(newRoot: URL, support: URL) {
        let fm = FileManager.default
        let legacy = support
            .appendingPathComponent("MacCrab")
            .appendingPathComponent("plugins")
            .appendingPathComponent("tier-b")
        guard fm.fileExists(atPath: legacy.path) else { return }
        // Ensure the new root exists (peer of `tier-b/` under `plugins/`).
        try? fm.createDirectory(at: newRoot, withIntermediateDirectories: true)
        guard let entries = try? fm.contentsOfDirectory(atPath: legacy.path) else {
            return
        }
        var moved = 0
        for entry in entries {
            let src = legacy.appendingPathComponent(entry)
            let dst = newRoot.appendingPathComponent(entry)
            if fm.fileExists(atPath: dst.path) {
                // Already migrated entry — skip; don't clobber.
                continue
            }
            do {
                try fm.moveItem(at: src, to: dst)
                moved += 1
            } catch {
                // Best-effort migration; failures don't block init.
            }
        }
        // If we moved everything, drop the empty legacy dir.
        if let leftover = try? fm.contentsOfDirectory(atPath: legacy.path),
           leftover.isEmpty {
            try? fm.removeItem(at: legacy)
        }
        if moved > 0 {
            FileHandle.standardError.write(Data(
                "MacCrab: migrated \(moved) plugin entr\(moved == 1 ? "y" : "ies") from plugins/tier-b/ to plugins/\n".utf8
            ))
        }
    }

    public nonisolated var pluginsRootPath: String { pluginsRoot.path }

    /// Install from a source directory containing the signed bundle
    /// files (`manifest.json` / `binary` / `signature` /
    /// `signing.key.pub`). Verifies the signature, refuses to
    /// install if the key is revoked, copies the bundle into the
    /// plugin root, and (when `trustOnInstall == true`) marks the
    /// publisher key as trusted.
    public func install(
        sourceDir: URL,
        trustOnInstall: Bool = false,
        force: Bool = false
    ) async throws -> InstalledPlugin {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: sourceDir.path, isDirectory: &isDir), isDir.boolValue else {
            throw InstallError.sourceNotADirectory(path: sourceDir.path)
        }
        try fm.createDirectory(at: pluginsRoot, withIntermediateDirectories: true)

        // Decode manifest to extract plugin id.
        let manifestURL = sourceDir.appendingPathComponent("manifest.json")
        guard let manifestData = try? Data(contentsOf: manifestURL) else {
            throw InstallError.manifestUnreadable(message: "could not read \(manifestURL.path)")
        }
        guard let obj = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            throw InstallError.manifestUnreadable(message: "manifest is not valid JSON")
        }
        // Full manifest validation before signature check so
        // hostile field values can't slip into the install dir
        // even briefly.
        try Self.validateManifest(obj)
        guard let pluginID = obj["id"] as? String, !pluginID.isEmpty else {
            throw InstallError.missingPluginID
        }
        // Source bundle must not contain symlinks. The
        // signature was computed against the bytes the verifier
        // sees — if the source has a symlink to /etc/passwd,
        // those bytes get incorporated into the install, then
        // an attacker swaps the symlink target post-install.
        try Self.assertNoSymlinks(in: sourceDir)

        // Verify against the current trust+revocation set.
        let trustedKeys = await currentTrustedKeys()
        let revokedKeys = await currentRevokedKeys()
        let publicKeyData = (try? Data(contentsOf: sourceDir.appendingPathComponent("signing.key.pub"))) ?? Data()
        let publicKeyHex = publicKeyData.map { String(format: "%02x", $0) }.joined()

        var verifyTrust = trustedKeys
        if trustOnInstall {
            verifyTrust.insert(publicKeyHex)
        }
        let trustStore = PluginSignatureVerifier.TrustStore(
            allowedKeyHexes: verifyTrust,
            revokedKeyHexes: revokedKeys
        )
        do {
            _ = try PluginSignatureVerifier.verify(
                bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: sourceDir),
                trustStore: trustStore
            )
        } catch {
            throw InstallError.verifyFailed(reason: "\(error)")
        }

        // Copy bundle into pluginsRoot/<pluginID>/ via an atomic swap: the
        // failure-prone copy lands in a sibling temp dir FIRST, so a failed
        // copy (disk full / permission denied) can never leave the
        // previously-installed plugin removed-but-not-replaced. Only after the
        // copy succeeds do we remove the old dir and rename the temp into place
        // (a same-volume rename, effectively atomic).
        let destURL = pluginsRoot.appendingPathComponent(pluginID)
        let alreadyInstalled = fm.fileExists(atPath: destURL.path)
        if alreadyInstalled && !force {
            throw InstallError.destinationAlreadyExists(path: destURL.path)
        }
        let tmpURL = pluginsRoot.appendingPathComponent("\(pluginID).tmp.\(UUID().uuidString)")
        do {
            try fm.copyItem(at: sourceDir, to: tmpURL)
        } catch {
            try? fm.removeItem(at: tmpURL)
            throw InstallError.ioError(message: error.localizedDescription)
        }
        do {
            if alreadyInstalled { try fm.removeItem(at: destURL) }
            try fm.moveItem(at: tmpURL, to: destURL)
        } catch {
            try? fm.removeItem(at: tmpURL)
            throw InstallError.ioError(message: error.localizedDescription)
        }
        // 0o700 on the install dir; 0o755 on the binary so it can
        // execute.
        try? fm.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: destURL.path
        )
        try? fm.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: destURL.appendingPathComponent("binary").path
        )

        if trustOnInstall {
            try await addTrustedKey(publicKeyHex)
        }
        return InstalledPlugin(
            pluginID: pluginID,
            installRoot: destURL.path,
            publicKeyHex: publicKeyHex
        )
    }

    /// Uninstall by plugin id. Removes the bundle directory.
    public func uninstall(pluginID: String) async throws {
        let dest = pluginsRoot.appendingPathComponent(pluginID)
        let fm = FileManager.default
        guard fm.fileExists(atPath: dest.path) else {
            throw InstallError.ioError(message: "not installed: \(pluginID)")
        }
        try fm.removeItem(at: dest)
    }

    /// List installed plugins.
    public func list() async throws -> [InstalledPlugin] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: pluginsRoot.path) else { return [] }
        let entries = try fm.contentsOfDirectory(atPath: pluginsRoot.path)
        var results: [InstalledPlugin] = []
        for entry in entries.sorted() where !entry.hasSuffix(".json") && !entry.contains(".tmp.") {
            let dir = pluginsRoot.appendingPathComponent(entry)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else { continue }
            let pubURL = dir.appendingPathComponent("signing.key.pub")
            let pubHex: String = {
                guard let data = try? Data(contentsOf: pubURL) else { return "" }
                return data.map { String(format: "%02x", $0) }.joined()
            }()
            results.append(InstalledPlugin(
                pluginID: entry,
                installRoot: dir.path,
                publicKeyHex: pubHex
            ))
        }
        return results
    }

    // MARK: - Trust + revocation lists

    /// A1-03: the trusted-keys list gates SANDBOXED plugin execution, so it is
    /// SIGNED with a per-host P256 key (dedicated `.trusted-keys.signkey`, 0o600,
    /// under the 0o700 plugins root). A same-uid edit that adds a publisher key
    /// without this host's signature fails verification and is rejected — the
    /// list reads as empty (trust nothing) rather than honoring the injected key.
    /// (The operator revoked-keys list keeps its flat form: dropping a revocation
    /// on tamper would fail OPEN — un-revoking — so it is not converted here.)
    private var trustedKeysPath: String {
        pluginsRoot.appendingPathComponent("trusted-keys.json").path
    }

    private var trustedKeysSigner: LocalTrustSigner {
        LocalTrustSigner(keyPath: pluginsRoot.appendingPathComponent(".trusted-keys.signkey"))
    }

    /// Read the SIGNED trusted-keys list. Missing → empty (bootstrap: nothing
    /// trusted yet). A present file that is unsigned (legacy/forged) or fails
    /// verification fails CLOSED to the empty set: an unverifiable trust list
    /// grants no trust, so an install then refuses rather than honoring a key an
    /// attacker slipped in. (Legacy unsigned lists from a pre-A1-03 install read
    /// as empty once — the operator re-trusts via `plugin install --trust`, which
    /// re-seals the list.)
    private func readTrustedKeys() -> Set<String> {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: trustedKeysPath)) else {
            return []
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              LocalTrustSigner.isEnvelope(obj),
              let body = trustedKeysSigner.open(obj),
              let arr = body["keys"] as? [String] else {
            FileHandle.standardError.write(Data(
                "MacCrab: trusted-keys.json integrity check FAILED (unsigned/tampered) at \(trustedKeysPath) — trusting no publisher key (A1-03)\n".utf8
            ))
            return []
        }
        return Set(arr)
    }

    /// Rewrite trusted-keys.json as a host-signed envelope (0o600).
    private func writeTrustedKeys(_ keys: Set<String>) throws {
        let body: [String: Any] = ["keys": keys.sorted()]
        let envelope = try trustedKeysSigner.seal(body: body)
        let data = try JSONSerialization.data(
            withJSONObject: envelope,
            options: [.prettyPrinted, .sortedKeys]
        )
        try data.write(to: URL(fileURLWithPath: trustedKeysPath), options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: trustedKeysPath
        )
    }

    public func currentTrustedKeys() async -> Set<String> {
        readTrustedKeys()
    }

    public func currentRevokedKeys() async -> Set<String> {
        Self.readKeySet(path: pluginsRoot.appendingPathComponent("revoked-keys.json").path)
    }

    public func addTrustedKey(_ keyHex: String) async throws {
        try ensureRoot()
        var keys = readTrustedKeys()
        keys.insert(keyHex)
        try writeTrustedKeys(keys)
        appendTrustAudit(action: "trust", keyHex: keyHex)
    }

    public func removeTrustedKey(_ keyHex: String) async throws {
        try ensureRoot()
        var keys = readTrustedKeys()
        keys.remove(keyHex)
        try writeTrustedKeys(keys)
        appendTrustAudit(action: "untrust", keyHex: keyHex)
    }

    public func revokeKey(_ keyHex: String) async throws {
        try ensureRoot()
        try await Self.mutateKeySet(
            path: pluginsRoot.appendingPathComponent("revoked-keys.json").path
        ) { $0.insert(keyHex) }
        // Removing from trust set is best-effort; revocation alone
        // is sufficient because verify() checks revocation first.
        try? await removeTrustedKey(keyHex)
        appendTrustAudit(action: "revoke", keyHex: keyHex)
    }

    public func unrevokeKey(_ keyHex: String) async throws {
        try ensureRoot()
        try await Self.mutateKeySet(
            path: pluginsRoot.appendingPathComponent("revoked-keys.json").path
        ) { $0.remove(keyHex) }
        appendTrustAudit(action: "unrevoke", keyHex: keyHex)
    }

    /// Append-only, tamper-EVIDENT audit of every trust-list mutation (who
    /// changed what, when), since a trusted key now gates SANDBOXED execution.
    /// `<pluginsRoot>/trust_audit.log`, 0o600. (Full tamper-PROOFING of
    /// trusted-keys.json against a same-uid foothold needs an offline/SE signer
    /// — out of band of the client; documented in the operator runbook. This log
    /// gives the operator a trail + the sandbox keeps a fooled trust contained.)
    private func appendTrustAudit(action: String, keyHex: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date()))\t\(action)\t\(keyHex)\t\(NSUserName())\n"
        let path = pluginsRoot.appendingPathComponent("trust_audit.log").path
        let fm = FileManager.default
        if !fm.fileExists(atPath: path) {
            try? Data().write(to: URL(fileURLWithPath: path))
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        }
        if let fh = FileHandle(forWritingAtPath: path) {
            defer { try? fh.close() }
            _ = try? fh.seekToEnd()
            try? fh.write(contentsOf: Data(line.utf8))
        }
    }

    // MARK: - Remote-revocation quarantine (O2, S2-03/04)

    /// File holding installed plugins quarantined because the rave signed
    /// revocation list (revocations.json) revokes their id+version. This is a
    /// SEPARATE store from `revoked-keys.json`: that list is the operator's
    /// key-hex set (manual + augmented by --revoke), keyed by publisher key;
    /// the remote signed list is keyed by plugin_id+version and AUGMENTS — it
    /// never rewrites — the operator list. Quarantine is non-destructive: a
    /// quarantined plugin is kept on disk (evidence preserved) but refused
    /// load by TierBRegistry.
    ///
    ///   quarantine.json  {"quarantined": {"<plugin-id>": {<record>}, ...}}
    private var quarantinePath: String {
        pluginsRoot.appendingPathComponent("quarantine.json").path
    }

    /// Per-plugin quarantine record. Carries the operator-facing reason so the
    /// dashboard / CLI can explain WHY a plugin stopped running, plus the
    /// signed revocations `serial` that was in effect when it was quarantined
    /// (provenance: "revoked as of serial N").
    public struct QuarantineRecord: Sendable, Equatable {
        public let pluginID: String
        public let installedVersion: String
        public let reason: String
        public let code: String
        public let advisoryURL: String?
        /// The revocations.json serial in effect when quarantined (nil for a
        /// pre-ceremony list with no serial).
        public let revocationsSerial: Int?
        public let quarantinedAt: String

        public init(
            pluginID: String,
            installedVersion: String,
            reason: String,
            code: String,
            advisoryURL: String?,
            revocationsSerial: Int?,
            quarantinedAt: String
        ) {
            self.pluginID = pluginID
            self.installedVersion = installedVersion
            self.reason = reason
            self.code = code
            self.advisoryURL = advisoryURL
            self.revocationsSerial = revocationsSerial
            self.quarantinedAt = quarantinedAt
        }
    }

    /// Current quarantine set (plugin-id → record). Missing/garbage file → empty.
    public func currentQuarantine() async -> [String: QuarantineRecord] {
        Self.readQuarantine(path: quarantinePath)
    }

    /// True iff `pluginID` is currently quarantined by the remote revocation
    /// reconciliation. TierBRegistry consults this before producing a runnable
    /// binary so a revoked-after-install plugin stops running.
    public func isQuarantined(_ pluginID: String) async -> Bool {
        Self.readQuarantine(path: quarantinePath)[pluginID] != nil
    }

    /// Reconcile the quarantine set against a freshly-verified revocation
    /// reconciliation result. NON-DESTRUCTIVE: nothing on disk is deleted —
    /// we only mark/unmark quarantine. Entries no longer revoked (e.g. a
    /// version bump that escapes the scope, or a list that no longer revokes
    /// the id) are un-quarantined so a legitimately-superseded plugin can run
    /// again. Returns the records that are quarantined after reconciliation.
    @discardableResult
    public func applyQuarantine(_ records: [QuarantineRecord]) async throws -> [QuarantineRecord] {
        try ensureRoot()
        let map = Dictionary(uniqueKeysWithValues: records.map { ($0.pluginID, $0) })
        try Self.writeQuarantine(path: quarantinePath, map: map)
        return records
    }

    private static func readQuarantine(path: String) -> [String: QuarantineRecord] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let q = obj["quarantined"] as? [String: [String: Any]] else {
            return [:]
        }
        var out: [String: QuarantineRecord] = [:]
        for (id, rec) in q {
            let installedVersion = (rec["installed_version"] as? String) ?? ""
            let reason = (rec["reason"] as? String) ?? ""
            let code = (rec["code"] as? String) ?? ""
            let advisory = rec["advisory_url"] as? String
            let serial = (rec["revocations_serial"] as? NSNumber)?.intValue
            let at = (rec["quarantined_at"] as? String) ?? ""
            out[id] = QuarantineRecord(
                pluginID: id,
                installedVersion: installedVersion,
                reason: reason,
                code: code,
                advisoryURL: advisory,
                revocationsSerial: serial,
                quarantinedAt: at
            )
        }
        return out
    }

    private static func writeQuarantine(path: String, map: [String: QuarantineRecord]) throws {
        var q: [String: Any] = [:]
        for (id, rec) in map {
            var entry: [String: Any] = [
                "installed_version": rec.installedVersion,
                "reason": rec.reason,
                "code": rec.code,
                "quarantined_at": rec.quarantinedAt,
            ]
            if let s = rec.revocationsSerial { entry["revocations_serial"] = s }
            if let u = rec.advisoryURL { entry["advisory_url"] = u }
            q[id] = entry
        }
        let payload: [String: Any] = ["quarantined": q]
        let data = try JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        )
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path
        )
    }

    private func ensureRoot() throws {
        try FileManager.default.createDirectory(
            at: pluginsRoot,
            withIntermediateDirectories: true
        )
        // pluginsRoot must be 0o700 — only the operator can read
        // or modify it.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: pluginsRoot.path
        )
    }

    /// Walk a directory looking for symlinks. Refuses to install
    /// any bundle that contains one. Symlinks are dangerous in a
    /// signed-bundle context because the verifier reads the
    /// symlink target (cumputing the signature on its bytes),
    /// but the target can be swapped post-install.
    private static func assertNoSymlinks(in dir: URL) throws {
        let fm = FileManager.default
        // Top-level dir itself: don't walk into it if it's a
        // symlink.
        let dirAttrs = try fm.attributesOfItem(atPath: dir.path)
        if (dirAttrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw InstallError.symlinkInSourceBundle(path: dir.path)
        }
        guard let enumerator = fm.enumerator(
            at: dir,
            includingPropertiesForKeys: [.isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else {
            return
        }
        for case let entry as URL in enumerator {
            let attrs = try fm.attributesOfItem(atPath: entry.path)
            let type = attrs[.type] as? FileAttributeType
            if type == .typeSymbolicLink {
                throw InstallError.symlinkInSourceBundle(path: entry.path)
            }
        }
    }

    private static func readKeySet(path: String) -> Set<String> {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let arr = obj["keys"] as? [String] else {
            return []
        }
        return Set(arr)
    }

    private static func mutateKeySet(
        path: String,
        _ change: (inout Set<String>) -> Void
    ) async throws {
        var keys = readKeySet(path: path)
        change(&keys)
        let payload: [String: Any] = ["keys": keys.sorted()]
        let data = try JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        )
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        // Lock to 0o600 — operator-only readable+writable. Trust
        // list contents aren't secret (Ed25519 publics are
        // public), but the *integrity* of the list is part of the
        // security boundary. A world-readable file invites
        // mode-mistake escalation paths.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path
        )
    }

    // MARK: - Version pins (operator-frozen plugins; update-inhibitor ONLY)

    /// File holding operator pins: plugin-id → frozen version. A pin EXCLUDES the
    /// plugin from update offers and refuses auto-update — purely a convenience
    /// for holding a plugin at a known version (e.g. staging / reproducing an
    /// issue). A pin NEVER affects revocation: a pinned plugin that later gets
    /// revoked is STILL quarantined, because the revocation reconcile sweep
    /// (`applyQuarantine` / `reconcileInstalledQuarantine`) ignores pins entirely.
    ///   pinned-versions.json  {"pins": {"<plugin-id>": "<version>", ...}}
    private var pinsPath: String {
        pluginsRoot.appendingPathComponent("pinned-versions.json").path
    }

    /// Current pin map (plugin-id → frozen version). Missing/garbage file → empty.
    public func currentPins() async -> [String: String] {
        Self.readPins(path: pinsPath)
    }

    /// The pinned version for `pluginID`, or nil when unpinned.
    public func pinnedVersion(id: String) async -> String? {
        Self.readPins(path: pinsPath)[id]
    }

    /// Freeze `pluginID` at `version`. Idempotent (overwrites any prior pin).
    public func pinPlugin(id: String, version: String) async throws {
        try ensureRoot()
        try await Self.mutatePins(path: pinsPath) { $0[id] = version }
    }

    /// Remove the pin for `pluginID` (no-op if not pinned).
    public func unpinPlugin(id: String) async throws {
        try ensureRoot()
        try await Self.mutatePins(path: pinsPath) { $0.removeValue(forKey: id) }
    }

    private static func readPins(path: String) -> [String: String] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pins = obj["pins"] as? [String: String] else {
            return [:]
        }
        return pins
    }

    private static func mutatePins(
        path: String,
        _ change: (inout [String: String]) -> Void
    ) async throws {
        var pins = readPins(path: path)
        change(&pins)
        let payload: [String: Any] = ["pins": pins]
        let data = try JSONSerialization.data(
            withJSONObject: payload,
            options: [.prettyPrinted, .sortedKeys]
        )
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: path
        )
    }
}

public struct InstalledPlugin: Sendable {
    public let pluginID: String
    public let installRoot: String
    public let publicKeyHex: String
}
