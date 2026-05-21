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

    /// Validate a manifest-declared path entry (member of
    /// fileReadSubpaths / fileWriteSubpaths). Rejects newlines /
    /// quotes / parens / control chars that could break out of
    /// SBPL string literals; rejects relative paths; caps length.
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
        // No control chars (newlines, tabs, etc.) — these can
        // close out the SBPL string literal in the profile.
        for scalar in path.unicodeScalars {
            let v = scalar.value
            if v < 0x20 || v == 0x7F || (v >= 0x80 && v <= 0x9F) {
                throw InstallError.invalidPluginID(
                    message: "\(field) entry contains control char U+\(String(v, radix: 16, uppercase: true)): \(path)"
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
    }

    private let pluginsRoot: URL

    public init(pluginsRoot: URL? = nil) {
        if let r = pluginsRoot {
            self.pluginsRoot = r
        } else {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            self.pluginsRoot = support
                .appendingPathComponent("MacCrab")
                .appendingPathComponent("plugins")
                .appendingPathComponent("tier-b")
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

        // Copy bundle into pluginsRoot/<pluginID>/.
        let destURL = pluginsRoot.appendingPathComponent(pluginID)
        if fm.fileExists(atPath: destURL.path) {
            if !force {
                throw InstallError.destinationAlreadyExists(path: destURL.path)
            }
            try? fm.removeItem(at: destURL)
        }
        do {
            try fm.copyItem(at: sourceDir, to: destURL)
        } catch {
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
        for entry in entries.sorted() where !entry.hasSuffix(".json") {
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

    public func currentTrustedKeys() async -> Set<String> {
        Self.readKeySet(path: pluginsRoot.appendingPathComponent("trusted-keys.json").path)
    }

    public func currentRevokedKeys() async -> Set<String> {
        Self.readKeySet(path: pluginsRoot.appendingPathComponent("revoked-keys.json").path)
    }

    public func addTrustedKey(_ keyHex: String) async throws {
        try ensureRoot()
        try await Self.mutateKeySet(
            path: pluginsRoot.appendingPathComponent("trusted-keys.json").path
        ) { $0.insert(keyHex) }
    }

    public func removeTrustedKey(_ keyHex: String) async throws {
        try ensureRoot()
        try await Self.mutateKeySet(
            path: pluginsRoot.appendingPathComponent("trusted-keys.json").path
        ) { $0.remove(keyHex) }
    }

    public func revokeKey(_ keyHex: String) async throws {
        try ensureRoot()
        try await Self.mutateKeySet(
            path: pluginsRoot.appendingPathComponent("revoked-keys.json").path
        ) { $0.insert(keyHex) }
        // Removing from trust set is best-effort; revocation alone
        // is sufficient because verify() checks revocation first.
        try? await removeTrustedKey(keyHex)
    }

    public func unrevokeKey(_ keyHex: String) async throws {
        try ensureRoot()
        try await Self.mutateKeySet(
            path: pluginsRoot.appendingPathComponent("revoked-keys.json").path
        ) { $0.remove(keyHex) }
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
}

public struct InstalledPlugin: Sendable {
    public let pluginID: String
    public let installRoot: String
    public let publicKeyHex: String
}
