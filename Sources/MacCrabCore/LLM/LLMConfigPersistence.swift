// LLMConfigPersistence.swift
// MacCrabCore
//
// The durable LLM configuration is deliberately split in two:
//   - provider, model, URL, and enablement live in llm_config.json;
//   - API keys live in the shared macOS Keychain access group.
//
// Older releases copied keys into JSON. Every reader goes through this file so
// an upgrade removes those copies before constructing an in-memory LLMConfig.

import Darwin
import Foundation

public enum LLMConfigFileError: Error, CustomStringConvertible {
    case relativePath(String)
    case invalidLeafName(String)
    case notRegularFile(String)
    case multipleHardLinks(String)
    case notOwnedByCurrentUser(String)
    case fileTooLarge(String)
    case invalidJSONObject(String)
    case legacySecretMigrationUnavailable(fields: [String])
    case legacySecretMigrationFailed(provider: String)
    case conflictingLegacySecret(provider: String)
    case io(operation: String, path: String, code: Int32)

    public var description: String {
        switch self {
        case .relativePath(let path):
            return "LLM config path is not absolute: \(path)"
        case .invalidLeafName(let path):
            return "LLM config path has no file name: \(path)"
        case .notRegularFile(let path):
            return "LLM config is not a regular file: \(path)"
        case .multipleHardLinks(let path):
            return "LLM config has multiple hard links and is unsafe to rewrite: \(path)"
        case .notOwnedByCurrentUser(let path):
            return "LLM config is not owned by the current process user: \(path)"
        case .fileTooLarge(let path):
            return "LLM config exceeds the 1 MiB safety limit: \(path)"
        case .invalidJSONObject(let path):
            return "LLM config is not a JSON object: \(path)"
        case .legacySecretMigrationUnavailable(let fields):
            return "LLM config contains \(fields.count) unsupported legacy credential field(s); plaintext config was left unchanged"
        case .legacySecretMigrationFailed(let provider):
            return "LLM legacy credential migration failed for \(provider); plaintext config was left unchanged"
        case .conflictingLegacySecret(let provider):
            return "LLM legacy credential conflicts with the existing Keychain value for \(provider); plaintext config was left unchanged"
        case .io(let operation, let path, let code):
            return "LLM config \(operation) failed for \(path) (errno=\(code))"
        }
    }
}

/// Injected persistence/read-back pair for upgrading legacy JSON credentials.
/// Tests use an in-memory implementation; production factories use the shared
/// Keychain access group. Error values are deliberately discarded by the
/// migration boundary so a hostile/injected error cannot echo a secret.
public struct LLMLegacySecretMigration {
    fileprivate let save: (SecretKey, String) throws -> Void
    fileprivate let readBack: (SecretKey) throws -> String?

    public init(
        save: @escaping (SecretKey, String) throws -> Void,
        readBack: @escaping (SecretKey) throws -> String?
    ) {
        self.save = save
        self.readBack = readBack
    }
}

/// No-secret persistence boundary for `llm_config.json`.
public enum LLMConfigFile {
    public static let legacySecretKeys: Set<String> = [
        "ollama_api_key",
        "claude_api_key",
        "openai_api_key",
        "mistral_api_key",
        "gemini_api_key",
    ]

    private static let maximumBytes = 1_048_576

    private struct OpenedFile {
        let data: Data
        let metadata: stat
    }

    private struct LegacySecretCandidate {
        let field: String
        let value: Any
    }

    private static let legacyFieldToSecretKey: [String: SecretKey] = [
        "ollama_api_key": .ollamaAPIKey,
        "claude_api_key": .claudeAPIKey,
        "openai_api_key": .openaiAPIKey,
        "mistral_api_key": .mistralAPIKey,
        "gemini_api_key": .geminiAPIKey,
    ]

    /// Remove every legacy plaintext API-key field while preserving all other
    /// JSON members, including fields newer binaries do not yet understand.
    public static func sanitizing(_ values: [String: Any]) -> (
        values: [String: Any], removedKeys: Set<String>
    ) {
        var removed: Set<String> = []
        let sanitized = sanitizingObject(values, removedKeys: &removed)
        return (sanitized, removed)
    }

    private static func sanitizingObject(
        _ values: [String: Any],
        removedKeys: inout Set<String>
    ) -> [String: Any] {
        var sanitized: [String: Any] = [:]
        sanitized.reserveCapacity(values.count)
        for (key, value) in values {
            if legacySecretKeys.contains(key) || key.lowercased().hasSuffix("_api_key") {
                removedKeys.insert(key)
                continue
            }
            sanitized[key] = sanitizingValue(value, removedKeys: &removedKeys)
        }
        return sanitized
    }

    private static func sanitizingValue(
        _ value: Any,
        removedKeys: inout Set<String>
    ) -> Any {
        if let object = value as? [String: Any] {
            return sanitizingObject(object, removedKeys: &removedKeys)
        }
        if let array = value as? [Any] {
            return array.map { sanitizingValue($0, removedKeys: &removedKeys) }
        }
        return value
    }

    private static func legacySecretCandidates(in value: Any) -> [LegacySecretCandidate] {
        if let object = value as? [String: Any] {
            return object.flatMap { key, child -> [LegacySecretCandidate] in
                if legacySecretKeys.contains(key) || key.lowercased().hasSuffix("_api_key") {
                    return [LegacySecretCandidate(field: key, value: child)]
                }
                return legacySecretCandidates(in: child)
            }
        }
        if let array = value as? [Any] {
            return array.flatMap { legacySecretCandidates(in: $0) }
        }
        return []
    }

    /// All-or-nothing FILE migration. Individual providers may already have
    /// been durably saved when a later provider fails; in that case the JSON is
    /// intentionally left byte-for-byte unchanged and a rerun is idempotent.
    /// This prevents a partial rewrite from erasing the only surviving copy of
    /// any provider credential.
    private static func migrateLegacySecrets(
        in object: [String: Any],
        using migration: LLMLegacySecretMigration?
    ) throws {
        let candidates = legacySecretCandidates(in: object)
        var expectedValues: [SecretKey: String] = [:]
        var fieldsRequiringMigration: Set<String> = []

        for candidate in candidates {
            // Empty/null legacy slots contain no credential and can be removed
            // without manufacturing a Keychain item.
            if candidate.value is NSNull { continue }
            guard let value = candidate.value as? String else {
                fieldsRequiringMigration.insert(candidate.field)
                continue
            }
            guard !value.isEmpty else { continue }
            fieldsRequiringMigration.insert(candidate.field)
            guard let key = legacyFieldToSecretKey[candidate.field.lowercased()] else {
                continue
            }
            if let prior = expectedValues[key], prior != value {
                throw LLMConfigFileError.conflictingLegacySecret(provider: key.displayName)
            }
            expectedValues[key] = value
        }

        let mappedFields = Set(candidates.compactMap { candidate -> String? in
            guard let value = candidate.value as? String,
                  !value.isEmpty,
                  legacyFieldToSecretKey[candidate.field.lowercased()] != nil
            else { return nil }
            return candidate.field
        })
        let unsupported = fieldsRequiringMigration.subtracting(mappedFields)
        guard unsupported.isEmpty else {
            throw LLMConfigFileError.legacySecretMigrationUnavailable(
                fields: Array(unsupported)
            )
        }
        guard !expectedValues.isEmpty else { return }
        guard let migration else {
            throw LLMConfigFileError.legacySecretMigrationUnavailable(
                fields: Array(fieldsRequiringMigration)
            )
        }

        for (key, expected) in expectedValues.sorted(by: {
            $0.key.rawValue < $1.key.rawValue
        }) {
            let existing: String?
            do { existing = try migration.readBack(key) }
            catch {
                throw LLMConfigFileError.legacySecretMigrationFailed(
                    provider: key.displayName
                )
            }
            if let existing {
                guard existing == expected else {
                    // Keychain is already authoritative; never overwrite a
                    // newer/different credential with a stale JSON copy.
                    throw LLMConfigFileError.conflictingLegacySecret(
                        provider: key.displayName
                    )
                }
                continue
            }
            do {
                try migration.save(key, expected)
                guard try migration.readBack(key) == expected else {
                    throw LLMConfigFileError.legacySecretMigrationFailed(
                        provider: key.displayName
                    )
                }
            } catch is LLMConfigFileError {
                throw LLMConfigFileError.legacySecretMigrationFailed(
                    provider: key.displayName
                )
            } catch {
                throw LLMConfigFileError.legacySecretMigrationFailed(
                    provider: key.displayName
                )
            }
        }
    }

    /// Read a config without ever following a symlink. If legacy secrets are
    /// present and this process owns the file, rewrite that verified no-follow
    /// descriptor with the sanitized object. A non-owner may still consume the
    /// sanitized in-memory view, but must not rewrite/chown another principal's
    /// file; its owning app or daemon performs the on-disk scrub at its own
    /// startup boundary.
    public static func loadAndScrub(
        atPath path: String,
        legacySecretMigration: LLMLegacySecretMigration? = nil,
        onScrubFailure: ((Error) -> Void)? = nil
    ) throws -> [String: Any]? {
        let (directoryFD, leaf) = try openParentDirectory(of: path)
        defer { Darwin.close(directoryFD) }

        guard let opened = try readFile(directoryFD: directoryFD, leaf: leaf, path: path) else {
            return nil
        }
        let object = try decodeObject(opened.data, path: path)
        let result = sanitizing(object)

        guard !result.removedKeys.isEmpty else { return result.values }
        guard isOwnedByEffectiveUser(opened.metadata.st_uid) else {
            onScrubFailure?(LLMConfigFileError.notOwnedByCurrentUser(path))
            return result.values
        }

        do {
            // Save every non-empty provider credential and verify exact
            // read-back before publishing bytes that omit the legacy fields.
            // Any provider failure leaves the original inode untouched.
            try migrateLegacySecrets(in: object, using: legacySecretMigration)
            let data = try JSONSerialization.data(
                withJSONObject: result.values,
                options: [.prettyPrinted, .sortedKeys]
            )
            try secureWrite(
                data,
                directoryFD: directoryFD,
                leaf: leaf,
                path: path,
                replacing: opened.metadata
            )
        } catch {
            // Never re-introduce the legacy value in memory merely because an
            // on-disk cleanup failed. Callers can log the value-free error.
            onScrubFailure?(error)
        }
        return result.values
    }

    /// Strict scrub entry point used by migrations/tests. Unlike
    /// `loadAndScrub`, an inability to rewrite an owned legacy file is surfaced
    /// to the caller as an error.
    @discardableResult
    public static func scrubLegacySecrets(
        atPath path: String,
        using migration: LLMLegacySecretMigration
    ) throws -> Bool {
        let (directoryFD, leaf) = try openParentDirectory(of: path)
        defer { Darwin.close(directoryFD) }
        guard let opened = try readFile(directoryFD: directoryFD, leaf: leaf, path: path) else {
            return false
        }
        guard isOwnedByEffectiveUser(opened.metadata.st_uid) else {
            throw LLMConfigFileError.notOwnedByCurrentUser(path)
        }
        let object = try decodeObject(opened.data, path: path)
        let result = sanitizing(object)
        guard !result.removedKeys.isEmpty else { return false }
        try migrateLegacySecrets(in: object, using: migration)
        let data = try JSONSerialization.data(
            withJSONObject: result.values,
            options: [.prettyPrinted, .sortedKeys]
        )
        try secureWrite(
            data,
            directoryFD: directoryFD,
            leaf: leaf,
            path: path,
            replacing: opened.metadata
        )
        return true
    }

    /// Persist only non-secret fields. Even if a caller accidentally supplies a
    /// legacy key, the serialized bytes never contain its name or value.
    public static func writeNonSecretJSON(
        _ values: [String: Any],
        toPath path: String,
        legacySecretMigration: LLMLegacySecretMigration? = nil,
        options: JSONSerialization.WritingOptions = [.prettyPrinted, .sortedKeys]
    ) throws {
        let sanitized = sanitizing(values).values
        let data = try JSONSerialization.data(withJSONObject: sanitized, options: options)
        let (directoryFD, leaf) = try openParentDirectory(of: path)
        defer { Darwin.close(directoryFD) }

        let existing = try readFile(directoryFD: directoryFD, leaf: leaf, path: path)
        if let existing, !isOwnedByEffectiveUser(existing.metadata.st_uid) {
            throw LLMConfigFileError.notOwnedByCurrentUser(path)
        }
        if let existing {
            let object = try decodeObject(existing.data, path: path)
            if !sanitizing(object).removedKeys.isEmpty {
                try migrateLegacySecrets(in: object, using: legacySecretMigration)
            }
        }
        try secureWrite(
            data,
            directoryFD: directoryFD,
            leaf: leaf,
            path: path,
            replacing: existing?.metadata
        )
    }

    /// Apply the non-secret JSON schema shared by the app, daemon, CLI, and MCP
    /// readers. File presence remains the v1.21.6 upgrade opt-in when the old
    /// file omitted `enabled`.
    public static func applyNonSecretValues(
        _ rawValues: [String: Any],
        to config: inout LLMConfig,
        missingEnabledMeansEnabled: Bool = true
    ) {
        let values = sanitizing(rawValues).values
        if missingEnabledMeansEnabled { config.enabled = true }
        if let enabled = values["enabled"] as? Bool { config.enabled = enabled }
        if let provider = values["provider"] as? String {
            config.provider = LLMProvider(rawValue: provider) ?? config.provider
        }
        if let value = values["ollama_url"] as? String { config.ollamaURL = value }
        if let value = values["ollama_model"] as? String { config.ollamaModel = value }
        if let value = values["claude_model"] as? String { config.claudeModel = value }
        if let value = values["openai_url"] as? String { config.openaiURL = value }
        if let value = values["openai_model"] as? String { config.openaiModel = value }
        if let value = values["mistral_model"] as? String { config.mistralModel = value }
        if let value = values["gemini_model"] as? String { config.geminiModel = value }
    }

    /// Ordered config candidates for unprivileged CLI/MCP readers.
    ///
    /// An explicit data-directory override is hermetic and wins by itself (the
    /// MCP protocol harness must never fall through into the live host). In the
    /// ordinary installed case, Settings' user-owned non-secret file wins; the
    /// data resolver and fixed installed directory are fallbacks. Duplicate
    /// paths are removed without changing order.
    public static func runtimeConfigReadPaths(
        explicitDataDirectory: String?,
        userDataDirectory: String,
        resolvedDataDirectory: String,
        installedDataDirectory: String = "/Library/Application Support/MacCrab"
    ) -> [String] {
        func configPath(in directory: String) -> String {
            directory.hasSuffix("/")
                ? directory + "llm_config.json"
                : directory + "/llm_config.json"
        }

        if let explicitDataDirectory, !explicitDataDirectory.isEmpty {
            return [configPath(in: explicitDataDirectory)]
        }

        var seen: Set<String> = []
        return [userDataDirectory, resolvedDataDirectory, installedDataDirectory]
            .filter { !$0.isEmpty }
            .map(configPath(in:))
            .filter { seen.insert($0).inserted }
    }

    // MARK: - Descriptor-relative, no-follow filesystem operations

    /// Root must not "helpfully" rewrite or chown a user-owned config (and a
    /// user process must not rewrite the root copy). Kept as a pure policy seam
    /// so this remains testable without creating privileged files.
    static func isOwnedByEffectiveUser(
        _ owner: uid_t,
        effectiveUser: uid_t = geteuid()
    ) -> Bool {
        owner == effectiveUser
    }

    private static func openParentDirectory(of path: String) throws -> (Int32, String) {
        guard path.hasPrefix("/") else { throw LLMConfigFileError.relativePath(path) }
        // Do not use NSString.standardizingPath here. On macOS it canonicalizes
        // an EXISTING /private/tmp path to /tmp; /tmp is a symlink, which both
        // defeats the no-follow contract and makes the component walk fail.
        // Walk the caller's absolute components exactly as supplied instead.
        let components = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard let leaf = components.last,
              !path.hasSuffix("/"),
              !components.contains("."),
              !components.contains("..") else {
            throw LLMConfigFileError.invalidLeafName(path)
        }
        let parentComponents = components.dropLast()

        var directoryFD = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else {
            throw LLMConfigFileError.io(operation: "open root directory", path: path, code: errno)
        }
        do {
            for component in parentComponents {
                let nextFD = component.withCString {
                    Darwin.openat(directoryFD, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
                }
                guard nextFD >= 0 else {
                    throw LLMConfigFileError.io(
                        operation: "open parent directory component \(component)",
                        path: path,
                        code: errno
                    )
                }
                Darwin.close(directoryFD)
                directoryFD = nextFD
            }
            return (directoryFD, leaf)
        } catch {
            Darwin.close(directoryFD)
            throw error
        }
    }

    private static func readFile(
        directoryFD: Int32,
        leaf: String,
        path: String
    ) throws -> OpenedFile? {
        let fd = leaf.withCString {
            // O_NONBLOCK is load-bearing: a same-uid attacker can race a FIFO
            // or device into the leaf after path resolution. Open first, then
            // fstat; without nonblocking the open itself can hang forever.
            Darwin.openat(
                directoryFD,
                $0,
                O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw LLMConfigFileError.io(operation: "open", path: path, code: errno)
        }
        defer { Darwin.close(fd) }

        var metadata = stat()
        guard Darwin.fstat(fd, &metadata) == 0 else {
            throw LLMConfigFileError.io(operation: "stat", path: path, code: errno)
        }
        guard (metadata.st_mode & S_IFMT) == S_IFREG else {
            throw LLMConfigFileError.notRegularFile(path)
        }
        guard metadata.st_nlink == 1 else {
            throw LLMConfigFileError.multipleHardLinks(path)
        }
        guard metadata.st_size <= maximumBytes else {
            throw LLMConfigFileError.fileTooLarge(path)
        }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while data.count <= maximumBytes {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(fd, bytes.baseAddress, bytes.count)
            }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw LLMConfigFileError.io(operation: "read", path: path, code: errno)
            }
            data.append(buffer, count: count)
            if data.count > maximumBytes { throw LLMConfigFileError.fileTooLarge(path) }
        }
        return OpenedFile(data: data, metadata: metadata)
    }

    private static func decodeObject(_ data: Data, path: String) throws -> [String: Any] {
        let decoded = try JSONSerialization.jsonObject(with: data)
        guard let object = decoded as? [String: Any] else {
            throw LLMConfigFileError.invalidJSONObject(path)
        }
        return object
    }

    /// Stage SANITIZED bytes in a 0600 no-follow/exclusive same-directory file,
    /// fsync it, verify the destination entry still names the single-link inode
    /// we read, then publish with one atomic rename. The original plaintext
    /// inode is never copied to a temp name, and a crash before rename leaves
    /// the complete old JSON while a crash after rename leaves the complete new
    /// JSON. `renameat` replaces the directory entry itself and never follows a
    /// raced leaf symlink. New files retain no-replace `linkat` publication.
    private static func secureWrite(
        _ data: Data,
        directoryFD: Int32,
        leaf: String,
        path: String,
        replacing metadata: stat?
    ) throws {
        let temporaryLeaf = ".llm-config-\(UUID().uuidString).tmp"
        let temporaryFD = temporaryLeaf.withCString {
            Darwin.openat(
                directoryFD,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard temporaryFD >= 0 else {
            throw LLMConfigFileError.io(operation: "create temporary file", path: path, code: errno)
        }

        var temporaryFDIsOpen = true
        var temporaryExists = true
        defer {
            if temporaryFDIsOpen { Darwin.close(temporaryFD) }
            if temporaryExists {
                temporaryLeaf.withCString { _ = Darwin.unlinkat(directoryFD, $0, 0) }
            }
        }

        let desiredMode: mode_t
        if let metadata {
            // Preserve already-secure owner permissions (including read-only),
            // but never preserve the legacy group/other-readable bits.
            desiredMode = mode_t(metadata.st_mode) & mode_t(0o600)
            guard Darwin.fchown(temporaryFD, metadata.st_uid, metadata.st_gid) == 0 else {
                throw LLMConfigFileError.io(operation: "preserve ownership", path: path, code: errno)
            }
        } else {
            desiredMode = mode_t(0o600)
        }
        guard Darwin.fchmod(temporaryFD, desiredMode) == 0 else {
            throw LLMConfigFileError.io(operation: "set secure permissions", path: path, code: errno)
        }

        try writeAll(data, to: temporaryFD, path: path, operation: "write temporary file")
        guard Darwin.fsync(temporaryFD) == 0 else {
            throw LLMConfigFileError.io(operation: "sync", path: path, code: errno)
        }
        guard Darwin.close(temporaryFD) == 0 else {
            temporaryFDIsOpen = false
            throw LLMConfigFileError.io(operation: "close", path: path, code: errno)
        }
        temporaryFDIsOpen = false

        if let metadata {
            // Pre-publication no-follow entry verification. Requiring nlink=1
            // both here and on the read closes same-uid hardlink substitution.
            var current = stat()
            let status = leaf.withCString {
                Darwin.fstatat(directoryFD, $0, &current, AT_SYMLINK_NOFOLLOW)
            }
            guard status == 0,
                  (current.st_mode & S_IFMT) == S_IFREG,
                  current.st_nlink == 1,
                  current.st_uid == metadata.st_uid,
                  current.st_dev == metadata.st_dev,
                  current.st_ino == metadata.st_ino else {
                throw LLMConfigFileError.io(
                    operation: "verify unchanged destination",
                    path: path,
                    code: status == 0 ? ESTALE : errno
                )
            }

            let renameStatus = temporaryLeaf.withCString { temporaryName in
                leaf.withCString { destinationName in
                    Darwin.renameat(
                        directoryFD,
                        temporaryName,
                        directoryFD,
                        destinationName
                    )
                }
            }
            guard renameStatus == 0 else {
                throw LLMConfigFileError.io(
                    operation: "atomically publish replacement",
                    path: path,
                    code: errno
                )
            }
            temporaryExists = false
        } else {
            // Hard-link publication is atomic and no-replace: EEXIST means a
            // regular file, directory, or symlink won the race. Leave it alone.
            let linkStatus = temporaryLeaf.withCString { temporaryName in
                leaf.withCString { destinationName in
                    Darwin.linkat(directoryFD, temporaryName, directoryFD, destinationName, 0)
                }
            }
            guard linkStatus == 0 else {
                throw LLMConfigFileError.io(operation: "publish new file", path: path, code: errno)
            }
            let unlinkStatus = temporaryLeaf.withCString {
                Darwin.unlinkat(directoryFD, $0, 0)
            }
            guard unlinkStatus == 0 else {
                throw LLMConfigFileError.io(
                    operation: "remove published temporary link",
                    path: path,
                    code: errno
                )
            }
            temporaryExists = false
        }
        guard Darwin.fsync(directoryFD) == 0 else {
            throw LLMConfigFileError.io(
                operation: "sync parent directory",
                path: path,
                code: errno
            )
        }
    }

    private static func writeAll(
        _ data: Data,
        to fileDescriptor: Int32,
        path: String,
        operation: String
    ) throws {
        var written = 0
        try data.withUnsafeBytes { bytes in
            while written < bytes.count {
                let count = Darwin.write(
                    fileDescriptor,
                    bytes.baseAddress?.advanced(by: written),
                    bytes.count - written
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw LLMConfigFileError.io(operation: operation, path: path, code: errno)
                }
                if count == 0 {
                    throw LLMConfigFileError.io(operation: operation, path: path, code: EIO)
                }
                written += count
            }
        }
    }
}

/// Central secret resolution for the daemon, CLI, and MCP entry points.
public enum LLMSecretLoader {
    public enum KeychainInteraction {
        case allowed
        case disallowed
    }

    /// Inject all provider keys with an injectable lookup so tests never touch
    /// the real Keychain. A failure in one slot does not block other providers.
    public static func applyKeychainSecrets(
        to config: inout LLMConfig,
        lookup: (SecretKey) throws -> String?,
        onError: ((SecretKey, Error) -> Void)? = nil
    ) {
        func value(_ key: SecretKey) -> String? {
            do { return try lookup(key) }
            catch {
                onError?(key, error)
                return nil
            }
        }
        if let value = value(.ollamaAPIKey) { config.ollamaAPIKey = value }
        if let value = value(.claudeAPIKey) { config.claudeAPIKey = value }
        if let value = value(.openaiAPIKey) { config.openaiAPIKey = value }
        if let value = value(.mistralAPIKey) { config.mistralAPIKey = value }
        if let value = value(.geminiAPIKey) { config.geminiAPIKey = value }
    }

    public static func applyKeychainSecrets(
        to config: inout LLMConfig,
        store: SecretsStore = SecretsStore(),
        interaction: KeychainInteraction,
        onError: ((SecretKey, Error) -> Void)? = nil
    ) {
        applyKeychainSecrets(
            to: &config,
            lookup: { key in
                switch interaction {
                case .allowed: return try store.get(key)
                case .disallowed: return try store.getNonInteractive(key)
                }
            },
            onError: onError
        )
    }

    /// Environment values are an explicit, ephemeral override and therefore
    /// run after Keychain injection. Returns true when an environment provider
    /// selection was present (CLI/MCP use that as an opt-in signal).
    @discardableResult
    public static func applyEnvironmentOverrides(
        _ environment: [String: String],
        to config: inout LLMConfig,
        trustEnvironmentOllamaURL: Bool = false,
        providerSelectionEnables: Bool = false
    ) -> Bool {
        var selectedProvider = false
        if let value = environment["MACCRAB_LLM_PROVIDER"] {
            config.provider = LLMProvider(rawValue: value) ?? config.provider
            selectedProvider = true
            if providerSelectionEnables { config.enabled = true }
        }
        if let value = environment["MACCRAB_LLM_OLLAMA_URL"] {
            config.ollamaURL = value
            if trustEnvironmentOllamaURL { config.trustLocalEndpoint = true }
        }
        if let value = environment["MACCRAB_LLM_OLLAMA_MODEL"] { config.ollamaModel = value }
        if let value = environment["MACCRAB_LLM_OLLAMA_KEY"] { config.ollamaAPIKey = value }
        if let value = environment["MACCRAB_LLM_CLAUDE_KEY"] { config.claudeAPIKey = value }
        if let value = environment["MACCRAB_LLM_CLAUDE_MODEL"] { config.claudeModel = value }
        if let value = environment["MACCRAB_LLM_OPENAI_URL"] { config.openaiURL = value }
        if let value = environment["MACCRAB_LLM_OPENAI_KEY"] { config.openaiAPIKey = value }
        if let value = environment["MACCRAB_LLM_OPENAI_MODEL"] { config.openaiModel = value }
        if let value = environment["MACCRAB_LLM_MISTRAL_KEY"] { config.mistralAPIKey = value }
        if let value = environment["MACCRAB_LLM_MISTRAL_MODEL"] { config.mistralModel = value }
        if let value = environment["MACCRAB_LLM_GEMINI_KEY"] { config.geminiAPIKey = value }
        if let value = environment["MACCRAB_LLM_GEMINI_MODEL"] { config.geminiModel = value }
        return selectedProvider
    }
}

public extension LLMLegacySecretMigration {
    /// Production migration into the same shared group used by runtime secret
    /// resolution. Background callers choose `.disallowed` so verification can
    /// never raise authentication UI; Settings/CLI may use `.allowed`.
    static func sharedKeychain(
        store: SecretsStore = SecretsStore(),
        interaction: LLMSecretLoader.KeychainInteraction
    ) -> Self {
        Self(
            save: { key, value in
                switch interaction {
                case .allowed: try store.set(key, value: value)
                case .disallowed: try store.setNonInteractive(key, value: value)
                }
            },
            readBack: { key in
                switch interaction {
                case .allowed: return try store.get(key)
                case .disallowed: return try store.getNonInteractive(key)
                }
            }
        )
    }
}
