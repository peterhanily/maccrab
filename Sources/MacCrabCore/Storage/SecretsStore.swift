// SecretsStore.swift
// MacCrabCore
//
// Keychain-backed storage for API keys, bearer tokens, and anything else
// that shouldn't sit in plaintext on disk or in the process environment.
//
// Queries use the service/account namespace below and an optional access-group
// attribute. This wrapper retains macOS's default file-based Keychain backend;
// it does not request the data-protection Keychain. Actual access depends on
// each process's Keychain context, search list and item ACL. Declaring the same
// access-group entitlement alone does not establish GUI/root/CLI/MCP sharing.
//
// Callers use this wrapper for persistent credentials. llm_config.json and the
// privileged-inbox bridge carry non-secret provider/model/URL settings only.
// Background callers request non-interactive access so authorization denial is
// returned instead of prompting; their credential access remains subject to
// the backend and ACL checks above.

import Foundation
import LocalAuthentication
import Security

// MARK: - SecretKey

/// Every secret the dashboard / CLI knows how to read from the Keychain.
///
/// The rawValue is stored in `kSecAttrAccount` — stable across versions
/// so we don't accidentally orphan existing Keychain items when we rename
/// an enum case.
public enum SecretKey: String, CaseIterable, Sendable {
    // LLM backends
    case claudeAPIKey  = "llm.claude"
    case openaiAPIKey  = "llm.openai"
    case geminiAPIKey  = "llm.gemini"
    case mistralAPIKey = "llm.mistral"
    case ollamaAPIKey  = "llm.ollama"       // optional — hosted Ollama endpoints

    // Threat intelligence
    case abuseCHAuthKey = "threatintel.abusech"
    case virusTotalKey = "threatintel.virustotal"
    case abuseIPDBKey  = "threatintel.abuseipdb"
    case alienVaultKey = "threatintel.alienvault"
    case shodanKey     = "threatintel.shodan"
    case urlScanKey    = "threatintel.urlscan"
    case greyNoiseKey  = "threatintel.greynoise"
    case haveIBeenPwnedKey = "threatintel.hibp"

    // Output transports (Splunk HEC, Datadog, etc. are resolved via tokenEnv
    // today; stored here when a future UI lets the user enter them directly)
    case splunkHECToken = "output.splunk_hec"
    case datadogAPIKey  = "output.datadog"
    case esAuthHeader   = "output.elasticsearch"

    /// Human-readable label for Settings UI and audit logging. Never shows
    /// the secret value itself.
    public var displayName: String {
        switch self {
        case .claudeAPIKey:       return "Anthropic Claude"
        case .openaiAPIKey:       return "OpenAI"
        case .geminiAPIKey:       return "Google Gemini"
        case .mistralAPIKey:      return "Mistral"
        case .ollamaAPIKey:       return "Ollama (hosted)"
        case .abuseCHAuthKey:     return "abuse.ch"
        case .virusTotalKey:      return "VirusTotal"
        case .abuseIPDBKey:       return "AbuseIPDB"
        case .alienVaultKey:      return "AlienVault OTX"
        case .shodanKey:          return "Shodan"
        case .urlScanKey:         return "URLScan.io"
        case .greyNoiseKey:       return "GreyNoise"
        case .haveIBeenPwnedKey:  return "Have I Been Pwned"
        case .splunkHECToken:     return "Splunk HEC"
        case .datadogAPIKey:      return "Datadog"
        case .esAuthHeader:       return "Elasticsearch"
        }
    }
}

// MARK: - Errors

public enum SecretsStoreError: Error, CustomStringConvertible {
    /// Keychain Services returned a non-success OSStatus. Wraps the raw
    /// status so callers can surface it; no human string because most of
    /// the time we want to log it and move on.
    case osStatus(OSStatus)
    /// Stored value couldn't be decoded as UTF-8. Practically never fires —
    /// the set() path only writes UTF-8 — but the API is defensive so a
    /// hand-edited Keychain item doesn't crash the process.
    case decodingFailed

    public var description: String {
        switch self {
        case .osStatus(let s):   return "SecretsStore Keychain error OSStatus=\(s)"
        case .decodingFailed:    return "SecretsStore: stored value is not UTF-8"
        }
    }
}

// Internal operation boundary for deterministic tests; production uses Security.framework.
// No test needs to query or mutate the user's Keychain to verify query scope.
struct SecretsStoreKeychainOperations: Sendable {
    var copyMatching: @Sendable ([String: Any], UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    var update: @Sendable ([String: Any], [String: Any]) -> OSStatus
    var add: @Sendable ([String: Any]) -> OSStatus
    var delete: @Sendable ([String: Any]) -> OSStatus

    static let system = Self(
        copyMatching: { SecItemCopyMatching($0 as CFDictionary, $1) },
        update: { SecItemUpdate($0 as CFDictionary, $1 as CFDictionary) },
        add: { SecItemAdd($0 as CFDictionary, nil) },
        delete: { SecItemDelete($0 as CFDictionary) }
    )
}

// MARK: - SecretsStore

/// Typed wrapper over `SecItemAdd` / `SecItemCopyMatching` / `SecItemUpdate`
/// / `SecItemDelete` for the secrets MacCrab needs to manage.
///
/// The store is stateless — it holds no handles and is cheap to copy.
/// The underlying Keychain access is thread-safe; callers can use the
/// store from any queue.
public struct SecretsStore: Sendable {

    /// Keychain service name shared by every item this store manages.
    /// Namespaced so the db-encryption and future features don't collide.
    public static let service = "com.maccrab.secrets"

    /// Default access-group attribute requested by callers. Its entitlement
    /// does not by itself prove access across process or user contexts; the
    /// selected Keychain backend and item ACL determine actual access.
    public static let defaultAccessGroup = "79S425CW99.com.maccrab.shared"

    /// Optional `kSecAttrAccessGroup` query attribute. Passing nil omits it;
    /// omission is not a test isolation boundary. Tests also need a unique
    /// service namespace.
    public let accessGroup: String?

    /// Instance service namespace. Production defaults remain unchanged;
    /// callers that require isolated storage must provide a separate service.
    public let serviceNamespace: String
    private let keychain: SecretsStoreKeychainOperations

    public init(
        accessGroup: String? = SecretsStore.defaultAccessGroup,
        service: String = SecretsStore.service
    ) {
        self.init(accessGroup: accessGroup, service: service, keychain: .system)
    }

    init(accessGroup: String?, service: String, keychain: SecretsStoreKeychainOperations) {
        self.accessGroup = accessGroup
        self.serviceNamespace = service
        self.keychain = keychain
    }

    /// Base query every SecItem* call starts from.
    private func baseQuery(for key: SecretKey) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: serviceNamespace,
            kSecAttrAccount as String: key.rawValue,
        ]
        if let group = accessGroup { q[kSecAttrAccessGroup as String] = group }
        return q
    }

    // MARK: get / set / delete / exists

    /// Read the stored value for `key`. Returns `nil` if no item exists;
    /// throws for any other error so callers can distinguish "not set"
    /// from "Keychain is sulking".
    ///
    /// v1.8.1 migration: if a with-group lookup misses AND we have a
    /// non-nil access group AND a without-group item exists, return its
    /// value AND silently rewrite it with-group so the next read finds
    /// it through the fast path. Preserve the original item: omitting an
    /// access group searches broadly, so it cannot identify an old-only item.
    public func get(_ key: SecretKey) throws -> String? {
        try get(key, migrateLegacy: true)
    }

    /// Read without allowing Keychain Services to display authentication UI.
    /// Background engine and MCP processes use this path: a locked/denied item
    /// degrades to the caller's fallback rather than hanging on a prompt. The
    /// pre-access-group migration is intentionally skipped because it performs
    /// a write and is owned by the interactive dashboard/CLI path.
    public func getNonInteractive(_ key: SecretKey) throws -> String? {
        let context = LAContext()
        context.interactionNotAllowed = true
        return try get(key, authenticationContext: context, migrateLegacy: false)
    }

    private func get(
        _ key: SecretKey,
        authenticationContext: LAContext? = nil,
        migrateLegacy: Bool
    ) throws -> String? {
        var q = baseQuery(for: key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        if let authenticationContext {
            q[kSecUseAuthenticationContext as String] = authenticationContext
        }

        var result: AnyObject?
        let status = keychain.copyMatching(q, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let str = String(data: data, encoding: .utf8) else {
                throw SecretsStoreError.decodingFailed
            }
            return str
        case errSecItemNotFound:
            // v1.8.1 access-group migration: if we're claiming a group,
            // an item written pre-v1.8.1 (without the group) won't match
            // the with-group query. Try the without-group lookup and
            // rewrite if found.
            if migrateLegacy, accessGroup != nil {
                if let migrated = try migrateLegacyItem(for: key) {
                    return migrated
                }
            }
            return nil
        default:
            throw SecretsStoreError.osStatus(status)
        }
    }

    /// Look up the item WITHOUT the access group. If found, rewrite it
    /// with the group attached and preserve the original entry. An unscoped
    /// query can also match the destination; it is not a safe deletion selector.
    /// Returns the copied value, or nil if no legacy item exists.
    private func migrateLegacyItem(for key: SecretKey) throws -> String? {
        let legacyQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: serviceNamespace,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]
        // No accessGroup attribute — a broad compatibility lookup, not an old-item identity.
        var result: AnyObject?
        let status = keychain.copyMatching(legacyQuery, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        // Rewrite with group attached. set() handles add-or-update.
        try set(key, value: str)
        // Retain the source. Without an exact, distinct old-item identity,
        // deletion could remove the destination just written (or another match).
        // This also preserves the item when the backend aliases grouped and
        // ungrouped queries. Do not change the production keychain backend here.
        return str
    }

    /// Write `value` for `key`, overwriting any existing item atomically.
    /// Passing an empty string deletes the item — treating "" as "unset"
    /// is the behaviour every UI callsite wants and matches how the
    /// SecureField onChange handler typically fires.
    public func set(_ key: SecretKey, value: String) throws {
        try set(key, value: value, authenticationContext: nil)
    }

    /// Write without allowing Keychain Services to display authentication UI.
    /// Root-engine and MCP legacy-file migrations use this path: if the item
    /// requires user presence, the operation fails with
    /// `errSecInteractionNotAllowed` and the plaintext source file remains
    /// byte-for-byte intact for a later interactive migration.
    public func setNonInteractive(_ key: SecretKey, value: String) throws {
        let context = LAContext()
        context.interactionNotAllowed = true
        try set(key, value: value, authenticationContext: context)
    }

    private func set(
        _ key: SecretKey,
        value: String,
        authenticationContext: LAContext?
    ) throws {
        if value.isEmpty {
            try delete(key, authenticationContext: authenticationContext)
            return
        }
        guard let data = value.data(using: .utf8) else {
            throw SecretsStoreError.decodingFailed
        }

        // Try update first — most writes are overwrites, and update is cheaper
        // than delete+add (which briefly leaves the key absent on disk).
        //
        // v1.8.0: also pass kSecAttrAccessible on update so an item created
        // by an older / buggier version with weaker accessibility (e.g. the
        // pre-fix DatabaseEncryption used …AfterFirstUnlock instead of
        // …AfterFirstUnlockThisDeviceOnly) gets tightened on next write.
        // Without this, accessibility tightening only happens on add and a
        // stale weak-acl item could persist indefinitely on the user's machine.
        var updateQuery = baseQuery(for: key)
        if let authenticationContext {
            updateQuery[kSecUseAuthenticationContext as String] = authenticationContext
        }
        let updateStatus = keychain.update(
            updateQuery,
            [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
        )
        if updateStatus == errSecSuccess { return }

        // Not present yet — add.
        if updateStatus == errSecItemNotFound {
            var q = baseQuery(for: key)
            q[kSecValueData as String] = data
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            if let authenticationContext {
                q[kSecUseAuthenticationContext as String] = authenticationContext
            }

            let addStatus = keychain.add(q)
            if addStatus == errSecSuccess { return }
            throw SecretsStoreError.osStatus(addStatus)
        }

        throw SecretsStoreError.osStatus(updateStatus)
    }

    /// Delete all accessible entries for this service/account, including legacy
    /// entries the compatibility lookup can read. Otherwise a later get() could
    /// copy a retained legacy value back after deletion. Other services and
    /// accounts are outside this scope. No-op if no matching item exists.
    public func delete(_ key: SecretKey) throws {
        try delete(key, authenticationContext: nil)
    }

    private func delete(
        _ key: SecretKey,
        authenticationContext: LAContext?
    ) throws {
        var query = baseQuery(for: key)
        // Explicit deletion targets the same logical key as the broad legacy
        // lookup. This is never used to clean up a source during migration.
        query.removeValue(forKey: kSecAttrAccessGroup as String)
        // File-based macOS Keychain defaults to one match, unlike the data-
        // protection backend. Specify all so a retained legacy copy cannot
        // survive a successful deletion and later be migrated back.
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }
        let status = keychain.delete(query)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw SecretsStoreError.osStatus(status)
        }
    }

    /// Cheap "does an item exist for this key" check without returning its
    /// value. Useful for Settings UIs that show "●●●●●●●" when a key is
    /// stored so the user doesn't re-type it, and "not set" when it isn't.
    public func exists(_ key: SecretKey) -> Bool {
        var q = baseQuery(for: key)
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecReturnData as String] = false  // don't decrypt if we don't need to
        let status = keychain.copyMatching(q, nil)
        return status == errSecSuccess
    }

    /// Delete every secret this store manages. Used by the uninstall
    /// script and "reset" flows. Swallows per-key failures because the
    /// operation is idempotent — partial cleanup is still better than
    /// nothing.
    public func deleteAll() {
        for key in SecretKey.allCases {
            try? delete(key)
        }
    }

    /// List which keys currently have a stored value. Returns display-safe
    /// enum cases only — never secret material.
    public func storedKeys() -> [SecretKey] {
        SecretKey.allCases.filter { exists($0) }
    }
}
