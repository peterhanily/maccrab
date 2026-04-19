// SecretsStore.swift
// MacCrabCore
//
// Keychain-backed storage for API keys, bearer tokens, and anything else
// that shouldn't sit in plaintext on disk or in the process environment.
//
// # Why
//
// Before v1.3.5, API keys lived in two places:
//   - `$MACCRAB_LLM_CLAUDE_KEY` (and friends) — shell env, inherited by every
//     child, visible in `ps e`, exportable via crash reports.
//   - `~/Library/Application Support/MacCrab/llm_config.json` — plaintext
//     JSON on disk with default file perms (0644 on first write — any other
//     user-level process can read).
//
// Neither is encrypted. Neither is scoped to MacCrab as the accessor.
// The macOS Keychain solves both: items are encrypted at rest under the
// user's login password (or Secure Enclave-wrapped where available) and
// only processes with a matching code-signing identity + access group can
// read them.
//
// # Current sysext gap
//
// The sysext runs under `sysextd`, which is NOT the user's login session,
// so it cannot read user-login keychain items by default. To close that
// gap the sysext and the app need a shared `keychain-access-groups`
// entitlement — which requires Apple to re-provision the ES profile.
// That's a follow-up. For now, the sysext continues to read API keys
// from the legacy env vars / llm_config.json paths the Dashboard
// writes alongside its Keychain updates.

import Foundation
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

    /// Optional `kSecAttrAccessGroup`. Defaults to nil (item is visible
    /// only to this signing identity). Set to `"79S425CW99.com.maccrab.shared"`
    /// once the `keychain-access-groups` entitlement is provisioned, to
    /// let the sysext read items written by the dashboard.
    public let accessGroup: String?

    public init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    /// Base query every SecItem* call starts from.
    private func baseQuery(for key: SecretKey) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: key.rawValue,
        ]
        if let group = accessGroup { q[kSecAttrAccessGroup as String] = group }
        return q
    }

    // MARK: get / set / delete / exists

    /// Read the stored value for `key`. Returns `nil` if no item exists;
    /// throws for any other error so callers can distinguish "not set"
    /// from "Keychain is sulking".
    public func get(_ key: SecretKey) throws -> String? {
        var q = baseQuery(for: key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let str = String(data: data, encoding: .utf8) else {
                throw SecretsStoreError.decodingFailed
            }
            return str
        case errSecItemNotFound:
            return nil
        default:
            throw SecretsStoreError.osStatus(status)
        }
    }

    /// Write `value` for `key`, overwriting any existing item atomically.
    /// Passing an empty string deletes the item — treating "" as "unset"
    /// is the behaviour every UI callsite wants and matches how the
    /// SecureField onChange handler typically fires.
    public func set(_ key: SecretKey, value: String) throws {
        if value.isEmpty {
            try delete(key)
            return
        }
        guard let data = value.data(using: .utf8) else {
            throw SecretsStoreError.decodingFailed
        }

        // Try update first — most writes are overwrites, and update is cheaper
        // than delete+add (which briefly leaves the key absent on disk).
        let updateStatus = SecItemUpdate(
            baseQuery(for: key) as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess { return }

        // Not present yet — add.
        if updateStatus == errSecItemNotFound {
            var q = baseQuery(for: key)
            q[kSecValueData as String] = data
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

            let addStatus = SecItemAdd(q as CFDictionary, nil)
            if addStatus == errSecSuccess { return }
            throw SecretsStoreError.osStatus(addStatus)
        }

        throw SecretsStoreError.osStatus(updateStatus)
    }

    /// Delete any existing item for `key`. No-op if the item doesn't exist.
    public func delete(_ key: SecretKey) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
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
        let status = SecItemCopyMatching(q as CFDictionary, nil)
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
