// DEKVault — abstraction over the storage layer that wraps each
// case's data-encryption key (DEK).
//
// Production path: KeychainDEKVault, which stores the DEK as a
// generic password Keychain item bound to device-passcode auth
// (Touch ID convenience layer arrives in v1.13b — see plan §10.4).
//
// Test path: InMemoryDEKVault, which keeps the DEK in process
// memory only and never prompts. Tests use it to exercise
// CaseManager behavior without the macOS authentication UI.
//
// Plan reference: §10.4 (encryption design + DEK caching scope).

import Foundation

/// Abstract DEK vault. The caller (CaseManager) never sees the
/// implementation details — for production it talks to the
/// macOS keychain; for tests it talks to an in-memory map.
public protocol DEKVault: Sendable {

    /// Persist a 32-byte AES-256 DEK for the given case. Replaces
    /// any existing wrapped key for that case id. Production
    /// implementations bind the entry to user authentication;
    /// callers must be running in a context where the macOS auth
    /// UI can present.
    func store(dek: Data, for caseID: String) async throws

    /// Retrieve the DEK for a case. Production implementations
    /// prompt the operator for device-passcode auth before
    /// returning. Tests never prompt.
    ///
    /// Throws `DEKVaultError.userCancelled` if the operator
    /// dismisses the prompt; `DEKVaultError.notFound` if the case
    /// has no wrapped DEK on file; `DEKVaultError.lockout` if the
    /// underlying OS keychain reports its own retry lockout (macOS
    /// Keychain Services / Secure Enclave throttle passcode and
    /// biometry retries — MacCrab does not layer an app-side
    /// attempt counter on top).
    func retrieve(for caseID: String) async throws -> Data

    /// Remove the wrapped DEK. Called by CaseManager.deleteCase()
    /// so a deleted case's vault entry doesn't linger.
    func delete(for caseID: String) async throws
}

/// DEKVault errors. Mapped at the CLI / dashboard layer to
/// operator-facing messages.
public enum DEKVaultError: Error, CustomStringConvertible, Equatable {

    /// No wrapped DEK exists for this case id.
    case notFound(caseID: String)

    /// Operator dismissed the auth prompt.
    case userCancelled

    /// The OS keychain surfaced its own auth-retry lockout. macOS
    /// throttles passcode/biometry retries at the Secure-Enclave
    /// level; MacCrab forwards that state rather than counting
    /// attempts itself. Cleared by the OS retry-cooldown.
    case lockout

    /// Underlying keychain / OS call failed for a reason not
    /// otherwise classified.
    case osError(status: Int32, message: String)

    /// Caller supplied a key of an unexpected size. The platform
    /// requires 32 bytes (AES-256 raw).
    case malformedDEK(actualBytes: Int)

    public var description: String {
        switch self {
        case .notFound(let id):
            return "DEKVault: no wrapped DEK for case '\(id)'"
        case .userCancelled:
            return "DEKVault: operator cancelled the auth prompt"
        case .lockout:
            return "DEKVault: keychain auth is temporarily locked out; wait for the OS retry cooldown"
        case .osError(let status, let message):
            return "DEKVault: OS error \(status): \(message)"
        case .malformedDEK(let bytes):
            return "DEKVault: DEK must be 32 bytes; got \(bytes)"
        }
    }
}

/// In-memory DEKVault. Use ONLY in tests — never persists, never
/// authenticates, never decreases the security posture of a real
/// case. The CLI / app paths construct a KeychainDEKVault instead.
public actor InMemoryDEKVault: DEKVault {
    private var store: [String: Data] = [:]

    public init(seed: [String: Data] = [:]) {
        self.store = seed
    }

    public func store(dek: Data, for caseID: String) async throws {
        guard dek.count == 32 else {
            throw DEKVaultError.malformedDEK(actualBytes: dek.count)
        }
        store[caseID] = dek
    }

    public func retrieve(for caseID: String) async throws -> Data {
        guard let d = store[caseID] else {
            throw DEKVaultError.notFound(caseID: caseID)
        }
        return d
    }

    public func delete(for caseID: String) async throws {
        store.removeValue(forKey: caseID)
    }
}
