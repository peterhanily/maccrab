// KeychainDEKVault — production DEKVault backed by macOS Keychain
// Services.
//
// Each case's DEK is stored as a generic-password keychain item
// with service = `com.maccrab.forensics.dek` and account = the
// case id. The item carries an access-control policy that requires
// device-passcode authentication; the OS prompts the operator on
// retrieve.
//
// Plan reference: §10.4 — "DEK wrapped via a Secure-Enclave-backed
// login-keychain item with access control
// kSecAccessControlBiometryAny | .or .devicePasscode |
// .privateKeyUsage." v1.13a-1 ships device-passcode only — Touch
// ID convenience layer lands in v1.13b.

import Foundation
import Security

/// Keychain-backed DEKVault. Construct one per CaseManager; safe
/// to share across cases (the service identifier scopes by case
/// id internally).
public actor KeychainDEKVault: DEKVault {

    /// Keychain service identifier; scopes the generic-password
    /// namespace MacCrab's per-case DEKs live in.
    public static let defaultService = "com.maccrab.forensics.dek"

    private let service: String

    public init(service: String = KeychainDEKVault.defaultService) {
        self.service = service
    }

    public func store(dek: Data, for caseID: String) async throws {
        guard dek.count == 32 else {
            throw DEKVaultError.malformedDEK(actualBytes: dek.count)
        }

        // Build the access control. v1.13a-1 uses device-passcode
        // only. v1.13b will add .biometryAny via a second
        // SecAccessControlCreateWithFlags call.
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.devicePasscode],
            &acError
        ) else {
            let msg = acError.map { String(describing: $0.takeRetainedValue()) } ?? "access control creation failed"
            throw DEKVaultError.osError(status: -1, message: msg)
        }

        // Delete any existing item for this (service, account)
        // first. Keychain's add-or-update semantics don't compose
        // cleanly with SecAccessControl — easier to atomic-replace.
        let deleteQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: caseID,
        ]
        _ = SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: caseID,
            kSecAttrAccessControl: access,
            kSecValueData: dek,
            // Mark synchronizable=false explicitly so this DEK
            // never escapes to iCloud Keychain.
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            throw DEKVaultError.osError(
                status: status,
                message: SecCopyErrorMessageString(status, nil) as String? ?? "SecItemAdd failed"
            )
        }
    }

    public func retrieve(for caseID: String) async throws -> Data {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: caseID,
            kSecReturnData: kCFBooleanTrue as Any,
            kSecMatchLimit: kSecMatchLimitOne,
            // Allow UI to present (otherwise the call returns
            // errSecInteractionNotAllowed when the user-prompt is
            // required).
            kSecUseAuthenticationUI: kSecUseAuthenticationUIAllow,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else {
                throw DEKVaultError.osError(
                    status: -2,
                    message: "Keychain returned non-32-byte DEK"
                )
            }
            return data
        case errSecItemNotFound:
            throw DEKVaultError.notFound(caseID: caseID)
        case errSecUserCanceled, errSecAuthFailed:
            throw DEKVaultError.userCancelled
        case errSecInteractionNotAllowed:
            throw DEKVaultError.osError(
                status: status,
                message: "Auth UI not allowed in this context"
            )
        default:
            throw DEKVaultError.osError(
                status: status,
                message: SecCopyErrorMessageString(status, nil) as String? ?? "SecItemCopyMatching failed (\(status))"
            )
        }
    }

    public func delete(for caseID: String) async throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: caseID,
        ]
        let status = SecItemDelete(query as CFDictionary)
        // errSecItemNotFound is fine — caller may be retrying a
        // deletion. Surface every other error.
        if status != errSecSuccess && status != errSecItemNotFound {
            throw DEKVaultError.osError(
                status: status,
                message: SecCopyErrorMessageString(status, nil) as String? ?? "SecItemDelete failed (\(status))"
            )
        }
    }
}
