// TCCInfo.swift
// MacCrabCore
//
// Transparency, Consent, and Control (TCC) permission event metadata.
// macOS-specific; captures grants and revocations of protected resources.

import Foundation

// MARK: - TCCInfo

/// Describes a TCC permission change event.
///
/// On macOS the TCC subsystem mediates access to privacy-sensitive resources
/// such as the camera, microphone, accessibility APIs, and screen capture.
public struct TCCInfo: Codable, Sendable, Hashable {

    /// The TCC service identifier (e.g. `"kTCCServiceAccessibility"`,
    /// `"kTCCServiceScreenCapture"`, `"kTCCServiceMicrophone"`).
    public let service: String

    /// Bundle identifier of the client application that was granted or denied access.
    public let client: String

    /// Full filesystem path of the client application.
    public let clientPath: String

    /// Whether access was granted (`true`) or revoked / denied (`false`).
    public let allowed: Bool

    /// Human-readable reason for the authorization decision
    /// (e.g. `"user_consent"`, `"system_policy"`, `"mdm_policy"`).
    public let authReason: String

    // MARK: Initializer

    public init(
        service: String,
        client: String,
        clientPath: String,
        allowed: Bool,
        authReason: String
    ) {
        self.service = service
        self.client = client
        self.clientPath = clientPath
        self.allowed = allowed
        self.authReason = authReason
    }
}
