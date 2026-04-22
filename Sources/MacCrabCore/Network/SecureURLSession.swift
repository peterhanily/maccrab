// SecureURLSession.swift
// MacCrabCore
//
// Factory for URLSessions with enforced TLS 1.2+ and optional SPKI certificate
// pinning for external API providers. Used by all LLM backends and threat-intel
// API callers to guard against MITM attacks on credentials and alert data.

import Foundation
import CryptoKit
import os.log

// MARK: - Known Providers

/// External API provider identifiers. Each entry carries its hostname and,
/// when available, pinned SHA-256 SPKI hashes (base64-encoded DER).
///
/// ## Adding / updating SPKI pins
///
/// Run the following command against the live server to obtain the current pin:
///
/// ```bash
/// openssl s_client -connect <host>:443 </dev/null 2>/dev/null \
///   | openssl x509 -pubkey -noout \
///   | openssl pkey -pubin -outform DER \
///   | openssl dgst -sha256 -binary \
///   | base64
/// ```
///
/// Pins should be refreshed before each release and whenever a provider
/// rotates their server key.
public enum APIProvider: String, Sendable {
    case anthropic = "api.anthropic.com"
    case openai    = "api.openai.com"
    case gemini    = "generativelanguage.googleapis.com"
    case mistral   = "api.mistral.ai"
    case virustotal = "www.virustotal.com"
    case shodan    = "api.shodan.io"
    case osv       = "api.osv.dev"
    case ollama    = "localhost"   // local — no pinning needed

    /// Known SHA-256 SPKI pins for this provider.
    /// Empty means "no pinning enforced, rely on OS trust store only."
    ///
    /// Each entry is a base64-encoded SHA-256 digest of the SubjectPublicKeyInfo
    /// (SPKI) structure in DER format. The pinning check accepts a match against
    /// ANY certificate in the server's presented chain (leaf OR intermediate CA),
    /// so intermediate CA pins remain valid through normal leaf cert rotation.
    ///
    /// ## Refreshing pins
    ///
    /// Run the following against the live server to obtain current leaf + CA pins:
    ///
    /// ```bash
    /// # Leaf cert SPKI pin:
    /// openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null \
    ///   | openssl x509 -pubkey -noout \
    ///   | openssl pkey -pubin -outform DER \
    ///   | openssl dgst -sha256 -binary | base64
    ///
    /// # Intermediate CA SPKI pin (second cert in chain):
    /// openssl s_client -connect <host>:443 -servername <host> -showcerts </dev/null 2>/dev/null \
    ///   | awk '/-----BEGIN CERTIFICATE-----/{n++} n==2{print} /-----END CERTIFICATE-----/ && n==2{exit}' \
    ///   | openssl x509 -pubkey -noout \
    ///   | openssl pkey -pubin -outform DER \
    ///   | openssl dgst -sha256 -binary | base64
    /// ```
    ///
    /// Leaf pins should be refreshed annually (or when a provider rotates their
    /// certificate). Intermediate CA pins are stable across leaf rotations but
    /// should be verified before each release. Last verified: 2026-04-08.
    var knownSPKIPins: [String] {
        switch self {
        case .anthropic:
            return [
                // Leaf cert — api.anthropic.com (Google Trust Services WE1)
                // Verified 2026-04-08 via openssl s_client
                "j5kESgiKjzimbszCPTJVwS5+IuoZ55eIIsx5UIY5rBk=",
                // Intermediate CA — Google Trust Services WE1
                // Shared by Anthropic, OpenAI, Mistral, Shodan (all GTS WE1)
                "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
            ]
        case .openai:
            return [
                // Leaf cert — api.openai.com (Google Trust Services WE1)
                "xiKNSl8SLMeEvynHDp4SxLxmkAJJf+66AglYicZnjgY=",
                // Intermediate CA — Google Trust Services WE1
                "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
            ]
        case .gemini:
            return [
                // Leaf cert — generativelanguage.googleapis.com (Google Trust Services WR2)
                "Zr9OBQdY/8iuAP5GGyuQROLgBzu6JYE7bBgOqqA2S4U=",
                // Intermediate CA — Google Trust Services WR2
                "YPtHaftLw6/0vnc2BnNKGF54xiCA28WFcccjkA4ypCM=",
            ]
        case .mistral:
            return [
                // Leaf cert — api.mistral.ai (Google Trust Services WE1)
                "H1mh77uO0FxfT226oUXYAQZB2YsPlszbN7wyuPAGKTE=",
                // Intermediate CA — Google Trust Services WE1
                "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
            ]
        case .virustotal:
            return [
                // Leaf cert — www.virustotal.com (Google Trust Services WR3)
                "7BtyalLCzV/bk7EEYAhghT1SqZX+NNW6NIIiRR/cTKs=",
                // Intermediate CA — Google Trust Services WR3
                "OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE=",
            ]
        case .shodan:
            return [
                // Leaf cert — api.shodan.io (Google Trust Services WE1)
                "/0cKVdo1Q3WKkrGy+axY18I8sDv3Di4RIcrvZK6hIvw=",
                // Intermediate CA — Google Trust Services WE1
                "kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=",
            ]
        case .osv:
            return []   // Public open API — OS trust store only
        case .ollama:
            return []   // Local only — no pinning needed
        }
    }
}

// MARK: - SecureURLSession

/// Builds hardened URLSession instances for external API communication.
///
/// Security properties enforced:
/// - TLS 1.2 minimum (blocks negotiation of deprecated TLS 1.0 / 1.1)
/// - SPKI certificate pinning when pins are configured AND
///   `MACCRAB_TLS_PINNING=strict` env var is set (opt-in, since pins require
///   maintenance to stay valid as providers rotate certificates)
/// - Reasonable request/resource timeouts to prevent hung connections
public final class SecureURLSession: NSObject, URLSessionDelegate, @unchecked Sendable {

    private let logger = Logger(subsystem: "com.maccrab", category: "tls")

    /// Whether strict pinning (reject connections with no matching pin) is active.
    /// Requires both `MACCRAB_TLS_PINNING=strict` env var AND the provider having
    /// at least one configured pin in `knownSPKIPins`.
    private let strictPinning: Bool

    /// Expected SPKI SHA-256 hashes (base64) for this session.
    private let expectedPins: Set<String>

    private init(provider: APIProvider) {
        let envPinning = Foundation.ProcessInfo.processInfo.environment["MACCRAB_TLS_PINNING"] == "strict"
        self.expectedPins = Set(provider.knownSPKIPins)
        self.strictPinning = envPinning && !provider.knownSPKIPins.isEmpty
        super.init()
    }

    // MARK: - Factory

    /// Create a secured URLSession for a given API provider.
    ///
    /// - Parameter provider: The target provider. Determines SPKI pins and
    ///   whether strict pinning mode is active.
    /// - Returns: A URLSession configured with TLS 1.2+ and the delegate wired up.
    public static func make(for provider: APIProvider) -> URLSession {
        let delegate = SecureURLSession(provider: provider)
        let config = URLSessionConfiguration.ephemeral
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 120
        // Disable persistent cookies and credential storage for API sessions
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    /// Create a hardened URLSession for user-supplied URLs (webhooks, arbitrary
    /// outbound HTTP) where SPKI pinning can't apply because the endpoint isn't
    /// known in advance.
    ///
    /// Gets the same baseline hardening as the provider-specific factory:
    /// - TLS 1.2+ enforced
    /// - Persistent cookie / credential storage disabled (prevents cross-request
    ///   credential bleed and cookie-based tracking)
    /// - Ephemeral configuration (no on-disk cache)
    /// - Caller-provided timeout and retry budget
    ///
    /// What it does NOT add:
    /// - SPKI pinning (no pin material to check against for user-supplied hosts).
    ///   OS trust store validation still applies.
    ///
    /// - Parameters:
    ///   - timeout: Per-request timeout in seconds.
    ///   - retryBudgetFactor: Multiplier applied to timeout to compute
    ///     `timeoutIntervalForResource`. Set to `retryCount + 1` so the total
    ///     session budget covers all retries.
    /// - Returns: A URLSession with no custom delegate.
    public static func makeGeneric(
        timeout: TimeInterval = 10,
        retryBudgetFactor: Int = 3
    ) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * TimeInterval(max(1, retryBudgetFactor))
        config.waitsForConnectivity = false
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        return URLSession(configuration: config)
    }

    // MARK: - URLSessionDelegate

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Only evaluate server trust challenges
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // Step 1: Standard OS trust evaluation (certificate chain + expiry + revocation)
        var error: CFError?
        let isTrusted = SecTrustEvaluateWithError(serverTrust, &error)
        guard isTrusted else {
            logger.error("TLS: OS trust evaluation failed for \(challenge.protectionSpace.host): \(String(describing: error))")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Step 2: SPKI pinning (only if strict mode is active and we have pins)
        if strictPinning {
            guard spkiMatchesPin(serverTrust: serverTrust) else {
                logger.error("TLS: SPKI pin mismatch for \(challenge.protectionSpace.host) — possible MITM")
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        } else if !expectedPins.isEmpty {
            // Pins configured but strict mode off — log mismatch as a warning
            if !spkiMatchesPin(serverTrust: serverTrust) {
                logger.warning("TLS: SPKI pin mismatch for \(challenge.protectionSpace.host) (non-strict mode — connection allowed)")
            }
        }

        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }

    // MARK: - SPKI Hash Extraction

    /// Returns true if ANY certificate in the server's presented chain has an
    /// SPKI SHA-256 hash matching one of the configured expected pins.
    ///
    /// Checking the full chain (not just the leaf) means intermediate CA pins
    /// remain valid through normal annual leaf certificate rotation, while still
    /// detecting a compromised or substituted certificate authority.
    private func spkiMatchesPin(serverTrust: SecTrust) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              !chain.isEmpty else { return false }
        return chain.contains { cert in
            guard let hash = extractSPKIHash(from: cert) else { return false }
            return expectedPins.contains(hash)
        }
    }

    /// Extracts the SHA-256 hash of the Subject Public Key Info (SPKI) from
    /// a certificate and returns it as a base64-encoded string.
    private func extractSPKIHash(from certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        // Prepend the ASN.1 SPKI header for RSA-2048/ECDSA-256/ECDSA-384 keys.
        // The raw key data from SecKeyCopyExternalRepresentation lacks the
        // AlgorithmIdentifier wrapper that makes it a proper SPKI structure.
        let spkiData = asn1SPKIWrapped(publicKeyData, key: publicKey)
        let digest = SHA256.hash(data: spkiData)
        return Data(digest).base64EncodedString()
    }

    /// Wrap raw key bytes in the minimal ASN.1 SubjectPublicKeyInfo structure.
    /// This matches what OpenSSL produces for the SPKI hash used in pins.
    private func asn1SPKIWrapped(_ keyData: Data, key: SecKey) -> Data {
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any],
              let keyType = attrs[kSecAttrKeyType as String] as? String,
              let keySize = attrs[kSecAttrKeySizeInBits as String] as? Int else {
            return keyData
        }

        // ASN.1 AlgorithmIdentifier headers for common key types
        // RSA:      OID 1.2.840.113549.1.1.1
        // EC P-256: OID 1.2.840.10045.3.1.7
        // EC P-384: OID 1.2.840.10045.3.1.34
        let rsaType = kSecAttrKeyTypeRSA as String
        let ecType  = kSecAttrKeyTypeEC as String
        let header: [UInt8]
        if keyType == rsaType && keySize == 2048 {
            header = [
                0x30, 0x82, 0x01, 0x22,
                0x30, 0x0d,
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00,
                0x03, 0x82, 0x01, 0x0f, 0x00
            ]
        } else if keyType == ecType && keySize == 256 {
            header = [
                0x30, 0x59,
                0x30, 0x13,
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                0x03, 0x42, 0x00
            ]
        } else if keyType == ecType && keySize == 384 {
            header = [
                0x30, 0x76,
                0x30, 0x10,
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
                0x03, 0x62, 0x00
            ]
        } else {
            // Unknown key type — return raw data (pin check will likely fail)
            return keyData
        }

        var spki = Data(header)
        spki.append(keyData)
        return spki
    }
}
