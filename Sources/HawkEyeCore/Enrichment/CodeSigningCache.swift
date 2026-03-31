// CodeSigningCache.swift
// HawkEyeCore
//
// Caches code-signing evaluation results keyed by binary path.
// Actual evaluation uses the macOS Security framework (SecStaticCode*),
// which is expensive; caching avoids repeated calls for the same binary.

import Foundation
import Security

// MARK: - CodeSigningCache

/// Thread-safe cache and evaluator for code-signing information.
///
/// Wraps `NSCache` for automatic eviction under memory pressure and
/// provides an `evaluate(path:)` method that transparently checks the
/// cache before falling back to the Security framework.
public actor CodeSigningCache {

    // MARK: Internal wrapper

    /// `NSCache` requires reference-type values, so we box the struct.
    private final class CachedEntry: NSObject {
        let info: CodeSignatureInfo
        init(_ info: CodeSignatureInfo) { self.info = info }
    }

    // MARK: Storage

    /// Underlying LRU cache. `NSCache` is thread-safe on its own but we
    /// access it exclusively through the actor to keep the API consistent.
    private let cache: NSCache<NSString, CachedEntry>

    private var cacheHits: Int = 0
    private var cacheMisses: Int = 0

    public func stats() -> (hits: Int, misses: Int, hitRate: Double) {
        let total = cacheHits + cacheMisses
        return (cacheHits, cacheMisses, total > 0 ? Double(cacheHits) / Double(total) : 0)
    }

    // MARK: Initialization

    /// Creates a new code-signing cache.
    ///
    /// - Parameter countLimit: Maximum number of entries to retain.
    ///   Defaults to 8192.
    public init(countLimit: Int = 8192) {
        self.cache = NSCache<NSString, CachedEntry>()
        self.cache.countLimit = countLimit
    }

    // MARK: Direct access

    /// Look up a previously cached result.
    ///
    /// - Parameter path: Absolute path to the binary on disk.
    /// - Returns: The cached `CodeSignatureInfo`, or `nil` on a cache miss.
    public func lookup(path: String) -> CodeSignatureInfo? {
        cache.object(forKey: path as NSString)?.info
    }

    /// Store a code-signing result in the cache.
    ///
    /// - Parameters:
    ///   - path: Absolute path to the binary on disk.
    ///   - info: The signing information to cache.
    public func store(path: String, info: CodeSignatureInfo) {
        cache.setObject(CachedEntry(info), forKey: path as NSString)
    }

    // MARK: Evaluate

    /// Evaluate code signing for a binary, using the cache when possible.
    ///
    /// On a cache miss the method calls into the Security framework to
    /// create a static code reference, validate it, and extract signing
    /// details. The result is cached before being returned.
    ///
    /// - Parameter path: Absolute path to the binary on disk.
    /// - Returns: Signing information for the binary.
    public func evaluate(path: String) -> CodeSignatureInfo {
        // 1. Cache hit — fast path.
        if let cached = lookup(path: path) {
            cacheHits += 1
            return cached
        }

        // 2. Cache miss — perform Security framework evaluation.
        cacheMisses += 1
        let info = performEvaluation(path: path)
        store(path: path, info: info)
        return info
    }

    // MARK: Security framework evaluation

    /// Perform the actual SecStaticCode evaluation.
    ///
    /// This is intentionally a synchronous, non-isolated helper. All
    /// Security framework calls happen on the actor's serial executor.
    private func performEvaluation(path: String) -> CodeSignatureInfo {
        let url = URL(fileURLWithPath: path) as CFURL

        // --- Create static code reference ---
        var staticCodeRef: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, [], &staticCodeRef)

        guard createStatus == errSecSuccess, let staticCode = staticCodeRef else {
            return CodeSignatureInfo(signerType: .unsigned)
        }

        // --- Check validity (don't fail hard; we still want partial info) ---
        let validityFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        let validStatus = SecStaticCodeCheckValidity(staticCode, validityFlags, nil)
        let isValid = (validStatus == errSecSuccess)

        // --- Copy signing information ---
        var infoDict: CFDictionary?
        let infoFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        let copyStatus = SecCodeCopySigningInformation(staticCode, infoFlags, &infoDict)

        guard copyStatus == errSecSuccess, let dict = infoDict as? [String: Any] else {
            return CodeSignatureInfo(signerType: isValid ? .adHoc : .unsigned)
        }

        // --- Extract fields ---
        let teamId = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let signingId = dict[kSecCodeInfoIdentifier as String] as? String
        let flags = dict[kSecCodeInfoFlags as String] as? UInt32 ?? 0

        // Certificate authority chain.
        var authorities: [String] = []
        if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate] {
            for cert in certs {
                var commonName: CFString?
                if SecCertificateCopyCommonName(cert, &commonName) == errSecSuccess,
                   let cn = commonName as String? {
                    authorities.append(cn)
                }
            }
        }

        // --- Determine signer type via SecRequirement checks ---
        let signerType = determineSignerType(staticCode: staticCode, isValid: isValid, flags: flags)

        // --- Check notarization (ticket stapled or notarization flag in flags) ---
        let isNotarized = checkNotarization(staticCode: staticCode)

        return CodeSignatureInfo(
            signerType: signerType,
            teamId: teamId,
            signingId: signingId,
            authorities: authorities,
            flags: flags,
            isNotarized: isNotarized
        )
    }

    /// Determine the signer type by testing the code against known requirements.
    ///
    /// Checks in order of specificity:
    /// 1. `"anchor apple"` -- Apple first-party.
    /// 2. App Store requirement (leaf CN = "Apple Mac OS Application Signing").
    /// 3. `"anchor apple generic"` -- Developer ID.
    /// 4. Falls back to `.adHoc` (valid but no Apple anchor) or `.unsigned`.
    private func determineSignerType(
        staticCode: SecStaticCode,
        isValid: Bool,
        flags: UInt32
    ) -> SignerType {
        guard isValid else {
            return .unsigned
        }

        // Apple first-party: "anchor apple"
        if satisfiesRequirement(staticCode: staticCode, requirement: "anchor apple") {
            return .apple
        }

        // Mac App Store: leaf certificate CN identifies App Store distribution.
        let appStoreReq =
            "anchor apple generic and certificate leaf[subject.CN] = " +
            "\"Apple Mac OS Application Signing\""
        if satisfiesRequirement(staticCode: staticCode, requirement: appStoreReq) {
            return .appStore
        }

        // Developer ID: signed with an Apple-issued Developer ID certificate.
        if satisfiesRequirement(staticCode: staticCode, requirement: "anchor apple generic") {
            return .devId
        }

        // Code is validly signed but not by any Apple-rooted chain.
        return .adHoc
    }

    /// Test whether a static code object satisfies a textual requirement string.
    private func satisfiesRequirement(staticCode: SecStaticCode, requirement: String) -> Bool {
        var reqRef: SecRequirement?
        guard SecRequirementCreateWithString(
            requirement as CFString,
            [],
            &reqRef
        ) == errSecSuccess, let req = reqRef else {
            return false
        }

        return SecStaticCodeCheckValidity(staticCode, [], req) == errSecSuccess
    }

    /// Check whether the binary has a notarization ticket stapled.
    ///
    /// Uses `SecStaticCodeCheckValidity` with the notarization requirement.
    /// A stapled ticket does not guarantee Apple's server-side check passed,
    /// but it is the best offline signal available.
    private func checkNotarization(staticCode: SecStaticCode) -> Bool {
        // The notarized requirement checks for a stapled ticket.
        let notarizedReq =
            "notarized"
        var reqRef: SecRequirement?
        // "notarized" is a known designated-requirement shorthand on macOS 10.15+.
        guard SecRequirementCreateWithString(
            notarizedReq as CFString,
            [],
            &reqRef
        ) == errSecSuccess, let req = reqRef else {
            return false
        }
        return SecStaticCodeCheckValidity(staticCode, [], req) == errSecSuccess
    }

    // MARK: Diagnostics

    /// Remove all cached entries.
    public func removeAll() {
        cache.removeAllObjects()
    }
}
