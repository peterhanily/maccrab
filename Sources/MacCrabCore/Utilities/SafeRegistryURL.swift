// SafeRegistryURL.swift
// MacCrabCore
//
// Validated URL construction for npm / PyPI / GitHub registry
// requests. v1.12.0 hardening after the pre-release audit flagged
// SSRF via wrong CharacterSet.urlPathAllowed semantics — that
// character set lets `/`, `:`, `@`, `;` through, so concatenating
// `"https://registry.npmjs.org/" + "evil.com/path"` produced a
// request to `evil.com`.
//
// All builders here validate the package / version against a strict
// allow-regex BEFORE concatenation, then use URLComponents (which
// percent-encodes every reserved character) for the final URL.

import Foundation

public enum SafeRegistryURL {

    public enum Error: Swift.Error, LocalizedError, Equatable {
        case invalidPackageName(name: String)
        case invalidVersion(version: String)
        case invalidRegistry

        public var errorDescription: String? {
            switch self {
            case .invalidPackageName(let n): return "Invalid package name: \(n)"
            case .invalidVersion(let v):     return "Invalid version: \(v)"
            case .invalidRegistry:           return "Invalid registry"
            }
        }
    }

    /// npm name validation per npm's own validate-npm-package-name
    /// crate: lowercase, digits, dots, dashes, underscores; optional
    /// scope (`@scope/name`). Max length 214 per npm registry rules.
    ///
    /// v1.12.0 post-audit (M-Sec4): the prior pattern allowed a name
    /// ending in `.` (e.g. `foo.`) — npm itself rejects that per RFC
    /// compliance, but some intermediaries normalize `/foo.` to
    /// `/foo`, which confuses the per-package cache key. The last-
    /// character class now excludes `.` so `foo.` is rejected before
    /// URLComponents construction.
    static let npmNamePattern = #"^@?[a-z0-9][a-z0-9._-]{0,212}[a-z0-9_-](/[a-z0-9][a-z0-9._-]{0,212}[a-z0-9_-])?$|^@?[a-z0-9](/[a-z0-9])?$"#
    /// PyPI name: PEP 503-style after normalization (Letters, digits,
    /// dot, underscore, dash). Slash NOT allowed. Trailing-dot
    /// guarded the same way as npm above.
    static let pypiNamePattern = #"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,212}[a-zA-Z0-9_-]$|^[a-zA-Z0-9]$"#
    /// Semver-ish or PEP 440 version: digits, dots, dashes, plus,
    /// alphanumerics, no whitespace, no special URL chars. Loose enough
    /// to accept oddities like "1.2.3+build.456" but tight enough that
    /// `..` / `/` / `?` / `@` are rejected.
    static let versionPattern = #"^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$"#

    /// Build https://registry.npmjs.org/<name> with validated name.
    public static func npmPackageMetadata(name: String) throws -> URL {
        try validateNpmName(name)
        var components = URLComponents()
        components.scheme = "https"
        components.host = "registry.npmjs.org"
        components.path = "/\(name)"  // URLComponents percent-encodes everything
        guard let url = components.url else { throw Error.invalidRegistry }
        return url
    }

    /// Build https://registry.npmjs.org/-/npm/v1/security/attestations/<name>@<version>.
    public static func npmAttestation(name: String, version: String) throws -> URL {
        try validateNpmName(name)
        try validateVersion(version)
        var components = URLComponents()
        components.scheme = "https"
        components.host = "registry.npmjs.org"
        components.path = "/-/npm/v1/security/attestations/\(name)@\(version)"
        guard let url = components.url else { throw Error.invalidRegistry }
        return url
    }

    /// Build https://pypi.org/pypi/<name>/json with validated name.
    public static func pypiPackageMetadata(name: String) throws -> URL {
        try validatePypiName(name)
        var components = URLComponents()
        components.scheme = "https"
        components.host = "pypi.org"
        components.path = "/pypi/\(name)/json"
        guard let url = components.url else { throw Error.invalidRegistry }
        return url
    }

    /// Build https://pypi.org/pypi/<name>/<version>/json.
    public static func pypiVersionMetadata(name: String, version: String) throws -> URL {
        try validatePypiName(name)
        try validateVersion(version)
        var components = URLComponents()
        components.scheme = "https"
        components.host = "pypi.org"
        components.path = "/pypi/\(name)/\(version)/json"
        guard let url = components.url else { throw Error.invalidRegistry }
        return url
    }

    // MARK: - Validators

    public static func validateNpmName(_ name: String) throws {
        guard !name.isEmpty, name.count <= 214 else { throw Error.invalidPackageName(name: name) }
        guard matches(name, pattern: npmNamePattern) else {
            throw Error.invalidPackageName(name: name)
        }
    }

    public static func validatePypiName(_ name: String) throws {
        guard !name.isEmpty, name.count <= 214 else { throw Error.invalidPackageName(name: name) }
        guard matches(name, pattern: pypiNamePattern) else {
            throw Error.invalidPackageName(name: name)
        }
    }

    public static func validateVersion(_ version: String) throws {
        guard !version.isEmpty, version.count <= 128 else { throw Error.invalidVersion(version: version) }
        guard matches(version, pattern: versionPattern) else {
            throw Error.invalidVersion(version: version)
        }
    }

    private static func matches(_ s: String, pattern: String) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return false }
        let range = NSRange(s.startIndex..<s.endIndex, in: s)
        return regex.firstMatch(in: s, range: range) != nil
    }
}

// MARK: - Hardened URLSession factory

import os.log

public enum HardenedRegistrySession {

    private static let logger = Logger(subsystem: "com.maccrab.network", category: "registry-session")

    /// Allowed hosts a redirect may target. Restricts the redirect
    /// follower to the registry the request was originally sent to.
    private static let allowedHosts: Set<String> = [
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "api.github.com",
    ]

    /// Use this once per request: builds a request and returns
    /// (data, response). Uses SecureURLSession.shared semantics
    /// (TLS 1.2 floor) but adds a redirect-validator delegate.
    public static func fetch(url: URL, timeout: TimeInterval = 10) async throws -> (Data, HTTPURLResponse)? {
        guard allowedHosts.contains(url.host ?? "") else {
            logger.warning("Refused fetch to disallowed host: \(url.host ?? "?", privacy: .public)")
            return nil
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        // Don't fingerprint the security product to log-mining attackers.
        request.setValue("Mozilla/5.0 (Macintosh)", forHTTPHeaderField: "User-Agent")
        request.httpShouldHandleCookies = false

        let delegate = RedirectValidator(allowedHosts: allowedHosts, originalHost: url.host ?? "")
        let config = URLSessionConfiguration.ephemeral
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        config.httpCookieAcceptPolicy = .never
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        // v1.12.0 post-audit (H-Sec1): cap end-to-end resource time so
        // a hostile mirror trickling 1 byte per 9s can't keep the
        // actor's `await session.data(for:)` alive for hours. URLSession's
        // default `timeoutIntervalForResource` is 7 days; we cut it to
        // 30s. timeoutIntervalForRequest stays per-byte (10s).
        config.timeoutIntervalForResource = 30
        config.timeoutIntervalForRequest = timeout
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        // v1.12.0 post-audit (M-Sec1): stream the response and enforce
        // the 16 MB cap during accumulation. Pre-fix, `session.data(for:)`
        // buffered the entire response into memory before the cap
        // check fired — a hostile mirror returning 1 GB of chunked
        // data would OOM the actor before the check ran. Switching
        // to `session.bytes(for:)` lets us break out at exactly
        // 16 MB +/- one chunk size.
        do {
            let (stream, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return nil
            }
            var buf = Data()
            buf.reserveCapacity(64 * 1024)
            let capBytes = 16 * 1024 * 1024
            for try await byte in stream {
                buf.append(byte)
                if buf.count > capBytes {
                    logger.warning("Response from \(url.host ?? "?", privacy: .public) exceeded 16 MB cap mid-stream")
                    return nil
                }
            }
            return (buf, http)
        } catch {
            return nil
        }
    }
}

/// URLSessionDelegate that refuses redirects to hosts outside the
/// allowed set. v1.12.0 post-audit (M2): also refuses redirects that
/// change host at all — registries never legitimately cross-redirect
/// between (e.g.) npmjs.org and pypi.org. Refusing same-allowlist
/// host changes closes a compromised-registry confusion vector.
private final class RedirectValidator: NSObject, URLSessionTaskDelegate {
    let allowedHosts: Set<String>
    let originalHost: String
    init(allowedHosts: Set<String>, originalHost: String) {
        self.allowedHosts = allowedHosts
        self.originalHost = originalHost
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        let host = request.url?.host ?? ""
        // Must be allowlisted, HTTPS, AND match the original host. The
        // original-host pin prevents a compromised registry from
        // bouncing requests to another registry within the allowlist.
        if allowedHosts.contains(host)
            && request.url?.scheme == "https"
            && host == originalHost {
            completionHandler(request)
        } else {
            completionHandler(nil) // cancel the redirect
        }
    }
}
