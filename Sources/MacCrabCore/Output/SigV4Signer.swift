// SigV4Signer.swift
// MacCrabCore
//
// AWS Signature Version 4 signer built on CryptoKit — no AWS SDK
// dependency. Used by S3Output for uploading NDJSON batches. Matches
// the reference algorithm in AWS docs:
// https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

import Foundation
import CryptoKit

public enum SigV4Signer {

    // MARK: - Public API

    public struct SignedHeaders: Sendable {
        public let headers: [String: String]
    }

    /// Build SigV4 headers for a single-shot request (PUT / POST to S3,
    /// DynamoDB, etc.). Returns the headers the caller should set on
    /// their URLRequest.
    ///
    /// - Parameters:
    ///   - method: HTTP verb, e.g. "PUT".
    ///   - url: Full request URL.
    ///   - headers: Additional headers to sign (e.g. Content-Type).
    ///     `Host` and `x-amz-date` / `x-amz-content-sha256` are added
    ///     automatically.
    ///   - body: Request payload (may be empty Data()).
    ///   - region: AWS region, e.g. "us-east-1".
    ///   - service: AWS service, e.g. "s3".
    ///   - accessKey: AWS access-key id (AKIA…).
    ///   - secretKey: AWS secret-access key.
    ///   - sessionToken: Optional STS session token; adds x-amz-security-token.
    ///   - now: Override for the timestamp (tests).
    public static func sign(
        method: String,
        url: URL,
        headers: [String: String] = [:],
        body: Data,
        region: String,
        service: String,
        accessKey: String,
        secretKey: String,
        sessionToken: String? = nil,
        now: Date = Date()
    ) -> SignedHeaders {
        let formatter = Self.amzDateFormatter
        let amzDate = formatter.string(from: now)                // yyyyMMdd'T'HHmmss'Z'
        let dateStamp = String(amzDate.prefix(8))                // yyyyMMdd

        let payloadHash = sha256Hex(body)

        // Baseline headers the signer always injects.
        var allHeaders: [String: String] = headers
        allHeaders["host"] = url.host ?? ""
        allHeaders["x-amz-date"] = amzDate
        allHeaders["x-amz-content-sha256"] = payloadHash
        if let token = sessionToken {
            allHeaders["x-amz-security-token"] = token
        }

        // Canonical request
        let (canonicalHeaders, signedHeaderList) = canonicalHeaders(from: allHeaders)
        let canonicalURI = canonicalize(path: url.path)
        let canonicalQuery = canonicalize(query: url.query)
        let canonicalRequest = [
            method.uppercased(),
            canonicalURI,
            canonicalQuery,
            canonicalHeaders,
            signedHeaderList,
            payloadHash,
        ].joined(separator: "\n")

        // String to sign
        let credentialScope = "\(dateStamp)/\(region)/\(service)/aws4_request"
        let stringToSign = [
            "AWS4-HMAC-SHA256",
            amzDate,
            credentialScope,
            sha256Hex(Data(canonicalRequest.utf8)),
        ].joined(separator: "\n")

        // Signing key
        let kDate = hmac(key: Data("AWS4\(secretKey)".utf8), data: Data(dateStamp.utf8))
        let kRegion = hmac(key: kDate, data: Data(region.utf8))
        let kService = hmac(key: kRegion, data: Data(service.utf8))
        let kSigning = hmac(key: kService, data: Data("aws4_request".utf8))

        let signature = hmac(key: kSigning, data: Data(stringToSign.utf8))
            .map { String(format: "%02x", $0) }
            .joined()

        let authorizationHeader = "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(credentialScope), SignedHeaders=\(signedHeaderList), Signature=\(signature)"

        // Final header set: everything we signed, plus Authorization.
        var out = allHeaders
        out["Authorization"] = authorizationHeader

        // Normalize presentation — title-case the keys we added so they
        // look right on the wire. AWS ignores case but operators read
        // logs.
        return SignedHeaders(headers: [
            "Authorization": authorizationHeader,
            "Host": allHeaders["host"] ?? "",
            "x-amz-date": amzDate,
            "x-amz-content-sha256": payloadHash,
            "x-amz-security-token": sessionToken ?? "",
        ].compactMapValues { $0.isEmpty ? nil : $0 }
         .merging(headers) { _, userValue in userValue })
    }

    // MARK: - Canonical construction

    private static func canonicalize(path: String) -> String {
        // S3 paths: each segment URL-encoded except the `/` separators.
        // RFC 3986 unreserved: A-Z a-z 0-9 - _ . ~
        if path.isEmpty { return "/" }
        let segments = path.split(separator: "/", omittingEmptySubsequences: false)
        return segments
            .map { segment -> String in
                guard !segment.isEmpty else { return "" }
                return String(segment).sigV4Encoded()
            }
            .joined(separator: "/")
    }

    private static func canonicalize(query: String?) -> String {
        guard let q = query, !q.isEmpty else { return "" }
        return q.split(separator: "&")
            .map { String($0) }
            .sorted()
            .joined(separator: "&")
    }

    /// Returns (canonicalHeadersBlock, signedHeadersList).
    /// Canonical block: "name:value\n" lines, sorted by lowercased name.
    /// Signed list: semicolon-separated lowercased names.
    private static func canonicalHeaders(
        from headers: [String: String]
    ) -> (String, String) {
        let lowered = headers.reduce(into: [String: String]()) { acc, kv in
            let trimmedValue = kv.value
                .trimmingCharacters(in: .whitespaces)
                .replacingOccurrences(of: #"  +"#, with: " ", options: .regularExpression)
            acc[kv.key.lowercased()] = trimmedValue
        }
        let sortedKeys = lowered.keys.sorted()
        let block = sortedKeys
            .map { "\($0):\(lowered[$0]!)\n" }
            .joined()
        let list = sortedKeys.joined(separator: ";")
        return (block, list)
    }

    // MARK: - Crypto

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func hmac(key: Data, data: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(
            for: data, using: SymmetricKey(data: key)
        )
        return Data(mac)
    }

    // MARK: - Shared formatter

    private static let amzDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f
    }()
}

// MARK: - String extension for SigV4 URL encoding

private extension String {
    /// Percent-encode per AWS SigV4 rules: unreserved characters only.
    func sigV4Encoded() -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.~")
        return self.addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }
}
