// BundleRedactor.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10b) — implements the §18.4 positive-list
// redaction at the bundle export boundary.
//
// Default redactions:
//   - /Users/<name>/ → ~/...
//   - hostname → [REDACTED-HOST]
//   - local IPv4 ranges in the 10/8, 172.16/12, 192.168/16 spaces → [REDACTED-IP]
//
// Deeper redaction (secret-shape command line, env vars, token strings,
// high-entropy keys) is applied at the daemon's collector boundary
// via the existing `CommandSanitizer` — by the time payloads reach
// the exporter, those have already been sanitized. The redactor here
// is a final sweep that catches user/host leakage in JSON serializations.
//
// The sweep is regex-based — imperfect (it doesn't parse JSON
// structurally) but practical: bundle artifacts are well-formed JSON
// where strings hold paths and hostnames, and the redactor's regexes
// only match path/host-shaped substrings.

import Foundation

public struct BundleRedactor: Sendable {

    public let redactHomePaths: Bool
    public let redactHostname: Bool
    public let redactPrivateIPs: Bool
    public let hostname: String
    public let userName: String

    public init(
        redactHomePaths: Bool = true,
        redactHostname: Bool = true,
        redactPrivateIPs: Bool = true,
        hostname: String = "",
        userName: String = ""
    ) {
        self.redactHomePaths = redactHomePaths
        self.redactHostname = redactHostname
        self.redactPrivateIPs = redactPrivateIPs
        self.hostname = hostname
        self.userName = userName
    }

    /// Default redactor — populates `hostname` and `userName` from the
    /// current process so the regex matches the actual machine's
    /// values. Tests override these via the explicit init.
    public static func systemDefault() -> BundleRedactor {
        BundleRedactor(
            hostname: Foundation.ProcessInfo.processInfo.hostName,
            userName: NSUserName()
        )
    }

    // MARK: - Regex helpers

    private static let userPathPattern = #"/Users/[A-Za-z0-9_.-]+/"#
    private static let userPathRegex = try! NSRegularExpression(pattern: userPathPattern)

    private static let privateIPPattern =
        #"\b(10(?:\.[0-9]{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}|192\.168(?:\.[0-9]{1,3}){2})\b"#
    private static let privateIPRegex = try! NSRegularExpression(pattern: privateIPPattern)

    // MARK: - String redaction

    /// Apply redaction to a single string.
    public func redact(_ input: String) -> String {
        var result = input

        if redactHomePaths {
            // First replace /Users/<currentUser>/ specifically with ~/ for
            // the most common case, then catch any remaining /Users/X/.
            if !userName.isEmpty {
                result = result.replacingOccurrences(
                    of: "/Users/\(userName)/",
                    with: "~/"
                )
            }
            // Generic catch-all for any remaining /Users/X/ — useful when
            // bundles include traces of other accounts on the same machine.
            let range = NSRange(result.startIndex..., in: result)
            result = Self.userPathRegex.stringByReplacingMatches(
                in: result,
                range: range,
                withTemplate: "/Users/[REDACTED]/"
            )
        }

        if redactHostname, !hostname.isEmpty {
            result = result.replacingOccurrences(
                of: hostname,
                with: "[REDACTED-HOST]"
            )
            // Hostname.local variant common on macOS.
            result = result.replacingOccurrences(
                of: hostname + ".local",
                with: "[REDACTED-HOST]"
            )
        }

        if redactPrivateIPs {
            let range = NSRange(result.startIndex..., in: result)
            result = Self.privateIPRegex.stringByReplacingMatches(
                in: result,
                range: range,
                withTemplate: "[REDACTED-IP]"
            )
        }

        return result
    }

    // MARK: - Directory sweep

    /// Apply redaction to every text file in a bundle directory after
    /// the exporter has written all artifacts. Operates on `.json`,
    /// `.jsonl`, `.md`, and `.html` files; skips binaries.
    public func redactDirectory(_ directory: URL) throws {
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        for case let fileURL as URL in enumerator {
            let resources = try fileURL.resourceValues(forKeys: [.isRegularFileKey])
            guard resources.isRegularFile == true else { continue }
            guard isTextExtension(fileURL.pathExtension) else { continue }
            // Skip the integrity hash chain + signature — they're
            // hash-of-hashes and signature bytes; redacting them
            // would corrupt the verification path. The signed
            // artifacts are the *post-redaction* outputs anyway.
            // Use pathComponents to dodge /var ↔ /private/var symlink
            // resolution that bites simple prefix comparisons on macOS.
            if fileURL.pathComponents.contains("integrity") {
                continue
            }
            let original = try String(contentsOf: fileURL, encoding: .utf8)
            let redacted = redact(original)
            if redacted != original {
                try redacted.write(to: fileURL, atomically: true, encoding: .utf8)
            }
        }
    }

    private func isTextExtension(_ ext: String) -> Bool {
        switch ext.lowercased() {
        case "json", "jsonl", "md", "html", "txt", "jsonld":
            return true
        default:
            return false
        }
    }
}
