import Foundation
import Darwin
import os.log

/// Prevents C2 callbacks by sinkholing malicious domains to localhost.
/// Writes entries to /etc/hosts that redirect threat-intel domains to 127.0.0.1.
public actor DNSSinkhole {

    /// MITRE D3FEND defensive technique this module implements.
    public nonisolated static let d3fend = D3FENDMapping.dnsSinkhole
    private let logger = Logger(subsystem: "com.maccrab.prevention", category: "dns-sinkhole")

    /// Marker comment in /etc/hosts to identify MacCrab-managed entries
    private static let marker = "# MacCrab DNS Sinkhole — DO NOT EDIT BELOW THIS LINE"
    private static let endMarker = "# MacCrab DNS Sinkhole — END"
    private let hostsPath = "/etc/hosts"

    private var sinkholdDomains: Set<String> = []
    private var isEnabled: Bool = false

    public init() {}

    /// Enable the sinkhole with initial domains from threat intel.
    /// Protected domains (apple.com, github.com, our own appcast, etc.) and
    /// IP literals are silently dropped — sinkholing them would brick code
    /// signing, auto-update, or strand the user.
    public func enable(domains: Set<String>) {
        let filtered = Self.filterProtected(domains)
        if !filtered.rejected.isEmpty {
            logger.warning("Refused to sinkhole \(filtered.rejected.count) protected entries: \(Self.formatRejected(filtered.rejected), privacy: .public)")
        }
        sinkholdDomains = filtered.accepted
        isEnabled = true
        writeHostsFile()
        logger.info("DNS sinkhole enabled: \(filtered.accepted.count) domains redirected to 127.0.0.1 (\(filtered.rejected.count) protected entries dropped)")
    }

    /// Add domains to the sinkhole.
    /// Protected domains and IP literals are silently dropped; see `enable`.
    public func addDomains(_ domains: Set<String>) {
        let filtered = Self.filterProtected(domains)
        if !filtered.rejected.isEmpty {
            logger.warning("Refused to sinkhole \(filtered.rejected.count) protected entries: \(Self.formatRejected(filtered.rejected), privacy: .public)")
        }
        let newDomains = filtered.accepted.subtracting(sinkholdDomains)
        guard !newDomains.isEmpty else { return }
        sinkholdDomains.formUnion(newDomains)
        if isEnabled { writeHostsFile() }
        logger.info("Added \(newDomains.count) domains to sinkhole (total: \(self.sinkholdDomains.count))")
    }

    /// Remove all MacCrab entries from /etc/hosts.
    public func disable() {
        isEnabled = false
        sinkholdDomains.removeAll()
        removeHostsEntries()
        logger.info("DNS sinkhole disabled — /etc/hosts cleaned")
    }

    /// Get current sinkhole stats.
    public func stats() -> (enabled: Bool, domainCount: Int) {
        (isEnabled, sinkholdDomains.count)
    }

    /// Verify that `path` is a regular file (or does not yet exist) and is NOT
    /// a symlink.  Returns `false` if a symlink is detected — writing through a
    /// symlink while running as root would let an attacker redirect the write to
    /// an arbitrary file.
    private func isNotSymlink(_ path: String) -> Bool {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
            return true  // File doesn't exist yet — safe to create
        }
        // Use lstat (attributesOfItem) which does NOT follow symlinks.
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let fileType = attrs[.type] as? FileAttributeType else {
            return false
        }
        return fileType != .typeSymbolicLink
    }

    private func writeHostsFile() {
        let fm = FileManager.default
        guard fm.isWritableFile(atPath: hostsPath) else {
            logger.warning("Cannot write to /etc/hosts (need root)")
            return
        }

        guard isNotSymlink(hostsPath) else {
            logger.error("Refusing to write: \(self.hostsPath) is a symlink (possible attack)")
            return
        }

        // Read existing hosts file
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }

        // Remove any existing MacCrab section
        if let startRange = content.range(of: Self.marker),
           let endRange = content.range(of: Self.endMarker) {
            // Safe upper bound: clamp to content.endIndex to avoid out-of-bounds
            let removeEnd = endRange.upperBound < content.endIndex
                ? content.index(after: endRange.upperBound)
                : content.endIndex
            content.removeSubrange(startRange.lowerBound..<removeEnd)
        }

        // Append new sinkhole entries
        var section = "\n\(Self.marker)\n"
        for domain in sinkholdDomains.sorted().prefix(10000) {  // Cap at 10K domains
            section += "127.0.0.1 \(domain)\n"
            section += "::1 \(domain)\n"
        }
        section += "\(Self.endMarker)\n"

        content += section

        // Write atomically
        do {
            try content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
        } catch {
            logger.error("Failed to write sinkhole entries to \(self.hostsPath): \(error.localizedDescription)")
        }
    }

    private func removeHostsEntries() {
        guard isNotSymlink(hostsPath) else {
            logger.error("Refusing to write: \(self.hostsPath) is a symlink (possible attack)")
            return
        }
        guard var content = try? String(contentsOfFile: hostsPath, encoding: .utf8) else { return }
        if let startRange = content.range(of: Self.marker),
           let endRange = content.range(of: Self.endMarker) {
            let removeEnd = endRange.upperBound < content.endIndex
                ? content.index(after: endRange.upperBound)
                : content.endIndex
            content.removeSubrange(startRange.lowerBound..<removeEnd)
            do {
                try content.write(toFile: hostsPath, atomically: true, encoding: .utf8)
            } catch {
                logger.error("Failed to clean sinkhole entries from \(self.hostsPath): \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Protected-domain allowlist
    //
    // Sinkholing certain domains brings the system to a halt in non-obvious
    // ways: ocsp.apple.com → code signing fails on every launch; gateway.
    // icloud.com → all iCloud sync stops; *.googleapis.com → Chrome stops
    // working; maccrab.com → our own auto-update breaks. The list below is
    // a hard refusal — even if a malicious threat-intel feed claims one of
    // these is a C2 domain, we drop the entry.

    /// Domains we will never sinkhole. `*.x` matches `x` and any subdomain.
    public static let protectedDomainPatterns: [String] = [
        // Apple — system function
        "apple.com", "*.apple.com",
        "icloud.com", "*.icloud.com",
        "mzstatic.com", "*.mzstatic.com",
        "apple-cloudkit.com", "*.apple-cloudkit.com",
        "*.apple-mapkit.com",
        "*.appstore.com",
        // Critical Apple endpoints by exact name (defense in depth)
        "ocsp.apple.com", "ocsp2.apple.com",
        "crl.apple.com", "crl3.apple.com", "crl4.apple.com", "crl5.apple.com",
        "time.apple.com",
        "gateway.icloud.com",
        "push.apple.com", "*.push.apple.com",
        "gsa.apple.com", "gs.apple.com",
        "albert.apple.com", "xp.apple.com",

        // Source / dependency hosting — sinkholing GitHub bricks Homebrew
        // installs and our own repo
        "github.com", "*.github.com",
        "githubusercontent.com", "*.githubusercontent.com",
        "github.io", "*.github.io",

        // Google APIs / Chrome safe browsing / sign-in
        "google.com", "*.google.com",
        "googleapis.com", "*.googleapis.com",
        "gstatic.com", "*.gstatic.com",

        // Cloudflare (DoH, NTP, public DNS infra)
        "cloudflare.com", "*.cloudflare.com",
        "cloudflare-dns.com", "*.cloudflare-dns.com",

        // MacCrab itself — never sinkhole our own appcast or update path
        "maccrab.com", "*.maccrab.com",

        // Microsoft — Office 365 sign-in, Teams, OneDrive, Outlook
        "microsoft.com", "*.microsoft.com",
        "office.com", "*.office.com",
        "office365.com", "*.office365.com",
        "live.com", "*.live.com",
        "outlook.com", "*.outlook.com",
        "microsoftonline.com", "*.microsoftonline.com",

        // AWS — sinkholing breaks any tool fetching from S3 / installing
        // via curl|bash that pulls from cloudfront
        "aws.amazon.com", "*.aws.amazon.com",
        "amazonaws.com", "*.amazonaws.com",

        // Stripe — payment infra; sinkholing breaks tools that charge cards
        "stripe.com", "*.stripe.com",

        // JetBrains — IDE auth and license server
        "jetbrains.com", "*.jetbrains.com",

        // Password managers — break credential sync
        "1password.com", "*.1password.com",
        "1password.eu", "*.1password.eu",
        "bitwarden.com", "*.bitwarden.com",

        // Mozilla — Firefox add-on update + telemetry
        "mozilla.org", "*.mozilla.org",
        "mozilla.net", "*.mozilla.net",

        // Adobe — Creative Cloud auth + cert validation
        "adobe.com", "*.adobe.com",
        "adobe.io", "*.adobe.io",

        // Slack — many users have it as their primary alert sink
        "slack.com", "*.slack.com",

        // Zoom
        "zoom.us", "*.zoom.us",

        // Linear — common dev workflow tool
        "linear.app", "*.linear.app",

        // Public CA OCSP / CRL infrastructure — sinkholing breaks code
        // signing verification system-wide for non-Apple-issued certs
        "digicert.com", "*.digicert.com",
        "sectigo.com", "*.sectigo.com",
        "letsencrypt.org", "*.letsencrypt.org",
        "globalsign.com", "*.globalsign.com",
        "verisign.com", "*.verisign.com",

        // Local / loopback — IP literals are caught separately, but the
        // hostname forms belong here too
        "localhost", "*.localhost",
        // Bonjour / mDNS — sinkholing breaks AirDrop, Continuity, etc.
        "*.local",
    ]

    /// Returns (accepted: passes the allowlist, rejected: must not be sinkholed).
    nonisolated static func filterProtected(_ input: Set<String>) -> (accepted: Set<String>, rejected: Set<String>) {
        var accepted: Set<String> = []
        var rejected: Set<String> = []
        for domain in input {
            if isProtected(domain) {
                rejected.insert(domain)
            } else {
                accepted.insert(domain)
            }
        }
        return (accepted, rejected)
    }

    /// True when `domain` either matches a protected pattern, is an IP
    /// literal, or is otherwise unsuitable for /etc/hosts redirection.
    nonisolated static func isProtected(_ domain: String) -> Bool {
        let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // Empty / whitespace is unsuitable for /etc/hosts.
        if trimmed.isEmpty { return true }
        // IP literals don't belong in a /etc/hosts hostname column at all.
        if isIPLiteral(trimmed) { return true }
        // Pattern match.
        for pattern in protectedDomainPatterns {
            if pattern.hasPrefix("*.") {
                let suffix = String(pattern.dropFirst(2))
                if trimmed == suffix || trimmed.hasSuffix("." + suffix) {
                    return true
                }
            } else if trimmed == pattern {
                return true
            }
        }
        return false
    }

    /// True when the input parses as a numeric IPv4 or IPv6 address.
    nonisolated static func isIPLiteral(_ s: String) -> Bool {
        var addr4 = in_addr()
        if s.withCString({ inet_pton(AF_INET, $0, &addr4) }) == 1 { return true }
        var addr6 = in6_addr()
        if s.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 { return true }
        return false
    }

    /// Renders a small set of rejected entries for logging. Caps at 10 to
    /// avoid log spam if an entire feed turns out to be rejected.
    nonisolated static func formatRejected(_ rejected: Set<String>) -> String {
        let capped = rejected.sorted().prefix(10)
        let suffix = rejected.count > 10 ? ", … (\(rejected.count - 10) more)" : ""
        return capped.joined(separator: ", ") + suffix
    }
}
