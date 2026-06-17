// BundledThreatIntel.swift
// MacCrabCore
//
// Static database of known-bad IOCs that ships with the binary.
// Provides immediate threat detection from first launch without
// requiring network access or feed updates.
//
// Sources:
//   - MalwareBazaar (abuse.ch) — macOS malware SHA-256 hashes
//   - Feodo Tracker (abuse.ch) — botnet C2 IP addresses
//   - URLhaus (abuse.ch) — malicious domains
//   - Public macOS malware research — AMOS, RustBucket, Poseidon, etc.
//   - Public cryptomining pool lists

import Foundation

/// Bundled threat intelligence that ships with MacCrab.
/// Provides immediate protection from first launch — no feed updates needed.
/// This data is supplemented by live feeds from abuse.ch and configured APIs.
public enum BundledThreatIntel {

    /// Load all bundled IOCs into a ThreatIntelFeed.
    public static func loadInto(_ feed: ThreatIntelFeed) async {
        await feed.addCustomIOCs(
            hashes: malwareHashes.map(\.hash),
            ips: c2IPs.map(\.ip),
            domains: Array(maliciousDomains)
        )
    }

    /// Number of bundled IOCs.
    public static var stats: (hashes: Int, ips: Int, domains: Int) {
        (malwareHashes.count, c2IPs.count, maliciousDomains.count)
    }

    // MARK: - IOC Entry Types

    /// A malware hash entry with metadata for logging/display.
    public struct MalwareHashEntry {
        public let hash: String
        public let family: String
        public let description: String
    }

    /// A C2 IP entry with metadata.
    public struct C2IPEntry {
        public let ip: String
        public let source: String
        public let description: String
    }

    // MARK: - Known macOS Malware Hashes (SHA-256)
    //
    // Intentionally empty. The hash-match path is driven by the LIVE feeds
    // (MalwareBazaar / abuse.ch) wired up at daemon startup — we do not ship a
    // bundled offline hash set. The earlier entries here were synthetic
    // placeholders (not real SHA-256s); they could never match a real file and
    // a shipping detection engine must not carry fabricated IOCs, so they were
    // removed. To bundle a real offline set in future, add VERIFIED entries:
    //   curl -s 'https://mb-api.abuse.ch/api/v1/' -d 'query=get_taginfo&tag=macos' | jq
    //   https://bazaar.abuse.ch/browse/tag/macos/

    public static let malwareHashes: [MalwareHashEntry] = []

    // MARK: - Known C2 / Malicious Domains
    //
    // Cryptomining-pool domains only. Connecting to a mining pool from non-mining
    // software is a strong, low-false-positive indicator of compromise.
    //
    // The former Apple-phishing / macOS-C2 / Cobalt-Strike / supply-chain /
    // credential-theft sections were removed: their own comments described them as
    // illustrative "patterns" / "impersonation themes" with no threat-feed
    // corroboration (functionally fabricated IOCs), and the dynamic-DNS base
    // domains (duckdns.org, no-ip.com, ddns.net, …) are legitimate services whose
    // wholesale match is a false-positive generator. Real phishing / C2 /
    // distribution domains arrive via the live URLhaus / abuse.ch feeds — we don't
    // bundle invented examples.

    public static let maliciousDomains: Set<String> = [
        // --- Cryptomining Pools (21 entries) ---
        // Connecting to these from non-mining software is a strong indicator of compromise.
        "xmr.pool.minergate.com",
        "pool.minexmr.com",
        "pool.supportxmr.com",
        "mine.moneropool.com",
        "monerohash.com",
        "monero.crypto-pool.fr",
        "stratum.antpool.com",
        "xmr-eu1.nanopool.org",
        "xmr-eu2.nanopool.org",
        "xmr-us-east1.nanopool.org",
        "xmr-us-west1.nanopool.org",
        "xmr-asia1.nanopool.org",
        "pool.hashvault.pro",
        "gulf.moneroocean.stream",
        "pool.monero.hashvault.pro",
        "xmrpool.eu",
        "xmrpool.net",
        "mine.c3pool.com",
        "auto.c3pool.org",
        "xmr.2miners.com",
        "pool.xmr.pt",
    ]

    // MARK: - Known C2 IP Addresses
    //
    // Sources: Feodo Tracker (abuse.ch), public APT reports, mining pool resolvers.
    // These IPs have documented malicious activity.

    public static let c2IPs: [C2IPEntry] = [
        // --- Feodo Tracker / Botnet C2 (19 entries) ---
        // Historical IPs from abuse.ch Feodo Tracker. The live Feodo list is
        // currently empty (post-Operation-Endgame 2024), so these are best-effort
        // offline snapshots in real hosting ranges; live botnet C2 arrives via the
        // abuse.ch feeds. (Removed 45.33.32.156 — that is scanme.nmap.org, a test
        // host that was mislabeled "Cobalt Strike C2".)
        C2IPEntry(ip: "23.111.114.52",   source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "51.75.33.120",    source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "51.75.33.122",    source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "51.75.33.127",    source: "Feodo Tracker", description: "QakBot C2"),
        C2IPEntry(ip: "62.171.178.147",  source: "Feodo Tracker", description: "TrickBot C2"),
        C2IPEntry(ip: "78.47.64.46",     source: "Feodo Tracker", description: "BumbleBee C2"),
        C2IPEntry(ip: "82.117.252.143",  source: "Feodo Tracker", description: "Dridex C2"),
        C2IPEntry(ip: "85.209.135.109",  source: "Feodo Tracker", description: "IcedID C2"),
        C2IPEntry(ip: "91.215.85.147",   source: "Feodo Tracker", description: "QakBot C2"),
        C2IPEntry(ip: "93.115.25.139",   source: "Feodo Tracker", description: "TrickBot C2"),
        C2IPEntry(ip: "94.232.41.105",   source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "103.43.46.182",   source: "Feodo Tracker", description: "AsyncRAT C2"),
        C2IPEntry(ip: "103.75.201.2",    source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "104.168.155.129", source: "Feodo Tracker", description: "Cobalt Strike C2"),
        C2IPEntry(ip: "107.182.129.235", source: "Feodo Tracker", description: "BumbleBee C2"),
        C2IPEntry(ip: "119.59.103.164",  source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "131.153.76.130",  source: "Feodo Tracker", description: "QakBot C2"),
        C2IPEntry(ip: "134.122.66.193",  source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "138.197.14.67",   source: "Feodo Tracker", description: "IcedID C2"),

        // --- DPRK / Lazarus APT Infrastructure (4 entries) ---
        // IPs attributed to North Korean threat actors in public reports.
        // (Removed 93.184.216.34 — that is example.com's IP, mislabeled "Lazarus
        // staging server". Corrected the ObjCShellz C2 to the published Jamf IOC.)
        C2IPEntry(ip: "104.168.174.80",  source: "DPRK APT", description: "RustBucket C2 (BlueNoroff)"),
        C2IPEntry(ip: "185.29.8.53",     source: "DPRK APT", description: "POOLRAT C2 (Lazarus)"),
        C2IPEntry(ip: "104.168.214.151", source: "DPRK APT", description: "ObjCShellz C2 (BlueNoroff, swissborg.blog lure)"),
        C2IPEntry(ip: "45.61.169.36",    source: "DPRK APT", description: "AppleJeus C2 (Lazarus)"),

        // --- Cryptomining Pool IPs (4 entries) ---
        // Direct IP connections to mining pools (bypass DNS detection).
        // (Removed 51.255.71.0 — a .0 network address that monero.crypto-pool.fr
        // never resolved to; a guaranteed mismatch.)
        C2IPEntry(ip: "5.9.28.116",      source: "Mining Pool", description: "MinerGate pool IP"),
        C2IPEntry(ip: "5.9.70.67",       source: "Mining Pool", description: "MinerGate pool IP"),
        C2IPEntry(ip: "46.173.219.161",  source: "Mining Pool", description: "MoneroOcean pool IP"),
        C2IPEntry(ip: "144.76.183.96",   source: "Mining Pool", description: "Nanopool XMR"),
    ]

    // MARK: - Suspicious TLDs
    //
    // Domains ending in these TLDs have high abuse rates and warrant extra scrutiny.
    // Used for risk scoring, NOT blocking — legitimate sites can use these TLDs.
    // Source: Spamhaus, SURBL, DGA research.

    public static let suspiciousTLDs: Set<String> = [
        // High-abuse generic TLDs (Spamhaus most-abused list)
        ".xyz",
        ".top",
        ".click",
        ".loan",
        ".work",
        ".buzz",
        ".monster",
        ".rest",
        ".icu",
        ".cam",

        // Free TLDs heavily abused for phishing/malware (Freenom legacy)
        ".gq",          // Equatorial Guinea (free)
        ".cf",          // Central African Republic (free)
        ".tk",          // Tokelau (free)
        ".ml",          // Mali (free)
        ".ga",          // Gabon (free)

        // DGA / bulk-registered abuse patterns
        ".support",
        ".live",
        ".fun",
        ".site",
        ".online",
        ".win",
        ".bid",
        ".download",
        ".racing",
        ".review",
        ".accountant",
        ".date",
        ".faith",
        ".party",
        ".science",
        ".stream",
        ".trade",
    ]

    // MARK: - Suspicious Process Names
    //
    // Process names commonly associated with macOS malware or attacker tooling.
    // Used for behavioral correlation, not sole detection.

    public static let suspiciousProcessNames: Set<String> = [
        // Crypto miners
        "xmrig",
        "xmr-stak",
        "minergate",
        "minerd",
        "cpuminer",
        "cgminer",

        // Known macOS malware binary names
        "amos",
        "poseidon",
        "cthulhu",

        // Common attacker tools on macOS
        "socat",
        "ncat",
        "chisel",
        "ligolo",
        "sliver-client",
        "cobaltstrike",
        "meterpreter",
    ]

    // MARK: - Suspicious Persistence Paths
    //
    // File path patterns commonly used by macOS malware for persistence or staging.

    public static let suspiciousPaths: [String] = [
        // Hidden directories in user home (common staging locations)
        ".local/share/.",       // Hidden subdirs under .local
        ".cachefs/",            // Fake cache directory
        ".systemservices/",     // Fake system services dir

        // Common macOS malware persistence via LaunchAgents with fake vendor names
        "Library/LaunchAgents/com.apple.update.plist",
        "Library/LaunchAgents/com.google.update.plist",
        "Library/LaunchAgents/com.adobe.update.plist",
        "Library/LaunchAgents/com.microsoft.update.plist",

        // Temp directory staging (attacker working directories)
        "/private/tmp/.hidden",
        "/private/var/tmp/.cache",
    ]

    // MARK: - Domain Reputation Check

    /// Check if a domain uses a suspicious TLD.
    /// Returns true if the domain ends with any TLD in the suspicious list.
    public static func hasSuspiciousTLD(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        return suspiciousTLDs.contains { lower.hasSuffix($0) }
    }

    /// Look up a hash and return its malware family if known.
    /// Returns nil if the hash is not in the bundled database.
    public static func malwareFamilyForHash(_ hash: String) -> MalwareHashEntry? {
        let lower = hash.lowercased()
        return malwareHashes.first { $0.hash == lower }
    }

    /// Look up an IP and return its C2 metadata if known.
    /// Returns nil if the IP is not in the bundled database.
    public static func c2InfoForIP(_ ip: String) -> C2IPEntry? {
        c2IPs.first { $0.ip == ip }
    }
}
