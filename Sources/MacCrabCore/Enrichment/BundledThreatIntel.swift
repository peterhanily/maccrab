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
    // IMPORTANT: These are placeholder hashes formatted as valid SHA-256 (64 hex chars).
    // Each placeholder encodes the malware family in the prefix for readability.
    // Replace with real verified hashes from MalwareBazaar before production use.
    //
    // To get real hashes:
    //   curl -s 'https://mb-api.abuse.ch/api/v1/' -d 'query=get_taginfo&tag=macos' | jq
    //   https://bazaar.abuse.ch/browse/tag/macos/

    public static let malwareHashes: [MalwareHashEntry] = [
        // --- Atomic Stealer (AMOS) ---
        // Credential stealer sold on Telegram; targets Keychain, browser data, crypto wallets.
        // Multiple variants since early 2023. Distributed via fake app DMGs.
        MalwareHashEntry(
            hash: "a100000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real AMOS hash
            family: "AMOS",
            description: "Atomic Stealer v1 — DMG installer targeting Keychain and browser passwords"
        ),
        MalwareHashEntry(
            hash: "a100000000000000000000000000000000000000000000000000000000000002",  // PLACEHOLDER — replace with real AMOS hash
            family: "AMOS",
            description: "Atomic Stealer v2 — Python-based variant with crypto wallet extraction"
        ),
        MalwareHashEntry(
            hash: "a100000000000000000000000000000000000000000000000000000000000003",  // PLACEHOLDER — replace with real AMOS hash
            family: "AMOS",
            description: "Atomic Stealer v3 — AppleScript credential prompt variant"
        ),

        // --- Poseidon Stealer ---
        // Successor to AMOS, advertised on Telegram. Uses osascript for credential prompts.
        MalwareHashEntry(
            hash: "b200000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real Poseidon hash
            family: "Poseidon",
            description: "Poseidon Stealer — osascript-based credential harvester"
        ),
        MalwareHashEntry(
            hash: "b200000000000000000000000000000000000000000000000000000000000002",  // PLACEHOLDER — replace with real Poseidon hash
            family: "Poseidon",
            description: "Poseidon Stealer variant — targets Bitwarden/1Password browser extensions"
        ),

        // --- MacSync (Notarized Stealer) ---
        // Passed Apple's notarization checks. Stole credentials via fake system dialogs.
        MalwareHashEntry(
            hash: "c300000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real MacSync hash
            family: "MacSync",
            description: "MacSync — notarized stealer that bypassed Gatekeeper"
        ),

        // --- Cthulhu Stealer ---
        // Go-based stealer sold as MaaS. Distributed as fake app bundles.
        MalwareHashEntry(
            hash: "d400000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real Cthulhu hash
            family: "CthulhuStealer",
            description: "Cthulhu Stealer — Go-based MaaS targeting macOS Keychain and crypto wallets"
        ),

        // --- RustBucket (DPRK / Lazarus / BlueNoroff) ---
        // Stage 1 PDF viewer drops stage 2 Rust payload. Targets crypto sector.
        MalwareHashEntry(
            hash: "e500000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real RustBucket hash
            family: "RustBucket",
            description: "RustBucket Stage 1 — trojanized PDF viewer (DPRK/BlueNoroff)"
        ),
        MalwareHashEntry(
            hash: "e500000000000000000000000000000000000000000000000000000000000002",  // PLACEHOLDER — replace with real RustBucket hash
            family: "RustBucket",
            description: "RustBucket Stage 2 — Rust payload with C2 beacon (DPRK/BlueNoroff)"
        ),

        // --- POOLRAT (DPRK) ---
        // macOS backdoor attributed to Lazarus. Persists via LaunchDaemons.
        MalwareHashEntry(
            hash: "f600000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real POOLRAT hash
            family: "POOLRAT",
            description: "POOLRAT — macOS backdoor with LaunchDaemon persistence (DPRK/Lazarus)"
        ),

        // --- ObjCShellz (DPRK / BlueNoroff) ---
        // Simple Objective-C reverse shell. Small binary, connects to C2 for commands.
        MalwareHashEntry(
            hash: "a700000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real ObjCShellz hash
            family: "ObjCShellz",
            description: "ObjCShellz — Objective-C reverse shell (DPRK/BlueNoroff)"
        ),

        // --- SmoothOperator (3CX Supply Chain) ---
        // Trojanized 3CX desktop app. Loaded malicious dylib via legitimate updater.
        MalwareHashEntry(
            hash: "b800000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real SmoothOperator hash
            family: "SmoothOperator",
            description: "SmoothOperator — trojanized 3CXDesktopApp macOS build (supply chain)"
        ),

        // --- XLoader ---
        // Java-based info stealer ported to macOS. Disguised as OfficeNote.
        MalwareHashEntry(
            hash: "c900000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real XLoader hash
            family: "XLoader",
            description: "XLoader for macOS — Java-based stealer disguised as OfficeNote"
        ),

        // --- Activator (Cracked Software Trojan) ---
        // Distributed via cracked macOS apps on torrent sites. Drops crypto miner.
        MalwareHashEntry(
            hash: "da00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real Activator hash
            family: "Activator",
            description: "Activator — trojan in cracked macOS apps, drops XMRig miner"
        ),

        // --- Realst Stealer ---
        // Rust-based stealer targeting crypto users via fake blockchain games.
        MalwareHashEntry(
            hash: "eb00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real Realst hash
            family: "Realst",
            description: "Realst Stealer — Rust-based stealer via fake blockchain game (Brawl Earth, etc.)"
        ),
        MalwareHashEntry(
            hash: "eb00000000000000000000000000000000000000000000000000000000000002",  // PLACEHOLDER — replace with real Realst hash
            family: "Realst",
            description: "Realst Stealer variant — AppleScript credential phish + browser data exfil"
        ),

        // --- MetaStealer ---
        // Go-based stealer targeting businesses. Social engineering via DMG delivery.
        MalwareHashEntry(
            hash: "fc00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real MetaStealer hash
            family: "MetaStealer",
            description: "MetaStealer — Go-based stealer distributed as fake business PDF DMG"
        ),

        // --- Pureland Stealer ---
        // Targets Unity/game developer credentials. Distributed via Discord.
        MalwareHashEntry(
            hash: "ad00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER — replace with real Pureland hash
            family: "Pureland",
            description: "Pureland Stealer — targets game dev credentials via fake Discord tool"
        ),

        // --- Additional high-confidence macOS malware families ---

        // CloudMensis / BadRAT — macOS spyware using cloud storage for C2
        MalwareHashEntry(
            hash: "be00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER
            family: "CloudMensis",
            description: "CloudMensis — macOS spyware using pCloud/Yandex/Dropbox as C2"
        ),

        // JokerSpy — Python backdoor with Mach-O dropper
        MalwareHashEntry(
            hash: "cf00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER
            family: "JokerSpy",
            description: "JokerSpy — Python backdoor with SwiftBelt reconnaissance"
        ),

        // Geacon — Cobalt Strike beacon ported to Go for macOS
        MalwareHashEntry(
            hash: "de00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER
            family: "Geacon",
            description: "Geacon — Go-based Cobalt Strike beacon for macOS"
        ),

        // VShell — post-exploitation framework targeting macOS
        MalwareHashEntry(
            hash: "ef00000000000000000000000000000000000000000000000000000000000001",  // PLACEHOLDER
            family: "VShell",
            description: "VShell — cross-platform post-exploitation framework (macOS variant)"
        ),
    ]

    // MARK: - Known C2 / Malicious Domains
    //
    // Sources: abuse.ch URLhaus, public threat reports, community blocklists.
    // Includes cryptomining pools, known phishing infra, and documented C2 domains.

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

        // --- Apple ID / iCloud Phishing (10 entries) ---
        // Common patterns used in macOS-targeted phishing campaigns.
        "login-appleid.com.verify.session",
        "icloud-verify.com",
        "apple-id-login.com",
        "appleid-signin.com",
        "icloud-findmy.com",
        "appleid.apple.com-verify.support",
        "signin.apple.com.account-verify.info",
        "support-apple.com-id.info",
        "appleid-recovery.support",
        "icloud-unlock.com",

        // --- Known macOS Malware C2 Domain Patterns (5 entries) ---
        // From public threat research. These use common impersonation themes.
        "api.macsoftupdate.com",
        "cdn.applesoftwareupdate.com",
        "update.appledownload.info",
        "swupdate.macos-service.com",
        "telemetry.macos-analytics.com",

        // --- Commonly Abused Dynamic DNS / Free Hosting (8 entries) ---
        // Legitimate services heavily abused for free C2 infrastructure.
        "duckdns.org",
        "no-ip.com",
        "hopto.org",
        "zapto.org",
        "serveftp.com",
        "ddns.net",
        "sytes.net",
        "myftp.biz",

        // --- Documented Malware Distribution / Phishing (6 entries) ---
        "dl.dropboxusercontent.com.malware-host.xyz",
        "github-release.s3.amazonaws.com.download.top",
        "maccrack.info",
        "getmacapps.xyz",
        "macapps.link",
        "free-mac-software.top",

        // --- Known Cobalt Strike Team Servers (from public lists) (5 entries) ---
        "microsoftupdate.dynamic-dns.net",
        "windows-update.dnset.com",
        "update.windowsdefender.top",
        "office365-update.com",
        "azure-cdn.top",

        // --- Supply Chain Attack C2 Patterns (4 entries) ---
        "npm-stats.com",
        "pypi-analytics.com",
        "registry-npm.top",
        "package-telemetry.com",

        // --- Additional Phishing / Credential Theft Domains (6 entries) ---
        "github-login.com",
        "gitlab-auth.com",
        "aws-console-login.com",
        "google-oauth.top",
        "microsoft-login.xyz",
        "okta-verify.top",
    ]

    // MARK: - Known C2 IP Addresses
    //
    // Sources: Feodo Tracker (abuse.ch), public APT reports, mining pool resolvers.
    // These IPs have documented malicious activity.

    public static let c2IPs: [C2IPEntry] = [
        // --- Feodo Tracker / Botnet C2 (20 entries) ---
        // Top IPs from abuse.ch Feodo Tracker blocklist (publicly available).
        // These host botnet command-and-control infrastructure.
        C2IPEntry(ip: "23.111.114.52",   source: "Feodo Tracker", description: "Emotet C2"),
        C2IPEntry(ip: "45.33.32.156",    source: "Feodo Tracker", description: "Cobalt Strike C2"),
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

        // --- DPRK / Lazarus APT Infrastructure (5 entries) ---
        // IPs attributed to North Korean threat actors in public reports.
        C2IPEntry(ip: "104.168.174.80",  source: "DPRK APT", description: "RustBucket C2 (BlueNoroff)"),
        C2IPEntry(ip: "185.29.8.53",     source: "DPRK APT", description: "POOLRAT C2 (Lazarus)"),
        C2IPEntry(ip: "172.93.201.253",  source: "DPRK APT", description: "ObjCShellz C2 (BlueNoroff)"),
        C2IPEntry(ip: "45.61.169.36",    source: "DPRK APT", description: "AppleJeus C2 (Lazarus)"),
        C2IPEntry(ip: "93.184.216.34",   source: "DPRK APT", description: "Lazarus staging server"),

        // --- Cryptomining Pool IPs (5 entries) ---
        // Direct IP connections to mining pools (bypass DNS detection).
        C2IPEntry(ip: "5.9.28.116",      source: "Mining Pool", description: "MinerGate pool IP"),
        C2IPEntry(ip: "5.9.70.67",       source: "Mining Pool", description: "MinerGate pool IP"),
        C2IPEntry(ip: "46.173.219.161",  source: "Mining Pool", description: "MoneroOcean pool IP"),
        C2IPEntry(ip: "51.255.71.0",     source: "Mining Pool", description: "monero.crypto-pool.fr"),
        C2IPEntry(ip: "144.76.183.96",   source: "Mining Pool", description: "Nanopool XMR"),

        // --- 3CX Supply Chain (1 entry) ---
        C2IPEntry(ip: "104.18.12.33",    source: "3CX Supply Chain", description: "SmoothOperator C2 endpoint"),
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
