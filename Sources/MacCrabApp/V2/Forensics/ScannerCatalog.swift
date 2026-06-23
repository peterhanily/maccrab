// ScannerCatalog.swift
//
// Operator-facing per-scanner reference: what files it reads,
// what it extracts, what TCC it needs, what heuristic flags it
// can raise. Used by the "How it works" kit sheet so the
// operator can decide what will actually happen on their Mac
// before they hit Run.
//
// Sourced from the plugin manifests + the scanner implementation,
// but kept in this single file rather than parsing manifests at
// runtime — manifests don't carry the natural-language source
// path strings the operator needs.

import Foundation

public struct ScannerFact: Sendable {
    public let pluginID: String
    /// One-line summary, used by the kit-sheet rows and the
    /// findings tab tooltip.
    public let purpose: String
    /// File / database paths the scanner reads, in human form.
    public let dataSources: [String]
    /// macOS privacy services this scanner needs, in human form.
    public let tccRequirements: [String]
    /// Content type ids this scanner emits (matched by
    /// ScannerDisplay.contentTypeNames for labelling).
    public let emits: [String]
    /// Privacy class — drives the "Will store encrypted at rest"
    /// affordance.
    public let privacyClass: PrivacyClassDisplay
}

public enum PrivacyClassDisplay: String, Sendable {
    case metadata
    case personalComms
    case content

    public var label: String {
        switch self {
        case .metadata:      return "Metadata only — safe in plaintext scan"
        case .personalComms: return "Personal communications — requires encrypted scan"
        case .content:       return "Content data — requires encrypted scan"
        }
    }
}

public enum ScannerCatalog {

    public static func fact(forPluginID id: String) -> ScannerFact? {
        facts[id]
    }

    private static let facts: [String: ScannerFact] = [
        "com.maccrab.forensics.tcc-lite": ScannerFact(
            pluginID: "com.maccrab.forensics.tcc-lite",
            purpose: "Snapshots every privacy permission grant currently in effect — which app has been allowed which sensitive service.",
            dataSources: [
                "/Library/Application Support/com.apple.TCC/TCC.db (system grants)",
                "~/Library/Application Support/com.apple.TCC/TCC.db (per-user grants)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["tcc.grant", "tcc.summary_by_service"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.launchd-lite": ScannerFact(
            pluginID: "com.maccrab.forensics.launchd-lite",
            purpose: "Inventories every launch agent + daemon + StartupItem on this Mac, with codesign + binary-path posture for each.",
            dataSources: [
                "/Library/LaunchAgents/, /Library/LaunchDaemons/, /System/Library/Launch*/",
                "~/Library/LaunchAgents/",
                "Background Activity Monitor (BAM) database",
            ],
            tccRequirements: ["Full Disk Access (for BAM)"],
            emits: ["launchd.entry", "launchd.bam_entry"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.quarantine": ScannerFact(
            pluginID: "com.maccrab.forensics.quarantine",
            purpose: "Pulls recent quarantine events from LaunchServices — downloads, AirDrop transfers, iMessage attachments, anything macOS Gatekeeper has touched.",
            dataSources: [
                "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["quarantine.event"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.safari-lite": ScannerFact(
            pluginID: "com.maccrab.forensics.safari-lite",
            purpose: "Reads Safari's history database — visited URLs, download list, installed extensions. No page bodies, no LocalStorage.",
            dataSources: [
                "~/Library/Safari/History.db (visits + downloads)",
                "~/Library/Safari/Extensions/ (installed extensions)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["safari.history_visit", "safari.download", "safari.extension"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.safari-deep": ScannerFact(
            pluginID: "com.maccrab.forensics.safari-deep",
            purpose: "Discovers (does not read) LocalStorage + IndexedDB databases per origin — names, paths, sizes. No stored values are read.",
            dataSources: [
                "~/Library/Safari/LocalStorage/",
                "~/Library/Safari/Databases/___IndexedDB/",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["safari.localstorage", "safari.indexeddb"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.mail": ScannerFact(
            pluginID: "com.maccrab.forensics.mail",
            purpose: "Walks Mail.app envelope database — sender, subject, headers, received-at. No message body content.",
            dataSources: [
                "~/Library/Mail/V*/MailData/Envelope Index (SQLite)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["mail.message"],
            privacyClass: .personalComms
        ),
        "com.maccrab.forensics.mail-bodies": ScannerFact(
            pluginID: "com.maccrab.forensics.mail-bodies",
            purpose: "Extracts full Mail.app message bodies. Used for phishing artefact extraction. Personal comms — requires encrypted scan.",
            dataSources: [
                "~/Library/Mail/V*/<account>/<mailbox>.mbox/Messages/*.emlx",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["mail.message_body"],
            privacyClass: .personalComms
        ),
        "com.maccrab.forensics.imessage-metadata": ScannerFact(
            pluginID: "com.maccrab.forensics.imessage-metadata",
            purpose: "iMessage handles + threads + URL mentions — who has the user talked to, and what links have been shared. No message bodies.",
            dataSources: [
                "~/Library/Messages/chat.db (SQLite)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["imessage.handle", "imessage.thread", "imessage.message_meta", "imessage.url_mention"],
            privacyClass: .personalComms
        ),
        "com.maccrab.forensics.imessage-bodies": ScannerFact(
            pluginID: "com.maccrab.forensics.imessage-bodies",
            purpose: "Full iMessage / SMS message text bodies. Content class — requires encrypted scan and opt-in.",
            dataSources: [
                "~/Library/Messages/chat.db (SQLite)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["imessage.message_body"],
            privacyClass: .content
        ),
        "com.maccrab.forensics.facetime": ScannerFact(
            pluginID: "com.maccrab.forensics.facetime",
            purpose: "FaceTime call history — peers, durations, connection state. Personal comms.",
            dataSources: [
                "~/Library/Application Support/CallHistoryDB/CallHistory.storedata",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["facetime.call"],
            privacyClass: .personalComms
        ),
        "com.maccrab.forensics.knowledgec": ScannerFact(
            pluginID: "com.maccrab.forensics.knowledgec",
            purpose: "Reads CoreDuet's KnowledgeC database — Apple's activity-bundle store: app usage, focus mode, screen time, where the user was when they did what.",
            dataSources: [
                "~/Library/Application Support/Knowledge/knowledgeC.db",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["knowledgec.event"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.biome": ScannerFact(
            pluginID: "com.maccrab.forensics.biome",
            purpose: "Discovers Biome stream names + sizes; does not yet decode per-event app-usage/location. Newer (Ventura+) replacement for parts of KnowledgeC.",
            dataSources: [
                "~/Library/Biome/",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["biome.stream"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.applescript-runtime": ScannerFact(
            pluginID: "com.maccrab.forensics.applescript-runtime",
            purpose: "Recent AppleScript / osascript invocations. AI agents and remote-access tools frequently use AppleScript to automate other apps.",
            dataSources: [
                "Unified logging subsystem com.apple.AppleScript",
            ],
            tccRequirements: [],
            emits: ["applescript.invocation"],
            privacyClass: .content
        ),
        "com.maccrab.forensics.posture-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.posture-analyzer",
            purpose: "Cross-references collected persistence + permissions + signing data. Surfaces unsigned persistence, unfamiliar-team automation, high-privilege unsigned binaries.",
            dataSources: [
                "Other plugins' committed artifacts in the same case",
            ],
            tccRequirements: [],
            emits: [
                "posture.unsigned_persistence",
                "posture.unfamiliar_team_persistence",
                "posture.automation_to_sensitive_target",
                "posture.high_privilege_unsigned_combo",
                "posture.permissioned_persistence",
            ],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.codesigning-graph": ScannerFact(
            pluginID: "com.maccrab.forensics.codesigning-graph",
            purpose: "Builds a signer-to-binary graph for installed apps and CLI tools. Used to spot unfamiliar Team IDs and signer reuse patterns.",
            dataSources: [
                "/Applications/, ~/Applications/, /usr/local/bin/, /opt/homebrew/bin/, /opt/homebrew/sbin/, /Library/PrivilegedHelperTools/",
                "codesign(1) per binary",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["codesigning.binary"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.macho-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.macho-analyzer",
            purpose: "Mach-O inspection: architecture, linked dylib list (otool -L), codesign status, entitlement key names.",
            dataSources: [
                "Mach-O binaries on disk (path-driven)",
            ],
            tccRequirements: [],
            emits: ["macho.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.dmg-pkg-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.dmg-pkg-analyzer",
            purpose: "Inspects DMG and PKG installers for signed + notarized posture (hdiutil imageinfo / pkgutil --check-signature + codesign + sha256). Useful when an installer landed in Quarantine.",
            dataSources: [
                "DMG / PKG files (path-driven)",
            ],
            tccRequirements: [],
            emits: ["dmg.analysis", "pkg.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.plist-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.plist-analyzer",
            purpose: "Dumps the top-level key names (plus format + size) of the inspected plist files.",
            dataSources: [
                "/System/Library/LaunchDaemons/com.apple.notifyd.plist, /Library/Preferences/com.apple.PowerManagement.plist",
            ],
            tccRequirements: [],
            emits: ["plist.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.fsevents": ScannerFact(
            pluginID: "com.maccrab.forensics.fsevents",
            purpose: "Enumerates /.fseventsd/ log files (UUID, size, mtime) and parses their gzipped binary records into per-path file-system events with decoded flags (≤1000 per log file).",
            dataSources: [
                "/.fseventsd/ (gzipped FSEvents log files)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["fsevents.log_file", "fsevents.record"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.image-metadata": ScannerFact(
            pluginID: "com.maccrab.forensics.image-metadata",
            purpose: "Extracts image metadata via ImageIO: dimensions, GPS lat/long, camera make/model/software, and presence flags for EXIF / IPTC / XMP.",
            dataSources: [
                "~/Downloads/ (or an operator-supplied --path image)",
            ],
            tccRequirements: [],
            emits: ["image.metadata"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.mobileconfig-inspector": ScannerFact(
            pluginID: "com.maccrab.forensics.mobileconfig-inspector",
            purpose: "Scans Managed Preferences profiles: top-level keys, declared PayloadContent types, CMS-signed flag, and certificate / DNS / VPN payload presence.",
            dataSources: [
                "/Library/Managed Preferences/, ~/Library/Managed Preferences/ (.mobileconfig / .plist)",
            ],
            tccRequirements: [],
            emits: ["mobileconfig.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.shortcuts-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.shortcuts-analyzer",
            purpose: "Catalogs loose Shortcuts files: name, path, size, mtime, sha256. Does not decode the internal action graph.",
            dataSources: [
                "~/Library/Shortcuts/, ~/Library/Mobile Documents/.../Documents/ (.shortcut / .wflow)",
            ],
            tccRequirements: [],
            emits: ["shortcuts.shortcut"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.archive-walker": ScannerFact(
            pluginID: "com.maccrab.forensics.archive-walker",
            purpose: "Lists archive contents without extraction (.zip via unzip -l, .tar/.tar.gz/.tgz via tar -t): entry count, format, size, sha256, capped filename preview.",
            dataSources: [
                "~/Downloads/ (.zip / .tar / .tar.gz / .tgz)",
            ],
            tccRequirements: [],
            emits: ["archive.listing"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.document-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.document-analyzer",
            purpose: "PDF dissection via PDFKit: page count, document metadata (author / producer / creator / dates), and embedded JavaScript / embedded-file detection. Office formats deferred.",
            dataSources: [
                "~/Downloads/ (.pdf)",
            ],
            tccRequirements: [],
            emits: ["document.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.office-document-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.office-document-analyzer",
            purpose: "Parses Office OPC packages (.docx/.xlsx/.pptx + macro variants): core.xml metadata (creator, lastModifiedBy, created/modified) and macro presence (vbaProject.bin).",
            dataSources: [
                "~/Downloads/ (.docx / .docm / .xlsx / .xlsm / .pptx / .pptm)",
            ],
            tccRequirements: [],
            emits: ["office.document"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.geoip-asn": ScannerFact(
            pluginID: "com.maccrab.enricher.geoip-asn",
            purpose: "Classifies an IPv4 address into its range type — loopback, private class A/B/C, CGNAT, link-local, or public. No ASN, no country (no MaxMind MMDB bundled).",
            dataSources: [
                "IPv4 host on the URL / path subject (no files read)",
            ],
            tccRequirements: [],
            emits: ["geoip.range_token"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.dns-passive-reputation": ScannerFact(
            pluginID: "com.maccrab.enricher.dns-passive-reputation",
            purpose: "Heuristic domain reputation: suspicious TLD, Cyrillic homoglyph, mixed-script, and brand-impersonation patterns. No live passive-DNS API.",
            dataSources: [
                "Domain host on the URL / path / process subject (no files read)",
            ],
            tccRequirements: [],
            emits: ["dns_reputation.suspicious_overall"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.threatintel-domain": ScannerFact(
            pluginID: "com.maccrab.enricher.threatintel-domain",
            purpose: "Checks a domain against the live daemon IOC cache (URLhaus / MalwareBazaar / Feodo) and labels a match with feed source + malware family.",
            dataSources: [
                "<app-support>/MacCrab/threat_intel/feed_cache.json (daemon-maintained IOC cache)",
            ],
            tccRequirements: [],
            emits: ["threatintel.is_known_malicious"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.threatintel-ip": ScannerFact(
            pluginID: "com.maccrab.enricher.threatintel-ip",
            purpose: "Checks an IP against the live daemon IOC cache (URLhaus / MalwareBazaar / Feodo) and labels a match with feed source + malware family.",
            dataSources: [
                "<app-support>/MacCrab/threat_intel/feed_cache.json (daemon-maintained IOC cache)",
            ],
            tccRequirements: [],
            emits: ["threatintel.ip_is_known_malicious"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.codesign-resolve": ScannerFact(
            pluginID: "com.maccrab.enricher.codesign-resolve",
            purpose: "Resolves a binary's codesign posture: signing status, team id, bundle id, notarization, hardened-runtime flag. Cached per path.",
            dataSources: [
                "Binary at the event / alert / path subject (via codesign)",
            ],
            tccRequirements: [],
            emits: ["codesign.signing_status"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.codesigning-anomaly": ScannerFact(
            pluginID: "com.maccrab.enricher.codesigning-anomaly",
            purpose: "Flags surprising codesign postures by path heuristics: unsigned in a system path, Developer-ID in /System/, ad-hoc outside the dev tree, unnotarized Dev-ID in a system area.",
            dataSources: [
                "Binary at the event / alert / path subject (via codesign)",
            ],
            tccRequirements: [],
            emits: ["codesigning_anomaly.has_anomalies"],
            privacyClass: .metadata
        ),
        "com.maccrab.enricher.stylometric-supply-chain": ScannerFact(
            pluginID: "com.maccrab.enricher.stylometric-supply-chain",
            purpose: "Heuristic supply-chain text flags: eval/exec markers, long base64 runs, long hex blobs. Drift-vs-baseline integration is shape-wired but deferred.",
            dataSources: [
                "First 16 KB of the path subject's file (path subjects only)",
            ],
            tccRequirements: [],
            emits: ["stylometric.suspicious_overall"],
            privacyClass: .metadata
        ),
    ]
}
