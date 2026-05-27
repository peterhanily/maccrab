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
            purpose: "Pulls Safari LocalStorage + IndexedDB contents — what websites have stored locally. Page-content class, requires encrypted scan.",
            dataSources: [
                "~/Library/Safari/LocalStorage/",
                "~/Library/Safari/Databases/Databases.db",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["safari.localstorage", "safari.indexeddb"],
            privacyClass: .content
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
            purpose: "Full iMessage / SMS message text bodies. Personal comms — requires encrypted scan and opt-in.",
            dataSources: [
                "~/Library/Messages/chat.db (SQLite)",
                "~/Library/Messages/Attachments/ (linked files)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["imessage.message_body"],
            privacyClass: .personalComms
        ),
        "com.maccrab.forensics.facetime": ScannerFact(
            pluginID: "com.maccrab.forensics.facetime",
            purpose: "FaceTime call history — peers, durations, connection state. Personal comms.",
            dataSources: [
                "~/Library/CallHistoryDB/CallHistory.storedata",
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
                "/private/var/db/CoreDuet/Knowledge/knowledgeC.db (system)",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["knowledgec.event"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.biome": ScannerFact(
            pluginID: "com.maccrab.forensics.biome",
            purpose: "Reads the Biome stream store — app usage, location, focus mode, notifications. Newer (Ventura+) replacement for parts of KnowledgeC.",
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
                "/Applications/, ~/Applications/, /usr/local/bin/, ~/.local/bin/",
                "codesign(1) per binary",
            ],
            tccRequirements: ["Full Disk Access"],
            emits: ["codesigning.binary"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.macho-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.macho-analyzer",
            purpose: "Deep Mach-O header inspection: dyld bindings, load commands, missing hardened-runtime, suspicious dylib injection paths.",
            dataSources: [
                "Mach-O binaries on disk (path-driven)",
            ],
            tccRequirements: [],
            emits: ["macho.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.dmg-pkg-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.dmg-pkg-analyzer",
            purpose: "Inspects DMG and PKG installer payloads for unsigned components and pre-install scripts. Useful when an installer landed in Quarantine.",
            dataSources: [
                "DMG / PKG files (path-driven)",
            ],
            tccRequirements: [],
            emits: ["dmg.analysis", "pkg.analysis"],
            privacyClass: .metadata
        ),
        "com.maccrab.forensics.plist-analyzer": ScannerFact(
            pluginID: "com.maccrab.forensics.plist-analyzer",
            purpose: "Walks plist files for suspicious entitlement, LSEnvironment, or login-item patterns.",
            dataSources: [
                "Plist files on disk (path-driven, kit-supplied targets)",
            ],
            tccRequirements: [],
            emits: ["plist.analysis"],
            privacyClass: .metadata
        ),
    ]
}
