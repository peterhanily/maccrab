// ScannerDisplay.swift
//
// Plain-English name + content-type label lookup for forensic
// scanner output. Five dashboard views were maintaining their
// own copy of this map (V2ForensicsScansView, ScanDetailView,
// FindingsView, SettingsSheet, RaveCatalogBrowserView); rc.10
// consolidates so adding a new plugin id only changes one place.

import Foundation

public enum ScannerDisplay {

    /// Operator-readable name for a plugin id.
    public static func name(forPluginID id: String) -> String {
        if let mapped = pluginNames[id] { return mapped }
        // Fallback: take the last reverse-DNS segment, replace
        // dashes with spaces, title-case it.
        guard let tail = id.split(separator: ".").last else { return id }
        return tail.replacingOccurrences(of: "-", with: " ").capitalized
    }

    /// Operator-readable label for a content type emitted by a
    /// plugin (e.g. "tcc.grant" → "Privacy permission grant").
    public static func name(forContentType ct: String) -> String {
        if let mapped = contentTypeNames[ct] { return mapped }
        return ct.replacingOccurrences(of: ".", with: " · ").capitalized
    }

    private static let pluginNames: [String: String] = [
        // First-party Tier A collectors (Bootstrap-registered).
        "com.maccrab.forensics.tcc-lite":               "Privacy permissions",
        "com.maccrab.forensics.launchd-lite":           "Launch items + persistence",
        "com.maccrab.forensics.quarantine":             "Quarantined downloads",
        "com.maccrab.forensics.safari-lite":            "Safari activity",
        "com.maccrab.forensics.safari-deep":            "Safari deep extract",
        "com.maccrab.forensics.mail":                   "Mail metadata",
        "com.maccrab.forensics.mail-bodies":            "Mail bodies",
        "com.maccrab.forensics.imessage-metadata":      "iMessage metadata",
        "com.maccrab.forensics.imessage-bodies":        "iMessage bodies",
        "com.maccrab.forensics.facetime":               "FaceTime call history",
        "com.maccrab.forensics.knowledgec":             "KnowledgeC activity",
        "com.maccrab.forensics.biome":                  "Biome streams",
        "com.maccrab.forensics.applescript-runtime":    "AppleScript activity",
        "com.maccrab.forensics.fsevents":               "FSEvents scan",

        // Analyzers
        "com.maccrab.forensics.posture-analyzer":       "Posture analyzer",

        // Static-analysis collectors
        "com.maccrab.forensics.macho-analyzer":         "Mach-O binary analysis",
        "com.maccrab.forensics.codesigning-graph":      "Codesigning graph",
        "com.maccrab.forensics.dmg-pkg-analyzer":       "DMG/PKG inspector",
        "com.maccrab.forensics.plist-analyzer":         "Plist analyzer",
        "com.maccrab.forensics.mobileconfig-inspector": "Mobileconfig inspector",
        "com.maccrab.forensics.shortcuts-analyzer":     "Shortcuts inspector",
        "com.maccrab.forensics.image-metadata":         "Image metadata",
        "com.maccrab.forensics.archive-walker":         "Archive walker",
        "com.maccrab.forensics.document-analyzer":      "Document analyzer",
        "com.maccrab.forensics.office-document-analyzer":"Office document analyzer",
        "com.maccrab.forensics.fixture":                "Fixture (dev only)",
    ]

    private static let contentTypeNames: [String: String] = [
        // TCC
        "tcc.grant":                 "Privacy permission grant",
        "tcc.summary_by_service":    "Privacy permission summary",

        // Launchd
        "launchd.entry":             "Launch item",
        "launchd.bam_entry":         "Background activity (BAM)",

        // Posture
        "posture.unsigned_persistence":          "Unsigned persistence",
        "posture.unfamiliar_team_persistence":   "Unfamiliar team persistence",
        "posture.automation_to_sensitive_target": "Automation → sensitive target",
        "posture.high_privilege_unsigned_combo":  "High-privilege unsigned combo",
        "posture.permissioned_persistence":       "Permissioned persistence",

        // Safari
        "safari.history_visit":      "Safari history visit",
        "safari.download":           "Safari download",
        "safari.extension":          "Safari extension",
        "safari.localstorage":       "Safari LocalStorage",
        "safari.indexeddb":          "Safari IndexedDB",

        // Mail
        "mail.message":              "Mail message",
        "mail.message_body":         "Mail message body",

        // iMessage
        "imessage.handle":           "iMessage handle",
        "imessage.thread":           "iMessage thread",
        "imessage.message_meta":     "iMessage message metadata",
        "imessage.message_body":     "iMessage message body",
        "imessage.url_mention":      "URL shared in iMessage",

        // FaceTime / Biome / KnowledgeC
        "facetime.call":             "FaceTime call",
        "biome.stream":              "Biome stream",
        "knowledgec.event":          "KnowledgeC event",

        // Quarantine / FSEvents / AppleScript
        "quarantine.event":          "Quarantined download",
        "fsevents.log_file":         "FSEvents log file",
        "fsevents.record":           "FSEvents record",
        "applescript.invocation":    "AppleScript invocation",

        // Static analysis
        "macho.analysis":            "Mach-O binary",
        "codesigning.binary":        "Codesigning entry",
        "dmg.analysis":              "DMG installer",
        "pkg.analysis":              "PKG installer",
        "plist.analysis":            "Plist file",
        "mobileconfig.analysis":     "Mobileconfig profile",
        "shortcuts.shortcut":        "Apple Shortcut",
        "image.metadata":            "Image metadata",
        "archive.listing":           "Archive contents",
        "document.analysis":         "Document",
        "office.document":           "Office document",
    ]
}
