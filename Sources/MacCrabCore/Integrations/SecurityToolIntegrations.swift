// SecurityToolIntegrations.swift
// MacCrabCore
//
// Read-only integrations with other macOS security tools.
// MacCrab observes and correlates — never modifies other tools' configuration.

import Foundation
import os.log

/// Read-only integrations with other macOS security tools.
/// MacCrab observes and correlates — never modifies other tools' configuration.
public actor SecurityToolIntegrations {
    private let logger = Logger(subsystem: "com.maccrab", category: "integrations")

    // MARK: - Tool Detection

    public struct InstalledTool: Sendable, Codable, Hashable {
        public let name: String
        public let path: String
        public let version: String?
        public let isRunning: Bool
        public let logPath: String?
        public let capabilities: [String]

        public init(name: String, path: String, version: String?, isRunning: Bool, logPath: String?, capabilities: [String]) {
            self.name = name
            self.path = path
            self.version = version
            self.isRunning = isRunning
            self.logPath = logPath
            self.capabilities = capabilities
        }
    }

    /// On-disk snapshot of `detectInstalledTools()` output. Written by
    /// the daemon (DaemonTimers) and read by the app (AppState) so the
    /// dashboard sees the daemon's enriched view (`isRunning` checks
    /// run from root and pick up launchds the user can't query) instead
    /// of repeating the scan from a less-privileged context.
    public struct Snapshot: Sendable, Codable {
        public let writtenAt: Date
        public let tools: [InstalledTool]

        public init(writtenAt: Date, tools: [InstalledTool]) {
            self.writtenAt = writtenAt
            self.tools = tools
        }
    }

    /// Write the current detection results to disk for cross-process
    /// consumption. Atomic via tmp-write + direct rename so a
    /// concurrent reader never observes a partial or missing file
    /// during the swap. Falls back to remove+rename only when the
    /// destination exists and direct rename refused (Foundation's
    /// `moveItem` is not atomic-overwrite by default).
    public func writeSnapshot(to path: String) {
        let tools = detectInstalledTools()
        let snapshot = Snapshot(writtenAt: Date(), tools: tools)
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        let tmpPath = path + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmpPath), options: .atomic)
            do {
                try FileManager.default.moveItem(atPath: tmpPath, toPath: path)
            } catch {
                try? FileManager.default.removeItem(atPath: path)
                try FileManager.default.moveItem(atPath: tmpPath, toPath: path)
            }
            // World-readable so the user-side dashboard can pick it up.
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: path
            )
        } catch {
            logger.warning("Failed to write integrations snapshot: \(error.localizedDescription, privacy: .public)")
            try? FileManager.default.removeItem(atPath: tmpPath)
        }
    }

    /// Read a snapshot the daemon wrote. Returns nil when the file is
    /// missing, unreadable, or malformed — callers fall back to an
    /// in-process scan in that case.
    public static func readSnapshot(at path: String) -> Snapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(Snapshot.self, from: data)
    }

    public init() {}

    /// Detect which security tools are installed on this system.
    public func detectInstalledTools() -> [InstalledTool] {
        var tools: [InstalledTool] = []
        let fm = FileManager.default

        // Little Snitch
        if fm.fileExists(atPath: "/Applications/Little Snitch.app") ||
           fm.fileExists(atPath: "/Library/Little Snitch") {
            tools.append(InstalledTool(
                name: "Little Snitch",
                path: "/Applications/Little Snitch.app",
                version: getBundleVersion("/Applications/Little Snitch.app"),
                isRunning: isProcessRunning("Little Snitch Agent"),
                logPath: nil,  // Accessed via CLI only
                capabilities: ["network-firewall", "per-process-rules", "traffic-logging"]
            ))
        }

        // BlockBlock
        if fm.fileExists(atPath: "/Library/Objective-See/BlockBlock") {
            tools.append(InstalledTool(
                name: "BlockBlock",
                path: "/Library/Objective-See/BlockBlock/BlockBlock.app",
                version: getBundleVersion("/Library/Objective-See/BlockBlock/BlockBlock.app"),
                isRunning: isProcessRunning("BlockBlock"),
                logPath: "/Library/Objective-See/BlockBlock/BlockBlock.log",
                capabilities: ["persistence-monitoring", "real-time-alerts"]
            ))
        }

        // LuLu
        if fm.fileExists(atPath: "/Library/Objective-See/LuLu") {
            tools.append(InstalledTool(
                name: "LuLu",
                path: "/Library/Objective-See/LuLu/LuLu.app",
                version: getBundleVersion("/Library/Objective-See/LuLu/LuLu.app"),
                isRunning: isProcessRunning("LuLu"),
                logPath: nil,  // Uses unified log
                capabilities: ["network-firewall", "outbound-blocking"]
            ))
        }

        // KnockKnock
        if fm.fileExists(atPath: "/Applications/KnockKnock.app") {
            tools.append(InstalledTool(
                name: "KnockKnock",
                path: "/Applications/KnockKnock.app",
                version: getBundleVersion("/Applications/KnockKnock.app"),
                isRunning: false,  // On-demand tool, not a daemon
                logPath: nil,
                capabilities: ["persistence-scanning", "virustotal-integration", "cli-json-output"]
            ))
        }

        // OverSight
        if fm.fileExists(atPath: "/Applications/OverSight.app") ||
           fm.fileExists(atPath: "/Library/Objective-See/OverSight") {
            tools.append(InstalledTool(
                name: "OverSight",
                path: "/Applications/OverSight.app",
                version: getBundleVersion("/Applications/OverSight.app"),
                isRunning: isProcessRunning("OverSight"),
                logPath: nil,
                capabilities: ["camera-monitoring", "microphone-monitoring", "external-action-script"]
            ))
        }

        // Santa
        if fm.fileExists(atPath: "/Applications/Santa.app") ||
           fm.fileExists(atPath: "/usr/local/bin/santactl") {
            tools.append(InstalledTool(
                name: "Santa",
                path: "/Applications/Santa.app",
                version: nil,
                isRunning: isProcessRunning("santad"),
                logPath: nil,
                capabilities: ["binary-authorization", "allow-block-lists"]
            ))
        }

        // CrowdStrike Falcon
        if fm.fileExists(atPath: "/Applications/Falcon.app") ||
           fm.fileExists(atPath: "/Library/CS") {
            tools.append(InstalledTool(
                name: "CrowdStrike Falcon",
                path: "/Applications/Falcon.app",
                version: nil,
                isRunning: isProcessRunning("falcond"),
                logPath: nil,
                capabilities: ["edr", "cloud-detection", "response"]
            ))
        }

        // SentinelOne
        if fm.fileExists(atPath: "/Library/Sentinel") {
            tools.append(InstalledTool(
                name: "SentinelOne",
                path: "/Library/Sentinel/sentinel-agent.bundle",
                version: nil,
                isRunning: isProcessRunning("sentineld"),
                logPath: nil,
                capabilities: ["edr", "autonomous-detection", "response"]
            ))
        }

        // Malwarebytes
        if fm.fileExists(atPath: "/Library/Application Support/Malwarebytes") {
            tools.append(InstalledTool(
                name: "Malwarebytes",
                path: "/Applications/Malwarebytes.app",
                version: getBundleVersion("/Applications/Malwarebytes.app"),
                isRunning: isProcessRunning("Malwarebytes"),
                logPath: nil,
                capabilities: ["malware-scanning", "real-time-protection"]
            ))
        }

        // v1.12.5: extend Objective-See coverage. The pre-fix list
        // had Little Snitch / BlockBlock / LuLu / KnockKnock / OverSight
        // but missed RansomWhere, ReiKey, DoNotDisturb, TaskExplorer,
        // NetiQuette, WhatsYourSign, and ProcessMonitor — common on
        // any user-installed Objective-See bundle. Reported by a user
        // who saw an empty Integrations panel despite running several
        // of these.

        // RansomWhere
        if fm.fileExists(atPath: "/Library/Objective-See/RansomWhere") {
            tools.append(InstalledTool(
                name: "RansomWhere?",
                path: "/Library/Objective-See/RansomWhere",
                version: getBundleVersion("/Library/Objective-See/RansomWhere/RansomWhere.app"),
                isRunning: isProcessRunning("RansomWhere"),
                logPath: nil,
                capabilities: ["ransomware-detection", "file-creation-monitoring"]
            ))
        }

        // ReiKey
        if fm.fileExists(atPath: "/Applications/ReiKey.app") {
            tools.append(InstalledTool(
                name: "ReiKey",
                path: "/Applications/ReiKey.app",
                version: getBundleVersion("/Applications/ReiKey.app"),
                isRunning: isProcessRunning("ReiKey"),
                logPath: nil,
                capabilities: ["keyboard-tap-monitoring", "event-tap-detection"]
            ))
        }

        // DoNotDisturb
        if fm.fileExists(atPath: "/Applications/DoNotDisturb.app") ||
           fm.fileExists(atPath: "/Library/Objective-See/DoNotDisturb") {
            tools.append(InstalledTool(
                name: "DoNotDisturb",
                path: "/Applications/DoNotDisturb.app",
                version: getBundleVersion("/Applications/DoNotDisturb.app"),
                isRunning: isProcessRunning("DoNotDisturb"),
                logPath: nil,
                capabilities: ["lid-close-detection", "stolen-laptop-monitoring"]
            ))
        }

        // TaskExplorer
        if fm.fileExists(atPath: "/Applications/TaskExplorer.app") {
            tools.append(InstalledTool(
                name: "TaskExplorer",
                path: "/Applications/TaskExplorer.app",
                version: getBundleVersion("/Applications/TaskExplorer.app"),
                isRunning: false,  // On-demand tool
                logPath: nil,
                capabilities: ["process-explorer", "loaded-dylibs", "open-files"]
            ))
        }

        // NetiQuette
        if fm.fileExists(atPath: "/Applications/Netiquette.app") {
            tools.append(InstalledTool(
                name: "Netiquette",
                path: "/Applications/Netiquette.app",
                version: getBundleVersion("/Applications/Netiquette.app"),
                isRunning: false,
                logPath: nil,
                capabilities: ["network-monitor", "process-connections-explorer"]
            ))
        }

        // WhatsYourSign (Finder extension)
        if fm.fileExists(atPath: "/Applications/WhatsYourSign.app") {
            tools.append(InstalledTool(
                name: "WhatsYourSign",
                path: "/Applications/WhatsYourSign.app",
                version: getBundleVersion("/Applications/WhatsYourSign.app"),
                isRunning: false,
                logPath: nil,
                capabilities: ["finder-codesign-extension"]
            ))
        }

        // ProcessMonitor (CLI)
        if fm.fileExists(atPath: "/usr/local/bin/ProcessMonitor") {
            tools.append(InstalledTool(
                name: "ProcessMonitor",
                path: "/usr/local/bin/ProcessMonitor",
                version: nil,
                isRunning: isProcessRunning("ProcessMonitor"),
                logPath: nil,
                capabilities: ["es-process-events", "cli-json-stream"]
            ))
        }

        // FileMonitor (CLI)
        if fm.fileExists(atPath: "/usr/local/bin/FileMonitor") {
            tools.append(InstalledTool(
                name: "FileMonitor",
                path: "/usr/local/bin/FileMonitor",
                version: nil,
                isRunning: isProcessRunning("FileMonitor"),
                logPath: nil,
                capabilities: ["es-file-events", "cli-json-stream"]
            ))
        }

        return tools
    }

    // MARK: - .lsrules Export (User imports manually)
    //
    // NOTE: the BlockBlock / KnockKnock / Little Snitch / LuLu log-ingestion
    // readers were removed — they had no consumer, no store, and no schema
    // (nothing surfaced their output). `detectInstalledTools` (above) still
    // reports each tool's presence/version, which IS wired into the
    // Intelligence workspace. generateLSRules below is kept (it has a test
    // and is a self-contained export primitive).

    /// Generate a Little Snitch .lsrules file from MacCrab's threat intel.
    /// Users subscribe to this file manually in Little Snitch.
    public func generateLSRules(domains: [String], ips: [String]) -> String {
        var rules: [[String: Any]] = []

        for domain in domains.prefix(5000) {
            rules.append([
                "action": "deny",
                "direction": "outgoing",
                "process": "any",
                "remote-domains": [domain],
                "notes": "MacCrab threat intelligence — malicious domain"
            ])
        }

        for ip in ips.prefix(5000) {
            rules.append([
                "action": "deny",
                "direction": "outgoing",
                "process": "any",
                "remote-addresses": [ip],
                "notes": "MacCrab threat intelligence — malicious IP"
            ])
        }

        let lsrules: [String: Any] = [
            "name": "MacCrab Threat Intelligence",
            "description": "Auto-generated deny rules from MacCrab threat intel feeds. Import into Little Snitch as a rule group.",
            "rules": rules
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: lsrules, options: [.prettyPrinted, .sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return "{}" }
        return json
    }

    // MARK: - Helpers

    private nonisolated func isProcessRunning(_ name: String) -> Bool {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        proc.arguments = ["-x", name]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        return proc.terminationStatus == 0
    }

    private nonisolated func getBundleVersion(_ appPath: String) -> String? {
        let plistPath = appPath + "/Contents/Info.plist"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plistPath)),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return nil }
        return plist["CFBundleShortVersionString"] as? String
    }
}
