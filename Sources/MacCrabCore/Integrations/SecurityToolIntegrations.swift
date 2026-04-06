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

    public struct InstalledTool: Sendable {
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

        return tools
    }

    // MARK: - BlockBlock Log Ingestion

    public struct BlockBlockAlert: Sendable {
        public let timestamp: String
        public let item: String
        public let process: String
        public let action: String  // "allowed" or "blocked"
        public let rawLine: String
    }

    /// Read and parse BlockBlock's log file for persistence alerts.
    public func readBlockBlockLog(since: Date? = nil) -> [BlockBlockAlert] {
        let logPath = "/Library/Objective-See/BlockBlock/BlockBlock.log"
        guard let content = try? String(contentsOfFile: logPath, encoding: .utf8) else { return [] }

        var alerts: [BlockBlockAlert] = []
        for line in content.components(separatedBy: "\n") where !line.isEmpty {
            // BlockBlock log format varies, parse key fields
            let alert = BlockBlockAlert(
                timestamp: String(line.prefix(19)),
                item: extractField(line, label: "item:") ?? extractField(line, label: "path:") ?? "",
                process: extractField(line, label: "process:") ?? "",
                action: line.lowercased().contains("blocked") ? "blocked" : "allowed",
                rawLine: String(line.prefix(500))
            )
            if !alert.item.isEmpty {
                alerts.append(alert)
            }
        }
        return alerts
    }

    // MARK: - KnockKnock Scan

    public struct KnockKnockItem: Sendable {
        public let category: String
        public let name: String
        public let path: String
        public let isTrusted: Bool
    }

    /// Run KnockKnock CLI scan and parse results.
    /// Returns nil if KnockKnock is not installed.
    public func runKnockKnockScan() async -> [KnockKnockItem]? {
        let kkPath = "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"
        guard FileManager.default.fileExists(atPath: kkPath) else { return nil }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: kkPath)
        proc.arguments = ["-whosthere", "-pretty", "-skipVT"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            proc.waitUntilExit()
        } catch { return nil }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }

        var items: [KnockKnockItem] = []
        for (category, value) in json {
            guard let entries = value as? [[String: Any]] else { continue }
            for entry in entries {
                let name = entry["name"] as? String ?? "Unknown"
                let path = entry["path"] as? String ?? ""
                let trusted = entry["isTrusted"] as? Bool ?? false
                items.append(KnockKnockItem(category: category, name: name, path: path, isTrusted: trusted))
            }
        }
        return items
    }

    // MARK: - Little Snitch Traffic Log

    public struct LittleSnitchConnection: Sendable {
        public let timestamp: String
        public let direction: String
        public let remoteHost: String
        public let port: Int
        public let process: String
        public let denied: Bool
        public let bytesIn: Int
        public let bytesOut: Int
    }

    /// Read Little Snitch traffic log via CLI.
    /// Returns nil if Little Snitch is not installed or CLI is not enabled.
    public func readLittleSnitchTraffic(lines: Int = 1000) async -> [LittleSnitchConnection]? {
        guard FileManager.default.fileExists(atPath: "/Applications/Little Snitch.app") else { return nil }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["littlesnitch", "log-traffic"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            // Read for a few seconds then terminate
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { proc.terminate() }
            proc.waitUntilExit()
        } catch { return nil }

        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        var connections: [LittleSnitchConnection] = []

        for line in output.components(separatedBy: "\n").prefix(lines) {
            let fields = line.components(separatedBy: ",")
            guard fields.count >= 12 else { continue }

            connections.append(LittleSnitchConnection(
                timestamp: fields[0],
                direction: fields[1],
                remoteHost: fields[4],
                port: Int(fields[6]) ?? 0,
                process: fields[10],
                denied: (Int(fields[8]) ?? 0) > 0,
                bytesIn: Int(fields[9]) ?? 0,
                bytesOut: Int(fields[10]) ?? 0
            ))
        }
        return connections.isEmpty ? nil : connections
    }

    // MARK: - Objective-See Unified Log

    /// Read LuLu alerts from the unified log.
    public func readLuLuLog(maxEntries: Int = 100) async -> [String]? {
        guard isProcessRunning("LuLu") else { return nil }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        proc.arguments = ["show", "--predicate", "subsystem == 'com.objective-see.lulu'", "--last", "1h", "--style", "compact"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            proc.waitUntilExit()
        } catch { return nil }

        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let entries = output.components(separatedBy: "\n").filter { !$0.isEmpty }.prefix(maxEntries).map { String($0) }
        return entries.isEmpty ? nil : entries
    }

    // MARK: - .lsrules Export (User imports manually)

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

    private func extractField(_ line: String, label: String) -> String? {
        guard let range = line.range(of: label) else { return nil }
        let after = line[range.upperBound...].trimmingCharacters(in: .whitespaces)
        let value = after.prefix(while: { $0 != "," && $0 != "\n" && $0 != "]" })
        return value.isEmpty ? nil : String(value)
    }
}
