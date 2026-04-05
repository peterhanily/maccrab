// ResponseAction.swift
// MacCrabCore
//
// Response actions that can be triggered when detection rules match.
// Actions range from passive (log, notify) to active (kill, quarantine, block).

import Foundation
import Darwin
import os.log

// MARK: - Action Types

/// A response action to execute when a rule fires.
public enum ResponseActionType: String, Codable, Sendable {
    /// Log the alert (default, always happens).
    case log
    /// Send a macOS notification banner.
    case notify
    /// Kill the process that triggered the alert.
    case kill
    /// Move the triggering file to a quarantine vault.
    case quarantine
    /// Run a custom shell script with alert context as environment variables.
    case script
    /// Block the network connection via PF firewall rule (requires root).
    case blockNetwork
    /// Send a high-priority macOS notification with action details.
    case escalateNotification
}

/// Configuration for a response action attached to a rule.
public struct ResponseActionConfig: Codable, Sendable {
    public let action: ResponseActionType
    /// For script actions: path to the script to execute.
    public let scriptPath: String?
    /// Only execute for alerts at or above this severity.
    public let minimumSeverity: Severity
    /// Require explicit confirmation before executing (for destructive actions).
    public let requireConfirmation: Bool
    /// For blockNetwork: how long (in seconds) to keep the block rule active.
    /// Defaults to 3600 (1 hour).
    public let blockDurationSeconds: Int?

    public init(
        action: ResponseActionType,
        scriptPath: String? = nil,
        minimumSeverity: Severity = .high,
        requireConfirmation: Bool = false,
        blockDurationSeconds: Int? = nil
    ) {
        self.action = action
        self.scriptPath = scriptPath
        self.minimumSeverity = minimumSeverity
        self.requireConfirmation = requireConfirmation
        self.blockDurationSeconds = blockDurationSeconds
    }
}

// MARK: - Response Engine

/// Executes response actions when alerts are generated.
public actor ResponseEngine {

    private let logger = Logger(subsystem: "com.maccrab", category: "response")

    /// Directory for quarantined files.
    private let quarantineDir: String

    /// Per-rule action configurations.
    private var ruleActions: [String: [ResponseActionConfig]] = [:]

    /// Global default actions (applied to all rules unless overridden).
    private var defaultActions: [ResponseActionConfig] = []

    /// Action execution log for auditing.
    private var executionLog: [(timestamp: Date, ruleId: String, action: ResponseActionType, target: String, success: Bool)] = []

    /// Path to the PF anchor file used for temporary block rules.
    private let pfAnchorPath: String

    /// Currently active network blocks for expiration tracking.
    private var activeBlocks: [NetworkBlock] = []

    /// Tracks info about a temporary PF block rule.
    private struct NetworkBlock: Sendable {
        let ip: String
        let addedAt: Date
        let expiresAt: Date
        let ruleId: String
    }

    public init(quarantineDir: String? = nil) {
        if let dir = quarantineDir {
            self.quarantineDir = dir
        } else {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first.map { $0.appendingPathComponent("MacCrab/quarantine").path }
                ?? NSHomeDirectory() + "/Library/Application Support/MacCrab/quarantine"
            self.quarantineDir = appSupport
        }
        self.pfAnchorPath = {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first.map { $0.appendingPathComponent("MacCrab").path }
                ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
            return (appSupport as NSString).appendingPathComponent("maccrab_blocks.conf")
        }()
        try? FileManager.default.createDirectory(
            atPath: self.quarantineDir,
            withIntermediateDirectories: true
        )
    }

    // MARK: - Configuration

    /// Set actions for a specific rule ID.
    public func setActions(forRule ruleId: String, actions: [ResponseActionConfig]) {
        ruleActions[ruleId] = actions
    }

    /// Set default actions applied to all rules.
    public func setDefaultActions(_ actions: [ResponseActionConfig]) {
        defaultActions = actions
    }

    /// Load action configuration from a JSON file.
    public func loadConfig(from path: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let config = try JSONDecoder().decode(ActionConfigFile.self, from: data)
        defaultActions = config.defaults ?? []
        ruleActions = config.rules ?? [:]
    }

    // MARK: - Execution

    /// Execute all configured response actions for an alert.
    public func execute(alert: Alert, event: Event) async {
        let actions = ruleActions[alert.ruleId] ?? defaultActions
        guard !actions.isEmpty else { return }

        // Expire any stale network blocks before processing new actions
        await expireNetworkBlocks()

        for config in actions {
            guard alert.severity >= config.minimumSeverity else { continue }

            // Skip log action (handled elsewhere)
            if config.action == .log { continue }

            let success: Bool
            let target: String

            switch config.action {
            case .kill:
                target = "pid:\(event.process.pid)"
                success = await killProcess(pid: event.process.pid)
                if success {
                    logger.notice("Killed process \(event.process.pid) (\(event.process.name)) for rule \(alert.ruleId)")
                }

            case .quarantine:
                let filePath = event.file?.path ?? event.process.executable
                target = filePath
                success = quarantineFile(path: filePath, alert: alert)
                if success {
                    logger.notice("Quarantined \(filePath) for rule \(alert.ruleId)")
                }

            case .script:
                guard let scriptPath = config.scriptPath else {
                    logger.warning("Script action configured but no scriptPath for rule \(alert.ruleId)")
                    continue
                }
                target = scriptPath
                success = await runScript(path: scriptPath, alert: alert, event: event)

            case .notify:
                // Handled by NotificationOutput; skip here
                target = "notification"
                success = true

            case .blockNetwork:
                let ip = event.network?.destinationIp ?? "unknown"
                target = ip
                if ip == "unknown" {
                    logger.warning("blockNetwork action: no destination IP in event for rule \(alert.ruleId)")
                    success = false
                } else {
                    let duration = config.blockDurationSeconds ?? 3600
                    success = await blockNetworkDestination(
                        ip: ip,
                        durationSeconds: duration,
                        ruleId: alert.ruleId
                    )
                    if success {
                        logger.notice("Blocked network destination \(ip) for \(duration)s (rule \(alert.ruleId))")
                    }
                }

            case .escalateNotification:
                target = "escalated_notification"
                success = sendEscalatedNotification(alert: alert, event: event)
                if success {
                    logger.notice("Sent escalated notification for rule \(alert.ruleId)")
                }

            case .log:
                continue
            }

            executionLog.append((
                timestamp: Date(),
                ruleId: alert.ruleId,
                action: config.action,
                target: target,
                success: success
            ))
        }
    }

    /// Get the action execution audit log.
    public func getExecutionLog() -> [(timestamp: Date, ruleId: String, action: ResponseActionType, target: String, success: Bool)] {
        executionLog
    }

    /// Get currently active network blocks.
    public func getActiveBlocks() -> [(ip: String, expiresAt: Date, ruleId: String)] {
        activeBlocks.map { ($0.ip, $0.expiresAt, $0.ruleId) }
    }

    // MARK: - Action Implementations

    // MARK: Kill Process

    /// Send SIGTERM first, wait up to 3 seconds, then SIGKILL if still alive.
    private nonisolated func killProcess(pid: Int32) async -> Bool {
        // First try graceful termination
        let termResult = kill(pid, SIGTERM)
        guard termResult == 0 else {
            // Process doesn't exist or we don't have permission
            return false
        }

        // Wait up to 3 seconds for the process to exit
        for _ in 0..<6 {
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            // Check if process is still alive (kill with signal 0 tests existence)
            if kill(pid, 0) != 0 {
                // Process has exited
                return true
            }
        }

        // Process still alive after 3 seconds — force kill
        let killResult = kill(pid, SIGKILL)
        return killResult == 0
    }

    // MARK: Quarantine File

    /// Move the suspicious file to the quarantine directory with a JSON metadata sidecar.
    private func quarantineFile(path: String, alert: Alert) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else {
            logger.warning("Quarantine target does not exist: \(path)")
            return false
        }

        let filename = (path as NSString).lastPathComponent
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let safeName = timestamp
            .replacingOccurrences(of: ":", with: "-")
            .replacingOccurrences(of: "+", with: "Z")
        let destName = "\(safeName)_\(filename)"
        let destPath = (quarantineDir as NSString).appendingPathComponent(destName)

        do {
            try fm.moveItem(atPath: path, toPath: destPath)

            // Write metadata sidecar
            let metadata: [String: Any] = [
                "original_path": path,
                "quarantined_at": timestamp,
                "reason": "MacCrab detection rule match",
                "rule_id": alert.ruleId,
                "rule_title": alert.ruleTitle,
                "severity": alert.severity.rawValue,
                "alert_id": alert.id,
                "process_name": alert.processName ?? "unknown",
                "process_path": alert.processPath ?? "unknown",
                "mitre_techniques": alert.mitreTechniques ?? "",
                "quarantine_path": destPath,
            ]
            let metaData = try JSONSerialization.data(
                withJSONObject: metadata,
                options: [.prettyPrinted, .sortedKeys]
            )
            try metaData.write(to: URL(fileURLWithPath: destPath + ".json"))

            // Set quarantine extended attribute (com.apple.quarantine) so macOS
            // Gatekeeper will flag the file if it is ever moved back.
            setQuarantineAttribute(at: destPath)

            return true
        } catch {
            logger.error("Failed to quarantine \(path): \(error.localizedDescription)")
            return false
        }
    }

    /// Stamp the macOS quarantine xattr on the quarantined file.
    private nonisolated func setQuarantineAttribute(at path: String) {
        // com.apple.quarantine format: flags;timestamp;agent_name;uuid
        let value = "0083;\(Int(Date().timeIntervalSince1970));MacCrab;\(UUID().uuidString)"
        _ = value.withCString { cValue in
            path.withCString { cPath in
                setxattr(cPath, "com.apple.quarantine", cValue, strlen(cValue), 0, 0)
            }
        }
    }

    // MARK: Block Network

    /// Add a temporary PF firewall rule to block the destination IP.
    /// Requires root privileges to modify PF rules.
    private func blockNetworkDestination(
        ip: String,
        durationSeconds: Int,
        ruleId: String
    ) async -> Bool {
        // Validate the IP to prevent injection
        guard isValidIP(ip) else {
            logger.error("blockNetwork: invalid IP address '\(ip)'")
            return false
        }

        // Check if this IP is already blocked
        if activeBlocks.contains(where: { $0.ip == ip }) {
            logger.info("blockNetwork: \(ip) is already blocked")
            return true
        }

        // Write the block rule to the anchor file
        let rule = "block drop out quick on en0 to \(ip)\nblock drop out quick on en1 to \(ip)\n"
        let success = writePFAnchor(appendingRule: rule)
        guard success else { return false }

        // Reload the PF anchor
        let reloadSuccess = await reloadPFAnchor()
        guard reloadSuccess else { return false }

        // Track the block for expiration
        let now = Date()
        let block = NetworkBlock(
            ip: ip,
            addedAt: now,
            expiresAt: now.addingTimeInterval(TimeInterval(durationSeconds)),
            ruleId: ruleId
        )
        activeBlocks.append(block)

        logger.info("Added PF block rule for \(ip) (expires in \(durationSeconds)s)")
        return true
    }

    /// Validate that a string is a well-formed IPv4 or IPv6 address using the
    /// system's `inet_pton()` parser. This rejects anything that is not a real
    /// IP address, preventing command injection through the PF rule string.
    private nonisolated func isValidIP(_ ip: String) -> Bool {
        var addr4 = in_addr()
        var addr6 = in6_addr()
        // Check IPv4
        if inet_pton(AF_INET, ip, &addr4) == 1 { return true }
        // Check IPv6
        if inet_pton(AF_INET6, ip, &addr6) == 1 { return true }
        return false
    }

    /// Append a rule to the PF anchor file.
    private func writePFAnchor(appendingRule rule: String) -> Bool {
        let fm = FileManager.default
        let dir = (pfAnchorPath as NSString).deletingLastPathComponent
        do {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
            if fm.fileExists(atPath: pfAnchorPath) {
                let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: pfAnchorPath))
                handle.seekToEndOfFile()
                if let data = rule.data(using: .utf8) {
                    handle.write(data)
                }
                handle.closeFile()
            } else {
                try rule.write(toFile: pfAnchorPath, atomically: true, encoding: .utf8)
            }
            return true
        } catch {
            logger.error("Failed to write PF anchor: \(error.localizedDescription)")
            return false
        }
    }

    /// Reload the PF anchor using pfctl. Requires root.
    private nonisolated func reloadPFAnchor() async -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        process.arguments = ["-a", "com.maccrab", "-f", pfAnchorPath]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    /// Remove expired network blocks and rewrite the anchor file.
    private func expireNetworkBlocks() async {
        let now = Date()
        let expired = activeBlocks.filter { $0.expiresAt <= now }
        guard !expired.isEmpty else { return }

        activeBlocks.removeAll { $0.expiresAt <= now }

        for block in expired {
            logger.info("Expiring PF block for \(block.ip) (rule \(block.ruleId))")
        }

        // Rewrite the anchor file with only active blocks
        rewritePFAnchor()
        await reloadPFAnchor()
    }

    /// Rewrite the entire PF anchor file from the active blocks list.
    private func rewritePFAnchor() {
        var content = "# MacCrab temporary block rules\n"
        content += "# Auto-generated — do not edit manually\n\n"
        for block in activeBlocks {
            content += "block drop out quick on en0 to \(block.ip)\n"
            content += "block drop out quick on en1 to \(block.ip)\n"
        }

        do {
            try content.write(toFile: pfAnchorPath, atomically: true, encoding: .utf8)
        } catch {
            logger.error("Failed to rewrite PF anchor: \(error.localizedDescription)")
        }
    }

    // MARK: Escalate Notification

    /// Send a high-priority macOS notification with detailed alert information.
    /// Uses osascript for reliable delivery from CLI daemons.
    private nonisolated func sendEscalatedNotification(alert: Alert, event: Event) -> Bool {
        let severityLabel: String
        let soundName: String
        switch alert.severity {
        case .critical:
            severityLabel = "CRITICAL"
            soundName = "Sosumi"
        case .high:
            severityLabel = "HIGH"
            soundName = "Basso"
        case .medium:
            severityLabel = "MEDIUM"
            soundName = "Purr"
        case .low:
            severityLabel = "LOW"
            soundName = "Pop"
        case .informational:
            severityLabel = "INFO"
            soundName = "Tink"
        }

        let processName = event.process.name
        let pid = event.process.pid
        let techniques = alert.mitreTechniques ?? "none"

        let title = "MacCrab [\(severityLabel)] \(alert.ruleTitle)"
        let body = "Process: \(processName) (PID \(pid))\\nRule: \(alert.ruleId)\\nMITRE: \(techniques)\\nAction required — check MacCrab dashboard"

        // Escape for AppleScript
        let escapedTitle = title.replacingOccurrences(of: "\"", with: "\\\"")
        let escapedBody = body.replacingOccurrences(of: "\"", with: "\\\"")

        let script = """
            display notification "\(escapedBody)" \
            with title "\(escapedTitle)" \
            sound name "\(soundName)"
            """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    // MARK: Run Script

    /// Execute a user-defined script with alert context as environment variables.
    private nonisolated func runScript(path: String, alert: Alert, event: Event) async -> Bool {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.environment = [
            "MACCRAB_ALERT_ID": alert.id,
            "MACCRAB_ALERT_RULE_ID": alert.ruleId,
            "MACCRAB_ALERT_RULE_TITLE": alert.ruleTitle,
            "MACCRAB_ALERT_SEVERITY": alert.severity.rawValue,
            "MACCRAB_ALERT_DESCRIPTION": alert.description ?? "",
            "MACCRAB_ALERT_MITRE_TACTICS": alert.mitreTactics ?? "",
            "MACCRAB_ALERT_MITRE_TECHNIQUES": alert.mitreTechniques ?? "",
            "MACCRAB_ALERT_EVENT_ID": alert.eventId,
            "MACCRAB_ALERT_PROCESS_PATH": alert.processPath ?? "",
            "MACCRAB_ALERT_PROCESS_NAME": alert.processName ?? "",
            "MACCRAB_PROCESS_NAME": event.process.name,
            "MACCRAB_PROCESS_PATH": event.process.executable,
            "MACCRAB_PROCESS_PID": String(event.process.pid),
            "MACCRAB_PROCESS_PPID": String(event.process.ppid),
            "MACCRAB_PROCESS_CMDLINE": event.process.commandLine,
            "MACCRAB_PROCESS_USER": event.process.userName,
            "MACCRAB_PROCESS_WORKING_DIR": event.process.workingDirectory,
            "MACCRAB_EVENT_ID": event.id.uuidString,
            "MACCRAB_EVENT_CATEGORY": event.eventCategory.rawValue,
            "MACCRAB_EVENT_TYPE": event.eventType.rawValue,
            "MACCRAB_EVENT_ACTION": event.eventAction,
            "MACCRAB_FILE_PATH": event.file?.path ?? "",
            "MACCRAB_DEST_IP": event.network?.destinationIp ?? "",
            "MACCRAB_DEST_PORT": event.network.map { String($0.destinationPort) } ?? "",
            "MACCRAB_DEST_HOSTNAME": event.network?.destinationHostname ?? "",
            "MACCRAB_SOURCE_IP": event.network?.sourceIp ?? "",
            "MACCRAB_SOURCE_PORT": event.network.map { String($0.sourcePort) } ?? "",
            "MACCRAB_RULE_ID": alert.ruleId,
            "MACCRAB_RULE_TITLE": alert.ruleTitle,
            "MACCRAB_SEVERITY": alert.severity.rawValue,
            "MACCRAB_MITRE_TECHNIQUES": alert.mitreTechniques ?? "",
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
}

// MARK: - Config File Format

/// JSON config file structure for response actions.
struct ActionConfigFile: Codable {
    let defaults: [ResponseActionConfig]?
    let rules: [String: [ResponseActionConfig]]?
}
