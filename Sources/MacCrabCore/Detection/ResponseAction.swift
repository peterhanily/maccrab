// ResponseAction.swift
// MacCrabCore
//
// Response actions that can be triggered when detection rules match.
// Actions range from passive (log, notify) to active (kill, quarantine).

import Foundation
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
    /// Block the network connection (requires Network Extension; placeholder).
    case blockNetwork
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

    public init(
        action: ResponseActionType,
        scriptPath: String? = nil,
        minimumSeverity: Severity = .high,
        requireConfirmation: Bool = false
    ) {
        self.action = action
        self.scriptPath = scriptPath
        self.minimumSeverity = minimumSeverity
        self.requireConfirmation = requireConfirmation
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

        for config in actions {
            guard alert.severity >= config.minimumSeverity else { continue }

            // Skip log action (handled elsewhere)
            if config.action == .log { continue }

            let success: Bool
            let target: String

            switch config.action {
            case .kill:
                target = "pid:\(event.process.pid)"
                success = killProcess(pid: event.process.pid)
                if success {
                    logger.notice("Killed process \(event.process.pid) (\(event.process.name)) for rule \(alert.ruleId)")
                }

            case .quarantine:
                let filePath = event.file?.path ?? event.process.executable
                target = filePath
                success = quarantineFile(path: filePath)
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
                target = event.network?.destinationIp ?? "unknown"
                logger.warning("blockNetwork action not yet implemented")
                success = false

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

    // MARK: - Action Implementations

    private nonisolated func killProcess(pid: Int32) -> Bool {
        let result = kill(pid, SIGKILL)
        return result == 0
    }

    private func quarantineFile(path: String) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return false }

        let filename = (path as NSString).lastPathComponent
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let destName = "\(timestamp)_\(filename)"
        let destPath = (quarantineDir as NSString).appendingPathComponent(destName)

        do {
            try fm.moveItem(atPath: path, toPath: destPath)

            // Write metadata sidecar
            let metadata: [String: String] = [
                "original_path": path,
                "quarantined_at": timestamp,
                "reason": "MacCrab detection rule match",
            ]
            let metaData = try JSONSerialization.data(withJSONObject: metadata, options: .prettyPrinted)
            try metaData.write(to: URL(fileURLWithPath: destPath + ".meta.json"))

            return true
        } catch {
            logger.error("Failed to quarantine \(path): \(error.localizedDescription)")
            return false
        }
    }

    private nonisolated func runScript(path: String, alert: Alert, event: Event) async -> Bool {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.environment = [
            "MACCRAB_RULE_ID": alert.ruleId,
            "MACCRAB_RULE_TITLE": alert.ruleTitle,
            "MACCRAB_SEVERITY": alert.severity.rawValue,
            "MACCRAB_PROCESS_NAME": event.process.name,
            "MACCRAB_PROCESS_PATH": event.process.executable,
            "MACCRAB_PROCESS_PID": String(event.process.pid),
            "MACCRAB_PROCESS_CMDLINE": event.process.commandLine,
            "MACCRAB_EVENT_ID": event.id.uuidString,
            "MACCRAB_MITRE_TECHNIQUES": alert.mitreTechniques ?? "",
            "MACCRAB_FILE_PATH": event.file?.path ?? "",
            "MACCRAB_DEST_IP": event.network?.destinationIp ?? "",
            "MACCRAB_DEST_PORT": event.network.map { String($0.destinationPort) } ?? "",
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
