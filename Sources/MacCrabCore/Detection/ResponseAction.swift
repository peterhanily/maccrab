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

    /// Tolerant decode: only `action` is required on disk. The writers (the
    /// dashboard ResponseActionsView + the CLI `actions` + the MCP
    /// set_response_action) omit `requireConfirmation` (and may omit
    /// minimumSeverity / scriptPath / blockDurationSeconds) when they are at
    /// their default — and JSONEncoder drops nil keys. With the synthesized
    /// decoder a single missing `requireConfirmation` threw keyNotFound and
    /// aborted the WHOLE-file load, so the engine silently kept its old config
    /// and the just-set action never fired. decodeIfPresent + defaults make an
    /// omitted key mean "default" instead of "undecodable". `encode(to:)` stays
    /// synthesized (it round-trips through this initializer).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.action = try c.decode(ResponseActionType.self, forKey: .action)
        self.scriptPath = try c.decodeIfPresent(String.self, forKey: .scriptPath)
        self.minimumSeverity = try c.decodeIfPresent(Severity.self, forKey: .minimumSeverity) ?? .high
        self.requireConfirmation = try c.decodeIfPresent(Bool.self, forKey: .requireConfirmation) ?? false
        self.blockDurationSeconds = try c.decodeIfPresent(Int.self, forKey: .blockDurationSeconds)
    }
}

// MARK: - Response Engine

/// Executes response actions when alerts are generated.
public actor ResponseEngine {
    /// Response-action maps can contain per-rule entries, so allow more room
    /// than a toggle file while keeping the root reload path bounded.
    static let maxActionConfigBytes = 4 * 1024 * 1024


    private let logger = Logger(subsystem: "com.maccrab", category: "response")

    /// Directory for quarantined files.
    private let quarantineDir: String

    /// Per-rule action configurations.
    private var ruleActions: [String: [ResponseActionConfig]] = [:]

    /// Global default actions (applied to all rules unless overridden).
    private var defaultActions: [ResponseActionConfig] = []

    /// Rule ids that must NEVER arm a response action — not even the global
    /// default. The rule-update channel populates this with its pushed
    /// (detection-only) rule ids, so a signed-but-hostile pushed corpus can add
    /// detections but can never reach kill / quarantine / blockNetwork.
    public var detectionOnlyRuleIDs: Set<String> = []

    /// Rules whose conclusion is produced by a heuristic/model rather than a
    /// deterministic observation are advisory evidence, not authorization to
    /// mutate the host. Keep the Sigma rule id here because `Alert` currently
    /// carries the originating id but not the rule tags. The focused drift test
    /// walks the rule corpus and requires every intent-classifier/LLM-verdict
    /// rule to remain represented by this boundary.
    ///
    /// The prefixes protect all built-in model commentary, counterfactual,
    /// forecast, Bayesian-intent, and prompt-intent alerts if they are routed
    /// through ResponseEngine in the future. Today those alerts are persisted
    /// directly and do not reach this actor. `maccrab.behavior.composite` is
    /// deliberately absent: it is deterministic observed-behavior evidence and
    /// remains eligible for the operator's response policy.
    nonisolated static let advisoryOnlyRuleIDs: Set<String> = [
        "d1a2b3c4-2059-4000-a000-000000002059",
    ]
    nonisolated static let advisoryOnlyRuleIDPrefixes: [String] = [
        "maccrab.intent.",
        "maccrab.prompt-intent.",
        "maccrab.llm.",
        "maccrab.mcp.baseline-anomaly.",
        "maccrab.counterfactual.",
        "maccrab.predict.",
    ]
    nonisolated static let advisoryOnlyDenialTarget =
        "policy:model-derived-alert-advisory-only"

    /// Replace the detection-only id set (called by the reload path with the
    /// engine's current pushed-rule ids).
    public func setDetectionOnlyRuleIDs(_ ids: Set<String>) { detectionOnlyRuleIDs = ids }

    /// Action execution log for auditing.
    private var executionLog: [(timestamp: Date, ruleId: String, action: ResponseActionType, target: String, success: Bool)] = []

    /// Path to the PF anchor file used for temporary block rules.
    private let pfAnchorPath: String

    /// Currently active network blocks for expiration tracking.
    private var activeBlocks: [NetworkBlock] = []

    /// Optional AlertSink for emitting "pending operator confirmation"
    /// alerts when an action is gated by requireConfirmation. v1.6.21:
    /// the gating mechanism (v1.6.20) skipped + logged silently, leaving
    /// the operator no surface to act on. Now: a synthetic alert flows
    /// to AlertStore + dashboard as an auditable pending record. It does not
    /// grant or execute the action; containment still requires a separately
    /// authorized manual workflow. Suppression remains the dismiss path.
    private var alertSinkForPending: AlertSink?

    /// Tracks info about a temporary PF block rule.
    private struct NetworkBlock: Sendable {
        let ip: String
        let addedAt: Date
        let expiresAt: Date
        let ruleId: String
    }

    public init(quarantineDir: String? = nil, supportDirectory: String? = nil) {
        let appSupport: String = {
            if let supportDirectory { return supportDirectory }
            if geteuid() == 0 { return "/Library/Application Support/MacCrab" }
            return FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first.map { $0.appendingPathComponent("MacCrab").path }
                ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        }()
        if let dir = quarantineDir {
            self.quarantineDir = dir
        } else {
            self.quarantineDir = (appSupport as NSString).appendingPathComponent("quarantine")
        }
        self.pfAnchorPath = (appSupport as NSString).appendingPathComponent("maccrab_blocks.conf")
        try? FileManager.default.createDirectory(
            atPath: self.quarantineDir,
            withIntermediateDirectories: true
        )
    }

    /// Wire an AlertSink for emitting pending-confirmation alerts.
    /// Called by DaemonSetup after both ResponseEngine and AlertSink exist.
    public func setAlertSinkForPending(_ sink: AlertSink) {
        self.alertSinkForPending = sink
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

    /// Load action configuration. Probes the system path first, then checks
    /// resolver-validated homes for a user `actions.json` (the app writes there
    /// because the system path is root-only). Prefers the most recently
    /// modified copy. v1.6.19.1 fix for the wire-the-orphans pattern: pre-
    /// fix, ResponseActionsView wrote to a path the daemon never read.
    public func loadConfig(from path: String) throws {
        let systemSnapshot = Self.configSnapshot(at: path)
        let userSnapshot = Self.findUserHomeActionsSnapshot()

        let chosen: Data? = {
            switch (systemSnapshot, userSnapshot) {
            case (nil, nil):              return nil
            case (let s?, nil):           return s.data
            case (nil, let u?):           return u.data
            case (let s?, let u?):
                return u.modificationDate > s.modificationDate ? u.data : s.data
            }
        }()
        guard let data = chosen else { return }
        let config = try JSONDecoder().decode(ActionConfigFile.self, from: data)
        defaultActions = config.defaults ?? []
        ruleActions = config.rules ?? [:]
    }

    nonisolated private static func configSnapshot(
        at path: String
    ) -> BoundedRegularFileReader.Snapshot? {
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
            at: path,
            maximumBytes: Self.maxActionConfigBytes
        ) else { return nil }
        return snapshot
    }

    /// Inspect resolver-validated homes and return the most recent snapshot whose
    /// descriptor owner matches the enclosing admin home. Selection metadata
    /// and bytes come from the same inode; a path stat followed by a later read
    /// would let a replacement file inherit the first inode's authority.
    nonisolated private static func findUserHomeActionsSnapshot()
        -> BoundedRegularFileReader.Snapshot? {
        var candidates: [BoundedRegularFileReader.Snapshot] = []
        for home in RealUserHomeResolver.all() {
            let path = home.appending("Library/Application Support/MacCrab/actions.json")
            guard let snapshot = configSnapshot(at: path),
                  home.userID == snapshot.ownerUID else { continue }
            // v1.21.1 (audit): response actions are privileged (kill / quarantine /
            // blockNetwork), so only honor a user-home actions.json owned by an
            // ADMIN user — the same bar the control-plane inbox enforces
            // (DaemonTimers.isAuthorizedInboxRequest). Without it, any unprivileged
            // local user could drop actions.json in their own home and steer the
            // root engine's response actions on the next reload.
            guard Self.isAdminUID(home.userID) else { continue }
            candidates.append(snapshot)
        }
        return candidates.max(by: { $0.modificationDate < $1.modificationDate })
    }

    /// True if `uid` belongs to the macOS `admin` group (gid 80). Mirrors
    /// DaemonTimers.isAdminUID; a user-home actions.json is only honored when
    /// its owner is an admin (the bar the control-plane inbox enforces).
    /// Replicated here because MacCrabCore cannot import MacCrabAgentKit.
    /// True when the CURRENT effective user is an admin — the bar a user-home
    /// `actions.json` must clear to be honored by the root engine. Exposed so the
    /// MCP `set_response_action` tool can tell the operator honestly whether a
    /// save will actually arm (#19-adjacent audit #15: a non-admin save succeeds
    /// on disk but the engine never loads it).
    public nonisolated static func currentUserIsAdmin() -> Bool {
        isAdminUID(geteuid())
    }

    nonisolated private static func isAdminUID(_ uid: UInt32) -> Bool {
        guard let pw = getpwuid(uid) else { return false }
        let name = String(cString: pw.pointee.pw_name)
        let baseGID = Int32(bitPattern: pw.pointee.pw_gid)
        var ngroups: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(ngroups))
        if getgrouplist(name, baseGID, &groups, &ngroups) == -1 {
            // Buffer too small; ngroups now holds the needed size — retry once.
            groups = [Int32](repeating: 0, count: Int(ngroups))
            guard getgrouplist(name, baseGID, &groups, &ngroups) != -1 else { return false }
        }
        return groups.prefix(Int(ngroups)).contains(80)   // gid 80 == admin
    }

    // MARK: - Execution

    /// True when this alert is model/heuristic-derived advisory output rather
    /// than a directly observed behavior. Internal so the corpus drift guard
    /// can pin the rule-to-policy mapping without widening the product API.
    nonisolated static func isAdvisoryOnlyRuleID(_ ruleID: String) -> Bool {
        advisoryOnlyRuleIDs.contains(ruleID)
            || advisoryOnlyRuleIDPrefixes.contains { ruleID.hasPrefix($0) }
    }

    /// Host-mutating actions require deterministic evidence or an explicit,
    /// rule-specific human-confirmation workflow. This exhaustive switch is a
    /// compiler guard: adding a new ResponseActionType requires an intentional
    /// decision here instead of silently inheriting permission.
    nonisolated static func mutatesHost(_ action: ResponseActionType) -> Bool {
        switch action {
        case .log, .notify, .escalateNotification:
            return false
        case .kill, .quarantine, .script, .blockNetwork:
            return true
        }
    }

    private func appendExecutionAudit(
        ruleID: String,
        action: ResponseActionType,
        target: String,
        success: Bool
    ) {
        executionLog.append((
            timestamp: Date(),
            ruleId: ruleID,
            action: action,
            target: target,
            success: success
        ))
        // Bound attempted, denied, and pending entries alike. Previously only
        // completed action attempts reached this cap, so a confirmation flood
        // could grow the same audit array without limit.
        if executionLog.count > 50_000 {
            executionLog.removeFirst(5_000)
        }
    }

    /// Execute all configured response actions for an alert.
    public func execute(alert: Alert, event: Event) async {
        // Detection-only rules (e.g. those pushed via the signed rule-update
        // channel) never arm an action — not even the global default. This is
        // the response-side half of the pushed-rule trust boundary.
        if detectionOnlyRuleIDs.contains(alert.ruleId) { return }
        let hasExplicitRuleActions = ruleActions[alert.ruleId] != nil
        let actions = ruleActions[alert.ruleId] ?? defaultActions
        guard !actions.isEmpty else { return }

        // Expire any stale network blocks before processing new actions
        await expireNetworkBlocks()

        for config in actions {
            guard alert.severity >= config.minimumSeverity else { continue }

            // Skip log action (handled elsewhere)
            if config.action == .log { continue }

            // A model or heuristic may raise an alert, feed logs, and notify an
            // operator, but its verdict is never authority for an automated
            // host mutation. This is deliberately enforced here rather than in
            // UI defaults: actions.json, MCP, CLI, and global defaults all
            // converge on this actor.
            //
            // Preserve one safe opt-in: a destructive action attached to THIS
            // exact rule with requireConfirmation=true may proceed to the
            // existing pending-only branch below. It records intent and never
            // executes. A global confirmation default is not specific enough
            // to count as an operator decision for an advisory-derived rule.
            if Self.isAdvisoryOnlyRuleID(alert.ruleId),
               Self.mutatesHost(config.action),
               !(hasExplicitRuleActions && config.requireConfirmation) {
                logger.error("REFUSED automated \(config.action.rawValue) for model/heuristic-derived rule \(alert.ruleId); advisory evidence cannot authorize a host mutation")
                appendExecutionAudit(
                    ruleID: alert.ruleId,
                    action: config.action,
                    target: Self.advisoryOnlyDenialTarget,
                    success: false
                )
                continue
            }

            // v1.6.20: respect requireConfirmation. Pre-v1.6.20 the field
            // was decoded but ignored — operators who set it expecting a
            // "click to fire" gate got instant execution instead.
            // v1.6.21: also emit a synthetic informational alert so the
            // pending action shows up in the operator's dashboard. The
            // synthetic record is evidence of operator intent only. It does not
            // itself authorize execution; a separately authorized manual
            // workflow is required to perform the action.
            if config.requireConfirmation {
                logger.notice("Action \(config.action.rawValue) for rule \(alert.ruleId) PENDING operator confirmation")
                appendExecutionAudit(
                    ruleID: alert.ruleId,
                    action: config.action,
                    target: "pending-confirmation",
                    success: false
                )
                if let sink = alertSinkForPending {
                    let pendingAlert = Alert(
                        ruleId: "maccrab.pending-action.\(config.action.rawValue)",
                        ruleTitle: "Pending: \(config.action.rawValue) for \(alert.ruleTitle)",
                        severity: .informational,
                        eventId: alert.eventId,
                        processPath: alert.processPath,
                        processName: alert.processName,
                        description: "MacCrab gated this \(config.action.rawValue) action because \"Require operator confirmation\" is enabled for rule \(alert.ruleId). Original alert: \(alert.id). This pending record does not authorize or execute the action; review the evidence and use a separately authorized manual workflow if containment is warranted, or suppress this notification to dismiss.",
                        mitreTactics: alert.mitreTactics,
                        mitreTechniques: alert.mitreTechniques,
                        suppressed: false
                    )
                    do {
                        _ = try await sink.submit(alert: pendingAlert, event: event)
                    } catch {
                        // Logging error doesn't impact correctness; the
                        // pending entry is already in executionLog.
                        logger.warning("Failed to emit pending-action alert: \(error.localizedDescription)")
                    }
                }
                continue
            }

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

            appendExecutionAudit(
                ruleID: alert.ruleId,
                action: config.action,
                target: target,
                success: success
            )
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
        // Refuse to kill PIDs whose termination would damage the system or
        // trap the user (PID 1, WindowServer, opendirectoryd, /System/...,
        // MacCrab itself, etc.). SafePIDValidator logs the rejection reason.
        guard SafePIDValidator.isSafeToKill(pid: pid) else { return false }

        // First try graceful termination
        let termResult = kill(pid, SIGTERM)
        guard termResult == 0 else {
            // Process doesn't exist or we don't have permission
            return false
        }

        let capturedStart = Self.processStartTime(pid: pid)

        // Wait up to 3 seconds for the process to exit
        for _ in 0..<6 {
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            // Check if process is still alive (kill with signal 0 tests existence)
            if kill(pid, 0) != 0 {
                // Process has exited
                return true
            }
        }

        guard SafePIDValidator.isSafeToKill(pid: pid) else { return false }
        if let capturedStart, Self.processStartTime(pid: pid) != capturedStart {
            logger.warning("Refusing SIGKILL: PID recycled during wait")
            return false
        }

        // Process still alive after 3 seconds — force kill
        let killResult = kill(pid, SIGKILL)
        return killResult == 0
    }

    static func processStartTime(pid: Int32) -> UInt64? {
        var info = proc_bsdinfo()
        let sz = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sz) == sz else { return nil }
        return UInt64(info.pbi_start_tvsec) &* 1_000_000 &+ UInt64(info.pbi_start_tvusec)
    }

    // MARK: Quarantine File

    /// Move the suspicious file to the quarantine directory with a JSON metadata sidecar.
    private func quarantineFile(path: String, alert: Alert) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else {
            logger.warning("Quarantine target does not exist: \(path)")
            return false
        }
        // SAFETY: refuse to move files in protected system / Apple-framework /
        // user-data locations. Quarantine is a destructive action; if a rule
        // (or hallucinated alert) names /System/Library/CoreServices/Finder.app
        // or ~/Library/Mail/V10/MailData/Envelope Index, moving it bricks the
        // user's machine in ways that need Recovery Mode to fix.
        guard SafeQuarantinePathValidator.isSafeToQuarantine(path: path) else { return false }

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
        // SAFETY: refuse to block public DNS, Apple's range, loopback,
        // link-local, multicast, and the user's default gateway. A
        // poisoned threat-intel feed naming 1.1.1.1 / 8.8.8.8 / 17.0.0.0/8
        // would otherwise silently take down DNS, OCSP, or LAN.
        guard SafeBlockableIP.isSafeToBlock(ip: ip) else { return false }

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
        BoundedPrivilegedProcessRunner.run(
            executable: "/sbin/pfctl",
            arguments: ["-a", "com.maccrab", "-f", pfAnchorPath],
            timeout: 10,
            maximumOutputBytes: nil
        )?.succeeded == true
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

    /// Escalate-notification response action.
    ///
    /// v1.17.2 (GitHub issue #2 conflict fix): this used to spawn
    /// `osascript -e 'display notification …'`. That is the EXACT legacy path
    /// issue #2 removed everywhere else — osascript banners are attributed to
    /// "Script Editor"/"System Events" (not MacCrab, so no entry to turn off)
    /// and outlive an uninstall. It also DOUBLE-posted: the alert is already
    /// written to the alert store, and the signed app's AlertNotifier polls
    /// the store and delivers every alert via UNUserNotificationCenter (under
    /// MacCrab's own identity, with sound). So the osascript banner added
    /// nothing but the regression.
    ///
    /// The app is now the sole OS-notification poster. This action is a no-op
    /// beyond logging — kept as a type so existing daemon_config.json files
    /// that list it still decode. The alert's presence in the store IS the
    /// escalation; severity-based emphasis belongs in the app's gate.
    private nonisolated func sendEscalatedNotification(alert: Alert, event: Event) -> Bool {
        logger.notice("escalateNotification for \(alert.ruleId, privacy: .public): delivery handled by the app (AlertNotifier); no daemon-side osascript banner")
        return true
    }

    // MARK: Run Script

    /// v1.8.0: only allow scripts under root-managed dirs the user cannot
    /// write to. The sysext runs as root; pre-fix, scriptPath came from a
    /// user-writable `actions.json` and was passed straight to Process.run,
    /// so any user could pick `/usr/bin/curl` (or drop a binary anywhere
    /// they had write access) and have it executed with root privileges
    /// plus sensitive event metadata in env vars — local privilege
    /// escalation. Now we require the script to live under one of the
    /// dirs below AND be owned by root:wheel AND have no world/group
    /// write bits. The allowlisted dir is created at install time with
    /// 0o755 root:wheel so a non-root user cannot drop scripts there.
    private static let scriptAllowlistedDirs: [String] = [
        "/Library/Application Support/MacCrab/scripts/",
        "/usr/local/maccrab/scripts/",
    ]

    private static func validatedScriptPath(_ path: String) -> String? {
        // Validate every ancestor, not merely the final file. This rejects an
        // allowlisted leaf reached through a user-writable/symlinked directory,
        // macOS ACL write grants that POSIX mode bits hide, set-id executables,
        // and scripts large enough to be an accidental resource sink.
        PrivilegedExecutablePolicy.validatedPath(
            path,
            kind: .regularFile(
                requireExecutable: true,
                maximumSize: 1 * 1024 * 1024
            ),
            allowedPrefixes: scriptAllowlistedDirs
        )
    }

    /// Execute a user-defined script with alert context as environment variables.
    private nonisolated func runScript(path: String, alert: Alert, event: Event) async -> Bool {
        guard let trustedScript = Self.validatedScriptPath(path) else {
            return false
        }

        // Execute through Apple's immutable /bin/sh rather than asking the
        // kernel to honor an arbitrary shebang interpreter (for example a
        // user-owned /opt/homebrew/bin/python). The root-owned script remains
        // free to opt into other tools explicitly; that is trusted admin code,
        // not a path selected by an unprivileged actions.json writer.
        var environment = BoundedPrivilegedProcessRunner.minimalEnvironment
        environment.merge([
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
        ], uniquingKeysWith: { _, alertValue in alertValue })

        guard let result = BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["--", trustedScript],
            environment: environment,
            timeout: 30,
            maximumOutputBytes: nil
        ) else { return false }
        return result.succeeded
    }
}

// MARK: - Config File Format

/// JSON config file structure for response actions.
struct ActionConfigFile: Codable {
    let defaults: [ResponseActionConfig]?
    let rules: [String: [ResponseActionConfig]]?
}
