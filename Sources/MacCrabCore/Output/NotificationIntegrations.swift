// NotificationIntegrations.swift
// MacCrabCore
//
// Sends MacCrab alerts to external notification services via webhooks.
// Supports Slack, Microsoft Teams, Discord, PagerDuty, and generic webhooks.

import Foundation
import Darwin
import os.log

/// Sends MacCrab alerts to external notification services via webhooks.
/// Supports Slack, Microsoft Teams, Discord, PagerDuty, and generic webhooks.
public actor NotificationIntegrations {
    private let logger = Logger(subsystem: "com.maccrab.output", category: "notifications")

    // MARK: - Configuration

    public struct Config: Codable, Sendable {
        public var slack: SlackConfig?
        public var teams: TeamsConfig?
        public var discord: DiscordConfig?
        public var pagerduty: PagerDutyConfig?
        public var email: EmailConfig?
        public var minimumSeverity: String  // "critical", "high", "medium", "low"

        public init(
            slack: SlackConfig? = nil,
            teams: TeamsConfig? = nil,
            discord: DiscordConfig? = nil,
            pagerduty: PagerDutyConfig? = nil,
            email: EmailConfig? = nil,
            minimumSeverity: String = "medium"
        ) {
            self.slack = slack
            self.teams = teams
            self.discord = discord
            self.pagerduty = pagerduty
            self.email = email
            self.minimumSeverity = minimumSeverity
        }
    }

    public struct SlackConfig: Codable, Sendable {
        public var webhookURL: String
        public var channel: String?
        public var username: String?

        public init(webhookURL: String, channel: String? = nil, username: String? = nil) {
            self.webhookURL = webhookURL
            self.channel = channel
            self.username = username
        }
    }

    public struct TeamsConfig: Codable, Sendable {
        public var webhookURL: String

        public init(webhookURL: String) {
            self.webhookURL = webhookURL
        }
    }

    public struct DiscordConfig: Codable, Sendable {
        public var webhookURL: String

        public init(webhookURL: String) {
            self.webhookURL = webhookURL
        }
    }

    public struct PagerDutyConfig: Codable, Sendable {
        public var routingKey: String
        public var severity: String  // "critical", "error", "warning", "info"

        public init(routingKey: String, severity: String = "error") {
            self.routingKey = routingKey
            self.severity = severity
        }
    }

    public struct EmailConfig: Codable, Sendable {
        public var smtpHost: String
        public var smtpPort: Int
        public var from: String
        public var to: [String]
        public var username: String?
        public var password: String?

        public init(smtpHost: String, smtpPort: Int, from: String, to: [String], username: String? = nil, password: String? = nil) {
            self.smtpHost = smtpHost
            self.smtpPort = smtpPort
            self.from = from
            self.to = to
            self.username = username
            self.password = password
        }
    }

    private var config: Config?
    private let configPath: String

    /// Webhook/SMTP configuration is small even with several integrations.
    /// This file can come from an admin user's writable home and is consumed by
    /// the root daemon at boot, so its carrier must remain finite and regular.
    static let maxConfigBytes = 1 * 1024 * 1024

    public init(configPath: String) {
        self.configPath = configPath
        self.config = Self.loadEffectiveConfig(systemPath: configPath)
    }

    /// Resolve the config from `systemPath` first. A valid root-owned system
    /// config is authoritative; otherwise fall back to the console user's
    /// `~/Library/Application Support/MacCrab/notifications.json` when the
    /// system path is missing or older. v1.6.19 wiring: SettingsView
    /// writes to the user-home path because the sysext's
    /// `/Library/Application Support/MacCrab/` is root-only. File ownership
    /// is validated against `/Users/<u>` so a rogue process running as a
    /// different user can't inject a webhook.
    private static func loadEffectiveConfig(systemPath: String) -> Config? {
        let systemSnapshot = configSnapshot(at: systemPath)
        let systemConfig = systemSnapshot.flatMap(decodeConfig)

        // A valid root-owned system config is authoritative. Return before
        // even opening a user-home carrier: the prior implementation decoded
        // both and only then discarded the user value, so an ignored FIFO could
        // still wedge daemon startup.
        if let systemConfig, systemSnapshot?.ownerUID == 0 {
            return systemConfig
        }

        let userSnapshot = findUserHomeConfigSnapshot()
        let userConfig = userSnapshot.flatMap(decodeConfig)
        switch (systemConfig, userConfig) {
        case (nil, nil):              return nil
        case (let sc?, nil):          return sc
        case (nil, let uc?):          return uc
        case (let sc?, let uc?):
            // Any valid root-owned system config returned above. Reaching this
            // case therefore means the system path is non-root-owned (the dev
            // ~/Library path); retain its legacy mtime precedence behavior.
            let sm = systemSnapshot?.modificationDate ?? .distantPast
            let um = userSnapshot?.modificationDate ?? .distantPast
            return um > sm ? uc : sc
        }
    }

    /// Inspect resolver-validated homes for a notifications.json and return
    /// the most-recent descriptor snapshot owned by the enclosing admin home.
    private static func findUserHomeConfigSnapshot()
        -> BoundedRegularFileReader.Snapshot? {
        var candidates: [BoundedRegularFileReader.Snapshot] = []
        for home in RealUserHomeResolver.all() {
            let path = home.appending(
                "Library/Application Support/MacCrab/notifications.json"
            )
            guard let snapshot = configSnapshot(at: path),
                  home.userID == snapshot.ownerUID else { continue }
            // v1.21.4 (audit A2-01): notifications.json points at webhook / Slack
            // / SMTP destinations that receive every alert payload. Mirror the
            // ResponseAction.findUserHomeActionsPath gate — only honor a
            // user-home config owned by an ADMIN user, so an unprivileged local
            // user on a shared / managed Mac can't redirect alert exfil to an
            // attacker endpoint (or override the operator's config).
            guard Self.isAdminUID(home.userID) else { continue }
            candidates.append(snapshot)
        }
        return candidates.max(by: { $0.modificationDate < $1.modificationDate })
    }

    /// True if `uid` belongs to the macOS `admin` group (gid 80). Mirrors
    /// `ResponseAction.isAdminUID` (which is file-private and cannot be reached
    /// cross-file) and `DaemonTimers.isAdminUID`; replicated here for the same
    /// reason ResponseAction replicates it — the canonical helper isn't visible
    /// from this type. A user-home notifications.json is only honored when its
    /// owner is an admin.
    private static func isAdminUID(_ uid: UInt32) -> Bool {
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

    private static func configSnapshot(
        at path: String
    ) -> BoundedRegularFileReader.Snapshot? {
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
            at: path,
            maximumBytes: maxConfigBytes
        ) else { return nil }
        return snapshot
    }

    private static func decodeConfig(
        _ snapshot: BoundedRegularFileReader.Snapshot
    ) -> Config? {
        try? JSONDecoder().decode(Config.self, from: snapshot.data)
    }

    public func reloadConfig() {
        config = Self.loadEffectiveConfig(systemPath: configPath)
        logger.info("Notification integrations reloaded: \(self.configuredServices().joined(separator: ", "))")
    }

    public func configuredServices() -> [String] {
        var services: [String] = []
        if config?.slack != nil { services.append("Slack") }
        if config?.teams != nil { services.append("Teams") }
        if config?.discord != nil { services.append("Discord") }
        if config?.pagerduty != nil { services.append("PagerDuty") }
        if config?.email != nil { services.append("Email") }
        return services
    }

    /// Send an alert to all configured notification services.
    public func sendAlert(
        ruleTitle: String,
        severity: String,
        processName: String?,
        processPath: String?,
        description: String,
        mitreTechniques: String?
    ) async {
        guard let config = config else { return }

        // Check minimum severity
        let severityOrder = ["informational", "low", "medium", "high", "critical"]
        let minIdx = severityOrder.firstIndex(of: config.minimumSeverity) ?? 0
        let alertIdx = severityOrder.firstIndex(of: severity.lowercased()) ?? 0
        guard alertIdx >= minIdx else { return }

        // Send to all configured services concurrently
        await withTaskGroup(of: Void.self) { group in
            if let slack = config.slack {
                group.addTask {
                    await self.sendSlack(
                        slack, ruleTitle: ruleTitle, severity: severity,
                        processName: processName, description: description,
                        mitre: mitreTechniques
                    )
                }
            }
            if let teams = config.teams {
                group.addTask {
                    await self.sendTeams(
                        teams, ruleTitle: ruleTitle, severity: severity,
                        processName: processName, description: description,
                        mitre: mitreTechniques
                    )
                }
            }
            if let discord = config.discord {
                group.addTask {
                    await self.sendDiscord(
                        discord, ruleTitle: ruleTitle, severity: severity,
                        processName: processName, description: description,
                        mitre: mitreTechniques
                    )
                }
            }
            if let pd = config.pagerduty {
                group.addTask {
                    await self.sendPagerDuty(
                        pd, ruleTitle: ruleTitle, severity: severity,
                        description: description
                    )
                }
            }
        }
    }

    // MARK: - Slack

    private func sendSlack(
        _ config: SlackConfig, ruleTitle: String, severity: String,
        processName: String?, description: String, mitre: String?
    ) async {
        let color = severityColor(severity)
        var fields: [[String: Any]] = [
            ["title": "Severity", "value": severity.uppercased(), "short": true],
            ["title": "Process", "value": processName ?? "N/A", "short": true],
        ]
        if let mitre = mitre {
            fields.append(["title": "MITRE", "value": mitre, "short": true])
        }

        let payload: [String: Any] = [
            "username": config.username ?? "MacCrab",
            "icon_emoji": ":crab:",
            "attachments": [[
                "color": color,
                "title": "\u{1F980} \(ruleTitle)",
                "text": description,
                "fields": fields,
                "footer": "MacCrab Detection Engine",
                "ts": Int(Date().timeIntervalSince1970)
            ] as [String: Any]]
        ]
        await postJSON(url: config.webhookURL, payload: payload)
    }

    // MARK: - Microsoft Teams

    private func sendTeams(
        _ config: TeamsConfig, ruleTitle: String, severity: String,
        processName: String?, description: String, mitre: String?
    ) async {
        let color = severityColor(severity)
        var facts: [[String: String]] = [
            ["name": "Process", "value": processName ?? "N/A"],
            ["name": "Description", "value": String(description.prefix(500))],
        ]
        if let mitre = mitre {
            facts.append(["name": "MITRE ATT&CK", "value": mitre])
        }

        let payload: [String: Any] = [
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color.replacingOccurrences(of: "#", with: ""),
            "summary": "MacCrab: \(ruleTitle)",
            "sections": [[
                "activityTitle": "\u{1F980} \(ruleTitle)",
                "activitySubtitle": "Severity: \(severity.uppercased())",
                "facts": facts,
                "markdown": true
            ] as [String: Any]]
        ]
        await postJSON(url: config.webhookURL, payload: payload)
    }

    // MARK: - Discord

    private func sendDiscord(
        _ config: DiscordConfig, ruleTitle: String, severity: String,
        processName: String?, description: String, mitre: String?
    ) async {
        let color = discordColor(severity)
        var fields: [[String: Any]] = [
            ["name": "Severity", "value": severity.uppercased(), "inline": true],
            ["name": "Process", "value": processName ?? "N/A", "inline": true],
        ]
        if let mitre = mitre {
            fields.append(["name": "MITRE", "value": mitre, "inline": true])
        }

        let payload: [String: Any] = [
            "username": "MacCrab",
            "embeds": [[
                "title": "\u{1F980} \(ruleTitle)",
                "description": String(description.prefix(2000)),
                "color": color,
                "fields": fields,
                "footer": ["text": "MacCrab Detection Engine"] as [String: String],
                "timestamp": ISO8601DateFormatter().string(from: Date())
            ] as [String: Any]]
        ]
        await postJSON(url: config.webhookURL, payload: payload)
    }

    // MARK: - PagerDuty

    private func sendPagerDuty(
        _ config: PagerDutyConfig, ruleTitle: String, severity: String,
        description: String
    ) async {
        let pdSeverity: String
        switch severity.lowercased() {
        case "critical": pdSeverity = "critical"
        case "high": pdSeverity = "error"
        case "medium": pdSeverity = "warning"
        default: pdSeverity = "info"
        }

        let payload: [String: Any] = [
            "routing_key": config.routingKey,
            "event_action": "trigger",
            "payload": [
                "summary": "MacCrab: \(ruleTitle)",
                "severity": pdSeverity,
                "source": "MacCrab Detection Engine",
                "custom_details": ["description": description] as [String: String]
            ] as [String: Any]
        ]
        await postJSON(url: "https://events.pagerduty.com/v2/enqueue", payload: payload)
    }

    // MARK: - Helpers

    private func postJSON(url: String, payload: [String: Any]) async {
        guard let requestURL = URL(string: url),
              let body = try? JSONSerialization.data(withJSONObject: payload) else { return }

        // v1.8.0: apply the same SSRF policy WebhookOutput uses to the
        // Slack/Teams/Discord/PagerDuty paths. Pre-fix, these accepted
        // http:// (cleartext token leak), RFC1918 (intranet pivot),
        // and 169.254.169.254 (cloud-metadata exfil). PagerDuty's URL
        // is hardcoded HTTPS in the caller so it always validates;
        // user-supplied Slack/Teams/Discord webhooks are the surface.
        do {
            try WebhookOutput.validate(
                url: requestURL,
                allowPrivate: Foundation.ProcessInfo.processInfo.environment["MACCRAB_NOTIFICATION_ALLOW_PRIVATE"] == "1"
            )
        } catch {
            logger.warning("Notification webhook URL rejected by SSRF policy: \(error.localizedDescription, privacy: .public)")
            return
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("MacCrab/\(MacCrabVersion.current)", forHTTPHeaderField: "User-Agent")
        request.httpBody = body
        request.timeoutInterval = 10

        do {
            let (_, response) = try await SecureURLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                // Webhook URLs include secret tokens (Slack hooks.slack.com/
                // services/T.../B.../<secret>; Discord similar) — `privacy:
                // .private` keeps the full URL out of the Unified Log so an
                // attacker with read access to logs can't exfiltrate it.
                logger.warning("Notification webhook failed: \(url, privacy: .private) returned \(http.statusCode)")
            }
        } catch {
            logger.warning("Notification webhook error: \(error.localizedDescription, privacy: .private)")
        }
    }

    private func severityColor(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return "#FF0000"
        case "high": return "#FF8C00"
        case "medium": return "#FFD700"
        case "low": return "#4169E1"
        default: return "#808080"
        }
    }

    private func discordColor(_ severity: String) -> Int {
        switch severity.lowercased() {
        case "critical": return 0xFF0000
        case "high": return 0xFF8C00
        case "medium": return 0xFFD700
        case "low": return 0x4169E1
        default: return 0x808080
        }
    }
}
