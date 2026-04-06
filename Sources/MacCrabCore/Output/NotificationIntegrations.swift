// NotificationIntegrations.swift
// MacCrabCore
//
// Sends MacCrab alerts to external notification services via webhooks.
// Supports Slack, Microsoft Teams, Discord, PagerDuty, and generic webhooks.

import Foundation
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

    public init(configPath: String) {
        self.configPath = configPath
        self.config = Self.loadConfigFromDisk(path: configPath)
    }

    private static func loadConfigFromDisk(path: String) -> Config? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let decoded = try? JSONDecoder().decode(Config.self, from: data) else { return nil }
        return decoded
    }

    public func reloadConfig() {
        // Not calling self method since we're in the actor; just inline it
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let decoded = try? JSONDecoder().decode(Config.self, from: data) else { return }
        config = decoded
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

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("MacCrab/1.0.0", forHTTPHeaderField: "User-Agent")
        request.httpBody = body
        request.timeoutInterval = 10

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                logger.warning("Notification webhook failed: \(url) returned \(http.statusCode)")
            }
        } catch {
            logger.warning("Notification webhook error: \(error.localizedDescription)")
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
