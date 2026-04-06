// ScheduledReports.swift
// MacCrabCore
//
// Schedules and delivers periodic security reports and digests.
// Integrates with ReportGenerator, SecurityDigest, and NotificationIntegrations.

import Foundation
import os.log

/// Schedules and delivers periodic security reports and digests.
public actor ScheduledReports {
    private let logger = Logger(subsystem: "com.maccrab.output", category: "scheduled-reports")

    // MARK: - Configuration

    public struct Schedule: Codable, Sendable {
        public var dailyDigestEnabled: Bool
        public var dailyDigestHour: Int      // 0-23, hour to send digest
        public var weeklyReportEnabled: Bool
        public var weeklyReportDay: Int      // 1=Mon, 7=Sun
        public var deliveryChannels: [String] // "slack", "email", "file"
        public var outputDir: String?        // For file delivery

        public init() {
            dailyDigestEnabled = true
            dailyDigestHour = 8
            weeklyReportEnabled = true
            weeklyReportDay = 1  // Monday
            deliveryChannels = ["file"]
            outputDir = nil
        }
    }

    // MARK: - State

    private var schedule: Schedule
    private var lastDailyDigest: Date?
    private var lastWeeklyReport: Date?
    private let supportDir: String

    // MARK: - Initialization

    public init(supportDir: String) {
        self.supportDir = supportDir
        self.schedule = Schedule()
        // Load saved schedule
        let configPath = supportDir + "/report_schedule.json"
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let decoded = try? JSONDecoder().decode(Schedule.self, from: data) {
            self.schedule = decoded
        }
    }

    // MARK: - Scheduled Check

    /// Check if any scheduled reports are due and generate them.
    /// Call this periodically (e.g., every hour from the maintenance timer).
    public func checkAndGenerate(
        alerts: [(ruleTitle: String, severity: String, processName: String, timestamp: Date)],
        eventCount: Int,
        securityScore: Int?,
        reportGenerator: ReportGenerator,
        digestGenerator: SecurityDigest,
        notificationIntegrations: NotificationIntegrations?
    ) async {
        let now = Date()
        let calendar = Calendar.current
        let currentHour = calendar.component(.hour, from: now)
        let currentWeekday = calendar.component(.weekday, from: now) // 1=Sun, 2=Mon...

        // Daily digest
        if schedule.dailyDigestEnabled && currentHour == schedule.dailyDigestHour {
            if lastDailyDigest == nil || !calendar.isDate(lastDailyDigest!, inSameDayAs: now) {
                let last24h = alerts.filter { now.timeIntervalSince($0.timestamp) < 86400 }
                let digest = await digestGenerator.generate(
                    alerts: last24h, eventCount: eventCount,
                    securityScore: securityScore, period: "24 hours"
                )
                let text = await digestGenerator.formatText(digest)

                await deliver(
                    content: text,
                    filename: "daily-digest-\(dateStamp(now)).txt",
                    subject: "MacCrab Daily Digest — \(String(digest.summary.prefix(80)))",
                    notificationIntegrations: notificationIntegrations
                )
                lastDailyDigest = now
                logger.info("Daily digest generated and delivered")
            }
        }

        // Weekly report
        // Convert from Apple weekday (1=Sun) to ISO (Mon=1)
        let adjustedWeekday = currentWeekday == 1 ? 7 : currentWeekday - 1
        if schedule.weeklyReportEnabled
            && adjustedWeekday == schedule.weeklyReportDay
            && currentHour == schedule.dailyDigestHour
        {
            if lastWeeklyReport == nil || now.timeIntervalSince(lastWeeklyReport!) > 6 * 86400 {
                let last7d = alerts.filter { now.timeIntervalSince($0.timestamp) < 7 * 86400 }

                // Build stub Alert objects for the report generator
                let stubAlerts: [Alert] = last7d.map { a in
                    Alert(
                        ruleId: "maccrab.scheduled",
                        ruleTitle: a.ruleTitle,
                        severity: Severity(rawValue: a.severity) ?? .medium,
                        eventId: UUID().uuidString,
                        processName: a.processName
                    )
                }

                let reportData = await reportGenerator.buildReportData(
                    alerts: stubAlerts,
                    title: "MacCrab Weekly Report",
                    timeRange: (now.addingTimeInterval(-7 * 86400), now)
                )
                let html = await reportGenerator.generateHTML(from: reportData)

                await deliver(
                    content: html,
                    filename: "weekly-report-\(dateStamp(now)).html",
                    subject: "MacCrab Weekly Report",
                    notificationIntegrations: notificationIntegrations
                )
                lastWeeklyReport = now
                logger.info("Weekly report generated and delivered")
            }
        }
    }

    // MARK: - Delivery

    private func deliver(
        content: String,
        filename: String,
        subject: String,
        notificationIntegrations: NotificationIntegrations?
    ) async {
        // File delivery
        let outputDir = schedule.outputDir ?? supportDir + "/reports"
        try? FileManager.default.createDirectory(
            atPath: outputDir,
            withIntermediateDirectories: true
        )
        let path = outputDir + "/" + filename
        try? content.write(toFile: path, atomically: true, encoding: .utf8)
        logger.info("Report saved to \(path)")

        // Slack/Teams/Discord delivery (send summary, not full report)
        if schedule.deliveryChannels.contains("slack"), let notif = notificationIntegrations {
            let summary = String(content.prefix(500))
            await notif.sendAlert(
                ruleTitle: subject,
                severity: "informational",
                processName: "MacCrab",
                processPath: nil,
                description: summary,
                mitreTechniques: nil
            )
        }
    }

    // MARK: - Configuration Access

    public func getSchedule() -> Schedule { schedule }

    public func updateSchedule(_ newSchedule: Schedule) {
        schedule = newSchedule
        let configPath = supportDir + "/report_schedule.json"
        if let data = try? JSONEncoder().encode(schedule) {
            try? data.write(to: URL(fileURLWithPath: configPath))
        }
        logger.info("Report schedule updated")
    }

    // MARK: - Helpers

    private func dateStamp(_ date: Date) -> String {
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd"
        return df.string(from: date)
    }
}
