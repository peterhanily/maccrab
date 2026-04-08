import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func generateReport(args: [String]) async {
        // Parse arguments
        var hours: Double = 24
        var outputPath: String? = nil

        var i = 0
        while i < args.count {
            if args[i] == "--hours" && i + 1 < args.count {
                hours = Double(args[i + 1]) ?? 24
                i += 2
            } else if args[i] == "--output" && i + 1 < args.count {
                outputPath = args[i + 1]
                i += 2
            } else {
                i += 1
            }
        }

        let supportDir = maccrabDataDir()
        let store: AlertStore
        do {
            store = try AlertStore(directory: supportDir)
        } catch {
            print("Error opening alert store: \(error)")
            return
        }

        let since = Date().addingTimeInterval(-hours * 3600)
        let alerts: [Alert]
        do {
            alerts = try await store.alerts(since: since)
        } catch {
            print("Error reading alerts: \(error)")
            return
        }

        // Separate campaign alerts from individual detection alerts so campaigns
        // don't skew the "top rules" chart and their severity is reported separately.
        let campaignAlerts = alerts.filter { $0.ruleId.hasPrefix("maccrab.campaign.") }
        let detectionAlerts = alerts.filter { !$0.ruleId.hasPrefix("maccrab.campaign.") }

        let generator = ReportGenerator()
        var reportData = await generator.buildReportData(
            alerts: detectionAlerts,
            title: "MacCrab Incident Report",
            timeRange: (start: since, end: Date())
        )

        // Generate LLM narrative summary if configured
        if let llmService = createCLILLMService() {
            if await llmService.isAvailable() {
                let severitySummary = detectionAlerts.reduce(into: [String: Int]()) { $0[$1.severity.rawValue, default: 0] += 1 }
                let topRules = Dictionary(grouping: detectionAlerts, by: \.ruleTitle)
                    .sorted { $0.value.count > $1.value.count }
                    .prefix(5)
                    .map { "\($0.key) (\($0.value.count))" }
                    .joined(separator: ", ")
                let campaignSummary = campaignAlerts.isEmpty ? "" :
                    "\nCampaigns detected: \(campaignAlerts.count) (\(campaignAlerts.map(\.ruleTitle).joined(separator: "; ")))"

                let context = """
                    Time range: last \(Int(hours)) hours
                    Total alerts: \(detectionAlerts.count)
                    By severity: \(severitySummary.map { "\($0.key): \($0.value)" }.joined(separator: ", "))
                    Top rules: \(topRules)\(campaignSummary)
                    """

                if let enhancement = await llmService.query(
                    systemPrompt: LLMPrompts.investigationSystem,
                    userPrompt: "Generate an executive summary for this security report.\n\n\(context)",
                    maxTokens: 1024, temperature: 0.3
                ) {
                    reportData.narrativeSummary = enhancement.response
                    print("  AI narrative: generated (\(enhancement.provider))")
                }
            }
        }

        let html = await generator.generateHTML(from: reportData)

        if let outputPath = outputPath {
            do {
                try await generator.writeReport(html: html, to: outputPath)
                print("Report written to \(outputPath)")
                print("  Time range: last \(Int(hours)) hours")
                print("  Alerts:     \(detectionAlerts.count)")
                if !campaignAlerts.isEmpty {
                    print("  Campaigns:  \(campaignAlerts.count)")
                }
            } catch {
                print("Error writing report: \(error)")
            }
        } else {
            // Write to stdout
            print(html)
        }
    }
}
