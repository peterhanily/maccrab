import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func huntThreats(query: String) async {
        let supportDir = maccrabDataDir()
        let eventsDBPath = supportDir + "/events.db"
        let alertsDBPath = supportDir + "/alerts.db"

        let hasEvents = FileManager.default.fileExists(atPath: eventsDBPath)
        let hasAlerts = FileManager.default.fileExists(atPath: alertsDBPath)
        guard hasEvents || hasAlerts else {
            print("No event or alert database found in \(supportDir)")
            print("The daemon must run first to collect events.")
            return
        }

        // Create LLM service from env vars if configured
        let llmService = createCLILLMService()
        let hunter = ThreatHunter(
            eventsDatabasePath: eventsDBPath,
            alertsDatabasePath: alertsDBPath,
            llmService: llmService
        )

        // Use LLM-enhanced hunting if available, otherwise fall back
        let result: ThreatHunter.HuntResult?
        if llmService != nil {
            result = await hunter.huntEnhanced(query)
        } else {
            result = await hunter.hunt(query)
        }

        guard let result else {
            print("Hunt returned no result.")
            return
        }

        print("Threat Hunt Results")
        print("══════════════════════════════════════════════════════════════")
        print("Query:          \(result.query)")
        print("Interpretation: \(result.interpretation)")
        print("Results:        \(result.resultCount)")
        print("Status:         \(result.status.rawValue)")
        print("Execution:      \(String(format: "%.3f", result.executionTime))s")

        if !result.sqlQuery.isEmpty {
            print("SQL:            \(result.sqlQuery)")
        }
        print(String(repeating: "─", count: 80))

        switch result.status {
        case .databaseUnavailable:
            print("Hunt could not run: the selected local database is unavailable.")
            print("This is not evidence that no matching activity exists.")
            return
        case .searchIndexDegraded:
            print("Full-text hunting is unavailable while the search index awaits repair.")
            print("No results is not proof of absence; typed event queries remain available.")
            return
        case .timedOut:
            print("Hunt timed out before completion.")
            print("Partial rows, if any, are not a complete absence-of-findings result.")
        case .rejected:
            print("Hunt query was rejected by the read-only SQL safety policy.")
            return
        case .rowLimitReached:
            print("Warning: row ceiling reached; results are truncated.")
        case .resultLimitReached:
            print("Warning: output-size or column ceiling reached; results are truncated.")
        case .completed:
            break
        }

        if result.results.isEmpty && result.status == .completed {
            print("No matching results found.")
            print("\nSuggested queries:")
            let suggestions = await hunter.suggestions()
            for suggestion in suggestions {
                print("  - \(suggestion)")
            }
        } else if result.results.isEmpty {
            print("No rows were safely returned before the hunt stopped.")
        } else {
            for (i, row) in result.results.enumerated() {
                print("\n[\(i + 1)]")
                for (key, value) in row.sorted(by: { $0.key < $1.key }) {
                    if !value.isEmpty {
                        print("  \(key): \(value)")
                    }
                }
            }
        }
    }

}
