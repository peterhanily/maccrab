import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func huntThreats(query: String) async {
        let supportDir = maccrabDataDir()
        let dbPath = supportDir + "/events.db"

        guard FileManager.default.fileExists(atPath: dbPath) else {
            print("No event database found at \(dbPath)")
            print("The daemon must run first to collect events.")
            return
        }

        // Create LLM service from env vars if configured
        let llmService = createCLILLMService()
        let hunter = ThreatHunter(databasePath: dbPath, llmService: llmService)

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
        print("Execution:      \(String(format: "%.3f", result.executionTime))s")

        if !result.sqlQuery.isEmpty {
            print("SQL:            \(result.sqlQuery)")
        }
        print(String(repeating: "─", count: 80))

        if result.results.isEmpty {
            print("No matching results found.")
            print("\nSuggested queries:")
            let suggestions = await hunter.suggestions()
            for suggestion in suggestions {
                print("  - \(suggestion)")
            }
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
