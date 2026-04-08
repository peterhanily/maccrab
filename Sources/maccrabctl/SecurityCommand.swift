import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func showSecurityScore() async {
        print("MacCrab Security Posture")
        print("══════════════════════════════════════════════════════════════")

        let result = await SecurityScorer().calculate()
        let gradeIndicator = result.totalScore >= 80 ? "✓" : result.totalScore >= 60 ? "⚠" : "✗"
        print("Overall Score:   \(result.grade)  (\(result.totalScore)/100)  \(gradeIndicator)")
        print("")

        // Group factors by category
        let categories = ["system", "runtime", "hygiene"]
        let categoryLabels = ["system": "System Configuration", "runtime": "Runtime Behavior", "hygiene": "Security Hygiene"]

        for category in categories {
            let categoryFactors = result.factors.filter { $0.category == category }
            guard !categoryFactors.isEmpty else { continue }

            let categoryScore = categoryFactors.reduce(0) { $0 + $1.score }
            let categoryMax = categoryFactors.reduce(0) { $0 + $1.maxScore }
            let label = categoryLabels[category] ?? category
            print("── \(label) (\(categoryScore)/\(categoryMax)) ──────────────────")

            for factor in categoryFactors {
                let icon: String
                switch factor.status {
                case "pass": icon = "✓"
                case "warn": icon = "⚠"
                default:     icon = "✗"
                }
                let scoreStr = "[\(factor.score)/\(factor.maxScore)]"
                print("  \(icon) \(factor.name.padding(toLength: 36, withPad: " ", startingAt: 0)) \(scoreStr.padding(toLength: 7, withPad: " ", startingAt: 0))  \(factor.detail)")
            }
            print("")
        }

        // Recommendations
        if !result.recommendations.isEmpty {
            print("── Recommendations ──────────────────────────────────────────")
            for (i, rec) in result.recommendations.enumerated() {
                print("  \(i + 1). \(rec)")
            }
            print("")
        }

        print("══════════════════════════════════════════════════════════════")
    }
}
