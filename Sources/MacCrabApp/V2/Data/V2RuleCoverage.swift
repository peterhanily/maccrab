import Foundation

public enum V2RuleCoverage: String, Hashable, Sendable {
    case unknown, disabled, unobserved, quiet, matched

    var label: String {
        switch self {
        case .unknown: return String(localized: "rules.coverage.unknown", defaultValue: "Coverage unknown")
        case .disabled: return String(localized: "rules.coverage.disabled", defaultValue: "Disabled")
        case .unobserved: return String(localized: "rules.coverage.unobserved", defaultValue: "No evaluations recorded")
        case .quiet: return String(localized: "rules.coverage.quiet", defaultValue: "Evaluated, no matches")
        case .matched: return String(localized: "rules.coverage.matched", defaultValue: "Matches recorded")
        }
    }
}
