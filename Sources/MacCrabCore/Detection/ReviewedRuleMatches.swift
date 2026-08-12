import Foundation

/// Canonical value ordering shared by the reviewed detection pipeline and the
/// sparse EventStore projection. Call order, actor completion order, and retry
/// boundaries must not change the match set persisted for one event UUID.
public enum ReviewedRuleMatches {
    public static func normalized(_ matches: [RuleMatch]) -> [RuleMatch] {
        let canonical = matches.map(canonicalized)
        return Array(Set(canonical)).sorted(by: orderedBefore)
    }

    public static func merged(
        _ first: [RuleMatch],
        _ second: [RuleMatch]
    ) -> [RuleMatch] {
        normalized(first + second)
    }

    private static func canonicalized(_ match: RuleMatch) -> RuleMatch {
        RuleMatch(
            ruleId: match.ruleId,
            ruleName: match.ruleName,
            severity: match.severity,
            description: match.description,
            mitreTechniques: Array(Set(match.mitreTechniques)).sorted(),
            tags: Array(Set(match.tags)).sorted(),
            suppressible: match.suppressible
        )
    }

    private static func orderedBefore(_ lhs: RuleMatch, _ rhs: RuleMatch) -> Bool {
        if lhs.ruleId != rhs.ruleId { return lhs.ruleId < rhs.ruleId }
        if lhs.ruleName != rhs.ruleName { return lhs.ruleName < rhs.ruleName }
        if lhs.severity.rawValue != rhs.severity.rawValue {
            return lhs.severity.rawValue < rhs.severity.rawValue
        }
        if lhs.description != rhs.description {
            return lhs.description < rhs.description
        }
        if lhs.mitreTechniques != rhs.mitreTechniques {
            return lhs.mitreTechniques.lexicographicallyPrecedes(
                rhs.mitreTechniques
            )
        }
        if lhs.tags != rhs.tags {
            return lhs.tags.lexicographicallyPrecedes(rhs.tags)
        }
        if lhs.suppressible != rhs.suppressible {
            return !lhs.suppressible && rhs.suppressible
        }
        return false
    }
}
