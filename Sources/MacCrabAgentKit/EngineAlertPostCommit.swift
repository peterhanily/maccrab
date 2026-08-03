import MacCrabCore

/// Candidate-only context that cannot itself authorize a side effect. EventLoop
/// keys these records by the candidate alert id, then this planner intersects
/// them with AlertSink's exact post-collapse, post-commit return value.
struct EngineAlertCandidateContext: Sendable {
    let match: RuleMatch
    let isSequence: Bool
}

struct EngineAlertCommittedContext: Sendable {
    let alert: Alert
    let match: RuleMatch
}

struct EngineAlertPostCommitPlan: Sendable {
    let survivors: [EngineAlertCommittedContext]
    let sequenceSurvivors: [EngineAlertCommittedContext]
    let triageAlert: Alert?
}

enum EngineAlertPostCommit {
    /// Build every downstream work list from committed alert ids only. Missing
    /// context fails closed: a row without its originating RuleMatch remains
    /// persisted, but cannot trigger a response, integration, campaign mutation,
    /// derivative, or other candidate-derived work.
    static func plan(
        persistedAlerts: [Alert],
        contextsByAlertID: [String: EngineAlertCandidateContext]
    ) -> EngineAlertPostCommitPlan {
        let survivors = persistedAlerts.compactMap { alert in
            contextsByAlertID[alert.id].map {
                EngineAlertCommittedContext(alert: alert, match: $0.match)
            }
        }
        let sequenceSurvivors = persistedAlerts.compactMap { alert -> EngineAlertCommittedContext? in
            guard let context = contextsByAlertID[alert.id], context.isSequence else {
                return nil
            }
            return EngineAlertCommittedContext(alert: alert, match: context.match)
        }
        return EngineAlertPostCommitPlan(
            survivors: survivors,
            sequenceSurvivors: sequenceSurvivors,
            // A persisted row whose candidate context is missing must fail
            // closed for LLM work too. Select from the exact mapped survivor
            // set rather than independently trusting the store return value.
            triageAlert: LLMBatchTriage.representative(
                from: survivors.map(\.alert)
            )
        )
    }
}
