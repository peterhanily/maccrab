import Foundation
import MacCrabCore

/// One durable emission boundary for every BehaviorScoring threshold crossing.
///
/// `BehaviorScoring` owns the score and a retryable delivery token; this type
/// owns the translation into an operator-visible alert. The token is resolved
/// only after AlertSink reports a committed row or an intentional filter /
/// collapse. A storage error leaves the same token pending for the next signal.
enum BehaviorScoreAlertEmitter {
    static func record(
        state: DaemonState,
        event: Event?,
        named name: String,
        detail: String = "",
        forProcess pid: Int32,
        path: String
    ) async {
        await record(
            behaviorScoring: state.behaviorScoring,
            alertSink: state.alertSink,
            notifier: state.notifier,
            responseEngine: state.responseEngine,
            event: event,
            isWarmingUp: state.isWarmingUp,
            named: name,
            detail: detail,
            forProcess: pid,
            path: path
        )
    }

    static func record(
        behaviorScoring: BehaviorScoring,
        alertSink: AlertSink,
        notifier: NotificationOutput,
        responseEngine: ResponseEngine?,
        event: Event?,
        isWarmingUp: Bool,
        named name: String,
        detail: String = "",
        forProcess pid: Int32,
        path: String
    ) async {
        guard let crossing = await behaviorScoring.addIndicator(
            named: name,
            detail: detail,
            forProcess: pid,
            path: path
        ) else { return }
        await emit(
            crossing,
            behaviorScoring: behaviorScoring,
            alertSink: alertSink,
            notifier: notifier,
            responseEngine: responseEngine,
            event: event,
            isWarmingUp: isWarmingUp
        )
    }

    static func recordRuleMatch(
        state: DaemonState,
        event: Event,
        match: RuleMatch
    ) async {
        guard let crossing = await state.behaviorScoring.addRuleMatch(
            severity: match.severity,
            ruleTitle: match.ruleName,
            forProcess: event.process.pid,
            path: event.process.executable
        ) else { return }
        await emit(crossing, state: state, event: event)
    }

    static func emit(
        _ crossing: BehaviorScoring.ScoringResult,
        state: DaemonState,
        event: Event?
    ) async {
        await emit(
            crossing,
            behaviorScoring: state.behaviorScoring,
            alertSink: state.alertSink,
            notifier: state.notifier,
            responseEngine: state.responseEngine,
            event: event,
            isWarmingUp: state.isWarmingUp
        )
    }

    static func emit(
        _ crossing: BehaviorScoring.ScoringResult,
        behaviorScoring: BehaviorScoring,
        alertSink: AlertSink,
        notifier: NotificationOutput,
        responseEngine: ResponseEngine?,
        event: Event?,
        isWarmingUp: Bool
    ) async {
        let indicatorSummary = crossing.indicators.prefix(5)
            .map { "\($0.name)(\($0.weight))" }
            .joined(separator: ", ")
        let processName = event?.process.name
            ?? (crossing.processPath as NSString).lastPathComponent
        var candidates = [RuleMatch(
            ruleId: "maccrab.behavior.composite",
            ruleName: "Behavioral Score Threshold: \(processName)",
            severity: crossing.severity,
            description: "Process accumulated suspicious behavior score of "
                + "\(String(format: "%.1f", crossing.totalScore)). "
                + "Top indicators: \(indicatorSummary)",
            mitreTechniques: [],
            tags: ["attack.execution", "attack.defense_evasion"]
        )]

        if let event {
            NoiseFilter.apply(
                &candidates,
                event: event,
                isWarmingUp: isWarmingUp
            )
        }
        guard let candidate = candidates.first else {
            _ = await behaviorScoring.resolveThreshold(
                deliveryToken: crossing.deliveryToken,
                as: .filteredOrSuppressed
            )
            return
        }

        let alert = Alert(
            ruleId: candidate.ruleId,
            ruleTitle: candidate.ruleName,
            severity: candidate.severity,
            eventId: event?.id.uuidString ?? UUID().uuidString,
            processPath: crossing.processPath,
            processName: processName,
            description: candidate.description,
            mitreTactics: "attack.execution,attack.defense_evasion",
            mitreTechniques: "",
            suppressed: false
        )

        do {
            let committed: Bool
            if let event {
                committed = try await alertSink.submit(
                    alert: alert,
                    event: event
                )
            } else {
                committed = try await alertSink.submit(alert: alert)
            }

            // `false` is a deliberate sink decision (built-in mute, duplicate,
            // or sealed admission), not a failed durable write. In each case no
            // immediate retry can improve the outcome, so settle the token.
            _ = await behaviorScoring.resolveThreshold(
                deliveryToken: crossing.deliveryToken,
                as: committed ? .committed : .filteredOrSuppressed
            )
            guard committed else { return }

            await notifier.notify(alert: alert)
            if let event, let responseEngine {
                await responseEngine.execute(alert: alert, event: event)
            }
        } catch {
            await behaviorScoring.recordThresholdDeliveryFailure(
                deliveryToken: crossing.deliveryToken
            )
            await StorageErrorTracker.shared.recordAlertError(error)
        }
    }
}
