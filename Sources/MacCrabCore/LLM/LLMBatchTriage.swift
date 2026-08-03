// LLMBatchTriage.swift
// MacCrabCore
//
// Deterministic admission for automatic per-event LLM investigation. The
// engine may produce many rule matches for one event, while AlertSink can
// collapse several of them to one persisted finding. Selection therefore
// happens only from the exact post-commit survivors returned by AlertSink.

import Foundation

public enum LLMBatchTriage {
    /// Pick at most one stored alert for automatic structured investigation.
    /// Critical wins over high; ties use stable alert fields rather than input
    /// order so the same persisted batch always produces the same candidate.
    public static func representative(from persistedAlerts: [Alert]) -> Alert? {
        persistedAlerts
            .filter {
                $0.severity >= .high
                    && !$0.ruleId.hasPrefix("maccrab.campaign.")
                    && !$0.ruleId.hasPrefix("maccrab.llm.")
            }
            .min(by: isPreferred)
    }

    private static func isPreferred(_ lhs: Alert, _ rhs: Alert) -> Bool {
        if lhs.severity != rhs.severity {
            // Treat greater severity as earlier in the priority ordering.
            return lhs.severity > rhs.severity
        }
        if lhs.timestamp != rhs.timestamp {
            // Earlier evidence is the deterministic representative.
            return lhs.timestamp < rhs.timestamp
        }
        return lhs.id < rhs.id
    }
}
