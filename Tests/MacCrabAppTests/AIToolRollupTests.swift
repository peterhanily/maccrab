// AIToolRollupTests.swift
// MacCrabAppTests
//
// UX-1: the AI-Guard "tools observed" table is driven by aiToolRollup, which
// groups agent-session snapshots by tool. Pin the aggregation (sessions /
// events / alerts / max-lastSeen) + the most-alerting-first sort.

import Testing
import Foundation
@testable import MacCrabApp
import MacCrabCore

@Suite("AI tool rollup (UX-1)")
struct AIToolRollupTests {

    private func session(_ tool: AIToolType, last: TimeInterval, events: [AgentEvent]) -> AgentSessionSnapshot {
        AgentSessionSnapshot(aiPid: 1, toolType: tool, projectDir: nil,
                             startTime: Date(timeIntervalSince1970: 0), events: events,
                             lastActivity: Date(timeIntervalSince1970: last))
    }
    private func alertEvent() -> AgentEvent {
        AgentEvent(timestamp: Date(timeIntervalSince1970: 1), kind: .alert(ruleTitle: "r", severity: .high))
    }
    private func llmEvent() -> AgentEvent {
        AgentEvent(timestamp: Date(timeIntervalSince1970: 1), kind: .llmCall(provider: "p", endpoint: "e", bytesUp: nil, bytesDown: nil))
    }

    @Test("groups by tool; sums sessions/events/alerts; takes max lastSeen; alerts-first sort")
    func grouping() {
        let sessions = [
            session(.claudeCode, last: 100, events: [alertEvent(), llmEvent()]),  // 2 events, 1 alert
            session(.claudeCode, last: 200, events: [llmEvent()]),                // 1 event,  0 alert
            session(.cursor, last: 50, events: [llmEvent(), llmEvent()]),         // 2 events, 0 alert
        ]
        let rows = aiToolRollup(sessions)
        #expect(rows.count == 2)
        let claude = rows.first { $0.tool == AIToolType.claudeCode.displayName }
        #expect(claude?.sessions == 2)
        #expect(claude?.events == 3)
        #expect(claude?.alerts == 1)
        #expect(claude?.lastSeen == Date(timeIntervalSince1970: 200))   // max across the two
        // claude (1 alert) sorts before cursor (0 alerts)
        #expect(rows.first?.tool == AIToolType.claudeCode.displayName)
    }

    @Test("empty input → empty rollup")
    func empty() { #expect(aiToolRollup([]).isEmpty) }
}
