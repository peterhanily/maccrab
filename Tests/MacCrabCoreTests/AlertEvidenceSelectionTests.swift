import Foundation
import Testing
@testable import MacCrabCore

@Suite("Bounded exact alert evidence selection")
struct AlertEvidenceSelectionTests {
    private let alertTime = Date(timeIntervalSince1970: 100_000)

    private struct Candidate: Equatable {
        let token: Int
        let timestamp: Date
        let id: String
        let severity: Severity
        let evidence: Int?
        let poison: Bool
        let corruptLegacy: Bool
        let inheritedLoss: Bool
        let resourceLimited: Bool
    }

    private func rank(_ candidate: Candidate) -> AlertEvidenceSelectionRank {
        AlertEvidenceSelectionRank(
            timestamp: candidate.timestamp,
            id: candidate.id,
            severity: candidate.severity,
            alertTimestamp: alertTime
        )
    }

    /// Deliberately independent of the production rank/helper. Equal ranks use
    /// scan position, spelling out the former stable sort's tie behavior.
    private func reference(_ input: [Candidate], limit: Int) -> [Candidate] {
        input.enumerated().sorted { lhs, rhs in
            let a = lhs.element
            let b = rhs.element
            if a.severity != b.severity { return a.severity > b.severity }
            let da = abs(a.timestamp.timeIntervalSince(alertTime))
            let db = abs(b.timestamp.timeIntervalSince(alertTime))
            if da != db { return da < db }
            if a.timestamp != b.timestamp { return a.timestamp > b.timestamp }
            if a.id != b.id { return a.id < b.id }
            return lhs.offset < rhs.offset
        }.prefix(limit).map(\.element)
    }

    @Test("every retained prefix matches full stable ranking in several scan orders")
    func selectionMatchesIndependentFullSort() {
        let severities: [Severity] = [
            .informational, .critical, .low, .high, .medium,
        ]
        let candidates = (0..<180).map { index in
            Candidate(
                token: index,
                // Repeated timestamps/IDs deliberately produce exact ties;
                // both sides of the alert exercise the distance/date tie-break.
                timestamp: alertTime.addingTimeInterval(Double(index % 9 - 4)),
                id: String(format: "%03d", index % 3),
                severity: severities[index % severities.count],
                evidence: index % 4 == 0 ? nil : index,
                poison: index % 7 == 0,
                corruptLegacy: index % 11 == 0,
                inheritedLoss: index % 13 == 0,
                resourceLimited: index % 17 == 0
            )
        }
        let orders = [
            candidates,
            Array(candidates.reversed()),
            (0..<candidates.count).map { candidates[($0 * 37) % candidates.count] },
        ]
        for limit in [0, 1, 2, 7, 50] {
            for order in orders {
                var selected = BoundedAlertEvidenceSelection<Candidate>(limit: limit)
                var seen: [Candidate] = []
                for candidate in order {
                    seen.append(candidate)
                    selected.consider(rank: rank(candidate)) { candidate }
                    #expect(selected.count <= limit)
                    // Equality checks the complete selected gap/payload state,
                    // not just count or membership of successful evidence.
                    #expect(selected.values == reference(seen, limit: limit))
                }
            }
        }
    }

    private final class Lifetime {
        var live = 0
        var peak = 0
        var constructions = 0
    }

    private final class CompactPayload {
        let token: Int
        let bytes: [UInt8]
        private let lifetime: Lifetime

        init(token: Int, lifetime: Lifetime) {
            self.token = token
            self.lifetime = lifetime
            bytes = [UInt8](repeating: UInt8(token % 255), count: 64 * 1_024)
            lifetime.live += 1
            lifetime.constructions += 1
            lifetime.peak = max(lifetime.peak, lifetime.live)
        }

        deinit { lifetime.live -= 1 }
    }

    @Test("losing ranks never compact and displacement releases before replacement")
    func boundedLazyCompactionAndOwnership() {
        let limit = 7
        let lifetime = Lifetime()
        var selected = BoundedAlertEvidenceSelection<CompactPayload>(limit: limit)
        weak var displaced: CompactPayload?
        for index in 0..<limit {
            let rank = AlertEvidenceSelectionRank(
                timestamp: alertTime.addingTimeInterval(-Double(index)),
                id: String(index), severity: .high, alertTimestamp: alertTime
            )
            selected.consider(rank: rank) {
                let payload = CompactPayload(token: index, lifetime: lifetime)
                if index == limit - 1 { displaced = payload }
                return payload
            }
        }
        #expect(displaced != nil)
        #expect(lifetime.live == limit)
        for index in 0..<4_096 {
            selected.consider(rank: AlertEvidenceSelectionRank(
                timestamp: alertTime,
                id: "loser-\(index)", severity: .informational,
                alertTimestamp: alertTime
            )) {
                Issue.record("rank-losing event reached compaction")
                return CompactPayload(token: index, lifetime: lifetime)
            }
            #expect(selected.count == limit)
        }
        #expect(lifetime.constructions == limit)
        selected.consider(rank: AlertEvidenceSelectionRank(
            timestamp: alertTime, id: "replacement", severity: .critical,
            alertTimestamp: alertTime
        )) {
            #expect(displaced == nil)
            #expect(lifetime.live == limit - 1)
            return CompactPayload(token: 99, lifetime: lifetime)
        }
        #expect(selected.values.map(\.token) == [99, 0, 1, 2, 3, 4, 5])
        #expect(lifetime.constructions == limit + 1)
        #expect(lifetime.peak == limit)
        #expect(lifetime.live == limit)
        selected = BoundedAlertEvidenceSelection<CompactPayload>(limit: limit)
        #expect(lifetime.live == 0)
    }

    @Test("zero limit and equal-rank losers do not call the payload factory")
    func zeroAndEqualRankStayLazy() {
        let same = AlertEvidenceSelectionRank(
            timestamp: alertTime, id: "same", severity: .high,
            alertTimestamp: alertTime
        )
        var zero = BoundedAlertEvidenceSelection<Int>(limit: 0)
        zero.consider(rank: same) {
            Issue.record("zero limit reached compaction")
            return 0
        }
        #expect(zero.values.isEmpty)
        var one = BoundedAlertEvidenceSelection<Int>(limit: 1)
        one.consider(rank: same) { 1 }
        one.consider(rank: same) {
            Issue.record("equal-rank later candidate displaced stable winner")
            return 2
        }
        #expect(one.values == [1])
    }

    @Test("selected gap-only candidates consume slots rather than falling back to evidence")
    func gapOnlyCandidatesPreserveSelectionSemantics() {
        let candidates = [
            Candidate(token: 0, timestamp: alertTime, id: "normal", severity: .low,
                      evidence: 0, poison: false, corruptLegacy: false,
                      inheritedLoss: false, resourceLimited: false),
            Candidate(token: 1, timestamp: alertTime, id: "gap", severity: .critical,
                      evidence: nil, poison: true, corruptLegacy: true,
                      inheritedLoss: true, resourceLimited: true),
        ]
        var selected = BoundedAlertEvidenceSelection<Candidate>(limit: 1)
        for candidate in candidates {
            selected.consider(rank: rank(candidate)) { candidate }
        }
        #expect(selected.values == [candidates[1]])
        #expect(selected.values.compactMap(\.evidence).isEmpty)
        #expect(selected.count == 1)
    }

    private func event(index: Int, timestamp: Date, severity: Severity) throws -> Event {
        let id = try #require(UUID(uuidString: String(
            format: "00000000-0000-4000-8000-%012d", index
        )))
        let process = ProcessInfo(
            pid: 123, ppid: 1, rpid: 1, name: "evidence-fixture",
            executable: "/usr/bin/true", commandLine: "/usr/bin/true",
            args: ["/usr/bin/true"], workingDirectory: "/tmp",
            userId: 501, userName: "tester", groupId: 20,
            startTime: Date(timeIntervalSince1970: 90_000), exitCode: nil,
            codeSignature: nil, ancestors: [], architecture: "arm64",
            isPlatformBinary: false
        )
        return Event(
            id: id, timestamp: timestamp, eventCategory: .process,
            eventType: .creation, eventAction: "exec", process: process,
            severity: severity
        )
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-evidence-selection-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    @Test("exact journal selection matches independent windowed ranking and chronological UUIDs")
    func exactStoreSelectionMatchesReference() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path)
        let severities: [Severity] = [.critical, .high, .medium, .low, .informational]
        let events = try (0..<140).map { index in
            try event(
                index: index,
                timestamp: alertTime.addingTimeInterval(Double(index % 40 - 35)),
                severity: severities[index % severities.count]
            )
        }
        let insertion = try await store.insert(events: events, lane: .priority)
        try #require(insertion.persistedCount == events.count)
        let requests: [(rows: Int, window: TimeInterval)] = [
            (0, 30), (1, 30), (7, 5), (50, 30), (10_000, 10_000), (7, 0),
        ]
        for request in requests {
            let lower = alertTime.addingTimeInterval(-min(30, request.window))
            let scoped = events.filter { $0.timestamp >= lower && $0.timestamp <= alertTime }
            let referenceCandidates = scoped.enumerated().map { index, event in
                Candidate(
                    token: index, timestamp: event.timestamp, id: event.id.uuidString,
                    severity: event.severity, evidence: index, poison: false,
                    corruptLegacy: false, inheritedLoss: false, resourceLimited: false
                )
            }
            let expected = reference(referenceCandidates, limit: min(50, request.rows)).sorted {
                $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp
            }.map(\.id)
            let snapshot = try await store.exactAlertEvidenceSnapshot(
                alertTimestamp: alertTime, windowSeconds: request.window, maxRows: request.rows
            )
            #expect(snapshot.isComplete)
            #expect(snapshot.candidates.map(\.eventId) == expected)
            #expect(Set(snapshot.candidates.map(\.eventId)).count == expected.count)
        }
    }

    @Test("exact selection ranks terminal-applied severity before compacting the winner")
    func terminalAppliedSeverityControlsAdmission() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path)
        var revised = try event(
            index: 1, timestamp: alertTime.addingTimeInterval(-20), severity: .low
        )
        let recent = try event(index: 2, timestamp: alertTime, severity: .high)
        try await store.insert(events: [revised, recent], lane: .priority)
        let before = try await store.exactAlertEvidenceSnapshot(
            alertTimestamp: alertTime, maxRows: 1
        )
        #expect(before.candidates.map(\.eventId) == [recent.id.uuidString])
        revised.severity = .critical
        revised.enrichments["benign_test_terminal"] = "complete"
        _ = try await store.appendTerminalRevision(revised, lane: .priority)
        let after = try await store.exactAlertEvidenceSnapshot(
            alertTimestamp: alertTime, maxRows: 1
        )
        #expect(after.isComplete)
        #expect(after.candidates.map(\.eventId) == [revised.id.uuidString])
        let candidate = try #require(after.candidates.first)
        let decoded = try JSONDecoder().decode(Event.self, from: Data(candidate.rawJSON.utf8))
        #expect(decoded.severity == .critical)
        #expect(decoded.enrichments["benign_test_terminal"] == "complete")
    }
}
