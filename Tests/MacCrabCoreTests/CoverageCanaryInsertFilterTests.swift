import Foundation
import Testing
@testable import MacCrabCore

@Suite("Coverage probes retain distinct persistence evidence")
struct CoverageCanaryInsertFilterTests {
    private func event(
        nonce: String? = nil,
        at timestamp: Date,
        filePath: String? = nil
    ) -> Event {
        let arguments = nonce.map { [CoverageCanary.spawnBinaryPath, $0] }
            ?? [CoverageCanary.spawnBinaryPath]
        let process = MacCrabCore.ProcessInfo(
            pid: 100, ppid: 1, rpid: 1,
            name: "true", executable: CoverageCanary.spawnBinaryPath,
            commandLine: arguments.joined(separator: " "), args: arguments,
            workingDirectory: "/", userId: 0, userName: "root", groupId: 0,
            startTime: timestamp, ancestors: [], isPlatformBinary: true
        )
        return Event(
            timestamp: timestamp,
            eventCategory: .process, eventType: .start, eventAction: "exec",
            process: process,
            file: filePath.map { FileInfo(path: $0, action: .open) }
        )
    }

    @Test("Ordinary true cannot suppress either nonce while routine duplicates remain filtered")
    func probesBypassOnlyDuplicateSuppression() {
        let filter = EventInsertFilter.defaultFilter(supportDir: "/private/fixture-maccrab")
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let ordinary = event(at: start)
        let first = event(nonce: CoverageCanary.makeNonce(), at: start.addingTimeInterval(1))
        let second = event(nonce: CoverageCanary.makeNonce(), at: start.addingTimeInterval(2))
        let repeated = event(at: start.addingTimeInterval(3))
        #expect(!filter.shouldDrop(event: ordinary))
        #expect(!filter.shouldDrop(event: first))
        #expect(!filter.shouldDrop(event: second))
        #expect(filter.shouldDrop(event: repeated))
        let counts = filter.counters.snapshot()
        #expect(counts.passed == 3)
        #expect(counts.dropped == 1)
        #expect(filter.counters.duplicateSnapshot() == 1)
    }

    @Test("A probe does not seed the duplicate window for the next ordinary true")
    func probeDoesNotBecomeRoutineExemplar() {
        let filter = EventInsertFilter(duplicateWindowSeconds: 300)
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        #expect(!filter.shouldDrop(event: event(
            nonce: CoverageCanary.makeNonce(), at: start
        )))
        #expect(!filter.shouldDrop(event: event(at: start.addingTimeInterval(1))))
        #expect(filter.shouldDrop(event: event(at: start.addingTimeInterval(2))))
    }

    @Test("Explicit process and path exclusions still apply to recognized probes")
    func explicitExclusionsRemainAuthoritative() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let nonce = CoverageCanary.makeNonce()
        let byProcess = EventInsertFilter(
            processNames: ["true"], duplicateWindowSeconds: 300
        )
        #expect(byProcess.shouldDrop(event: event(nonce: nonce, at: start)))
        #expect(byProcess.counters.duplicateSnapshot() == 0)
        let byPath = EventInsertFilter(
            pathSubstrings: ["/private/explicit-exclusion/"],
            duplicateWindowSeconds: 300
        )
        #expect(byPath.shouldDrop(event: event(
            nonce: nonce, at: start, filePath: "/private/explicit-exclusion/item"
        )))
        #expect(byPath.counters.duplicateSnapshot() == 0)
    }

    @Test("Normal journal batch preserves both canaries in searchable sparse projection")
    func journalBatchKeepsDistinctCanaryEvidence() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("canary-insert-filter-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(path: directory.appendingPathComponent("events.db").path)
        let filter = EventInsertFilter.defaultFilter(supportDir: directory.path)
        await store.setInsertFilter(filter)
        let start = Date().addingTimeInterval(-30)
        let firstNonce = CoverageCanary.makeNonce()
        let secondNonce = CoverageCanary.makeNonce()
        let ordinary = event(at: start)
        let first = event(nonce: firstNonce, at: start.addingTimeInterval(1))
        let second = event(nonce: secondNonce, at: start.addingTimeInterval(2))
        let repeated = event(at: start.addingTimeInterval(3))
        // The normal v8 batch API applies the production insert filter before
        // block formation, then commits the journal and sparse projection.
        let result = try await store.insert(
            events: [ordinary, first, second, repeated], lane: .priority
        )
        #expect(result.persistedCount == 3)
        #expect(result.filteredCount == 1)
        #expect(result.inputDispositions == [
            .durable(eventID: ordinary.id), .durable(eventID: first.id),
            .durable(eventID: second.id), .filtered(eventID: repeated.id)
        ])
        #expect(filter.counters.duplicateSnapshot() == 1)
        let firstHit = try await store.searchSnapshot(
            text: firstNonce, since: start.addingTimeInterval(-1), until: Date(), limit: 1
        )
        #expect(firstHit.events.map(\.id) == [first.id])
        #expect(firstHit.events.first?.process.commandLine.contains(firstNonce) == true)
        let secondHit = try await store.searchSnapshot(
            text: secondNonce, since: start.addingTimeInterval(-1), until: Date(), limit: 1
        )
        #expect(secondHit.events.map(\.id) == [second.id])
        #expect(secondHit.events.first?.process.commandLine.contains(secondNonce) == true)
        // Presence proves this nonce. Deliberate sparse omissions elsewhere do
        // not justify asserting a complete retained search window here.
        withExtendedLifetime(firstHit) {}
        withExtendedLifetime(secondHit) {}
    }
}
