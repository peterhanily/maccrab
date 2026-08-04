// EventEnricherHashingTests.swift
// Proves EventEnricher wires a ProcessHasher through on exec/fork events
// and leaves other event types alone.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventEnricher hashing")
struct EventEnricherHashingTests {

    private func deferredPlane() -> HeavyEnrichmentPlane {
        // This suite verifies hash evidence and stable-file binding, not the
        // production 50 ms work budget. Full-suite utility-executor contention
        // must not convert the fixture into a deliberate timeout test.
        HeavyEnrichmentPlane(configuration: .init(operationTimeoutSeconds: 30))
    }

    private func applyingHashPatch(
        from enricher: EventEnricher,
        to event: Event
    ) async -> Event {
        let initiallyEnriched = await enricher.enrich(event)
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(30_000_000_000)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        while DispatchTime.now().uptimeNanoseconds < deadline {
            if let patch = await enricher.drainDeferredEnrichments(limit: 16).first(where: {
                $0.component == .processHashes
            }), let applied = patch.applying(to: initiallyEnriched) {
                return applied
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return initiallyEnriched
    }

    private func makeTempFile(bytes: Data) throws -> String {
        let path = NSTemporaryDirectory() + "maccrab_enricher_hash_\(UUID().uuidString).bin"
        try bytes.write(to: URL(fileURLWithPath: path))
        return path
    }

    private func cleanup(_ path: String) {
        try? FileManager.default.removeItem(atPath: path)
    }

    private func makeProcess(
        executable: String,
        pid: Int32 = 999_999,
        existingHashes: ProcessHashes? = nil
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: 1,
            rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [executable],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: Date(),
            hashes: existingHashes
        )
    }

    @Test("exec event gets SHA-256 populated by injected ProcessHasher")
    func execEventHashes() async throws {
        let path = try makeTempFile(bytes: "hello".data(using: .utf8)!)
        defer { cleanup(path) }

        let plane = deferredPlane()
        let enricher = EventEnricher(
            processHasher: ProcessHasher(),
            heavyEnrichmentPlane: plane
        )
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(executable: path)
        )

        let enriched = await applyingHashPatch(from: enricher, to: event)
        #expect(enriched.process.hashes?.sha256 ==
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        _ = await enricher.shutdownHeavyEnrichment()
    }

    @Test("file event is NOT hashed (avoids re-hash on every I/O)")
    func fileEventNotHashed() async throws {
        let path = try makeTempFile(bytes: "abc".data(using: .utf8)!)
        defer { cleanup(path) }

        let enricher = EventEnricher(processHasher: ProcessHasher())
        let event = Event(
            eventCategory: .file,
            eventType: .change,
            eventAction: "write",
            process: makeProcess(executable: path),
            file: FileInfo(
                path: "/tmp/other",
                name: "other",
                directory: "/tmp",
                extension_: nil,
                size: 10,
                action: .write
            )
        )

        let enriched = await enricher.enrich(event)
        #expect(enriched.process.hashes == nil)
    }

    @Test("Existing collector-provided hashes are preserved, not overwritten")
    func preservesExistingHashes() async throws {
        let path = try makeTempFile(bytes: "fresh".data(using: .utf8)!)
        defer { cleanup(path) }

        let existing = ProcessHashes(sha256: "existing-sha", cdhash: "existing-cdhash", md5: nil)
        let enricher = EventEnricher(processHasher: ProcessHasher())
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(executable: path, existingHashes: existing)
        )

        let enriched = await enricher.enrich(event)
        #expect(enriched.process.hashes?.sha256 == "existing-sha")
        #expect(enriched.process.hashes?.cdhash == "existing-cdhash")
    }

    @Test("No ProcessHasher injected → hashes remain nil")
    func noHasherInjected() async throws {
        let path = try makeTempFile(bytes: "x".data(using: .utf8)!)
        defer { cleanup(path) }

        let enricher = EventEnricher()  // no processHasher
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(executable: path)
        )

        let enriched = await enricher.enrich(event)
        #expect(enriched.process.hashes == nil)
    }

    @Test("fork event also triggers hashing")
    func forkEventHashes() async throws {
        let path = try makeTempFile(bytes: "fork-me".data(using: .utf8)!)
        defer { cleanup(path) }

        let plane = deferredPlane()
        let enricher = EventEnricher(
            processHasher: ProcessHasher(),
            heavyEnrichmentPlane: plane
        )
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "fork",
            process: makeProcess(executable: path)
        )

        let enriched = await applyingHashPatch(from: enricher, to: event)
        #expect(enriched.process.hashes?.sha256 != nil)
        _ = await enricher.shutdownHeavyEnrichment()
    }
}
