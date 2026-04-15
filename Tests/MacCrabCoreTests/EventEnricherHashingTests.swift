// EventEnricherHashingTests.swift
// Proves EventEnricher wires a ProcessHasher through on exec/fork events
// and leaves other event types alone.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventEnricher hashing")
struct EventEnricherHashingTests {

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

        let enricher = EventEnricher(processHasher: ProcessHasher())
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(executable: path)
        )

        let enriched = await enricher.enrich(event)
        #expect(enriched.process.hashes?.sha256 ==
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
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

        let enricher = EventEnricher(processHasher: ProcessHasher())
        let event = Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "fork",
            process: makeProcess(executable: path)
        )

        let enriched = await enricher.enrich(event)
        #expect(enriched.process.hashes?.sha256 != nil)
    }
}
