import Testing
import Foundation
@testable import MacCrabCore

@Suite("SQLite store open failures preserve evidence")
struct SQLiteStoreOpenFailureTests {
    private func makeDirectory(base: String) throws -> (URL, Data) {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-open-failure-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let evidence = Data("not a sqlite database; retain this forensic evidence".utf8)
        try evidence.write(to: directory.appendingPathComponent(base))
        return (directory, evidence)
    }

    private func assertExplicitCorruption(
        _ error: Error,
        directory: URL,
        base: String,
        evidence: Data
    ) throws {
        let details = SQLiteFailureClassifier.details(from: error)
        #expect(details != nil)
        #expect(details?.isExplicitCorruption == true)
        #expect(SQLiteFailureClassifier.disposition(for: error)
            == .quarantineExplicitCorruption)

        // Classification alone is read-only. Core open must not move or
        // recreate anything; the recovery owner performs atomic quarantine
        // only after inspecting these exact result codes.
        #expect(try Data(contentsOf: directory.appendingPathComponent(base)) == evidence)
        let entries = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(!entries.contains { $0.contains(".corrupt-") })
    }

    @Test("EventStore returns typed NOTADB/CORRUPT metadata without moving the file")
    func eventStorePreservesCorruptFile() throws {
        let (directory, evidence) = try makeDirectory(base: "events.db")
        defer { try? FileManager.default.removeItem(at: directory) }

        do {
            _ = try EventStore(directory: directory.path)
            Issue.record("EventStore unexpectedly opened a non-SQLite database")
        } catch {
            try assertExplicitCorruption(
                error,
                directory: directory,
                base: "events.db",
                evidence: evidence
            )
        }
    }

    @Test("AlertStore returns typed NOTADB/CORRUPT metadata without moving the file")
    func alertStorePreservesCorruptFile() throws {
        let (directory, evidence) = try makeDirectory(base: "alerts.db")
        defer { try? FileManager.default.removeItem(at: directory) }

        do {
            _ = try AlertStore(directory: directory.path)
            Issue.record("AlertStore unexpectedly opened a non-SQLite database")
        } catch {
            try assertExplicitCorruption(
                error,
                directory: directory,
                base: "alerts.db",
                evidence: evidence
            )
        }
    }
}
