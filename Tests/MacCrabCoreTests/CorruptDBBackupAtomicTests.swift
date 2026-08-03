import Testing
import Foundation
@testable import MacCrabCore

@Suite("Atomic SQLite database-family quarantine")
struct CorruptDBBackupAtomicTests {
    private struct InjectedMoveFailure: Error {}

    private func makeFamily() throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-corrupt-family-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        for member in CorruptDBFamilyMember.allCases {
            try Data("evidence:\(member.rawValue)".utf8).write(
                to: directory.appendingPathComponent("evidence.db\(member.rawValue)")
            )
        }
        return directory
    }

    private func assertOriginalFamilyIntact(_ directory: URL) throws {
        for member in CorruptDBFamilyMember.allCases {
            let source = directory.appendingPathComponent(
                "evidence.db\(member.rawValue)"
            )
            #expect(FileManager.default.fileExists(atPath: source.path))
            #expect(try Data(contentsOf: source) == Data("evidence:\(member.rawValue)".utf8))
        }
        let entries = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(!entries.contains { $0.contains(".corrupt-") })
    }

    @Test("failure at every family member rolls all earlier moves back")
    func everyForwardMoveFailureRollsBack() throws {
        for failedMember in CorruptDBFamilyMember.allCases {
            let directory = try makeFamily()
            defer { try? FileManager.default.removeItem(at: directory) }

            #expect(throws: CorruptDBBackupError.self) {
                try CorruptDBBackup.quarantineAtomically(
                    directory: directory.path,
                    base: "evidence.db",
                    timestamp: 1_700_000_000,
                    moveOperation: { move, phase in
                        if phase == .quarantine && move.member == failedMember {
                            throw InjectedMoveFailure()
                        }
                        try FileManager.default.moveItem(
                            atPath: move.source,
                            toPath: move.destination
                        )
                    }
                )
            }
            try assertOriginalFamilyIntact(directory)
        }
    }

    @Test("successful quarantine moves every member under one stamp")
    func successMovesWholeFamily() throws {
        let directory = try makeFamily()
        defer { try? FileManager.default.removeItem(at: directory) }
        let stamp = 1_700_000_001

        let result = try CorruptDBBackup.quarantineAtomically(
            directory: directory.path,
            base: "evidence.db",
            timestamp: stamp
        )

        #expect(result.moves.count == CorruptDBFamilyMember.allCases.count)
        for member in CorruptDBFamilyMember.allCases {
            let source = directory.appendingPathComponent(
                "evidence.db\(member.rawValue)"
            )
            let destination = URL(fileURLWithPath: source.path + ".corrupt-\(stamp)")
            #expect(!FileManager.default.fileExists(atPath: source.path))
            #expect(try Data(contentsOf: destination) == Data("evidence:\(member.rawValue)".utf8))
        }
    }

    @Test("destination collision preserves the complete original family")
    func collisionPreservesEvidence() throws {
        let directory = try makeFamily()
        defer { try? FileManager.default.removeItem(at: directory) }
        let stamp = 1_700_000_002
        let collision = directory.appendingPathComponent(
            "evidence.db-wal.corrupt-\(stamp)"
        )
        try Data("older evidence".utf8).write(to: collision)

        #expect(throws: CorruptDBBackupError.self) {
            try CorruptDBBackup.quarantineAtomically(
                directory: directory.path,
                base: "evidence.db",
                timestamp: stamp
            )
        }
        for member in CorruptDBFamilyMember.allCases {
            #expect(FileManager.default.fileExists(
                atPath: directory.appendingPathComponent(
                    "evidence.db\(member.rawValue)"
                ).path
            ))
        }
        #expect(try Data(contentsOf: collision) == Data("older evidence".utf8))
    }
}
