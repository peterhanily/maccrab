import Foundation
import Testing
@testable import MacCrabCore

@Suite("Bounded legacy EventStore upgrade allowance")
struct EventStoreLegacyUpgradeEnvelopeTests {
    private struct Fixture {
        let directory: URL
        var path: String { directory.appendingPathComponent("events.db").path }
        var receiptURL: URL {
            URL(fileURLWithPath: EventStoreLegacyUpgradeEnvelope.receiptPath(for: path))
        }
        var policy: SQLitePersistentStorePolicy {
            SQLitePersistentStorePolicy(
                maxFootprintBytes: 16_384, freeSpaceFloorBytes: 0,
                transactionReserveBytes: 4_096, storageVolumePath: directory.path
            )
        }
    }

    // The envelope measures and identifies regular files before SQLite schema
    // work. Small private family members exercise that boundary directly;
    // actual predecessor schema/recovery is covered by the upgrade suite.
    private func fixture() throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("event-upgrade-envelope-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fixture = Fixture(directory: directory)
        try Data(repeating: 0, count: 8_192).write(to: URL(fileURLWithPath: fixture.path))
        try Data(repeating: 0, count: 4_096).write(to: URL(fileURLWithPath: fixture.path + "-wal"))
        return fixture
    }

    private func expectRefusal(_ operation: () throws -> Void) throws {
        do {
            try operation()
            Issue.record("Unsafe legacy upgrade allowance was accepted")
        } catch let error as EventStoreError {
            guard case .storageNotReady = error else { throw error }
        }
    }

    @Test("Retries and finalized reopens keep one fixed allowance; exhaustion requires an explicit cap increase")
    func fixedAllowanceCannotRatchet() throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let (effective, rawReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        let receipt = try #require(rawReceipt)
        // Main + WAL, plus checkpoint duplication of the WAL, plus two
        // transaction reserves. The disk floor and transaction size do not grow.
        #expect(effective.maxFootprintBytes == 24_576)
        #expect(effective.freeSpaceFloorBytes == fixture.policy.freeSpaceFloorBytes)
        #expect(effective.transactionReserveBytes == fixture.policy.transactionReserveBytes)
        let fixedBytes = try Data(contentsOf: fixture.receiptURL)

        let writer = try FileHandle(forWritingTo: URL(fileURLWithPath: fixture.path))
        defer { try? writer.close() }
        try writer.seekToEnd()
        try writer.write(contentsOf: Data(repeating: 0, count: 4_096))
        for needsUpgrade in [true, false, true] {
            let (retryPolicy, retryReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: needsUpgrade
            )
            #expect(retryPolicy == effective)
            #expect(retryReceipt == receipt)
            #expect(try Data(contentsOf: fixture.receiptURL) == fixedBytes)
        }

        try writer.write(contentsOf: Data(repeating: 0, count: 8_193))
        try expectRefusal {
            _ = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
            )
        }
        #expect(try Data(contentsOf: fixture.receiptURL) == fixedBytes)
        let explicitlyRaised = SQLitePersistentStorePolicy(
            maxFootprintBytes: 32_768, freeSpaceFloorBytes: fixture.policy.freeSpaceFloorBytes,
            transactionReserveBytes: fixture.policy.transactionReserveBytes,
            storageVolumePath: fixture.directory.path
        )
        let (raised, sameReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: explicitlyRaised, needsJournalUpgrade: true
        )
        #expect(raised == explicitlyRaised)
        #expect(sameReceipt == receipt)
        #expect(try Data(contentsOf: fixture.receiptURL) == fixedBytes)
    }

    private enum InvalidReceipt: String, CaseIterable, Sendable {
        case malformed, symlink, hardlink, overflow
    }

    @Test("Malformed, linked and overflowing receipts cannot grant a transition allowance",
          arguments: InvalidReceipt.allCases)
    private func invalidReceiptIsRefused(kind: InvalidReceipt) throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        _ = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        switch kind {
        case .malformed:
            try Data("{broken".utf8).write(to: fixture.receiptURL)
        case .symlink:
            let target = fixture.directory.appendingPathComponent("receipt-target.json")
            try FileManager.default.moveItem(at: fixture.receiptURL, to: target)
            try FileManager.default.createSymbolicLink(at: fixture.receiptURL, withDestinationURL: target)
        case .hardlink:
            try FileManager.default.linkItem(
                at: fixture.receiptURL,
                to: fixture.directory.appendingPathComponent("receipt-alias.json")
            )
        case .overflow:
            var object = try #require(try JSONSerialization.jsonObject(
                with: Data(contentsOf: fixture.receiptURL)
            ) as? [String: Any])
            object["inheritedFamilyBytes"] = Int64.max
            object["ceilingBytes"] = Int64.max
            try JSONSerialization.data(withJSONObject: object).write(to: fixture.receiptURL)
        }
        try expectRefusal {
            _ = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
            )
        }
    }

    @Test("A receipt for a replaced database grants neither its old allowance nor a newly measured one")
    func replacedDatabaseHasNoAllowance() throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        _ = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        let originalReceipt = try Data(contentsOf: fixture.receiptURL)
        let main = URL(fileURLWithPath: fixture.path)
        try FileManager.default.moveItem(at: main, to: fixture.directory.appendingPathComponent("original.db"))
        try Data(repeating: 0, count: 20_000).write(to: main)
        let (effective, receipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        #expect(effective == fixture.policy)
        #expect(receipt == nil)
        #expect(try Data(contentsOf: fixture.receiptURL) == originalReceipt)
    }

    @Test("A completed receipt retires headroom and refuses a newly incomplete transition")
    func completedReceiptCannotRearm() throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let (_, receipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        try EventStoreLegacyUpgradeEnvelope.complete(path: fixture.path, receipt: #require(receipt))
        let completed = try #require(try EventStoreLegacyUpgradeEnvelope.read(for: fixture.path))
        #expect(completed.completed)
        let completedBytes = try Data(contentsOf: fixture.receiptURL)
        let (effective, activeReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: false
        )
        #expect(effective == fixture.policy)
        #expect(activeReceipt == nil)
        try expectRefusal {
            _ = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
            )
        }
        #expect(try Data(contentsOf: fixture.receiptURL) == completedBytes)
    }

    @Test("An overflowing initial allowance is refused before its receipt is published")
    func overflowingAllowanceIsNotPublished() throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let overflowingPolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: Int64.max, freeSpaceFloorBytes: 0,
            transactionReserveBytes: Int64.max / 2 + 1,
            storageVolumePath: fixture.directory.path
        )
        try expectRefusal {
            _ = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: overflowingPolicy, needsJournalUpgrade: true
            )
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.receiptURL.path))
    }
}
