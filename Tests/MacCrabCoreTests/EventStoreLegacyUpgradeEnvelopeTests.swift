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

    private func rewriteReceipt(
        _ fixture: Fixture, change: (inout [String: Any]) throws -> Void
    ) throws {
        var object = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: fixture.receiptURL)
        ) as? [String: Any])
        try change(&object)
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            .write(to: fixture.receiptURL)
    }

    // Only the persisted mount number changes. The real file, its inode,
    // birth time and volume remain intact, as they do across a remount.
    private func recordPreviousBootDevice(_ fixture: Fixture) throws {
        try rewriteReceipt(fixture) { object in
            let device = try #require(object["databaseDevice"] as? NSNumber)
            object["databaseDevice"] = device.uint64Value ^ 1
        }
    }

    @Test("A changed mount device number preserves pending headroom and completion without remeasuring")
    func pendingReceiptSurvivesRebootDeviceChange() throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let (initialPolicy, initialReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        let original = try #require(initialReceipt)
        try recordPreviousBootDevice(fixture)
        let previousBootReceipt = try #require(try EventStoreLegacyUpgradeEnvelope.read(for: fixture.path))
        #expect(previousBootReceipt.databaseDevice != original.databaseDevice)
        let fixedBytes = try Data(contentsOf: fixture.receiptURL)

        let writer = try FileHandle(forWritingTo: URL(fileURLWithPath: fixture.path))
        try writer.seekToEnd()
        try writer.write(contentsOf: Data(repeating: 0, count: 8_192))
        try writer.close()
        // The family now exceeds the ordinary cap. A fresh measurement would
        // grant 32 KiB, while the already-published allowance remains 24 KiB.
        #expect(try SQLitePersistentStoreAdmission.measureFamily(fixture.path) > fixture.policy.maxFootprintBytes)
        for needsUpgrade in [true, false, true] {
            let (effective, activeReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: needsUpgrade
            )
            #expect(effective == initialPolicy)
            #expect(activeReceipt == previousBootReceipt)
            #expect(effective.maxFootprintBytes == 24_576)
            #expect(try Data(contentsOf: fixture.receiptURL) == fixedBytes)
        }
        try EventStoreLegacyUpgradeEnvelope.complete(path: fixture.path, receipt: previousBootReceipt)
        let completed = try #require(try EventStoreLegacyUpgradeEnvelope.read(for: fixture.path))
        var expected = previousBootReceipt
        expected.completed = true
        #expect(completed == expected)
        let (ordinary, noAllowance) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: false
        )
        #expect(ordinary == fixture.policy)
        #expect(noAllowance == nil)
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
        case missingVolumeUUID, malformedVolumeUUID, noncanonicalVolumeUUID, unknownSchema
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
        case .missingVolumeUUID:
            try rewriteReceipt(fixture) { $0.removeValue(forKey: "databaseVolumeUUID") }
        case .malformedVolumeUUID:
            try rewriteReceipt(fixture) { $0["databaseVolumeUUID"] = "not-a-volume-uuid" }
        case .noncanonicalVolumeUUID:
            try rewriteReceipt(fixture) {
                $0["databaseVolumeUUID"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            }
        case .unknownSchema:
            try rewriteReceipt(fixture) { $0["schemaVersion"] = 3 }
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

    private enum DifferentDatabaseIdentity: String, CaseIterable, Sendable {
        case volume, inode, birthSeconds, birthNanoseconds
    }

    @Test("A receipt from another volume, inode or birth identity grants no allowance and cannot complete",
          arguments: DifferentDatabaseIdentity.allCases)
    private func differentStableIdentityHasNoAllowance(kind: DifferentDatabaseIdentity) throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        _ = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        try rewriteReceipt(fixture) { object in
            #expect(object["schemaVersion"] as? Int == 2)
            switch kind {
            case .volume:
                let original = try #require(object["databaseVolumeUUID"] as? String)
                let replacement = UUID().uuidString
                try #require(original != replacement)
                object["databaseVolumeUUID"] = replacement
            case .inode:
                let original = try #require(object["databaseInode"] as? NSNumber)
                object["databaseInode"] = original.uint64Value ^ 1
            case .birthSeconds:
                let original = try #require(object["databaseBirthSeconds"] as? NSNumber)
                object["databaseBirthSeconds"] = original.int64Value + 1
            case .birthNanoseconds:
                let original = try #require(object["databaseBirthNanoseconds"] as? NSNumber)
                object["databaseBirthNanoseconds"] = (original.int64Value + 1) % 1_000_000_000
            }
        }
        let mismatched = try #require(try EventStoreLegacyUpgradeEnvelope.read(for: fixture.path))
        let saved = try Data(contentsOf: fixture.receiptURL)
        for needsUpgrade in [true, false] {
            let (effective, receipt) = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: needsUpgrade
            )
            #expect(effective == fixture.policy)
            #expect(receipt == nil)
            #expect(try Data(contentsOf: fixture.receiptURL) == saved)
        }
        try expectRefusal {
            try EventStoreLegacyUpgradeEnvelope.complete(path: fixture.path, receipt: mismatched)
        }
        #expect(try Data(contentsOf: fixture.receiptURL) == saved)
    }

    @Test("Completed v2 tombstones stay retired after the mount device number changes")
    func completedTombstoneSurvivesRebootDeviceChange() throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let (_, rawReceipt) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        try EventStoreLegacyUpgradeEnvelope.complete(path: fixture.path, receipt: #require(rawReceipt))
        try recordPreviousBootDevice(fixture)
        let completed = try #require(try EventStoreLegacyUpgradeEnvelope.read(for: fixture.path))
        #expect(completed.schemaVersion == 2)
        #expect(completed.completed)
        let saved = try Data(contentsOf: fixture.receiptURL)
        let (ordinary, active) = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: false
        )
        #expect(ordinary == fixture.policy)
        #expect(active == nil)
        try expectRefusal {
            _ = try EventStoreLegacyUpgradeEnvelope.establish(
                path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
            )
        }
        #expect(try Data(contentsOf: fixture.receiptURL) == saved)
    }

    @Test("Version-one pending receipts fail closed; finalized tombstones keep ordinary policy",
          arguments: [false, true])
    func legacyVersionOneReceiptCannotRegainHeadroom(completed: Bool) throws {
        let fixture = try fixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        _ = try EventStoreLegacyUpgradeEnvelope.establish(
            path: fixture.path, configured: fixture.policy, needsJournalUpgrade: true
        )
        try rewriteReceipt(fixture) { object in
            object["schemaVersion"] = 1
            object.removeValue(forKey: "databaseVolumeUUID")
            object["completed"] = completed
            let device = try #require(object["databaseDevice"] as? NSNumber)
            object["databaseDevice"] = device.uint64Value ^ 1
        }
        let legacy = try #require(try EventStoreLegacyUpgradeEnvelope.read(for: fixture.path))
        #expect(legacy.schemaVersion == 1)
        let saved = try Data(contentsOf: fixture.receiptURL)
        for needsUpgrade in [false, true] {
            if completed && !needsUpgrade {
                let (ordinary, active) = try EventStoreLegacyUpgradeEnvelope.establish(
                    path: fixture.path, configured: fixture.policy, needsJournalUpgrade: needsUpgrade
                )
                #expect(ordinary == fixture.policy)
                #expect(active == nil)
            } else {
                try expectRefusal {
                    _ = try EventStoreLegacyUpgradeEnvelope.establish(
                        path: fixture.path, configured: fixture.policy, needsJournalUpgrade: needsUpgrade
                    )
                }
            }
            #expect(try Data(contentsOf: fixture.receiptURL) == saved)
        }
        if !completed {
            try expectRefusal {
                try EventStoreLegacyUpgradeEnvelope.complete(path: fixture.path, receipt: legacy)
            }
        }
        #expect(try Data(contentsOf: fixture.receiptURL) == saved)
    }
}
