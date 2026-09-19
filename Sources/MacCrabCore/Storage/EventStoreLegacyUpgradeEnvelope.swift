import Foundation
import Darwin

/// A one-time, fixed allowance for converting an inherited event family.
/// The receipt precedes schema mutation and survives through cap convergence;
/// measuring a new allowance on every restart would let a failed upgrade grow
/// without a bound. Ordinary stores and read-only consumers never opt in.
enum EventStoreLegacyUpgradeEnvelope {
    struct Receipt: Codable, Sendable, Equatable {
        let schemaVersion: Int
        let databaseDevice: UInt64
        let databaseInode: UInt64
        let databaseBirthSeconds: Int64
        let databaseBirthNanoseconds: Int64
        let inheritedFamilyBytes: Int64
        let inheritedSidecarBytes: Int64
        let configuredCapBytes: Int64
        let transactionReserveBytes: Int64
        let ceilingBytes: Int64
        var completed: Bool
    }

    static func receiptPath(for path: String) -> String {
        path + ".legacy-upgrade.json"
    }

    private static func failure(_ reason: String) -> EventStoreError {
        .storageNotReady("Legacy event-store upgrade: \(reason). Existing history is preserved; export diagnostics before recovery.")
    }

    private static func identity(_ path: String) throws -> (UInt64, UInt64, Int64, Int64) {
        guard case .success(let snapshot) = BoundedRegularFileReader.readPrefixOutcome(
            at: path, maximumBytes: 0
        ) else { throw failure("cannot establish the database identity") }
        var metadata = stat()
        guard lstat(path, &metadata) == 0,
              UInt64(metadata.st_dev) == snapshot.deviceID,
              UInt64(metadata.st_ino) == snapshot.inodeNumber,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              (metadata.st_mode & S_IFMT) == S_IFREG else {
            throw failure("database identity or ownership changed")
        }
        return (snapshot.deviceID, snapshot.inodeNumber,
                Int64(metadata.st_birthtimespec.tv_sec),
                Int64(metadata.st_birthtimespec.tv_nsec))
    }

    static func read(for path: String) throws -> Receipt? {
        let receiptPath = receiptPath(for: path)
        switch BoundedRegularFileReader.readOutcome(at: receiptPath, maximumBytes: 4_096) {
        case .rejected(.notFound): return nil
        case .rejected:
            throw failure("cannot safely read the fixed transition allowance")
        case .success(let snapshot):
            guard snapshot.ownerUID == geteuid() else {
                throw failure("transition receipt is owned by another user")
            }
            let receipt: Receipt
            do { receipt = try JSONDecoder().decode(Receipt.self, from: snapshot.data) }
            catch { throw failure("transition receipt is invalid") }
            guard receipt.schemaVersion == 1,
                  receipt.inheritedFamilyBytes >= 0,
                  receipt.inheritedSidecarBytes >= 0,
                  receipt.inheritedSidecarBytes <= receipt.inheritedFamilyBytes,
                  receipt.transactionReserveBytes > 0,
                  receipt.configuredCapBytes > receipt.transactionReserveBytes,
                  receipt.ceilingBytes == (try ceiling(
                    configuredCap: receipt.configuredCapBytes,
                    family: receipt.inheritedFamilyBytes,
                    sidecars: receipt.inheritedSidecarBytes,
                    reserve: receipt.transactionReserveBytes
                  )) else { throw failure("transition receipt accounting is invalid") }
            return receipt
        }
    }

    private static func ceiling(
        configuredCap: Int64, family: Int64, sidecars: Int64, reserve: Int64
    ) throws -> Int64 {
        let twiceReserve = reserve.multipliedReportingOverflow(by: 2)
        let checkpointPeak = family.addingReportingOverflow(sidecars)
        let bound = checkpointPeak.partialValue.addingReportingOverflow(twiceReserve.partialValue)
        guard !twiceReserve.overflow, !checkpointPeak.overflow, !bound.overflow else {
            throw failure("transition allowance overflows byte accounting")
        }
        return max(configuredCap, bound.partialValue)
    }

    static func establish(
        path: String,
        configured: SQLitePersistentStorePolicy,
        needsJournalUpgrade: Bool
    ) throws -> (SQLitePersistentStorePolicy, Receipt?) {
        let dbIdentity = try identity(path)
        func matches(_ receipt: Receipt) -> Bool {
            receipt.databaseDevice == dbIdentity.0
                && receipt.databaseInode == dbIdentity.1
                && receipt.databaseBirthSeconds == dbIdentity.2
                && receipt.databaseBirthNanoseconds == dbIdentity.3
        }
        var receipt = try read(for: path)
        if let stored = receipt {
            guard matches(stored) else {
                // Corruption recovery can legitimately move the old family
                // aside and recreate this path. A stale receipt grants the
                // replacement no allowance; its ordinary policy still applies.
                return (configured, nil)
            }
            if stored.completed {
                guard !needsJournalUpgrade else {
                    throw failure("a completed transition has become incomplete")
                }
                return (configured, nil)
            }
        } else {
            guard needsJournalUpgrade else { return (configured, nil) }
            let family = try SQLitePersistentStoreAdmission.measureFamily(path)
            let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
            guard family >= main else { throw failure("family measurement is inconsistent") }
            let cap = try ceiling(
                configuredCap: configured.maxFootprintBytes, family: family,
                sidecars: family - main, reserve: configured.transactionReserveBytes
            )
            let created = Receipt(
                schemaVersion: 1, databaseDevice: dbIdentity.0,
                databaseInode: dbIdentity.1, databaseBirthSeconds: dbIdentity.2,
                databaseBirthNanoseconds: dbIdentity.3,
                inheritedFamilyBytes: family, inheritedSidecarBytes: family - main,
                configuredCapBytes: configured.maxFootprintBytes,
                transactionReserveBytes: configured.transactionReserveBytes,
                ceilingBytes: cap, completed: false
            )
            // Prove the unchanged disk floor and checkpoint scratch before
            // publishing permission for any schema mutation.
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: path, policy: policy(configured, ceiling: cap)
            )
            try admission.admitCheckpoint()
            do {
                try SecureFileIO.atomicCreate(
                    at: receiptPath(for: path), data: try JSONEncoder().encode(created), mode: 0o600
                )
                receipt = created
            } catch SecureFileIO.Error.fileAlreadyExists {
                // Another bootstrap won exclusive publication. Its immutable
                // allowance governs both connections, never our new measure.
                receipt = try read(for: path)
            }
        }
        guard let receipt, matches(receipt), !receipt.completed,
              receipt.transactionReserveBytes == configured.transactionReserveBytes else {
            throw failure("transition receipt changed during bootstrap")
        }
        let effective = policy(configured, ceiling: receipt.ceilingBytes)
        let family = try SQLitePersistentStoreAdmission.measureFamily(path)
        guard family <= effective.maxFootprintBytes else {
            throw failure("the fixed \(effective.maxFootprintBytes)-byte upgrade allowance is exhausted (family \(family) bytes); increase the events storage limit before retrying")
        }
        return (effective, receipt)
    }

    private static func policy(
        _ configured: SQLitePersistentStorePolicy, ceiling: Int64
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            // An explicit later preference increase is authorized; a restart
            // by itself can never increase the receipt's ceiling.
            maxFootprintBytes: max(configured.maxFootprintBytes, ceiling),
            freeSpaceFloorBytes: configured.freeSpaceFloorBytes,
            transactionReserveBytes: configured.transactionReserveBytes,
            storageVolumePath: configured.storageVolumePath
        )
    }

    static func complete(path: String, receipt: Receipt) throws {
        guard try read(for: path) == receipt else {
            throw failure("transition receipt changed before completion")
        }
        let currentIdentity = try identity(path)
        guard receipt.databaseDevice == currentIdentity.0,
              receipt.databaseInode == currentIdentity.1,
              receipt.databaseBirthSeconds == currentIdentity.2,
              receipt.databaseBirthNanoseconds == currentIdentity.3 else {
            throw failure("database was replaced before transition completion")
        }
        var completed = receipt
        completed.completed = true
        // Keep a small completed tombstone: deleting the only receipt would
        // let an interrupted/malformed transition silently get a fresh budget.
        try SecureFileIO.atomicReplace(
            at: receiptPath(for: path), data: try JSONEncoder().encode(completed), mode: 0o600
        )
    }
}
