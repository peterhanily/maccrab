import Foundation
import Darwin

/// A one-time, fixed allowance for converting an inherited event family.
/// The receipt precedes schema mutation and survives through cap convergence;
/// measuring a new allowance on every restart would let a failed upgrade grow
/// without a bound. Ordinary stores and read-only consumers never opt in.
enum EventStoreLegacyUpgradeEnvelope {
    struct Receipt: Codable, Sendable, Equatable {
        let schemaVersion: Int
        // st_dev is a mount-session identifier on macOS, retained only for
        // diagnostics. Persistent matching uses the volume UUID instead.
        let databaseDevice: UInt64
        let databaseVolumeUUID: String?
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

    private struct DatabaseIdentity: Equatable {
        let device: UInt64
        let inode: UInt64
        let birthSeconds: Int64
        let birthNanoseconds: Int64
        var volumeUUID: String?
    }

    private static func fileIdentity(_ path: String) throws -> DatabaseIdentity {
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
        return DatabaseIdentity(
            device: snapshot.deviceID, inode: snapshot.inodeNumber,
            birthSeconds: Int64(metadata.st_birthtimespec.tv_sec),
            birthNanoseconds: Int64(metadata.st_birthtimespec.tv_nsec)
        )
    }

    private static func identity(
        _ path: String, resolveVolumeUUID: Bool
    ) throws -> DatabaseIdentity {
        let before = try fileIdentity(path)
        guard resolveVolumeUUID else { return before }
        // Foundation documents volumeUUIDString as persistent across launches;
        // volumeIdentifier and stat.st_dev are not persistent volume identities.
        // The lookup uses a fresh URL, and anchored no-follow reads plus stat
        // checks bind the same database incarnation on both sides of it.
        let resourceValues: URLResourceValues
        do {
            resourceValues = try URL(fileURLWithPath: path).resourceValues(
                forKeys: [.volumeUUIDStringKey]
            )
        } catch { throw failure("cannot establish a persistent database volume identity") }
        guard let rawUUID = resourceValues.volumeUUIDString,
              let volumeUUID = UUID(uuidString: rawUUID)?.uuidString else {
            throw failure("the database volume has no persistent UUID for its fixed transition allowance")
        }
        guard try fileIdentity(path) == before else {
            throw failure("database identity or ownership changed during volume lookup")
        }
        var result = before
        result.volumeUUID = volumeUUID
        return result
    }

    private static func matches(_ receipt: Receipt, _ identity: DatabaseIdentity) -> Bool {
        receipt.schemaVersion == 2
            && receipt.databaseVolumeUUID != nil
            && receipt.databaseVolumeUUID == identity.volumeUUID
            && receipt.databaseInode == identity.inode
            && receipt.databaseBirthSeconds == identity.birthSeconds
            && receipt.databaseBirthNanoseconds == identity.birthNanoseconds
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
            let identitySchemaIsValid: Bool
            switch receipt.schemaVersion {
            case 1:
                identitySchemaIsValid = receipt.databaseVolumeUUID == nil
            case 2:
                if let volumeUUID = receipt.databaseVolumeUUID {
                    identitySchemaIsValid = UUID(uuidString: volumeUUID)?.uuidString == volumeUUID
                } else {
                    identitySchemaIsValid = false
                }
            default:
                identitySchemaIsValid = false
            }
            guard identitySchemaIsValid,
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
        var receipt = try read(for: path)
        // Ordinary finalized stores still undergo the existing no-follow file
        // identity/owner/link checks, but need no new persistent-volume lookup.
        let needsPersistentIdentity = receipt?.schemaVersion != 1
            && (needsJournalUpgrade || receipt?.completed == false)
        let dbIdentity = try identity(path, resolveVolumeUUID: needsPersistentIdentity)
        if let stored = receipt {
            if stored.schemaVersion == 1 {
                // Unpublished v1 candidates persisted a mount-session device
                // number. A pending v1 allowance cannot be safely rebound to a
                // volume after reboot, and must never trigger a fresh measure.
                guard stored.completed else {
                    throw failure("the pending version-1 transition receipt has no persistent volume identity; its allowance cannot be resumed automatically")
                }
                guard !needsJournalUpgrade else {
                    throw failure("a completed transition has become incomplete")
                }
                return (configured, nil)
            }
            if stored.completed && !needsJournalUpgrade {
                // Preserve the tombstone and use only the ordinary configured
                // cap. No allowance is granted, including for a replaced store.
                return (configured, nil)
            }
            guard matches(stored, dbIdentity) else {
                // Corruption recovery can legitimately move the old family
                // aside and recreate this path. A stale receipt grants the
                // replacement no allowance; its ordinary policy still applies.
                return (configured, nil)
            }
            if stored.completed {
                throw failure("a completed transition has become incomplete")
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
                schemaVersion: 2, databaseDevice: dbIdentity.device,
                databaseVolumeUUID: dbIdentity.volumeUUID,
                databaseInode: dbIdentity.inode, databaseBirthSeconds: dbIdentity.birthSeconds,
                databaseBirthNanoseconds: dbIdentity.birthNanoseconds,
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
        guard let receipt, matches(receipt, dbIdentity), !receipt.completed,
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
        let currentIdentity = try identity(path, resolveVolumeUUID: true)
        guard matches(receipt, currentIdentity) else {
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
