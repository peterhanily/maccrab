// CorruptDBBackup.swift
// MacCrabCore
//
// Shared corruption-quarantine helper: move a corrupt SQLite database (plus
// its -wal / -shm / -journal sidecars) aside to timestamped `.corrupt-<ts>`
// siblings, and keep only the N most-recent corruption events per database.
//
// Extracted so that BOTH corruption-recovery paths share one naming scheme
// and one bounded retention budget:
//   - init-time recovery in `MacCrabAgentKit/DaemonSetup` (C-03), and
//   - the mid-run self-heal in `EventStore` (C-04).
// Because they emit the identical `<base>*.corrupt-<ts>` name shape, either
// path's prune sweep bounds the other path's backups too.

import Foundation

public enum CorruptDBFamilyMember: String, CaseIterable, Sendable {
    case database = ""
    case wal = "-wal"
    case shm = "-shm"
    case journal = "-journal"
}

public enum CorruptDBMovePhase: Sendable, Equatable {
    case quarantine
    case rollback
}

public struct CorruptDBMove: Sendable, Equatable {
    public let member: CorruptDBFamilyMember
    public let source: String
    public let destination: String

    public init(member: CorruptDBFamilyMember, source: String, destination: String) {
        self.member = member
        self.source = source
        self.destination = destination
    }
}

public struct CorruptDBBackupResult: Sendable, Equatable {
    public let timestamp: Int
    public let moves: [CorruptDBMove]
}

public enum CorruptDBBackupError: Error, LocalizedError {
    case noDatabaseFamily(String)
    case destinationExists(String)
    case moveFailed(
        failed: CorruptDBMove,
        message: String,
        rolledBack: [CorruptDBMove],
        rollbackFailures: [String]
    )

    public var errorDescription: String? {
        switch self {
        case .noDatabaseFamily(let path):
            return "No SQLite database family exists at \(path)"
        case .destinationExists(let path):
            return "Refusing to overwrite existing corruption evidence at \(path)"
        case let .moveFailed(failed, message, _, rollbackFailures):
            let rollback = rollbackFailures.isEmpty
                ? "all prior moves rolled back"
                : "rollback failures: \(rollbackFailures.joined(separator: "; "))"
            return "Failed to quarantine \(failed.source) to \(failed.destination): \(message) (\(rollback))"
        }
    }
}

public enum CorruptDBBackup {

    /// How many distinct corruption events to retain per database. Each event
    /// drops up to four sibling files (db + -wal / -shm / -journal), all sharing
    /// one `corrupt-<unix-ts>` stamp; we keep the newest `N` stamps' worth.
    public static let defaultRetention = 3

    /// A move hook used by tests to fail each member and verify rollback.  The
    /// default is `FileManager.moveItem`, which is a same-directory rename for
    /// every member emitted by this helper.
    public typealias MoveOperation = @Sendable (
        _ move: CorruptDBMove,
        _ phase: CorruptDBMovePhase
    ) throws -> Void

    /// Atomically-at-the-family-level move `base` and every present SQLite
    /// sidecar to `.corrupt-<unix-ts>` siblings. If any move fails, every prior
    /// move is rolled back in reverse order. No source is deleted and pruning
    /// occurs only after the complete family has been quarantined.
    ///
    /// `timestamp` and `moveOperation` are injectable for exhaustive failure
    /// tests. Production callers should use their defaults.
    @discardableResult
    public static func quarantineAtomically(
        directory: String,
        base: String,
        keep: Int = defaultRetention,
        timestamp requestedTimestamp: Int? = nil,
        moveOperation: MoveOperation? = nil
    ) throws -> CorruptDBBackupResult {
        let fm = FileManager.default
        let operation: MoveOperation = moveOperation ?? { move, _ in
            try FileManager.default.moveItem(
                atPath: move.source,
                toPath: move.destination
            )
        }
        let present = CorruptDBFamilyMember.allCases.compactMap { member -> (CorruptDBFamilyMember, String)? in
            let source = "\(directory)/\(base)\(member.rawValue)"
            guard fm.fileExists(atPath: source) else { return nil }
            return (member, source)
        }
        guard !present.isEmpty else {
            throw CorruptDBBackupError.noDatabaseFamily("\(directory)/\(base)")
        }

        func makeMoves(for timestamp: Int) -> [CorruptDBMove] {
            present.map { member, source in
                CorruptDBMove(
                    member: member,
                    source: source,
                    destination: "\(source).corrupt-\(timestamp)"
                )
            }
        }

        var timestamp = requestedTimestamp ?? Int(Date().timeIntervalSince1970)
        var moves = makeMoves(for: timestamp)
        if requestedTimestamp == nil {
            // Multiple bounded heals can happen within one wall-clock second.
            // Pick the next free integer stamp rather than overwriting or
            // refusing because an earlier evidence family has that timestamp.
            while moves.contains(where: { fm.fileExists(atPath: $0.destination) }) {
                timestamp += 1
                moves = makeMoves(for: timestamp)
            }
        } else if let collision = moves.first(where: {
            fm.fileExists(atPath: $0.destination)
        }) {
            throw CorruptDBBackupError.destinationExists(collision.destination)
        }

        var completed: [CorruptDBMove] = []
        for move in moves {
            do {
                try operation(move, .quarantine)
                completed.append(move)
            } catch {
                var rolledBack: [CorruptDBMove] = []
                var rollbackFailures: [String] = []
                for prior in completed.reversed() {
                    let reverse = CorruptDBMove(
                        member: prior.member,
                        source: prior.destination,
                        destination: prior.source
                    )
                    do {
                        try operation(reverse, .rollback)
                        rolledBack.append(prior)
                    } catch {
                        rollbackFailures.append(
                            "\(prior.destination) -> \(prior.source): \(error.localizedDescription)"
                        )
                    }
                }
                throw CorruptDBBackupError.moveFailed(
                    failed: move,
                    message: error.localizedDescription,
                    rolledBack: rolledBack,
                    rollbackFailures: rollbackFailures
                )
            }
        }
        prune(directory: directory, base: base, keep: keep)
        return CorruptDBBackupResult(timestamp: timestamp, moves: moves)
    }

    /// Compatibility shim for the existing daemon recovery call site. New
    /// recovery code must use `quarantineAtomically` and handle failure before
    /// attempting to create a fresh database. This shim keeps that separate
    /// cross-target migration buildable until DaemonSetup is updated.
    @available(*, deprecated, message: "Use quarantineAtomically and handle errors")
    @discardableResult
    public static func backup(
        directory: String,
        base: String,
        keep: Int = defaultRetention
    ) -> Int {
        let timestamp = Int(Date().timeIntervalSince1970)
        _ = try? quarantineAtomically(
            directory: directory,
            base: base,
            keep: keep,
            timestamp: timestamp
        )
        return timestamp
    }

    /// Keep the `keep` most-recent corruption events (grouped by timestamp) for
    /// `base`; delete every older file. Mirrors the count-based prune idiom the
    /// stores use (`pruneOldest(count:)`).
    ///
    /// Safe for the privileged system dir: it only ever `removeItem`s an entry
    /// whose name matches a stamp we generated, and `removeItem` unlinks the
    /// entry itself (it never follows a symlinked final component). We also skip
    /// any matched entry that is itself a symlink, matching the quarantine
    /// path's refuse-on-symlink stance.
    public static func prune(
        directory: String,
        base: String,
        keep: Int = defaultRetention
    ) {
        let fm = FileManager.default
        guard keep >= 0,
              let entries = try? fm.contentsOfDirectory(atPath: directory) else { return }
        // Names come in two shapes, both starting with `base`:
        //   events.db-wal.corrupt-<ts>          (backup, above)
        //   tracegraph.db.corrupt-<ts>-wal      (openCausalStore quarantine)
        // so parse the leading run of digits after `.corrupt-` to recover <ts>.
        var stamped: [(name: String, ts: Int)] = []
        for name in entries {
            guard name.hasPrefix(base), let r = name.range(of: ".corrupt-") else { continue }
            let digits = String(name[r.upperBound...].prefix { $0.isNumber })
            guard let ts = Int(digits) else { continue }
            stamped.append((name, ts))
        }
        // Dedupe to distinct corruption events BEFORE taking the newest `keep`,
        // so a stamp's sidecars don't each count against the retention budget.
        let distinctStamps = Set(stamped.map { $0.ts }).sorted(by: >)
        let keepStamps = Set(distinctStamps.prefix(keep))
        for entry in stamped where !keepStamps.contains(entry.ts) {
            let path = "\(directory)/\(entry.name)"
            let isSymlink = (try? URL(fileURLWithPath: path)
                .resourceValues(forKeys: [.isSymbolicLinkKey]))?.isSymbolicLink == true
            if isSymlink { continue }
            try? fm.removeItem(atPath: path)
        }
    }
}
