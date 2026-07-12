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

public enum CorruptDBBackup {

    /// How many distinct corruption events to retain per database. Each event
    /// drops up to four sibling files (db + -wal / -shm / -journal), all sharing
    /// one `corrupt-<unix-ts>` stamp; we keep the newest `N` stamps' worth.
    public static let defaultRetention = 3

    /// Move `base` and its `-wal` / `-shm` / `-journal` sidecars in `directory`
    /// to `.corrupt-<unix-ts>` siblings, then prune to `keep` corruption events.
    /// Allows a fresh init/reopen to succeed while preserving the corrupted DB
    /// for forensics. Returns the timestamp stamp used (for logging/tests).
    @discardableResult
    public static func backup(
        directory: String,
        base: String,
        keep: Int = defaultRetention
    ) -> Int {
        let ts = Int(Date().timeIntervalSince1970)
        let suffixes = ["", "-wal", "-shm", "-journal"]
        for suffix in suffixes {
            let src = "\(directory)/\(base)\(suffix)"
            let dst = "\(directory)/\(base)\(suffix).corrupt-\(ts)"
            if FileManager.default.fileExists(atPath: src) {
                try? FileManager.default.moveItem(atPath: src, toPath: dst)
            }
        }
        prune(directory: directory, base: base, keep: keep)
        return ts
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
