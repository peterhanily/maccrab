import MacCrabCore

extension MacCrabCtl {
    /// Open daemon-owned evidence for an operator query without ever first
    /// attempting a read-write SQLite handle.
    ///
    /// The evidence files can be readable to the console user's `admin` group
    /// while their WAL directory remains writable only by root.  Letting a
    /// query client try read-write first is therefore unsafe: SQLite can open
    /// the main file and only discover the missing write authority when a
    /// startup PRAGMA or WAL operation runs.  At that point the store does not
    /// take its read-only fallback and a harmless command fails with
    /// `attempt to write a readonly database`.
    ///
    /// Keep every shipped `maccrabctl` query on these factories.  Maintenance
    /// commands that intentionally mutate a store (currently `rollup`) must
    /// continue to construct their writer explicitly instead.
    static func openEventStoreForReading(
        directory: String,
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
    ) throws -> EventStore {
        try EventStore(directory: directory, forceReadOnly: true, liveMemoryBudget: liveMemoryBudget)
    }

    static func openAlertStoreForReading(directory: String) throws -> AlertStore {
        try AlertStore(directory: directory, forceReadOnly: true)
    }
}
