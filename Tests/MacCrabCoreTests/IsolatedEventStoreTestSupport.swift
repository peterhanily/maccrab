import MacCrabCore

/// Swift Testing schedules suites in one process. Each temporary database is
/// a separate production-process analogue, so its decode accounting must not
/// contend with unrelated fixture stores.
extension EventStore {
    init(
        directory: String = "/Library/Application Support/MacCrab",
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        try self.init(
            directory: directory,
            forceReadOnly: forceReadOnly,
            storagePolicy: storagePolicy,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        )
    }

    init(
        path: String,
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        try self.init(
            path: path,
            forceReadOnly: forceReadOnly,
            storagePolicy: storagePolicy,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting()
        )
    }
}
