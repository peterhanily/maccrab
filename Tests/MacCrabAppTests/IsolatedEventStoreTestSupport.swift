import MacCrabCore

/// Keep temporary app fixtures independent when Swift Testing runs targets and
/// suites concurrently in one process.
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
