import MacCrabCore

/// The MCP server is an unprivileged query client for the daemon-owned
/// evidence stores.  Skip the read-write open attempt entirely: access to the
/// main DB file does not imply authority to create or mutate its root-owned WAL
/// family, and discovering that mismatch during a startup PRAGMA makes an
/// otherwise harmless read tool fail.
func openMCPEventStoreForReading(
    directory: String,
    liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
) throws -> EventStore {
    try EventStore(
        directory: directory,
        forceReadOnly: true,
        liveMemoryBudget: liveMemoryBudget
    )
}

func openMCPAlertStoreForReading(directory: String) throws -> AlertStore {
    try AlertStore(directory: directory, forceReadOnly: true)
}
