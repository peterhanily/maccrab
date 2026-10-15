import Foundation

/// One AppState dashboard poll at a time. Timer ticks join existing work
/// instead of canceling slow reads or queuing a trailing poll on every tick.
/// Cancellation keeps the slot occupied until the current read has unwound.
@MainActor
final class DashboardRefreshCoordinator {
    private var currentTask: Task<Void, Never>?
    private var currentID: UUID?
    private var cancellationGeneration = UUID()

    var isRunning: Bool { currentTask != nil }

    deinit { currentTask?.cancel() }

    @discardableResult
    func request(_ operation: @escaping @MainActor () async -> Void) -> Task<Void, Never> {
        if let currentTask { return currentTask }
        let id = UUID()
        currentID = id
        let task = Task { @MainActor [weak self] in
            defer {
                if self?.currentID == id {
                    self?.currentTask = nil
                    self?.currentID = nil
                }
            }
            guard !Task.isCancelled else { return }
            await operation()
        }
        currentTask = task
        return task
    }

    /// Explicit refreshes join an active poll. After stop/restart, wait for the
    /// cancelled predecessor before starting new work; never overlap handles.
    func run(_ operation: @escaping @MainActor () async -> Void) async {
        guard !Task.isCancelled else { return }
        let generation = cancellationGeneration
        if let previous = currentTask, previous.isCancelled {
            await previous.value
            guard !Task.isCancelled, generation == cancellationGeneration else { return }
        }
        await request(operation).value
    }

    func cancel() {
        cancellationGeneration = UUID()
        currentTask?.cancel()
    }
}
