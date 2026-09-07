import Foundation
import Combine

/// Owned by the workspace's provider-scoped SwiftUI task, independently of
/// periodic table refreshes. Replacements join the previous cancelled loop so
/// even a slow point read cannot create overlapping confirmation batches.
@MainActor
final class V2MutationConfirmationLoop: ObservableObject {
    private let interval: Duration
    private var currentTask: Task<Void, Never>?
    private var generation: UUID?

    init(interval: Duration = .seconds(5)) {
        self.interval = interval
    }

    deinit { currentTask?.cancel() }

    func run(
        nextBatch: @escaping @MainActor () -> [V2MutationRequest],
        confirm: @escaping @MainActor (V2MutationRequest) async -> V2MutationConfirmation,
        observed: @escaping @MainActor (V2MutationRequest, V2MutationConfirmation) -> Void
    ) async {
        guard !Task.isCancelled else { return }
        let previous = currentTask
        previous?.cancel()
        let token = UUID()
        generation = token
        let interval = interval
        let task = Task { @MainActor in
            await previous?.value
            while !Task.isCancelled {
                // The tracker rotates the batch fairly; this limit also keeps
                // the scheduling boundary bounded if a caller supplies more.
                for request in nextBatch().prefix(100) {
                    guard !Task.isCancelled else { return }
                    let result = await confirm(request)
                    // A view/provider may disappear during the point read.
                    // Discard its observation and issue no follow-on reads.
                    guard !Task.isCancelled else { return }
                    observed(request, result)
                }
                do {
                    try await Task.sleep(for: interval)
                } catch {
                    return
                }
            }
        }
        currentTask = task
        await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
        if generation == token {
            currentTask = nil
            generation = nil
        }
    }
}
