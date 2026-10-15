import Foundation
import Testing

/// Explicit synchronization, with a hang deadline only (never a timing oracle).
actor V2DetectionFixtureGate {
    private enum WaitError: Error { case deadline }
    private var opened = false
    private var waiters: [UUID: (CheckedContinuation<Void, Error>, Task<Void, Never>)] = [:]

    func wait() async throws {
        if opened { return }
        let id = UUID()
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let watchdog = Task {
                    do { try await Task.sleep(for: .seconds(30)) }
                    catch { return }
                    self.finish(id, error: WaitError.deadline)
                }
                waiters[id] = (continuation, watchdog)
            }
        } onCancel: {
            Task { await self.finish(id, error: CancellationError()) }
        }
    }

    func waitOrRecord() async {
        do { try await wait() }
        catch is CancellationError { }
        catch { Issue.record("Synthetic detection read exceeded its hang deadline: \(error)") }
    }

    func open() {
        opened = true
        for (_, (continuation, watchdog)) in waiters {
            watchdog.cancel()
            continuation.resume()
        }
        waiters.removeAll()
    }

    private func finish(_ id: UUID, error: Error) {
        guard let (continuation, watchdog) = waiters.removeValue(forKey: id) else { return }
        watchdog.cancel()
        continuation.resume(throwing: error)
    }
}
