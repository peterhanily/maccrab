import Foundation

/// One window-owned backend lane. A view owns only a waiter, never the read's
/// cancellation. The occupied slot survives cancellation until Core returns.
@MainActor
final class EventReadFlight<Key: Equatable, Value> {
    enum Failure: Error { case deadlineExceeded, tooManyWaiters }
    static var maximumWaiters: Int { 16 }
    static var deadlineNanoseconds: UInt64 { 120_000_000_000 }

    private struct Flight {
        let id: UUID
        let key: Key
        var task: Task<Void, Never>?
        var deadline: Task<Void, Never>?
        var cancelled = false
        var timedOut = false
    }
    private var flight: Flight?
    private var waiters: [UUID: CheckedContinuation<Result<Value, Error>, Never>] = [:]
    private let waitForDeadline: @Sendable () async throws -> Void

    init(waitForDeadline: @escaping @Sendable () async throws -> Void = {
        try await Task.sleep(nanoseconds: 120_000_000_000)
    }) {
        self.waitForDeadline = waitForDeadline
    }

    deinit {
        flight?.task?.cancel()
        flight?.deadline?.cancel()
    }

    /// Window teardown/source replacement detaches callers promptly. The slot
    /// remains occupied: a noncooperative backend cannot overlap a replacement.
    func cancel() {
        guard flight != nil else { return }
        flight?.cancelled = true
        flight?.task?.cancel()
        finishWaiters(.failure(CancellationError()))
    }

    func cancel(if matches: (Key) -> Bool) {
        if let active = flight, matches(active.key) { cancel() }
    }

    func read(
        key: Key,
        cancelExisting: (Key) -> Bool,
        isCurrent: () -> Bool,
        operation: @escaping @MainActor () async throws -> Value
    ) async throws -> Value {
        while true {
            try Task.checkCancellation()
            guard isCurrent() else { throw CancellationError() }
            if let active = flight {
                if active.timedOut { throw Failure.deadlineExceeded }
                if !active.cancelled, active.key == key {
                    let result = await wait(for: active.id)
                    try Task.checkCancellation()
                    guard isCurrent() else { throw CancellationError() }
                    return try result.get()
                }
                if !active.cancelled, cancelExisting(active.key) { cancel() }
                // Different coverage must execute its own exact query after
                // the old read has unwound; never relabel an old page as fresh.
                let drained = await wait(for: active.id)
                if case .failure(let error) = drained, let failure = error as? Failure {
                    throw failure
                }
                continue
            }
            let id = UUID()
            flight = Flight(id: id, key: key)
            let task = Task { @MainActor [weak self] in
                let result: Result<Value, Error>
                do {
                    try Task.checkCancellation()
                    let value = try await operation()
                    try Task.checkCancellation()
                    result = .success(value)
                } catch { result = .failure(error) }
                self?.complete(id, result: result)
            }
            flight?.task = task
            let delay = waitForDeadline
            flight?.deadline = Task { @MainActor [weak self] in
                #if DEBUG
                defer { self?.completedDeadlineTasksForTesting += 1 }
                #endif
                do { try await delay(); try Task.checkCancellation() }
                catch { return }
                self?.expire(id)
            }
            let result = await wait(for: id)
            try Task.checkCancellation()
            guard isCurrent() else { throw CancellationError() }
            return try result.get()
        }
    }

    private func wait(for id: UUID) async -> Result<Value, Error> {
        let waiter = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled, flight?.id == id else {
                    continuation.resume(returning: .failure(CancellationError()))
                    return
                }
                guard waiters.count < Self.maximumWaiters else {
                    continuation.resume(returning: .failure(Failure.tooManyWaiters))
                    return
                }
                waiters[waiter] = continuation
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.waiters.removeValue(forKey: waiter)?.resume(returning: .failure(CancellationError()))
            }
        }
    }

    private func expire(_ id: UUID) {
        guard flight?.id == id else { return }
        flight?.timedOut = true
        flight?.cancelled = true
        flight?.task?.cancel()
        finishWaiters(.failure(Failure.deadlineExceeded))
    }

    private func complete(_ id: UUID, result: Result<Value, Error>) {
        guard let active = flight, active.id == id else { return }
        active.deadline?.cancel()
        flight = nil
        if active.timedOut { finishWaiters(.failure(Failure.deadlineExceeded)) }
        else if active.cancelled { finishWaiters(.failure(CancellationError())) }
        else { finishWaiters(result) }
    }

    private func finishWaiters(_ result: Result<Value, Error>) {
        let pending = Array(waiters.values)
        waiters.removeAll()
        for waiter in pending { waiter.resume(returning: result) }
    }

    #if DEBUG
    private(set) var completedDeadlineTasksForTesting = 0
    var occupiedForTesting: Bool { flight != nil }
    var waiterCountForTesting: Int { waiters.count }
    func expireForTesting() { if let id = flight?.id { expire(id) } }
    #endif
}
