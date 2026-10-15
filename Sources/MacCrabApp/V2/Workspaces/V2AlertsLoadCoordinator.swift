import Foundation
import Combine

/// A timer tick joins an in-flight read for the same context. Only a different
/// provider/filter or an explicit lifecycle stop cancels it. SQLite may finish
/// an already-issued read after cancellation, so publication also checks the
/// current context and ticket after every suspension.
@MainActor
final class V2AlertsLoadCoordinator<Context: Equatable>: ObservableObject {
    struct Ticket: Equatable {
        let id: UUID
        let context: Context
    }

    private var current: Ticket?
    private var task: Task<Void, Never>?

    @discardableResult
    func request(
        context: Context,
        operation: @escaping @MainActor (Ticket) async -> Void
    ) -> Task<Void, Never> {
        if current?.context == context, let task { return task }
        task?.cancel()
        let ticket = Ticket(id: UUID(), context: context)
        current = ticket
        let next = Task { @MainActor [weak self] in
            defer {
                if self?.current == ticket {
                    self?.current = nil
                    self?.task = nil
                }
            }
            guard !Task.isCancelled else { return }
            await operation(ticket)
        }
        task = next
        return next
    }

    func accepts(_ ticket: Ticket, context: Context) -> Bool {
        !Task.isCancelled && current == ticket && ticket.context == context
    }

    func cancel() {
        task?.cancel()
        task = nil
        current = nil
    }
}

struct V2AlertsLoadContext: Hashable {
    let providerID: ObjectIdentifier
    let timeRange: String
    let windowStart: Date?
    let windowEnd: Date?
}
