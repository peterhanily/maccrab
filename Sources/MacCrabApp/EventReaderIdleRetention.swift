import Foundation

/// MainActor-owned admission bookkeeping. A lease starts BEFORE an actor hop,
/// so queued reads count too. Invalidating a cache never erases outstanding
/// lease IDs: an old completion cannot release a replacement reader's lease.
struct EventReaderIdleRetention {
    static let maximumIdleSeconds: TimeInterval = 60

    struct Pause: Equatable {
        fileprivate let id: UUID
        let startedAt: TimeInterval
        let deadline: TimeInterval
    }

    private(set) var acceptsReads = true
    private var admissions: Set<UUID> = []
    private var pause: Pause?
    private var certified = false
    var admittedReadCount: Int { admissions.count }

    mutating func admit() -> UUID? {
        guard acceptsReads else { return nil }
        let id = UUID()
        admissions.insert(id)
        return id
    }

    mutating func finish(_ id: UUID) {
        precondition(admissions.remove(id) != nil, "Event reader lease released twice")
    }

    /// Repeated background notifications do not extend a retention deadline.
    mutating func closeAdmission(now: TimeInterval) -> Pause? {
        guard acceptsReads else { return nil }
        acceptsReads = false
        invalidate()
        guard admissions.isEmpty, now.isFinite, now >= 0 else { return nil }
        let deadline = now + Self.maximumIdleSeconds
        guard deadline.isFinite, deadline > now else { return nil }
        let token = Pause(id: UUID(), startedAt: now, deadline: deadline)
        pause = token
        return token
    }

    mutating func certify(_ token: Pause, idle: Bool, now: TimeInterval) -> Bool {
        guard matches(token) else { return false }
        certified = false
        guard admissions.isEmpty, idle, validTime(now, for: token) else { return false }
        certified = true
        return true
    }

    /// Returns whether the existing cache can be reused. Pending/failed
    /// certification, a reversed clock and an expired deadline all fail closed.
    mutating func resume(now: TimeInterval) -> Bool {
        let reusable = acceptsReads || (certified && pause.map { validTime(now, for: $0) } == true)
        acceptsReads = true
        invalidate()
        return reusable
    }

    mutating func invalidate() {
        pause = nil
        certified = false
    }

    func matches(_ token: Pause) -> Bool { !acceptsReads && pause == token }

    func expirationDue(_ token: Pause, now: TimeInterval) -> Bool {
        matches(token) && (!now.isFinite || now < token.startedAt || now >= token.deadline)
    }

    private func validTime(_ now: TimeInterval, for token: Pause) -> Bool {
        now.isFinite && now >= token.startedAt && now < token.deadline
    }
}
