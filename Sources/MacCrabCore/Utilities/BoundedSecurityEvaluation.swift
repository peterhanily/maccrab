// BoundedSecurityEvaluation.swift
// MacCrabCore
//
// Waits a bounded time for Security.framework to evaluate a path a local
// user can shape, and bounds the threads such an evaluation can strand.

import Foundation
import os.log

/// Security.framework opens the files inside a bundle itself: its main
/// executable, `_CodeSignature/CodeResources` and the sealed resources. A FIFO
/// at any of them holds the evaluating thread until a writer appears, and
/// `SecurityEvaluationPrecheck` sees only the path it is given, so one
/// `mkfifo` in `~/Downloads/X.app` stopped the system policy scan, the library
/// scan or the TCC pass for good. A caller now waits at most its deadline.
/// Work still running then is stuck for its site until it returns; a key with
/// stuck work is not started again, and a site with `stuckLimit` stuck
/// evaluations starts none, so stranded threads stay bounded.
final class BoundedSecurityEvaluation: @unchecked Sendable {
    enum Site: String, Sendable {
        case codeSigning
        case downloads
        case libraryInventory
    }

    static let shared = BoundedSecurityEvaluation()

    /// A first-seen bundle's sealed resources are hashed, which takes tens of
    /// seconds for a large app.
    static let codeSigningDeadline: TimeInterval = 30
    /// One Downloads entry or one loaded library.
    static let scanDeadline: TimeInterval = 10

    let stuckLimit: Int
    private let lock = NSLock()
    /// Stuck evaluations per site, by key. Guarded by `lock`.
    private var stuck: [Site: [String: Int]] = [:]
    private let queue = DispatchQueue(
        label: "com.maccrab.security-evaluation",
        qos: .utility,
        attributes: .concurrent
    )
    private let deadlines = DispatchQueue(label: "com.maccrab.security-evaluation.deadline", qos: .utility)
    private let logger = Logger(subsystem: "com.maccrab", category: "security-evaluation")

    init(stuckLimit: Int = 4) {
        self.stuckLimit = stuckLimit
    }

    /// Evaluations at `site` still running past their deadline.
    func stuckCount(_ site: Site) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return total(site)
    }

    /// `body`'s result, or nil when it did not return within `deadline`, when
    /// `key` already has stuck work at `site`, or when `site` is at its limit;
    /// the last two start no work. `body` runs on `queue`, this type's own by
    /// default, at the waiting task's priority.
    func run<T: Sendable>(
        _ site: Site,
        key: String,
        deadline: TimeInterval,
        on queue: DispatchQueue? = nil,
        _ body: @escaping @Sendable () -> T
    ) async -> T? {
        lock.lock()
        let admitted = stuck[site]?[key] == nil && total(site) < stuckLimit
        lock.unlock()
        guard admitted else { return nil }

        let race = Race()
        let qos = BlockingWorkOffload.dispatchQoS(waitedOnAt: Task.currentPriority, floor: .utility)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
            let expiry = DispatchWorkItem { [self] in
                lock.lock()
                let expired = race.phase == .running
                var reachedLimit = false
                if expired {
                    race.phase = .expired
                    stuck[site, default: [:]][key, default: 0] += 1
                    reachedLimit = total(site) == stuckLimit
                }
                lock.unlock()
                guard expired else { return }
                if reachedLimit {
                    logger.warning("Security evaluations at \(site.rawValue, privacy: .public) are blocked at their limit of \(self.stuckLimit, privacy: .public); new ones are skipped until one returns")
                }
                continuation.resume(returning: nil)
            }
            (queue ?? self.queue).async(qos: qos, flags: .enforceQoS) { [self] in
                let value = body()
                expiry.cancel()
                lock.lock()
                let onTime = race.phase == .running
                var leftLimit = false
                if onTime {
                    race.phase = .finished
                } else {
                    leftLimit = total(site) == stuckLimit
                    let count = stuck[site]?[key] ?? 0
                    stuck[site]?[key] = count > 1 ? count - 1 : nil
                }
                lock.unlock()
                if leftLimit {
                    logger.notice("A blocked Security evaluation at \(site.rawValue, privacy: .public) returned; evaluations resume")
                }
                if onTime { continuation.resume(returning: value) }
            }
            deadlines.asyncAfter(deadline: .now() + deadline, execute: expiry)
        }
    }

    /// Which of the work and its deadline finished first. Guarded by `lock`.
    private final class Race: @unchecked Sendable {
        enum Phase { case running, finished, expired }
        var phase = Phase.running
    }

    /// Caller holds `lock`.
    private func total(_ site: Site) -> Int {
        stuck[site]?.values.reduce(0, +) ?? 0
    }
}
