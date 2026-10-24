// BoundedSecurityEvaluation.swift
// MacCrabCore
//
// Waits a bounded time for Security.framework to evaluate a path a local
// user can shape, breaks a blocked evaluation free, and bounds the threads
// one can hold.

import Darwin
import Foundation
import os.log

/// Security.framework opens the files inside a bundle itself: its main
/// executable, `_CodeSignature/CodeResources` and the sealed resources. A FIFO
/// at any of them holds the evaluating thread until a writer appears, and
/// `SecurityEvaluationPrecheck` sees only the path it is given, so one
/// `mkfifo` in `~/Downloads/X.app` stopped the system policy scan, the library
/// scan or the TCC pass for good. A caller now waits at most its deadline.
/// Every run has a thread of its own, so a run still waiting after its
/// deadline can be interrupted: a signal to that thread alone fails the
/// blocked open with EINTR and Security.framework returns an error. That
/// reaches a FIFO wherever it is, renamed away or deep in a large bundle,
/// which no path walk could. That holds only while Security.framework
/// validates on the run's thread: callers pass `kSecCSSingleThreaded`,
/// because by default it validates nested code and sealed resources on GCD
/// workers, which block the signal, while the run's thread waits in a
/// dispatch group the signal cannot end. A run that stays blocked counts
/// against its site, and a site with `stuckLimit` of them, or with its
/// in-flight limit of runs, starts no more, so threads stay bounded. A key
/// whose run had to be interrupted is answered as blocked from then on,
/// until the object changes and with it the key.
public final class BoundedSecurityEvaluation: @unchecked Sendable {
    enum Site: String, Sendable, CaseIterable {
        case codeSigning = "code_signing"
        case tcc
        case downloads
        case libraryInventory = "library_inventory"
    }

    /// How a bounded evaluation ended for one caller.
    enum Outcome<Value: Sendable>: Sendable {
        /// The work returned within the deadline: this caller's run, or the
        /// run for the same key it joined.
        case finished(Value)
        /// The deadline passed first. The work keeps running and is interrupted.
        case timedOut
        /// The same key's earlier run is still blocked, or Security.framework
        /// blocked on this object before and its run was interrupted; nothing
        /// was started.
        case blocked
        /// The site has `stuckLimit` blocked runs, or its in-flight limit of
        /// runs; nothing was started.
        case refused
        /// The waiting task was cancelled. The work keeps running.
        case cancelled

        var value: Value? {
            if case .finished(let value) = self { return value }
            return nil
        }
    }

    /// What the work can ask about its own run.
    struct Attempt: Sendable {
        /// True once the runner has signalled the work's thread. Its result
        /// then describes the interruption, not the code, and must not be kept.
        let wasInterrupted: @Sendable () -> Bool
        /// True once every caller stopped waiting: the result reaches none, so
        /// only something the work stores itself can serve it later.
        let isLate: @Sendable () -> Bool

        /// For work that runs without a bound.
        static let unbounded = Attempt(wasInterrupted: { false }, isLate: { false })
    }

    static let shared = BoundedSecurityEvaluation()

    /// A first-seen bundle's sealed resources are hashed, which takes tens of
    /// seconds for a large app.
    static let codeSigningDeadline: TimeInterval = 30
    /// One Downloads entry or one loaded library.
    static let scanDeadline: TimeInterval = 10

    /// Runs per site in flight at once, running or past their deadline. Each
    /// holds a thread and whatever Security.framework has open, and a caller
    /// the heavy plane cancels frees its worker but not its run: unbounded, an
    /// exec storm of distinct binaries could start thousands. Code signing
    /// serves every exec, so it gets more.
    static let defaultInFlightLimits: [Site: Int] = [.codeSigning: 8, .tcc: 4, .downloads: 4, .libraryInventory: 4]
    /// Interrupted keys remembered per site, oldest dropped first.
    static let interruptedKeyCapacity = 256

    /// Sent to one run's thread to fail its blocked call with EINTR. Nothing
    /// else in MacCrab uses it; the handler does nothing and is installed
    /// without SA_RESTART, so the interrupted call returns instead of resuming.
    static let interruptSignal = SIGVTALRM
    private static let interruptHandlerInstalled: Bool = {
        var action = sigaction()
        action.__sigaction_u.__sa_handler = { _ in }
        action.sa_flags = 0
        sigemptyset(&action.sa_mask)
        return sigaction(interruptSignal, &action, nil) == 0
    }()

    /// Consecutive samples, 50 ms apart, that must find a stranded run's
    /// thread waiting before it is signalled: a run that is computing (a large
    /// bundle being hashed) is left to finish, and its late verdict kept.
    static let waitingSamplesBeforeInterrupt = 3
    /// Samples taken after a deadline before a run is left as blocked.
    static let samplesAfterDeadline = 40

    let stuckLimit: Int
    let inFlightLimits: [Site: Int]
    /// Off only in tests that need a run to stay blocked.
    private let interruptsStranded: Bool
    private let lock = NSLock()
    /// The current run per site and key: running, or past its deadline and
    /// still blocked. Guarded by `lock`.
    private var runs: [Site: [String: Run]] = [:]
    /// Keys whose run was interrupted: Security.framework blocked on that
    /// object, so starting it again would only strand another thread for
    /// the deadline. Guarded by `lock`.
    private var interruptedKeys: [Site: InterruptedKeys] = [:]
    private var totals = Totals()
    private let deadlines = DispatchQueue(label: "com.maccrab.security-evaluation.deadline", qos: .utility)
    private let logger = Logger(subsystem: "com.maccrab", category: "security-evaluation")

    init(
        stuckLimit: Int = 4,
        inFlightLimits: [Site: Int] = BoundedSecurityEvaluation.defaultInFlightLimits,
        interruptsStranded: Bool = true
    ) {
        self.stuckLimit = stuckLimit
        self.inFlightLimits = inFlightLimits
        self.interruptsStranded = interruptsStranded
        _ = Self.interruptHandlerInstalled
    }

    /// Runs at `site` past their deadline and still blocked.
    func stuckCount(_ site: Site) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return blocked(site)
    }

    /// Blocked runs per site and lifetime counts, for the heartbeat.
    public static func heartbeatDiagnostics() -> [String: Any] { shared.diagnostics() }

    func diagnostics() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        var stuck: [String: Int] = [:]
        var inFlight: [String: Int] = [:]
        for site in Site.allCases {
            stuck[site.rawValue] = blocked(site)
            inFlight[site.rawValue] = runs[site]?.count ?? 0
        }
        return [
            "stuck": stuck,
            "in_flight": inFlight,
            "started_total": totals.started,
            "timed_out_total": totals.timedOut,
            "interrupted_total": totals.interrupted,
            "blocked_total": totals.blocked,
            "refused_total": totals.refused,
        ]
    }

    /// Runs `body` on a thread of its own and waits at most `deadline` for it.
    /// A caller for a key whose run is still within its deadline joins that
    /// run instead of starting another. `key` must change when the object
    /// does (callers add its identity), so a replaced file is evaluated afresh.
    func run<T: Sendable>(
        _ site: Site,
        key: String,
        deadline: TimeInterval,
        _ body: @escaping @Sendable (Attempt) -> T
    ) async -> Outcome<T> {
        let qos = Self.threadQoS(waitedOnAt: Task.currentPriority)
        let ticket = Ticket()
        let outcome: Outcome<any Sendable> = await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Outcome<any Sendable>, Never>) in
                switch admit(site: site, key: key, ticket: ticket, resume: { continuation.resume(returning: $0) }) {
                case .answered(let answer):
                    continuation.resume(returning: answer)
                case .joined:
                    break
                case .started(let run):
                    start(run, deadline: deadline, qos: qos, body)
                }
            }
        } onCancel: {
            cancel(ticket)
        }
        switch outcome {
        case .finished(let value):
            guard let typed = value as? T else { return .refused }
            return .finished(typed)
        case .timedOut: return .timedOut
        case .blocked: return .blocked
        case .refused: return .refused
        case .cancelled: return .cancelled
        }
    }

    // MARK: - Runs

    private final class Run: @unchecked Sendable {
        enum Phase { case running, expired, finished }
        let site: Site
        let key: String
        var phase = Phase.running
        var thread: pthread_t?
        var interrupted = false
        var sampling = false
        var waitingSamples = 0
        var waiters: [Int: @Sendable (Outcome<any Sendable>) -> Void] = [:]
        var nextWaiter = 0

        init(site: Site, key: String) {
            self.site = site
            self.key = key
        }

        func addWaiter(_ resume: @escaping @Sendable (Outcome<any Sendable>) -> Void) -> Int {
            let id = nextWaiter
            nextWaiter += 1
            waiters[id] = resume
            return id
        }
    }

    /// Callers waiting on `key`'s run at `site`.
    func waiterCount(_ site: Site, key: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return runs[site]?[key]?.waiters.count ?? 0
    }

    /// At most `capacity` keys, oldest dropped first; a hit counts as use.
    private struct InterruptedKeys {
        private var keys: Set<String> = []
        private var order: [String] = []

        mutating func insert(_ key: String, capacity: Int) {
            if keys.insert(key).inserted {
                order.append(key)
            } else {
                order.removeAll { $0 == key }
                order.append(key)
            }
            while order.count > capacity { keys.remove(order.removeFirst()) }
        }

        mutating func use(_ key: String) -> Bool {
            guard keys.contains(key) else { return false }
            order.removeAll { $0 == key }
            order.append(key)
            return true
        }
    }

    /// One caller's place in a run, so its cancellation can find it.
    private final class Ticket: @unchecked Sendable {
        var cancelled = false
        var run: Run?
        var waiter: Int?
    }

    private struct Totals {
        var started = 0
        var timedOut = 0
        var interrupted = 0
        var blocked = 0
        var refused = 0
    }

    private enum Admission {
        case answered(Outcome<any Sendable>)
        case joined
        case started(Run)
    }

    private func admit(
        site: Site,
        key: String,
        ticket: Ticket,
        resume: @escaping @Sendable (Outcome<any Sendable>) -> Void
    ) -> Admission {
        lock.lock()
        defer { lock.unlock() }
        if ticket.cancelled { return .answered(.cancelled) }
        if let existing = runs[site]?[key] {
            guard existing.phase == .running else {
                totals.blocked += 1
                sampleStranded(at: site)
                return .answered(.blocked)
            }
            ticket.run = existing
            ticket.waiter = existing.addWaiter(resume)
            return .joined
        }
        if interruptedKeys[site, default: InterruptedKeys()].use(key) {
            totals.blocked += 1
            return .answered(.blocked)
        }
        guard blocked(site) < stuckLimit, (runs[site]?.count ?? 0) < inFlightLimits[site, default: stuckLimit] else {
            totals.refused += 1
            sampleStranded(at: site)
            return .answered(.refused)
        }
        let run = Run(site: site, key: key)
        ticket.run = run
        ticket.waiter = run.addWaiter(resume)
        runs[site, default: [:]][key] = run
        totals.started += 1
        return .started(run)
    }

    private func start<T: Sendable>(
        _ run: Run,
        deadline: TimeInterval,
        qos: QualityOfService,
        _ body: @escaping @Sendable (Attempt) -> T
    ) {
        let attempt = Attempt(
            wasInterrupted: { [self] in lock.lock(); defer { lock.unlock() }; return run.interrupted },
            isLate: { [self] in lock.lock(); defer { lock.unlock() }; return run.phase != .running }
        )
        let thread = Thread { [self] in
            // A thread inherits its creator's signal mask, and the cooperative
            // pool's threads block this signal.
            var unblock = sigset_t()
            sigemptyset(&unblock)
            sigaddset(&unblock, Self.interruptSignal)
            pthread_sigmask(SIG_UNBLOCK, &unblock, nil)
            lock.lock()
            run.thread = pthread_self()
            lock.unlock()
            finish(run, with: body(attempt))
        }
        thread.name = "com.maccrab.security-evaluation.\(run.site.rawValue)"
        thread.qualityOfService = qos
        thread.start()
        deadlines.asyncAfter(deadline: .now() + deadline) { [self] in expire(run) }
    }

    private func finish(_ run: Run, with value: any Sendable) {
        lock.lock()
        let wasBlocked = run.phase == .expired
        let interrupted = run.interrupted
        let waiters = run.waiters
        run.waiters = [:]
        run.phase = .finished
        if runs[run.site]?[run.key] === run { runs[run.site]?[run.key] = nil }
        if interrupted {
            interruptedKeys[run.site, default: InterruptedKeys()].insert(run.key, capacity: Self.interruptedKeyCapacity)
        }
        let resumed = wasBlocked && blocked(run.site) == stuckLimit - 1
        lock.unlock()
        if wasBlocked {
            logger.notice("A Security evaluation at \(run.site.rawValue, privacy: .public) returned after its deadline (\(interrupted ? "interrupted" : "slow", privacy: .public))")
        }
        if resumed {
            logger.notice("Security evaluations at \(run.site.rawValue, privacy: .public) are below their limit again")
        }
        for resume in waiters.values { resume(.finished(value)) }
    }

    private func expire(_ run: Run) {
        lock.lock()
        guard run.phase == .running else {
            lock.unlock()
            return
        }
        run.phase = .expired
        let waiters = run.waiters
        run.waiters = [:]
        totals.timedOut += 1
        let atLimit = blocked(run.site) >= stuckLimit
        run.sampling = interruptsStranded
        lock.unlock()
        logger.warning("A Security evaluation at \(run.site.rawValue, privacy: .public) passed its deadline; interrupting it if it is blocked")
        if atLimit {
            logger.warning("Security evaluations at \(run.site.rawValue, privacy: .public) are blocked at their limit of \(self.stuckLimit, privacy: .public); new ones are skipped until one returns")
        }
        for resume in waiters.values { resume(.timedOut) }
        if interruptsStranded { sample(run, remaining: Self.samplesAfterDeadline) }
    }

    /// Signals a stranded run's thread once it has been seen waiting in the
    /// kernel for `waitingSamplesBeforeInterrupt` samples in a row.
    private func sample(_ run: Run, remaining: Int) {
        deadlines.asyncAfter(deadline: .now() + 0.05) { [self] in
            lock.lock()
            guard run.phase == .expired else {
                run.sampling = false
                lock.unlock()
                return
            }
            if let thread = run.thread {
                run.waitingSamples = Self.isWaiting(thread) ? run.waitingSamples + 1 : 0
                if run.waitingSamples >= Self.waitingSamplesBeforeInterrupt {
                    run.waitingSamples = 0
                    run.interrupted = true
                    totals.interrupted += 1
                    // The run is still inside its body under this lock, so the
                    // thread is alive and is this run's.
                    pthread_kill(thread, Self.interruptSignal)
                }
            }
            let more = remaining > 1
            if !more { run.sampling = false }
            lock.unlock()
            if more { sample(run, remaining: remaining - 1) }
        }
    }

    /// A caller turned away at `site` looks again at its stranded runs: a
    /// thread may have moved into a wait an interrupt can end. Caller holds
    /// `lock`.
    private func sampleStranded(at site: Site) {
        guard interruptsStranded else { return }
        for run in (runs[site] ?? [:]).values where run.phase == .expired && !run.sampling {
            run.sampling = true
            run.waitingSamples = 0
            sample(run, remaining: Self.waitingSamplesBeforeInterrupt + 2)
        }
    }

    private func cancel(_ ticket: Ticket) {
        lock.lock()
        ticket.cancelled = true
        var resume: (@Sendable (Outcome<any Sendable>) -> Void)?
        if let run = ticket.run, let waiter = ticket.waiter {
            resume = run.waiters.removeValue(forKey: waiter)
        }
        lock.unlock()
        resume?(.cancelled)
    }

    /// Caller holds `lock`.
    private func blocked(_ site: Site) -> Int {
        runs[site]?.values.reduce(0) { $0 + ($1.phase == .expired ? 1 : 0) } ?? 0
    }

    /// Whether `thread` is in an interruptible wait in the kernel, as a read
    /// or open of a FIFO is; a computing thread is running.
    private static func isWaiting(_ thread: pthread_t) -> Bool {
        var info = thread_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<thread_basic_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                thread_info(pthread_mach_thread_np(thread), thread_flavor_t(THREAD_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS && info.run_state == TH_STATE_WAITING
    }

    private static func threadQoS(waitedOnAt priority: TaskPriority) -> QualityOfService {
        switch BlockingWorkOffload.dispatchQoS(waitedOnAt: priority, floor: .utility).qosClass {
        case .userInteractive: return .userInteractive
        case .userInitiated: return .userInitiated
        case .default: return .default
        case .background: return .background
        default: return .utility
        }
    }
}
