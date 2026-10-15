import Foundation
import Testing
@testable import MacCrabApp

/// An intentionally non-cancellable read, released by the test. A 30-second
/// watchdog fails hangs only; ordering/correctness uses continuations, never
/// elapsed-time thresholds, live stores or the installed application.
@MainActor
final class DashboardReadTestGate {
    private var blocked: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    private var expired = false
    private var released = false
    private var watchdog: Task<Void, Never>?

    init() {
        watchdog = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(30)) }
            catch { return }
            guard let self else { return }
            self.expired = true
            Issue.record("Synthetic dashboard read exceeded its hang deadline")
            self.release()
        }
    }

    deinit {
        watchdog?.cancel()
        blocked?.resume()
        observer?.resume()
    }

    func pause() async {
        guard !expired, !released else { return }
        await withCheckedContinuation { continuation in
            blocked = continuation
            observer?.resume()
            observer = nil
        }
    }

    func waitUntilPaused() async {
        guard blocked == nil, !expired, !released else { return }
        await withTaskCancellationHandler {
            guard !Task.isCancelled else { return }
            await withCheckedContinuation { observer = $0 }
        } onCancel: {
            Task { @MainActor [weak self] in self?.release() }
        }
    }

    func release() {
        released = true
        watchdog?.cancel()
        blocked?.resume()
        blocked = nil
        observer?.resume()
        observer = nil
    }
}

@MainActor
@Suite("Dashboard refresh single-flight")
struct DashboardRefreshCoordinatorTests {
    @Test("A read spanning many timer ticks is neither cancelled nor duplicated")
    func slowReadSurvivesPollTicks() async {
        let coordinator = DashboardRefreshCoordinator()
        let gate = DashboardReadTestGate()
        var starts = 0
        var publications = 0
        let first = coordinator.request {
            starts += 1
            await gate.pause()
            #expect(!Task.isCancelled)
            publications += 1
        }
        await gate.waitUntilPaused()
        // Each request represents a later five-second timer tick while the
        // earlier read is still blocked. Logical duration exceeds the polling
        // interval without making the test depend on host scheduling speed.
        for _ in 0..<20 {
            coordinator.request { starts += 1 }
        }
        #expect(starts == 1 && publications == 0 && coordinator.isRunning)
        gate.release()
        await first.value
        #expect(starts == 1 && publications == 1 && !coordinator.isRunning)
        await coordinator.run { starts += 1 }
        #expect(starts == 2 && !coordinator.isRunning)
    }

    @Test("Stop keeps the slot until a late read unwinds, then restart can proceed")
    func stopAndRestartNeverOverlap() async {
        let coordinator = DashboardRefreshCoordinator()
        let gate = DashboardReadTestGate()
        var active = 0
        var maximumActive = 0
        var publications = 0
        var restarted = false
        let first = coordinator.request {
            active += 1
            maximumActive = max(maximumActive, active)
            await gate.pause()
            defer { active -= 1 }
            guard !Task.isCancelled else { return }
            publications += 1
        }
        await gate.waitUntilPaused()
        coordinator.cancel()
        #expect(coordinator.isRunning && first.isCancelled)
        // A restarted timer still joins the cancelled predecessor while its
        // underlying actor read unwinds; it cannot open another handle.
        let joined = coordinator.request { Issue.record("overlapping poll") }
        #expect(joined.isCancelled)
        let restart = Task { @MainActor in
            await coordinator.run {
                restarted = true
                active += 1
                maximumActive = max(maximumActive, active)
                active -= 1
                publications += 1
            }
        }
        #expect(!restarted && active == 1)
        gate.release()
        await first.value
        await restart.value
        #expect(restarted && maximumActive == 1 && active == 0)
        #expect(publications == 1 && !coordinator.isRunning)
    }

    @Test("Cancellation before execution starts does not issue a read")
    func cancelBeforeStart() async {
        let coordinator = DashboardRefreshCoordinator()
        var starts = 0
        let task = coordinator.request { starts += 1 }
        coordinator.cancel()
        await task.value
        #expect(starts == 0 && !coordinator.isRunning)
    }

    @Test("A second stop invalidates an explicit restart still waiting for old work")
    func repeatedStopDoesNotResurrectWaitingRefresh() async {
        let coordinator = DashboardRefreshCoordinator()
        let gate = DashboardReadTestGate()
        let first = coordinator.request { await gate.pause() }
        await gate.waitUntilPaused()
        coordinator.cancel()
        var restarted = false
        var waiter: Task<Void, Never>?
        await withCheckedContinuation { started in
            waiter = Task { @MainActor in
                started.resume()
                // No suspension between signalling and entering run; the
                // waiting test resumes after run is awaiting the old flight.
                await coordinator.run { restarted = true }
            }
        }
        coordinator.cancel()
        gate.release()
        await first.value
        await waiter?.value
        #expect(!restarted && !coordinator.isRunning)
    }
}
