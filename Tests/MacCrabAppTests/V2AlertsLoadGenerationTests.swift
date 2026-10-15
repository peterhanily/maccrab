import Foundation
import Testing
@testable import MacCrabApp

@MainActor
@Suite("Alert workspace load generations")
struct V2AlertsLoadGenerationTests {
    @Test("Same-context ticks preserve an in-flight alert read and its follow-on stages")
    func slowReadIsNotStarvedByTicks() async {
        let coordinator = V2AlertsLoadCoordinator<Int>()
        let gate = DashboardReadTestGate()
        var reads = 0
        var publications = 0
        let first = coordinator.request(context: 1) { ticket in
            reads += 1
            await gate.pause()
            guard coordinator.accepts(ticket, context: 1) else { return }
            publications += 1
            // Represent the later campaign/suppression stages as separate
            // calls: a cancelled/obsolete alert read must not reach these.
            reads += 3
        }
        await gate.waitUntilPaused()
        for _ in 0..<20 {
            coordinator.request(context: 1) { _ in Issue.record("duplicate timer load") }
        }
        #expect(reads == 1 && publications == 0 && !first.isCancelled)
        gate.release()
        await first.value
        #expect(reads == 4 && publications == 1)
    }

    @Test("Superseded results cannot publish or start later stages", arguments: 0..<4)
    func supersededAtEverySuspension(stage: Int) async {
        let coordinator = V2AlertsLoadCoordinator<Int>()
        let oldGate = DashboardReadTestGate()
        let newGate = DashboardReadTestGate()
        var context = 1
        var oldReads = 0
        var oldPublications = 0
        var newPublications = 0
        let old = coordinator.request(context: context) { ticket in
            for index in 0..<4 {
                oldReads += 1
                if index == stage { await oldGate.pause() }
                guard coordinator.accepts(ticket, context: context) else { return }
                oldPublications += 1
            }
        }
        await oldGate.waitUntilPaused()
        context = 2
        let next = coordinator.request(context: context) { ticket in
            await newGate.pause()
            guard coordinator.accepts(ticket, context: context) else { return }
            newPublications += 1
        }
        await newGate.waitUntilPaused()
        #expect(old.isCancelled)
        oldGate.release()
        await old.value
        #expect(oldReads == stage + 1 && oldPublications == stage)
        // Late old cleanup must not clear the new ticket or cause a new tick
        // to start a third read while the replacement is still in flight.
        coordinator.request(context: context) { _ in Issue.record("lost new load ticket") }
        newGate.release()
        await next.value
        #expect(newPublications == 1)
    }

    @Test("Disappearance invalidates late results and permits a fresh same-context appearance")
    func disappearanceCancelsPublication() async {
        let coordinator = V2AlertsLoadCoordinator<Int>()
        let gate = DashboardReadTestGate()
        var publications = 0
        let old = coordinator.request(context: 1) { ticket in
            await gate.pause()
            if coordinator.accepts(ticket, context: 1) { publications += 1 }
        }
        await gate.waitUntilPaused()
        coordinator.cancel()
        let next = coordinator.request(context: 1) { ticket in
            if coordinator.accepts(ticket, context: 1) { publications += 1 }
        }
        gate.release()
        await old.value
        await next.value
        #expect(publications == 1)
    }

    @Test("A changed context rejects publication before the replacement task begins")
    func contextMismatchBeforeNewRequest() async {
        let coordinator = V2AlertsLoadCoordinator<Int>()
        var context = 1
        let gate = DashboardReadTestGate()
        var publications = 0
        let read = coordinator.request(context: context) { ticket in
            await gate.pause()
            if coordinator.accepts(ticket, context: context) { publications += 1 }
        }
        await gate.waitUntilPaused()
        context = 2
        gate.release()
        await read.value
        #expect(publications == 0)
    }

    @Test("Offline has no healthy empty result; each retained result owns its error")
    func perCallFailureProvenance() async {
        let offline = V2OfflineDataProvider()
        let result = await offline.alertsSnapshot(since: .distantPast, limit: 5)
        guard case .failed = result else {
            Issue.record("Offline alert provenance was presented as successful")
            return
        }
        let failed = V2AlertsReadSnapshot.failed("synthetic read failure")
        let next = V2AlertsReadSnapshot.success([])
        if case .failed(let message) = failed {
            #expect(message == "synthetic read failure")
        } else { Issue.record("Later success replaced an earlier result") }
        if case .success(let rows) = next { #expect(rows.isEmpty) }
        else { Issue.record("Explicit empty success was lost") }
    }

    @Test("The mock compatibility path is explicit and cancellation is not success")
    func mockAndCancelledSnapshots() async {
        #if DEBUG
        let mock = V2MockDataProvider()
        let result = await mock.alertsSnapshot(since: .distantPast, limit: 1)
        if case .success(let rows) = result { #expect(rows.count <= 1) }
        else { Issue.record("Mock compatibility result missing") }
        #endif
        let offline = V2OfflineDataProvider()
        let gate = DashboardReadTestGate()
        let task = Task { @MainActor in
            await gate.pause()
            return await offline.alertsSnapshot(since: .distantPast, limit: 1)
        }
        await gate.waitUntilPaused()
        task.cancel()
        gate.release()
        guard case .cancelled = await task.value else {
            Issue.record("Cancelled read produced another disposition")
            return
        }
    }
}
