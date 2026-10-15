import Foundation
import Testing
@testable import MacCrabApp

@Suite("Detection selected-tab reads and latest-result publication")
@MainActor
struct V2DetectionLoadSessionTests {
    private final class ProviderIdentity {}
    private final class Probe {
        var rules = 0
        var browser = 0
        var mcp = 0
        var agents = 0
    }

    private func row(_ id: String, title: String? = nil) -> V2MockRule {
        .init(id: id, title: title ?? id, category: "File", severity: .low, mitre: [],
              isEnabled: true, lastFired: nil, firesLastWeek: 0, isCustom: false,
              description: "Inert display fixture", status: "stable")
    }

    private func operations(_ probe: Probe, rows: [V2MockRule] = []) -> V2DetectionLoadSession.Operations {
        .init(rules: { probe.rules += 1; return .prepare(rows, directory: nil) },
              browser: { probe.browser += 1; return [] },
              mcp: { probe.mcp += 1; return [] },
              agents: { probe.agents += 1; return [] })
    }

    @Test("rules and a nonempty filter publish without requesting hidden tabs")
    func selectedTabAndFilterIndependence() async throws {
        let identity = ProviderIdentity(), probe = Probe(), session = V2DetectionLoadSession()
        let rows = [row("one", title: "Ordinary alpha"), row("two", title: "Ordinary beta")]
        let result = await session.load(tab: .rules, providerID: ObjectIdentifier(identity),
                                        operations: operations(probe, rows: rows))
        guard case .rules(let snapshot) = result else { Issue.record("Missing rule snapshot"); return }
        let filtered = await V2DetectionRuleFilter().filter(rules: snapshot.rules, haystack: snapshot.haystack, query: "beta")
        #expect(filtered?.map(\.id) == ["two"])
        #expect(probe.rules == 1)
        #expect(probe.browser == 0 && probe.mcp == 0 && probe.agents == 0)
        _ = await session.load(tab: .mcp, providerID: ObjectIdentifier(identity), operations: operations(probe))
        #expect(probe.rules == 1 && probe.browser == 0 && probe.mcp == 1 && probe.agents == 0)
    }

    @Test("a polling replacement joins a stalled read instead of cancelling or duplicating it")
    func pollingJoinsStalledRead() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate(), joined = V2DetectionFixtureGate()
        let session = V2DetectionLoadSession(onJoin: { _ in Task { await joined.open() } })
        let identity = ProviderIdentity(), probe = Probe(), expected = row("current")
        var ops = operations(probe)
        ops.rules = {
            probe.rules += 1
            await entered.open()
            await release.waitOrRecord()
            #expect(!Task.isCancelled, "Polling must not cancel the shared operation")
            return .prepare([expected], directory: nil)
        }
        let first = Task { await session.load(tab: .rules, providerID: ObjectIdentifier(identity), operations: ops) }
        defer { first.cancel(); session.invalidate(); Task { await release.open() } }
        try await entered.wait()
        first.cancel() // SwiftUI .task(id: refreshTick) replaces the consumer.
        let second = Task { await session.load(tab: .rules, providerID: ObjectIdentifier(identity), operations: ops) }
        defer { second.cancel() }
        try await joined.wait()
        #expect(probe.rules == 1)
        await release.open()
        if let _ = await first.value { Issue.record("Cancelled consumer published") }
        guard case .rules(let snapshot) = await second.value else { Issue.record("Current consumer did not publish"); return }
        #expect(snapshot.rules == [expected])
        #expect(probe.rules == 1)
    }

    @Test("provider replacement waits for a noncooperative old read and discards its result")
    func providerReplacementIsBounded() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate(), joined = V2DetectionFixtureGate()
        let session = V2DetectionLoadSession(onJoin: { _ in Task { await joined.open() } })
        let oldIdentity = ProviderIdentity(), newIdentity = ProviderIdentity(), oldProbe = Probe(), newProbe = Probe()
        let oldRow = row("old"), newRow = row("new")
        // The inner task models a read that cannot promptly observe caller
        // cancellation. It is explicitly released/cleaned up by this fixture.
        let uninterruptibleRead = Task { try await release.wait() }
        defer { uninterruptibleRead.cancel(); Task { await release.open() } }
        var oldOps = operations(oldProbe)
        oldOps.rules = {
            oldProbe.rules += 1
            await entered.open()
            _ = try? await uninterruptibleRead.value
            return .prepare([oldRow], directory: nil)
        }
        let first = Task { await session.load(tab: .rules, providerID: ObjectIdentifier(oldIdentity), operations: oldOps) }
        defer { first.cancel(); session.invalidate() }
        try await entered.wait()
        let second = Task { await session.load(tab: .rules, providerID: ObjectIdentifier(newIdentity),
                                               operations: operations(newProbe, rows: [newRow])) }
        defer { second.cancel() }
        try await joined.wait()
        #expect(oldProbe.rules == 1 && newProbe.rules == 0)
        await release.open()
        if let _ = await first.value { Issue.record("Superseded provider published") }
        guard case .rules(let snapshot) = await second.value else { Issue.record("New provider did not publish"); return }
        #expect(snapshot.rules == [newRow])
        #expect(oldProbe.rules == 1 && newProbe.rules == 1)
    }

    @Test("tab replacement cancels old work while the new tab can finish independently")
    func tabReplacementIsIndependent() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate()
        let session = V2DetectionLoadSession(), identity = ProviderIdentity(), probe = Probe()
        var ops = operations(probe)
        ops.rules = {
            probe.rules += 1
            await entered.open()
            await release.waitOrRecord()
            #expect(Task.isCancelled)
            return .prepare([], directory: nil)
        }
        let first = Task { await session.load(tab: .rules, providerID: ObjectIdentifier(identity), operations: ops) }
        defer { first.cancel(); session.invalidate(); Task { await release.open() } }
        try await entered.wait()
        let result = await session.load(tab: .browser, providerID: ObjectIdentifier(identity), operations: operations(probe))
        guard case .browser = result else { Issue.record("Selected browser tab did not finish"); return }
        if let _ = await first.value { Issue.record("Hidden rules tab published") }
        #expect(probe.rules == 1 && probe.browser == 1 && probe.mcp == 0 && probe.agents == 0)
    }

    @Test("disappearance prevents publication and subsequent appearance starts a fresh read")
    func disappearanceInvalidates() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate()
        let session = V2DetectionLoadSession(), identity = ProviderIdentity(), probe = Probe()
        var ops = operations(probe)
        ops.rules = {
            probe.rules += 1
            await entered.open()
            await release.waitOrRecord()
            return .prepare([], directory: nil)
        }
        let first = Task { await session.load(tab: .rules, providerID: ObjectIdentifier(identity), operations: ops) }
        defer { first.cancel(); session.invalidate(); Task { await release.open() } }
        try await entered.wait()
        session.invalidate()
        if let _ = await first.value { Issue.record("Disappeared view published") }
        let expected = row("reappeared")
        let result = await session.load(tab: .rules, providerID: ObjectIdentifier(identity),
                                        operations: operations(probe, rows: [expected]))
        guard case .rules(let snapshot) = result else { Issue.record("Fresh read missing"); return }
        #expect(snapshot.rules == [expected])
        #expect(probe.rules == 2)
    }

    @Test("out-of-order and cancelled filters never replace the latest result")
    func latestFilterWins() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate()
        let filter = V2DetectionRuleFilter(), old = row("old"), latest = row("latest")
        let first = Task {
            await filter.filter {
                await entered.open()
                await release.waitOrRecord()
                return [old]
            }
        }
        defer { first.cancel(); filter.invalidate(); Task { await release.open() } }
        try await entered.wait()
        #expect(await filter.filter(operation: { [latest] }) == [latest])
        await release.open()
        #expect(await first.value == nil)
        let cancelEntered = V2DetectionFixtureGate(), cancelRelease = V2DetectionFixtureGate()
        let cancelled = Task {
            await filter.filter {
                await cancelEntered.open()
                await cancelRelease.waitOrRecord()
                return [old]
            }
        }
        defer { cancelled.cancel(); Task { await cancelRelease.open() } }
        try await cancelEntered.wait()
        cancelled.cancel()
        #expect(await cancelled.value == nil)
    }
}
