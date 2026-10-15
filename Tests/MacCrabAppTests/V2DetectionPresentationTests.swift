import Foundation
import Testing
@testable import MacCrabApp

@Suite("Window-owned bounded Detection presentation")
@MainActor
struct V2DetectionPresentationTests {
    private final class ProviderIdentity {}
    private final class Probe { var calls = 0 }

    private func key(_ provider: ProviderIdentity, directory: String = "/inert-fixture-not-read",
                     epoch: UInt64 = 1) -> V2DetectionPresentation.Identity {
        .init(provider: ObjectIdentifier(provider), directory: directory, epoch: epoch)
    }

    private func row(_ id: String, title: String? = nil, matches: Int = 0,
                     enabled: Bool = true, description: String = "Inert searchable résumé",
                     category: String = "File") -> V2MockRule {
        .init(id: id, title: title ?? id, category: category, severity: .low,
              mitre: ["T0000"], isEnabled: enabled, lastFired: nil, firesLastWeek: matches,
              isCustom: false, description: description, status: "stable")
    }

    @Test("leave-return displays the matching cache while a fresh read is pending")
    func retainedWindowSnapshot() async throws {
        let provider = ProviderIdentity(), model = V2DetectionPresentation()
        let identity = key(provider), old = row("old", title: "alpha"), next = row("old", title: "alpha", matches: 3)
        await model.refresh(identity: identity, query: "alpha") { .success([old]) }
        await model.filter(identity: identity, query: "alpha", debounce: false)
        #expect(model.rows(for: identity, query: " ALPHA ") == [old])
        #expect(model.readiness(for: identity, query: "alpha").phase == .loadedNonempty)
        let oldSnapshot = try #require(model.snapshot(for: identity))
        model.leave()
        #expect(model.rows(for: identity, query: "alpha") == [old])
        #expect(!model.isCurrent(for: identity))
        #expect(!model.readiness(for: identity, query: "alpha").phase.isFreshCompletion)
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate()
        let refresh = Task {
            await model.refresh(identity: identity, query: "alpha") {
                await entered.open()
                await release.waitOrRecord()
                return .success([next])
            }
        }
        defer { refresh.cancel(); model.leave(); Task { await release.open() } }
        try await entered.wait()
        #expect(model.rows(for: identity, query: "alpha") == [old])
        #expect(model.phase == .refreshingCached)
        #expect(model.readiness(for: identity, query: "alpha").phase == .refreshingCached)
        #expect(!model.isCurrent(for: identity))
        await release.open()
        await refresh.value
        #expect(model.rows(for: identity, query: "alpha") == [next])
        #expect(model.snapshot(for: identity)?.haystack == oldSnapshot.haystack)
        #expect(model.hasFilteredResult(for: identity, query: "alpha"))
        #expect(model.readiness(for: identity, query: "alpha").phase == .loadedNonempty)
    }

    @Test("readiness follows the exact final filter and rejects unrelated cached queries")
    func filterReadiness() async {
        let provider = ProviderIdentity(), model = V2DetectionPresentation()
        let identity = key(provider), first = row("one", title: "alpha"), second = row("two", title: "beta")
        await model.refresh(identity: identity, query: "alpha") { .success([first, second]) }
        #expect(!model.readiness(for: identity, query: "alpha").phase.isFreshCompletion)
        await model.filter(identity: identity, query: "alpha", debounce: false)
        let alphaGeneration = model.readiness(for: identity, query: "alpha").generation
        #expect(model.rows(for: identity, query: "alpha") == [first])
        #expect(model.rows(for: identity, query: "beta").isEmpty)
        #expect(!model.readiness(for: identity, query: "beta").phase.isFreshCompletion)
        await model.filter(identity: identity, query: "beta", debounce: false)
        #expect(model.rows(for: identity, query: "beta") == [second])
        #expect(model.readiness(for: identity, query: "beta").generation != alphaGeneration)
        await model.filter(identity: identity, query: "no-match", debounce: false)
        #expect(model.hasFilteredResult(for: identity, query: "no-match"))
        #expect(model.readiness(for: identity, query: "no-match").phase == .loadedEmpty)
        await model.filter(identity: identity, query: "", debounce: false)
        #expect(model.rows(for: identity, query: "") == [first, second])
        #expect(model.readiness(for: identity, query: "").phase == .loadedNonempty)
    }

    @Test("unchanged search fields reuse membership but definition changes require a new accepted filter")
    func definitionVersusTelemetryRefresh() async {
        let provider = ProviderIdentity(), model = V2DetectionPresentation(), identity = key(provider)
        let old = row("one", title: "alpha"), telemetry = row("one", title: "alpha", matches: 9, enabled: false)
        await model.refresh(identity: identity, query: "alpha") { .success([old]) }
        await model.filter(identity: identity, query: "alpha", debounce: false)
        await model.refresh(identity: identity, query: "alpha") { .success([telemetry]) }
        #expect(model.rows(for: identity, query: "alpha") == [telemetry])
        #expect(model.hasFilteredResult(for: identity, query: "alpha"))
        #expect(model.readiness(for: identity, query: "alpha").phase == .loadedNonempty)
        let changed = row("one", title: "beta", matches: 9)
        await model.refresh(identity: identity, query: "alpha") { .success([changed]) }
        #expect(!model.hasFilteredResult(for: identity, query: "alpha"))
        #expect(!model.readiness(for: identity, query: "alpha").phase.isFreshCompletion)
        await model.filter(identity: identity, query: "alpha", debounce: false)
        #expect(model.rows(for: identity, query: "alpha").isEmpty)
        #expect(model.readiness(for: identity, query: "alpha").phase == .loadedEmpty)
    }

    @Test("failed and cancelled reads never manufacture fresh empty or fresh cached rows")
    func failedReadsAndEmptyRetention() async {
        let provider = ProviderIdentity(), model = V2DetectionPresentation(), identity = key(provider)
        await model.refresh(identity: identity) { .failed }
        #expect(model.phase == .failed && model.snapshot(for: identity) == nil)
        #expect(model.readiness(for: identity, query: "").phase == .failed)
        let cached = row("cached")
        await model.refresh(identity: identity) { .success([cached]) }
        await model.refresh(identity: identity) { .failed }
        #expect(model.rows(for: identity, query: "") == [cached])
        #expect(!model.isCurrent(for: identity))
        await model.filter(identity: identity, query: "cached", debounce: false)
        #expect(model.rows(for: identity, query: "cached") == [cached])
        #expect(model.readiness(for: identity, query: "cached").phase == .failed)
        await model.refresh(identity: identity) { .cancelled }
        #expect(model.rows(for: identity, query: "") == [cached])
        #expect(!model.readiness(for: identity, query: "").phase.isFreshCompletion)
        await model.filter(identity: identity, query: "cached", debounce: false)
        #expect(model.rows(for: identity, query: "cached") == [cached])
        #expect(model.readiness(for: identity, query: "cached").phase == .unavailable)
        #expect(!model.isCurrent(for: identity))
        await model.refresh(identity: identity) { .success([]) }
        #expect(model.readiness(for: identity, query: "").phase == .loadedEmpty)
        #expect(model.status(for: identity).contains("not a healthy-detection"))
        model.leave()
        #expect(model.snapshot(for: identity) == nil)
        #expect(!model.readiness(for: identity, query: "").phase.isFreshCompletion)
    }

    @Test("provider, source and engine epoch mismatches hide old rows before any async rebind")
    func immediateIdentityIsolation() async {
        let provider = ProviderIdentity(), other = ProviderIdentity(), model = V2DetectionPresentation()
        let identity = key(provider)
        await model.refresh(identity: identity) { .success([row("old")]) }
        for mismatch in [key(other), key(provider, directory: "/other-inert-source"), key(provider, epoch: 2)] {
            #expect(model.rows(for: mismatch, query: "").isEmpty)
            #expect(model.snapshot(for: mismatch) == nil)
            #expect(!model.isCurrent(for: mismatch))
            #expect(!model.readiness(for: mismatch, query: "").phase.isFreshCompletion)
        }
        #expect(V2DetectionPresentation().snapshot(for: identity) == nil)
    }

    @Test("poll replacement joins one read and only the latest consumer publishes")
    func singleFlightPolling() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate(), joined = V2DetectionFixtureGate()
        let provider = ProviderIdentity(), probe = Probe()
        let model = V2DetectionPresentation(onJoin: { Task { await joined.open() } }), identity = key(provider)
        let expected = row("current")
        let operation: @MainActor () async -> V2DetectionRulesRead = {
            probe.calls += 1
            await entered.open()
            await release.waitOrRecord()
            #expect(!Task.isCancelled)
            return .success([expected])
        }
        let first = Task { await model.refresh(identity: identity, operation: operation) }
        defer { first.cancel(); model.leave(); Task { await release.open() } }
        try await entered.wait()
        let generation = model.readiness(for: identity, query: "").generation
        first.cancel()
        let replacement = Task { await model.refresh(identity: identity, operation: operation) }
        defer { replacement.cancel() }
        try await joined.wait()
        #expect(probe.calls == 1)
        #expect(model.readiness(for: identity, query: "").generation == generation)
        await release.open()
        await first.value
        await replacement.value
        #expect(probe.calls == 1)
        #expect(model.rows(for: identity, query: "") == [expected])
        #expect(model.readiness(for: identity, query: "").phase == .loadedNonempty)
    }

    @Test("a noncooperative old source cannot publish and does not overlap replacement preparation")
    func supersededSourceCompletion() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate(), joined = V2DetectionFixtureGate()
        let provider = ProviderIdentity(), probe = Probe()
        let model = V2DetectionPresentation(onJoin: { Task { await joined.open() } })
        let oldKey = key(provider), newKey = key(provider, epoch: 2), old = row("old"), current = row("current")
        let uninterruptible = Task { try await release.wait() }
        defer { uninterruptible.cancel(); Task { await release.open() } }
        let first = Task {
            await model.refresh(identity: oldKey) {
                await entered.open()
                _ = try? await uninterruptible.value
                return .success([old])
            }
        }
        defer { first.cancel(); model.leave() }
        try await entered.wait()
        let replacement = Task {
            await model.refresh(identity: newKey) { probe.calls += 1; return .success([current]) }
        }
        defer { replacement.cancel() }
        try await joined.wait()
        #expect(probe.calls == 0)
        #expect(model.rows(for: oldKey, query: "").isEmpty)
        await release.open()
        await first.value
        await replacement.value
        #expect(probe.calls == 1)
        #expect(model.rows(for: newKey, query: "") == [current])
        #expect(model.rows(for: oldKey, query: "").isEmpty)
    }

    @Test("leaving cancels publication without retaining a hidden running workspace")
    func hiddenCompletionRejected() async throws {
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate()
        let provider = ProviderIdentity(), model = V2DetectionPresentation(), identity = key(provider)
        let first = Task {
            await model.refresh(identity: identity) {
                await entered.open()
                await release.waitOrRecord()
                return .success([row("hidden")])
            }
        }
        defer { first.cancel(); model.leave(); Task { await release.open() } }
        try await entered.wait()
        model.leave()
        await first.value
        #expect(model.snapshot(for: identity) == nil)
        #expect(!model.readiness(for: identity, query: "").phase.isFreshCompletion)
        let visible = row("visible")
        await model.refresh(identity: identity) { .success([visible]) }
        #expect(model.rows(for: identity, query: "") == [visible])
    }

    @Test("row and accounted-byte limits refuse whole snapshots, never silently truncate")
    func boundedAdmission() async {
        let provider = ProviderIdentity(), model = V2DetectionPresentation(), identity = key(provider)
        let cached = row("cached")
        await model.refresh(identity: identity) { .success([cached]) }
        let oversized = Array(repeating: row("same-inert-id"), count: V2DetectionPresentation.maximumRows + 1)
        await model.refresh(identity: identity) { .success(oversized) }
        #expect(model.phase == .failed)
        #expect(model.rows(for: identity, query: "") == [cached])
        let big = row("large", description: String(repeating: "x", count: V2DetectionPresentation.maximumAccountedBytes))
        #expect(V2DetectionPresentation.prepare([big], previous: nil, directory: nil) == nil)
        let maximumRows = (0..<V2DetectionPresentation.maximumRows).map { row(String($0), description: "") }
        let admitted = V2DetectionPresentation.prepare(maximumRows, previous: nil, directory: nil)
        #expect(admitted?.rules.count == V2DetectionPresentation.maximumRows)
        #expect(admitted?.rules.map(\.id) == maximumRows.map(\.id))
    }

    @Test("all existing search fields and composite labels survive preparation; stale clocks disable current actions")
    func searchAndFreshnessContract() async {
        let provider = ProviderIdentity(), model = V2DetectionPresentation(), identity = key(provider)
        let value = row("unique-id", title: "Alpha", category: "Sequence")
        await model.refresh(identity: identity) { .success([value]) }
        for query in ["unique-id", "ALPHA", "sequence", "t0000", "RÉSUMÉ"] {
            await model.filter(identity: identity, query: query, debounce: false)
            #expect(model.rows(for: identity, query: query) == [value])
        }
        #expect(model.snapshot(for: identity)?.compositeLabels["unique-id"] == "Alpha")
        #expect(!model.isCurrent(for: identity, now: .distantPast))
        #expect(!model.isCurrent(for: identity, now: .distantFuture))
        #expect(!model.isCurrent(for: identity, now: Date(timeIntervalSince1970: .nan)))
    }
}
