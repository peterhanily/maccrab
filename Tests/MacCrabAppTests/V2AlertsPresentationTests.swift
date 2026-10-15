import Foundation
import Testing
import MacCrabCore
@testable import MacCrabApp

@MainActor
@Suite("Bounded window-owned Alerts presentation")
struct V2AlertsPresentationTests {
    private let provider = NSObject()
    private let now = Date(timeIntervalSince1970: 10_000_000)

    private func context(range: String = "7d", directory: String? = "/synthetic/alerts",
                         epoch: Double? = 100, start: Date? = nil, end: Date? = nil,
                         providerID: ObjectIdentifier? = nil) -> V2AlertsPresentationContext {
        .init(query: .init(providerID: providerID ?? ObjectIdentifier(provider), timeRange: range,
                           windowStart: start, windowEnd: end), directory: directory,
              engine: epoch.map { .init(EngineTelemetryIdentity(pid: 123, startedAtUnix: $0,
                                                               version: "synthetic", build: "unit")) })
    }

    private func row(_ id: String = "synthetic-1", at: Date? = nil,
                     payload: String = "") -> V2MockAlert {
        .init(id: id, title: "Synthetic alert", severity: .low, ruleId: "unit-rule",
              process: "fixture", processPath: "/synthetic/fixture", pid: 123,
              parent: "fixture-parent", user: "fixture-user", triggeringEventsJson: payload,
              timestamp: at ?? now, mitre: [], category: "fixture", description: "Inert metadata",
              actionsTaken: [], suppressed: false)
    }

    @Test("Remount shows matching cached rows synchronously but not a fresh all-clear")
    func cachedRemount() async {
        let model = V2AlertsPresentationModel()
        let key = context()
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .success([row()]) }
        #expect(model.isFresh(for: key))
        model.pause()
        #expect(model.rows(for: key).map(\.id) == ["synthetic-1"])
        #expect(!model.isFresh(for: key))
        let gate = DashboardReadTestGate()
        defer { gate.release() }
        let refresh = Task { @MainActor in
            await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in
                await gate.pause()
                return .success([row("synthetic-2")])
            }
        }
        await gate.waitUntilPaused()
        #expect(model.rows(for: key).first?.id == "synthetic-1")
        #expect(model.readiness(for: key).phase == .refreshingCached)
        #expect(!model.isFresh(for: key))
        gate.release()
        await refresh.value
        #expect(model.rows(for: key).first?.id == "synthetic-2")
        #expect(model.isFresh(for: key))
    }

    @Test("Twenty logical poll ticks join one slow read without starvation")
    func slowRefreshCoalesces() async {
        let model = V2AlertsPresentationModel()
        let key = context()
        let gate = DashboardReadTestGate()
        defer { gate.release() }
        var reads = 0
        let first = Task { @MainActor in
            await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in
                reads += 1
                await gate.pause()
                #expect(!Task.isCancelled)
                return .success([row()])
            }
        }
        await gate.waitUntilPaused()
        let arrivals = DashboardReadTestGate()
        defer { arrivals.release() }
        var arrivalsCount = 0
        let ticks = (0..<20).map { _ in Task { @MainActor in
            var arrived = false
            await model.refresh(context: key, now: now, isCurrent: {
                if !arrived {
                    arrived = true
                    arrivalsCount += 1
                    if arrivalsCount == 20 { arrivals.release() }
                }
                return true
            }) { _, _ in
                reads += 1
                Issue.record("Overlapping same-context provider read")
                return .success([])
            }
        } }
        // isCurrent runs inside refresh before its first suspension. The last
        // arrival then joins the occupied flight before this waiter resumes.
        await arrivals.pause()
        #expect(reads == 1)
        gate.release()
        await first.value
        for tick in ticks { await tick.value }
        #expect(reads == 1 && model.isFresh(for: key))
    }

    @Test("Open to History consumer replacement joins one live backend population")
    func samePopulationTabReplacement() async {
        let model = V2AlertsPresentationModel()
        let key = context()
        let gate = DashboardReadTestGate()
        let arrival = DashboardReadTestGate()
        defer { gate.release(); arrival.release() }
        var reads = 0
        let openConsumer = Task { @MainActor in
            await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in
                reads += 1
                await gate.pause()
                #expect(!Task.isCancelled)
                return .success([row()])
            }
        }
        await gate.waitUntilPaused()
        // Cancelling the old view-task is NOT a workspace pause. Its successor
        // consumes the same provider/source/query and must not inherit that
        // obsolete consumer's generation or cause a second provider query.
        openConsumer.cancel()
        let historyConsumer = Task { @MainActor in
            await model.refresh(context: key, now: now, isCurrent: {
                arrival.release()
                return true
            }) { _, _ in
                reads += 1
                Issue.record("Tab switch reissued the same backend read")
                return .success([])
            }
        }
        await arrival.pause()
        #expect(reads == 1)
        gate.release()
        await openConsumer.value
        await historyConsumer.value
        #expect(reads == 1 && model.isFresh(for: key))
        #expect(model.rows(for: key).count == 1)
    }

    @Test("Changed provider, directory, birth identity and backend filters hide rows before a new task", arguments: 0..<5)
    func mismatchesHaveNoStaleFlash(kind: Int) async {
        let model = V2AlertsPresentationModel()
        let original = context()
        await model.refresh(context: original, now: now, isCurrent: { true }) { _, _ in .success([row()]) }
        let otherProvider = NSObject()
        let replacement: V2AlertsPresentationContext
        switch kind {
        case 0: replacement = context(providerID: ObjectIdentifier(otherProvider))
        case 1: replacement = context(directory: "/synthetic/other")
        case 2: replacement = context(epoch: 101)
        case 3: replacement = context(range: "24h")
        default: replacement = context(start: now.addingTimeInterval(-60), end: now)
        }
        #expect(model.rows(for: replacement).isEmpty)
        #expect(!model.hasSnapshot(for: replacement) && !model.isFresh(for: replacement))
        #expect(model.error(for: replacement) == nil)
        #expect(model.readiness(for: replacement).phase == .unavailable)
    }

    @Test("Paused non-cooperative reads occupy the slot until return; only latest reentry starts")
    func boundedNavigationStorm() async {
        let model = V2AlertsPresentationModel()
        let key = context()
        let gate = DashboardReadTestGate()
        defer { gate.release() }
        var generation = 0
        var reads = 0
        var active = 0
        var maximumActive = 0
        let old = Task { @MainActor in
            await model.refresh(context: key, now: now, isCurrent: { generation == 0 }) { _, _ in
                reads += 1; active += 1; maximumActive = max(maximumActive, active)
                defer { active -= 1 }
                await gate.pause() // deliberately returns despite cancellation
                return .success([row("obsolete")])
            }
        }
        await gate.waitUntilPaused()
        let arrivals = DashboardReadTestGate()
        defer { arrivals.release() }
        var arrivalsCount = 0
        var returns: [Task<Void, Never>] = []
        for next in 1...20 {
            model.pause()
            generation = next
            returns.append(Task { @MainActor in
                var arrived = false
                await model.refresh(context: key, now: now, isCurrent: {
                    if !arrived {
                        arrived = true
                        arrivalsCount += 1
                        if arrivalsCount == 20 { arrivals.release() }
                    }
                    return generation == next
                }) { _, _ in
                    reads += 1; active += 1; maximumActive = max(maximumActive, active)
                    defer { active -= 1 }
                    return .success([row("latest")])
                }
            })
        }
        await arrivals.pause()
        #expect(reads == 1 && active == 1)
        gate.release()
        await old.value
        for task in returns { await task.value }
        #expect(reads == 2 && maximumActive == 1)
        #expect(model.rows(for: key).map(\.id) == ["latest"])
        #expect(model.isFresh(for: key))
    }

    @Test("Context replacement waits for old backend completion and rejects its late success")
    func contextReplacement() async {
        let model = V2AlertsPresentationModel()
        let oldKey = context()
        let newKey = context(epoch: 102)
        var current = oldKey
        let oldGate = DashboardReadTestGate()
        let newGate = DashboardReadTestGate()
        defer { oldGate.release(); newGate.release() }
        var reads = 0
        let old = Task { @MainActor in
            await model.refresh(context: oldKey, now: now, isCurrent: { current == oldKey }) { _, _ in
                reads += 1
                await oldGate.pause()
                return .success([row("old")])
            }
        }
        await oldGate.waitUntilPaused()
        current = newKey
        let arrival = DashboardReadTestGate()
        defer { arrival.release() }
        let replacement = Task { @MainActor in
            await model.refresh(context: newKey, now: now, isCurrent: {
                arrival.release()
                return current == newKey
            }) { _, _ in
                reads += 1
                await newGate.pause()
                return .success([row("new")])
            }
        }
        await arrival.pause()
        #expect(reads == 1 && model.rows(for: newKey).isEmpty)
        oldGate.release()
        await old.value
        await newGate.waitUntilPaused()
        #expect(reads == 2 && model.rows(for: newKey).isEmpty)
        newGate.release()
        await replacement.value
        #expect(model.rows(for: newKey).map(\.id) == ["new"])
    }

    @Test("Failure and cancellation cannot turn cached or missing rows into healthy empty")
    func failureAndEmptyProvenance() async {
        let model = V2AlertsPresentationModel()
        let key = context()
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .failed("synthetic unavailable") }
        #expect(!model.hasSnapshot(for: key) && !model.isFresh(for: key))
        #expect(model.readiness(for: key).phase == .failed)
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .success([row()]) }
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .failed("synthetic failure") }
        #expect(model.rows(for: key).count == 1 && !model.isFresh(for: key))
        #expect(model.error(for: key) == "synthetic failure")
        #expect(model.readiness(for: key).phase == .failed)
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .cancelled }
        #expect(model.rows(for: key).count == 1 && !model.isFresh(for: key))
        #expect(model.readiness(for: key).phase == .unavailable)
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .success([]) }
        #expect(model.rows(for: key).isEmpty && model.isFresh(for: key))
        #expect(model.readiness(for: key).phase == .loadedEmpty && model.error(for: key) == nil)
        model.pause()
        #expect(model.hasSnapshot(for: key) && !model.isFresh(for: key))
    }

    @Test("Window bounds and requested limits are unchanged; over-limit results fail rather than truncate")
    func queryContract() async {
        let model = V2AlertsPresentationModel()
        let start = now.addingTimeInterval(-100)
        let end = now.addingTimeInterval(-50)
        let key = context(start: start, end: end)
        await model.refresh(context: key, now: now, isCurrent: { true }) { since, limit in
            #expect(since == start && limit == 200)
            return .success([row("before", at: start.addingTimeInterval(-1)), row("start", at: start),
                             row("end", at: end), row("after", at: end.addingTimeInterval(1))])
        }
        #expect(model.rows(for: key).map(\.id) == ["start", "end"])
        #expect(context(range: "24h").lowerBound(now: now) == now.addingTimeInterval(-86_400))
        #expect(context().lowerBound(now: now) == now.addingTimeInterval(-7 * 86_400))
        #expect(context(range: "30d").fetchLimit == 1000)
        #expect(context(range: "all").lowerBound(now: now) == .distantPast)
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in
            .success((0..<201).map { row("row-\($0)", at: start) })
        }
        #expect(model.rows(for: key).map(\.id) == ["start", "end"])
        #expect(!model.isFresh(for: key) && model.readiness(for: key).phase == .failed)
    }

    @Test("Hidden retention accounts UTF-8 payload and requires known source and engine", arguments: 0..<3)
    func retentionLimits(kind: Int) async {
        let model = V2AlertsPresentationModel()
        let key = context(directory: kind == 1 ? nil : "/synthetic/alerts", epoch: kind == 2 ? nil : 100)
        // Multibyte input exceeds 4MiB in bytes while remaining below it in
        // Character count. This is authored inert metadata, never decoded.
        let payload = kind == 0 ? String(repeating: "é", count: 2 * 1024 * 1024) : ""
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in .success([row(payload: payload)]) }
        #expect(model.rows(for: key).count == 1 && model.isFresh(for: key))
        model.pause()
        #expect(model.rows(for: key).isEmpty && !model.hasSnapshot(for: key))
        #expect(!model.isFresh(for: key))
    }

    @Test("Exactly 1000 small rows are retained; a 1001-row success is not fabricated")
    func maximumRetainedRows() async {
        let model = V2AlertsPresentationModel()
        let key = context(range: "all")
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, limit in
            #expect(limit == 1000)
            return .success((0..<1000).map { row("synthetic-\($0)") })
        }
        model.pause()
        #expect(model.rows(for: key).count == 1000 && !model.isFresh(for: key))
        await model.refresh(context: key, now: now, isCurrent: { true }) { _, _ in
            .success((0..<1001).map { row("over-limit-\($0)") })
        }
        #expect(model.rows(for: key).count == 1000)
        #expect(model.rows(for: key).first?.id == "synthetic-0")
        #expect(!model.isFresh(for: key) && model.readiness(for: key).phase == .failed)
    }
}
