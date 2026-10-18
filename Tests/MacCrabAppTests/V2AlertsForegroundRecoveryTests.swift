import Foundation
import Testing
import MacCrabCore
@testable import MacCrabApp

@MainActor
@Suite("Alerts composed foreground recovery")
struct V2AlertsForegroundRecoveryTests {
    private func context(_ identity: NSObject) -> V2AlertsPresentationContext {
        .init(query: .init(providerID: ObjectIdentifier(identity), timeRange: "7d", windowStart: nil, windowEnd: nil),
              directory: "/synthetic/alerts-foreground",
              engine: V2AlertsPresentationContext.Engine(
                EngineTelemetryIdentity(pid: 123, startedAtUnix: 100, version: "fixture", build: "unit")))
    }

    @Test("Foreground refresh replaces a paused model read without waiting for another timer tick")
    func pausedReadCannotConsumeForegroundRefresh() async {
        let identity = NSObject()
        let context = V2AlertsPresentationContext(
            query: .init(providerID: ObjectIdentifier(identity), timeRange: "7d", windowStart: nil, windowEnd: nil),
            directory: "/synthetic/alerts-foreground",
            engine: V2AlertsPresentationContext.Engine(
                EngineTelemetryIdentity(pid: 123, startedAtUnix: 100, version: "fixture", build: "unit")))
        let model = V2AlertsPresentationModel()
        let coordinator = V2AlertsLoadCoordinator<Int>()
        let gate = DashboardReadTestGate()
        defer { gate.release() }
        var reads = 0
        var active = 0
        var maximumActive = 0
        func request() -> Task<Void, Never> {
            coordinator.request(context: 1, lifecycle: model.pauseGeneration) { _ in
                await model.refresh(context: context, isCurrent: { true }) { _, _ in
                    reads += 1
                    active += 1
                    maximumActive = max(maximumActive, active)
                    defer { active -= 1 }
                    if reads == 1 { await gate.pause() }
                    return .success([])
                }
            }
        }
        let old = request()
        await gate.waitUntilPaused()
        // Mirrors shell inactivity: the inner model is paused; the mounted
        // workspace's outer coordinator is not a disappeared view.
        model.pause()
        #expect(!model.isFresh(for: context))
        let foreground = request() // exactly the immediate refreshTick route
        gate.release()
        await old.value
        await foreground.value
        #expect(reads == 2, "The foreground request must survive the cancelled predecessor")
        #expect(maximumActive == 1)
        #expect(model.isFresh(for: context))
        #expect(model.readiness(for: context).phase == .loadedEmpty)
        // A later ordinary tick is a positive control, not a substitute for
        // the foreground assertions above; old code recovers only here.
        let beforeNextTick = reads
        await request().value
        #expect(reads == beforeNextTick + 1 && model.isFresh(for: context))
    }

    @Test("Healthy list ticks retain the pause token and join one backend read")
    func ordinaryTicksDoNotRestart() async {
        let identity = NSObject(), model = V2AlertsPresentationModel()
        let context = context(identity), coordinator = V2AlertsLoadCoordinator<Int>()
        let gate = DashboardReadTestGate()
        defer { gate.release() }
        let lifecycle = model.pauseGeneration
        var reads = 0
        func request() -> Task<Void, Never> {
            coordinator.request(context: 1, lifecycle: model.pauseGeneration) { _ in
                await model.refresh(context: context, isCurrent: { true }) { _, _ in
                    reads += 1
                    await gate.pause()
                    #expect(!Task.isCancelled)
                    return .success([])
                }
            }
        }
        let first = request()
        await gate.waitUntilPaused()
        let ticks = (0..<20).map { _ in request() }
        #expect(model.pauseGeneration == lifecycle && reads == 1 && !first.isCancelled)
        gate.release()
        await first.value
        for tick in ticks { await tick.value }
        #expect(model.pauseGeneration == lifecycle && reads == 1 && model.isFresh(for: context))
    }

    @Test("Several pause and return edges retain one occupied backend and only latest consumer publishes")
    func pauseStormKeepsOneBackend() async {
        let identity = NSObject(), model = V2AlertsPresentationModel()
        let context = context(identity), coordinator = V2AlertsLoadCoordinator<Int>()
        let gate = DashboardReadTestGate(), joined = DashboardReadTestGate()
        defer { gate.release(); joined.release() }
        var reads = 0, active = 0, maximumActive = 0, completedConsumers = 0
        func request(signalJoin: Bool = false) -> Task<Void, Never> {
            coordinator.request(context: 1, lifecycle: model.pauseGeneration) { ticket in
                await model.refresh(context: context, isCurrent: {
                    if signalJoin { joined.release() }
                    return coordinator.accepts(ticket, context: 1)
                }) { _, _ in
                    reads += 1; active += 1; maximumActive = max(maximumActive, active)
                    defer { active -= 1 }
                    if reads == 1 { await gate.pause() }
                    return .success([])
                }
                if coordinator.accepts(ticket, context: 1) && model.isFresh(for: context) {
                    completedConsumers += 1
                }
            }
        }
        var requests = [request()]
        await gate.waitUntilPaused()
        for index in 0..<10 {
            let previous = model.pauseGeneration
            model.pause()
            #expect(model.pauseGeneration != previous)
            #expect(reads == 1, "Pause itself must not schedule a replacement read")
            requests.append(request(signalJoin: index == 9))
        }
        await joined.pause()
        #expect(reads == 1 && active == 1)
        gate.release()
        for request in requests { await request.value }
        #expect(reads == 2 && maximumActive == 1 && completedConsumers == 1)
        #expect(model.isFresh(for: context))
    }

    @Test("Workspace uses pause generation only at list request admission, not as a SwiftUI task trigger")
    func workspaceWiring() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let text = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabApp/V2/Workspaces/V2AlertsWorkspace.swift"), encoding: .utf8)
        #expect(text.contains("let lifecycle = isAlertList ? presentation.pauseGeneration : nil"))
        #expect(text.contains("loadCoordinator.request(context: context, lifecycle: lifecycle)"))
        #expect(text.contains(".task(id: loadContext)"))
        #expect(text.contains(".onChange(of: state.refreshTick) { _ in requestReload() }"))
        #expect(!text.contains(".task(id: presentation.pauseGeneration)"))
    }
}
