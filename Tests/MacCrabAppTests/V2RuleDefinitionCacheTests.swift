import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("Rule definition cache and live telemetry separation")
struct V2RuleDefinitionCacheTests {
    // Keep the actual thread query synchronous; Thread.isMainThread is marked
    // unavailable directly from async contexts in the Swift 6 SDK.
    private nonisolated static func fixtureIsMainThread() -> Bool { Thread.isMainThread }

    private actor Probe {
        var calls = 0
        func record() { calls += 1 }
    }

    private final class StampProbe: @unchecked Sendable {
        private let lock = NSLock()
        private var samples: [Double] = []

        func read(_ directory: String) throws -> V2RuleDefinitionStamp {
            #expect(!Thread.isMainThread, "Synchronous metadata scanning must run off the main thread")
            let start = Foundation.ProcessInfo.processInfo.systemUptime
            let result = try V2RuleDefinitionStamp.read(directory: directory)
            lock.lock()
            samples.append((Foundation.ProcessInfo.processInfo.systemUptime - start) * 1_000)
            lock.unlock()
            return result
        }

        func timings() -> [Double] {
            lock.lock()
            defer { lock.unlock() }
            return samples
        }
    }

    private func fixture() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-rule-cache-\(UUID())")
        for relative in ["compiled_rules/sequences", "compiled_rules/graph", "user_rules"] {
            try FileManager.default.createDirectory(at: root.appendingPathComponent(relative), withIntermediateDirectories: true)
        }
        return root
    }

    private func writeRule(_ root: URL, folder: String = "compiled_rules", id: String = "ordinary", title: String = "Ordinary file activity",
                           enabled: Bool = true, status: String = "stable", severity: MacCrabCore.Severity = .low) throws {
        let rule = CompiledRule(id: id, title: title, description: "Inert display fixture",
            level: severity, tags: [], logsource: LogSource(category: "file_event", product: "macos"),
            predicates: [], condition: .allOf, falsepositives: [], enabled: enabled, status: status)
        try JSONEncoder().encode(rule).write(to: root.appendingPathComponent(folder + "/" + id + ".json"))
    }

    private func context(fires: UInt64, current: Bool = true, disabled: Bool = false, sameEpoch: Bool = true) -> RuleTelemetryContext {
        let now = Date(timeIntervalSince1970: 2_000)
        let identity = EngineTelemetryIdentity(pid: 42, startedAtUnix: 1_000, version: "fixture", build: "fixture")
        let snapshot = RuleEngine.TelemetrySnapshot(writtenAt: now,
            stats: [.init(ruleId: "ordinary", evaluationCount: 20, fireCount: fires)],
            autoDisabledRuleIds: disabled ? ["ordinary"] : [], engineIdentity: identity,
            loadedRuleIds: ["ordinary"], enabledRuleIds: ["ordinary"])
        let heartbeatIdentity = sameEpoch ? identity : EngineTelemetryIdentity(
            pid: 43, startedAtUnix: 1_999, version: "fixture", build: "fixture")
        return RuleTelemetryContext(snapshot: snapshot, heartbeatIdentity: heartbeatIdentity,
            heartbeatWrittenAt: now, ruleProfile: "stable", now: current ? now : now.addingTimeInterval(121))
    }

    @Test("telemetry writes never reload definitions, while counters and freshness change")
    func telemetryIsNotDefinitionInvalidation() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root)
        let probe = Probe()
        let cache = V2RuleDefinitionCache(load: { directory, profile in
            await probe.record()
            return try await V2LiveDataProvider.loadRuleDefinitions(directory: directory, profile: profile)
        })
        let first = try await cache.definitions(directory: root.path, profile: "stable")
        try Data("{\"fixture\":1}".utf8).write(to: root.appendingPathComponent("rule_telemetry.json"))
        let second = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(await probe.calls == 1)
        #expect(first.singleEvent == second.singleEvent)
        #expect(first.overlay(context(fires: 1)).first?.firesLastWeek == 1)
        #expect(second.overlay(context(fires: 9)).first?.firesLastWeek == 9)
        #expect(second.overlay(context(fires: 9, current: false)).first?.telemetryCoverage == .unknown)
        #expect(second.overlay(context(fires: 9, current: false)).first?.firesLastWeek == 0)
        #expect(second.overlay(context(fires: 9, sameEpoch: false)).first?.telemetryCoverage == .unknown)
        #expect(second.overlay(context(fires: 9, sameEpoch: false)).first?.firesLastWeek == 0)
        #expect(second.overlay(context(fires: 9, disabled: true)).first?.isEnabled == false)
    }

    @Test("a representative 5k inert corpus parses once across telemetry-only refreshes")
    func representativeCorpusColdAndWarm() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let expectedIDs = Set((0..<5_000).map { "display-fixture-\($0)" })
        for id in expectedIDs { try writeRule(root, id: id, title: "Ordinary file display \(id)") }
        let probe = Probe(), stamps = StampProbe()
        let cache = V2RuleDefinitionCache(stamp: { try stamps.read($0) }, load: { directory, profile in
            #expect(!Self.fixtureIsMainThread(), "Definition loader entry must not execute synchronous work on main")
            await probe.record()
            return try await V2LiveDataProvider.loadRuleDefinitions(directory: directory, profile: profile)
        })
        let coldStart = Foundation.ProcessInfo.processInfo.systemUptime
        let coldTask = await MainActor.run { Task { try await cache.definitions(directory: root.path, profile: "stable") } }
        let cold = try await coldTask.value
        let coldMilliseconds = (Foundation.ProcessInfo.processInfo.systemUptime - coldStart) * 1_000
        let coldIDsMatch = Set(cold.singleEvent.map(\.id)) == expectedIDs
        #expect(cold.singleEvent.count == 5_000 && coldIDsMatch)
        var warmMilliseconds: [Double] = []
        for tick in 1...2 {
            try Data("{\"fixture_tick\":\(tick)}".utf8).write(to: root.appendingPathComponent("rule_telemetry.json"))
            let start = Foundation.ProcessInfo.processInfo.systemUptime
            let warm = try await cache.definitions(directory: root.path, profile: "stable")
            warmMilliseconds.append((Foundation.ProcessInfo.processInfo.systemUptime - start) * 1_000)
            let definitionsMatch = warm.singleEvent == cold.singleEvent && warm.other == cold.other
            #expect(definitionsMatch, "Telemetry-only refresh changed definition rows")
        }
        #expect(await probe.calls == 1)
        #expect(stamps.timings().count == 4) // cold before/after, then one scan per warm request.
        // Descriptive local-fixture measurements only: no absolute speed or
        // latency claim, and no timing threshold controls pass/fail.
        print("V2_RULE_CACHE_BENIGN_5000 cold_ms=\(coldMilliseconds) warm_ms=\(warmMilliseconds) metadata_ms=\(stamps.timings())")
    }

    @Test("in-place and nested file edits invalidate without changing the parent directory mtime")
    func actualDefinitionChangesInvalidate() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root, title: "Alpha")
        let cache = V2RuleDefinitionCache()
        let first = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(first.singleEvent.first?.title == "Alpha")
        let parent = root.appendingPathComponent("compiled_rules")
        let parentDate = try #require(FileManager.default.attributesOfItem(atPath: parent.path)[.modificationDate] as? Date)
        try writeRule(root, title: "Bravo")
        // Do not set the directory mtime back: that would change directory
        // ctime and accidentally make a directory-only cache pass this test.
        let updatedParentDate = try FileManager.default.attributesOfItem(atPath: parent.path)[.modificationDate] as? Date
        #expect(updatedParentDate == parentDate)
        let next = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(next.singleEvent.first?.title == "Bravo")
        let nested = root.appendingPathComponent("compiled_rules/sequences/ordinary.json")
        try Data("{\"id\":\"ordinary-sequence\",\"title\":\"Nested A\",\"status\":\"stable\"}".utf8).write(to: nested)
        let added = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(added.other.first { $0.id == "ordinary-sequence" }?.title == "Nested A")
        try Data("{\"id\":\"ordinary-sequence\",\"title\":\"Nested B\",\"status\":\"stable\"}".utf8).write(to: nested)
        let edited = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(edited.other.first { $0.id == "ordinary-sequence" }?.title == "Nested B")
        try FileManager.default.removeItem(at: nested)
        let removed = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(!removed.other.contains { $0.id == "ordinary-sequence" })
    }

    @Test("composite JSON named manifest is tracked while base integrity metadata remains excluded")
    func compositeManifestFilenameInvalidates() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root)
        let cache = V2RuleDefinitionCache()
        for family in ["sequences", "graph"] {
            let directory = root.appendingPathComponent("compiled_rules/" + family)
            let file = directory.appendingPathComponent("manifest.json")
            let id = "ordinary-" + family
            try Data("{\"id\":\"\(id)\",\"title\":\"First\",\"status\":\"stable\"}".utf8).write(to: file)
            let first = try await cache.definitions(directory: root.path, profile: "stable")
            #expect(first.other.first { $0.id == id }?.title == "First")
            let before = try V2RuleDefinitionStamp.read(directory: root.path)
            try Data("{\"id\":\"\(id)\",\"title\":\"Later\",\"status\":\"stable\"}".utf8).write(to: file)
            let after = try V2RuleDefinitionStamp.read(directory: root.path)
            // Exact directory metadata is unchanged: only the consumed file
            // entry can invalidate this in-place, same-size rewrite.
            #expect(before.entries.filter { $0.path == directory.path } == after.entries.filter { $0.path == directory.path })
            #expect(before != after)
            let next = try await cache.definitions(directory: root.path, profile: "stable")
            #expect(next.other.first { $0.id == id }?.title == "Later")
        }
        let baseManifest = root.appendingPathComponent("compiled_rules/manifest.json")
        try Data("{\"fixture\":1}".utf8).write(to: baseManifest)
        let before = try V2RuleDefinitionStamp.read(directory: root.path)
        try Data("{\"fixture\":2}".utf8).write(to: baseManifest)
        #expect(try V2RuleDefinitionStamp.read(directory: root.path) == before)
    }

    @Test("profile, user overrides and built-in settings retain their existing effects")
    func profileAndOverrides() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root, status: "experimental")
        let cache = V2RuleDefinitionCache()
        let stable = try await cache.definitions(directory: root.path, profile: "stable")
        #expect(stable.singleEvent.first?.isEnabled == false)
        let all = try await cache.definitions(directory: root.path, profile: "all")
        #expect(all.singleEvent.first?.isEnabled == true)
        try writeRule(root, folder: "user_rules", title: "Operator label", enabled: false, severity: .high)
        let overridden = try await cache.definitions(directory: root.path, profile: "all")
        #expect(overridden.singleEvent.count == 1)
        #expect(overridden.singleEvent.first?.title == "Operator label")
        #expect(overridden.singleEvent.first?.severity == .high)
        #expect(overridden.singleEvent.first?.isEnabled == false)
        let builtin = try #require(BuiltinRuleCatalog.all.first)
        try BuiltinRuleSettings(rules: [builtin.id: .init(enabled: false, severityOverride: .low)]).save(toDir: root.path)
        let settings = try await cache.definitions(directory: root.path, profile: "all")
        #expect(settings.other.first { $0.id == builtin.id }?.isEnabled == false)
        #expect(settings.other.first { $0.id == builtin.id }?.severityOverrideRaw == "low")
    }

    @Test("a missing required corpus does not return an old successful cache")
    func failedReadIsNotStaleSuccess() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root)
        let cache = V2RuleDefinitionCache()
        _ = try await cache.definitions(directory: root.path, profile: "stable")
        try FileManager.default.removeItem(at: root.appendingPathComponent("compiled_rules"))
        do {
            _ = try await cache.definitions(directory: root.path, profile: "stable")
            Issue.record("A failed corpus read returned stale definitions")
        } catch { #expect(error is RuleEngineError) }
    }

    @Test("concurrent consumers share a load and one cancellation does not cancel another")
    func sharedLoadSurvivesOneCancellation() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root)
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate(), joined = V2DetectionFixtureGate()
        let probe = Probe()
        let cache = V2RuleDefinitionCache(load: { directory, profile in
            await probe.record()
            await entered.open()
            try await release.wait()
            return try await V2LiveDataProvider.loadRuleDefinitions(directory: directory, profile: profile)
        }, onJoin: { await joined.open() })
        let first = Task { try await cache.definitions(directory: root.path, profile: "stable") }
        defer { first.cancel(); Task { await release.open() } }
        try await entered.wait()
        let second = Task { try await cache.definitions(directory: root.path, profile: "stable") }
        defer { second.cancel() }
        try await joined.wait()
        first.cancel()
        await release.open()
        do { _ = try await first.value; Issue.record("Cancelled caller published definitions") }
        catch { #expect(error is CancellationError) }
        #expect((try await second.value).singleEvent.map(\.id) == ["ordinary"])
        #expect(await probe.calls == 1)
    }

    @Test("a different profile waits for the active load and cannot receive its gated rows")
    func overlappingProfilesDoNotMix() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root, status: "experimental")
        let entered = V2DetectionFixtureGate(), release = V2DetectionFixtureGate(), joined = V2DetectionFixtureGate()
        let probe = Probe()
        let cache = V2RuleDefinitionCache(load: { directory, profile in
            await probe.record()
            if profile == "stable" {
                await entered.open()
                try await release.wait()
            }
            return try await V2LiveDataProvider.loadRuleDefinitions(directory: directory, profile: profile)
        }, onJoin: { await joined.open() })
        let stable = Task { try await cache.definitions(directory: root.path, profile: "stable") }
        defer { stable.cancel(); Task { await release.open() } }
        try await entered.wait()
        let all = Task { try await cache.definitions(directory: root.path, profile: "all") }
        defer { all.cancel() }
        try await joined.wait()
        #expect(await probe.calls == 1)
        await release.open()
        let stableRows = try await stable.value.singleEvent
        let allRows = try await all.value.singleEvent
        #expect(stableRows.map(\.id) == ["ordinary"] && stableRows.first?.isEnabled == false)
        #expect(allRows.map(\.id) == ["ordinary"] && allRows.first?.isEnabled == true)
        #expect(await probe.calls == 2)
    }
}
