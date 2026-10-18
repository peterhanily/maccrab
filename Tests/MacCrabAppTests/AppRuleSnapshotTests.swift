import Combine
import Foundation
import MacCrabCore
import Testing
@testable import MacCrabApp

#if DEBUG
/// The old loadRules() was MainActor-isolated despite its async spelling. A
/// synchronous reader that blocks below would also block this suite's actor.
/// A bounded watchdog fails that regression; correctness uses the handshake,
/// never an elapsed-time performance threshold. No installed stores or prefs.
private final class RuleSnapshotTestGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var entered = false
    private var released = false
    private var expired = false
    private var onMainThread = false
    private var observer: CheckedContinuation<Void, Never>?
    private var watchdog: DispatchWorkItem?

    init() {
        let item = DispatchWorkItem { [weak self] in self?.expire() }
        watchdog = item
        DispatchQueue.global().asyncAfter(deadline: .now() + 30, execute: item)
    }

    deinit { watchdog?.cancel() }

    func pause() throws {
        condition.lock()
        entered = true
        onMainThread = Thread.isMainThread
        let waiting = observer
        observer = nil
        condition.unlock()
        waiting?.resume()
        condition.lock()
        while !released { condition.wait() }
        let failed = expired
        condition.unlock()
        if failed { throw CancellationError() }
    }

    func waitUntilEntered() async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                condition.lock()
                if entered || released {
                    condition.unlock()
                    continuation.resume()
                } else {
                    observer = continuation
                    condition.unlock()
                }
            }
        } onCancel: { self.release() }
    }

    var readerWasOnMainThread: Bool {
        condition.lock()
        defer { condition.unlock() }
        return onMainThread
    }

    func release() {
        condition.lock()
        released = true
        let waiting = observer
        observer = nil
        condition.broadcast()
        condition.unlock()
        watchdog?.cancel()
        waiting?.resume()
    }

    private func expire() {
        condition.lock()
        guard !released else { condition.unlock(); return }
        expired = true
        condition.unlock()
        Issue.record("Synthetic rule reader exceeded its hang deadline")
        release()
    }
}

@MainActor
@Suite("AppState off-main rule snapshots")
struct AppRuleSnapshotTests {
    private func fixture() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-snapshot-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("compiled_rules"),
                                               withIntermediateDirectories: true)
        return root
    }

    private func state(_ root: URL) -> AppState {
        AppState(engineSource: .init(directory: root.path), startBackgroundWork: false,
                 readStartupPreferences: {
            Issue.record("Inert rule fixture read startup preferences")
            return .init(fdaBannerDismissedByUser: false, agentTracesReceiverEnabled: false)
        })
    }

    private nonisolated static func row(_ id: String, enabled: Bool = true) -> RuleViewModel {
        .init(id: id, title: "Inert \(id)", level: "low", tags: ["attack.discovery"],
              description: "Synthetic display-only rule", enabled: enabled)
    }

    private func writeRule(_ root: URL, name: String, id: String, enabled: Bool = true) throws {
        let rule = CompiledRule(id: id, title: "Inert \(id)", description: "Synthetic display-only rule",
            level: .low, tags: ["attack.discovery"],
            logsource: LogSource(category: "file_event", product: "macos"), predicates: [],
            condition: .allOf, falsepositives: [], enabled: enabled, status: "experimental")
        try JSONEncoder().encode(rule).write(to: root.appendingPathComponent("compiled_rules/" + name))
    }

    @Test("Reader preserves original suffix, malformed-skip, duplicate, order and enabled semantics")
    func parserEquivalence() throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root, name: "second.json", id: "same", enabled: false)
        try writeRule(root, name: "first.json", id: "same")
        try writeRule(root, name: "ignored.JSON", id: "ignored")
        try Data("not JSON".utf8).write(to: root.appendingPathComponent("compiled_rules/malformed.json"))
        try FileManager.default.createDirectory(at: root.appendingPathComponent("compiled_rules/directory.json"),
                                               withIntermediateDirectories: false)
        let files = ["second.json", "malformed.json", "ignored.JSON", "directory.json", "absent.json", "first.json"]
        let directory = root.appendingPathComponent("compiled_rules").path
        // Exact previous parser as the independent equivalence oracle.
        let decoder = JSONDecoder()
        let expected: [RuleViewModel] = files.compactMap { file in
            guard file.hasSuffix(".json"),
                  let data = try? Data(contentsOf: URL(fileURLWithPath: directory + "/" + file)),
                  let rule = try? decoder.decode(CompiledRule.self, from: data) else { return nil }
            return RuleViewModel(id: rule.id, title: rule.title, level: rule.level.rawValue,
                                 tags: rule.tags, description: rule.description, enabled: rule.enabled)
        }
        let actual = try AppRuleSnapshotReader.decode(directory: directory, files: files)
        #expect(actual == expected)
        #expect(actual == [Self.row("same", enabled: false), Self.row("same")])
    }

    @Test("The mtime shortcut requires matching directory, nonempty cache and existing JSON entries")
    func cacheContract() throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeRule(root, name: "rule.json", id: "ordinary")
        let directory = root.appendingPathComponent("compiled_rules").path
        let first = try AppRuleSnapshotReader.read(.init(directory: directory))
        guard case .loaded(let rows, let mtime) = first else {
            Issue.record("Owned corpus did not load"); return
        }
        #expect(rows == [Self.row("ordinary")])
        let knownMtime = try #require(mtime)
        let request = AppRuleSnapshotRequest(directory: directory, cachedDirectory: directory,
                                             cachedModificationDate: knownMtime, hasCachedRows: true)
        #expect(try AppRuleSnapshotReader.read(request) == .unchanged)
        #expect(try AppRuleSnapshotReader.read(.init(directory: directory, cachedDirectory: directory,
            cachedModificationDate: knownMtime, hasCachedRows: false)) == first)
        #expect(try AppRuleSnapshotReader.read(.init(directory: directory, cachedDirectory: directory + "/other",
            cachedModificationDate: knownMtime, hasCachedRows: true)) == first)
        try FileManager.default.removeItem(at: root.appendingPathComponent("compiled_rules/rule.json"))
        #expect(try AppRuleSnapshotReader.read(request) == .missing)
    }

    @Test("Missing or malformed corpus retries; valid accepted data latches; unchanged cache does not republish")
    func retryAndPublishContract() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root)
        #expect(await app.loadRules() == false)
        #expect(!app.ruleSnapshotAcceptedForTesting && app.rules.isEmpty && app.rulesLoaded == 0)
        try Data("invalid".utf8).write(to: root.appendingPathComponent("compiled_rules/bad.json"))
        #expect(await app.loadRules() == false)
        #expect(!app.ruleSnapshotAcceptedForTesting)
        try writeRule(root, name: "rule.json", id: "ordinary")
        #expect(await app.loadRules())
        #expect(app.rules == [Self.row("ordinary")] && app.rulesLoaded == 1)
        #expect(app.ruleSnapshotAcceptedForTesting)
        var emissions = 0
        let token = app.objectWillChange.sink { emissions += 1 }
        defer { token.cancel() }
        #expect(await app.loadRules())
        #expect(emissions == 0)
    }

    @Test("A blocked synchronous reader is off-main and leaves MainActor responsive")
    func offMainReader() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root), gate = RuleSnapshotTestGate()
        defer { gate.release() }
        let directory = root.appendingPathComponent("compiled_rules").path
        let task = Task { @MainActor in
            await app.loadRules(readSnapshot: { request in
                #expect(request.directory == directory)
                try gate.pause()
                return .loaded(rows: [Self.row("ordinary")], modificationDate: nil)
            })
        }
        await gate.waitUntilEntered()
        // Reaching this actor while its reader is still blocked is the oracle.
        #expect(!gate.readerWasOnMainThread && app.rules.isEmpty)
        gate.release()
        #expect(await task.value)
        #expect(app.rules == [Self.row("ordinary")])
    }

    @Test("An older noncooperative read cannot overwrite a newer accepted request")
    func requestSupersession() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root), gate = RuleSnapshotTestGate()
        defer { gate.release() }
        let old = Task { @MainActor in
            await app.loadRules(readSnapshot: { _ in
                try gate.pause()
                return .loaded(rows: [Self.row("old")], modificationDate: nil)
            })
        }
        await gate.waitUntilEntered()
        #expect(await app.loadRules(readSnapshot: { _ in
            .loaded(rows: [Self.row("new")], modificationDate: nil)
        }))
        gate.release()
        #expect(await old.value == false)
        #expect(app.rules == [Self.row("new")] && app.ruleSnapshotAcceptedForTesting)
    }

    @Test("Cancellation rejects a late successful value without latching previously displayed rules")
    func cancellationCannotLatchOldData() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root), gate = RuleSnapshotTestGate()
        defer { gate.release() }
        app.rules = [Self.row("displayed")]
        app.rulesLoaded = 1
        var emissions = 0
        let token = app.objectWillChange.sink { emissions += 1 }
        defer { token.cancel() }
        let task = Task { @MainActor in
            await app.loadRules(readSnapshot: { _ in
                try gate.pause() // Intentionally returns a value despite cancellation.
                return .loaded(rows: [Self.row("late")], modificationDate: nil)
            })
        }
        await gate.waitUntilEntered()
        task.cancel()
        gate.release()
        #expect(await task.value == false)
        #expect(app.rules == [Self.row("displayed")] && app.rulesLoaded == 1)
        #expect(!app.ruleSnapshotAcceptedForTesting && emissions == 0)
        #expect(await app.loadRules(readSnapshot: { _ in
            .loaded(rows: [Self.row("restarted")], modificationDate: nil)
        }))
        #expect(app.rules == [Self.row("restarted")] && app.ruleSnapshotAcceptedForTesting)
    }

    @Test("A poll-stop generation alone rejects late publication without starting timers")
    func pollingGeneration() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root), gate = RuleSnapshotTestGate()
        defer { gate.release() }
        // First stop closes event admission; the second increments only the
        // poll generation, proving it is checked independently of store epoch.
        app.stopPolling()
        let epoch = app.eventQueryEpoch
        let task = Task { @MainActor in
            await app.loadRules(readSnapshot: { _ in
                try gate.pause()
                return .loaded(rows: [Self.row("late")], modificationDate: nil)
            })
        }
        await gate.waitUntilEntered()
        app.stopPolling()
        #expect(app.eventQueryEpoch == epoch)
        gate.release()
        #expect(await task.value == false)
        #expect(app.rules.isEmpty && !app.ruleSnapshotAcceptedForTesting)
    }

    @Test("Source epoch changes reject an old snapshot", arguments: [false, true])
    func sourceEpoch(engineRestart: Bool) async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root), gate = RuleSnapshotTestGate()
        defer { gate.release() }
        if engineRestart {
            _ = app.reconcileEngineIdentity(.init(pid: 101, startedAtUnix: 100, version: "fixture", build: "fixture"))
        }
        let task = Task { @MainActor in
            await app.loadRules(readSnapshot: { _ in
                try gate.pause()
                return .loaded(rows: [Self.row("old-source")], modificationDate: nil)
            })
        }
        await gate.waitUntilEntered()
        if engineRestart {
            #expect(app.reconcileEngineIdentity(.init(pid: 102, startedAtUnix: 200, version: "fixture", build: "fixture")))
        } else { _ = app.reconcileEventReadDeferral(true) }
        gate.release()
        #expect(await task.value == false)
        #expect(app.rules.isEmpty && app.rulesLoaded == 0 && !app.ruleSnapshotAcceptedForTesting)
    }

    @Test("An already-cancelled request never invokes the reader")
    func cancelledBeforeStart() async throws {
        let root = try fixture()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = state(root)
        let task = Task { @MainActor in
            await app.loadRules(readSnapshot: { _ in
                Issue.record("Cancelled request invoked reader")
                return .missing
            })
        }
        task.cancel()
        #expect(await task.value == false)
        #expect(!app.ruleSnapshotAcceptedForTesting)
    }
}
#endif
