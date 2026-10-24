import Foundation
import Testing
@testable import MacCrabCore
@testable import maccrabctl

@Suite("Saved suppression removal contracts")
struct SuppressionRemovalContractTests {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-suppression-contract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    @Test("legacy rule-path removal preserves every unrelated path")
    func legacyRemoval() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("suppressions.json")
        try JSONEncoder().encode(["fixture.rule": ["/Applications/One.app", "/Applications/Two.app"],
                                  "fixture.other": ["/Applications/Three.app"]]).write(to: path)
        let removal = try await MacCrabCtl.removeRuleSuppressions(directory: root.path,
            ruleId: "fixture.rule", processPath: "/Applications/One.app",
            inboxDirectory: root.appendingPathComponent("inbox").path)
        guard case .savedLegacy(1) = removal else {
            Issue.record("a v1 store is edited in place: \(removal)")
            return
        }
        let saved = try JSONDecoder().decode([String: [String]].self, from: Data(contentsOf: path))
        #expect(saved["fixture.rule"] == ["/Applications/Two.app"])
        #expect(saved["fixture.other"] == ["/Applications/Three.app"])
    }

    @Test("v2 removal asks the engine for each matching entry and leaves the store to it")
    func versionTwoRemoval() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = SuppressionManager(dataDir: root.path, publishReadableSnapshot: true)
        let removedEntry = Suppression(scope: .rulePath(ruleId: "fixture.rule", path: "/Applications/One.app"),
                                       source: .cli, reason: "Ordinary temporary allowlist")
        let retained = Suppression(createdAt: Date(timeIntervalSince1970: 1000),
            expiresAt: Date(timeIntervalSince1970: 3000), scope: .ruleHash(ruleId: "fixture.rule", sha256: "fixture-hash"),
            source: .ui, reason: "Keep this separate review decision")
        await manager.add(removedEntry)
        await manager.add(retained)
        let inbox = root.appendingPathComponent("inbox")
        let removal = try await MacCrabCtl.removeRuleSuppressions(directory: root.path,
            ruleId: "fixture.rule", processPath: "/Applications/One.app", inboxDirectory: inbox.path)
        guard case let .requested(requests) = removal else {
            Issue.record("a v2 removal goes through the engine: \(removal)")
            return
        }
        // Only the rule-path entry matches; the engine removes it from memory
        // and file together, so the CLI writes neither.
        #expect(requests.map(\.id) == [removedEntry.id])
        let name = try #require(requests.first.map { "remove-suppression-\($0.request.uuidString).json" })
        let payload = try #require(try JSONSerialization.jsonObject(
            with: Data(contentsOf: inbox.appendingPathComponent(name))) as? [String: Any])
        #expect(payload["id"] as? String == removedEntry.id)
        let saved = try #require(try SuppressionFile.read(at: root.appendingPathComponent("suppressions.json")))
        #expect(Set(saved.entries.map(\.id)) == [removedEntry.id, retained.id])
    }

    @Test("rules unsuppress reaches the root-only inbox under sudo")
    func unsuppressUsesTheRequestInbox() throws {
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrabctl/AlertCommands.swift"), encoding: .utf8)
        let start = try #require(source.range(of: "static func unsuppressRule(ruleId: String, processPath: String?) async {"))
        let end = try #require(source.range(of: "enum RemovalOutcome: Equatable {", range: start.upperBound..<source.endIndex))
        let body = String(source[start.lowerBound..<end.lowerBound])
        #expect(body.contains("inboxDirectory: requestInboxDirectory(dataDir: dataDir)"))
        #expect(!body.contains("removePersisted("))
        // One shared wait for every request, every outcome printed before the
        // failure exit, and the queued requests kept when a submission fails.
        #expect(body.contains("} catch let partial as PartialRemovalSubmission {"))
        #expect(body.components(separatedBy: "removalOutcomes(requests, timeout: 15)").count == 2)
        #expect(!body.contains("awaitTerminalReceipt("))
        let printed = try #require(body.range(of: "report.lines.forEach { print($0) }"))
        let exit = try #require(body.range(of: "if let failure = report.failure { cliFailure(failure) }"))
        #expect(printed.upperBound <= exit.lowerBound)
    }

    @Test("a partial submission names its queued requests wherever it is printed")
    func partialSubmissionDescribesItself() {
        struct DiskFull: LocalizedError { var errorDescription: String? { "No space left on device" } }
        let request = UUID()
        let partial = MacCrabCtl.PartialRemovalSubmission(queued: [("entry-1", request)], failure: DiskFull())
        #expect(partial.localizedDescription.contains(request.uuidString))
        #expect(partial.localizedDescription.contains("No space left on device"))
    }

    private func receipt(_ request: UUID, _ state: RuntimeRequestReceipt.State, reason: String = "") -> RuntimeRequestReceipt {
        RuntimeRequestReceipt(requestID: request, operation: "remove-suppression", state: state,
                              engineIdentity: EngineTelemetryIdentity(pid: 42, startedAtUnix: 1000,
                                                                      version: "1.22.0", build: "fixture"),
                              reason: reason)
    }

    @Test("unconfirmed removals share one wait instead of one wait each")
    func removalsShareOneWait() async {
        let requests = (0..<10).map { (id: "entry-\($0)", request: UUID()) }
        final class Reads: @unchecked Sendable { var count: [UUID: Int] = [:] }
        let reads = Reads()
        let start = Date()
        let outcomes = await MacCrabCtl.removalOutcomes(requests, timeout: 0.3) { request in
            reads.count[request, default: 0] += 1
            return nil
        }
        let elapsed = Date().timeIntervalSince(start)
        // Ten requests waited for in turn would take at least 3 s.
        #expect(elapsed < 2.5, "elapsed \(elapsed) s")
        #expect(outcomes.map(\.outcome) == Array(repeating: .pending, count: 10))
        #expect(requests.allSatisfy { (reads.count[$0.request] ?? 0) >= 1 })
    }

    @Test("a rejection in the middle still reports every other entry")
    func rejectionReportsTheRest() async {
        let requests = ["a", "b", "c"].map { (id: $0, request: UUID()) }
        let states: [UUID: RuntimeRequestReceipt] = [
            requests[0].request: receipt(requests[0].request, .applied),
            requests[1].request: receipt(requests[1].request, .rejected, reason: "no longer present"),
            requests[2].request: receipt(requests[2].request, .applied),
        ]
        let outcomes = await MacCrabCtl.removalOutcomes(requests, timeout: 1) { states[$0] }
        #expect(outcomes.map(\.outcome) == [.applied, .rejected(reason: "no longer present"), .applied])
        let report = MacCrabCtl.unsuppressReport(outcomes, submissionFailure: nil)
        #expect(report.lines == ["Removed a.", "The engine did not remove b: no longer present", "Removed c."])
        #expect(report.failure == "unsuppress: the engine did not remove 1 suppression(s)")
    }

    @Test("a submission that fails partway reports the requests already queued")
    func partialSubmissionIsReported() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = SuppressionManager(dataDir: root.path, publishReadableSnapshot: true)
        for scope in [SuppressionScope.rule("fixture.rule"),
                      .rulePath(ruleId: "fixture.rule", path: "/Applications/One.app"),
                      .ruleHash(ruleId: "fixture.rule", sha256: "fixture-hash")] {
            await manager.add(Suppression(scope: scope, source: .cli, reason: "Ordinary fixture"))
        }
        struct DiskFull: Error {}
        final class Calls: @unchecked Sendable { var ids: [String] = [] }
        let calls = Calls()
        let firstRequest = UUID()
        do {
            _ = try await MacCrabCtl.removeRuleSuppressions(directory: root.path, ruleId: "fixture.rule",
                processPath: nil, inboxDirectory: root.appendingPathComponent("inbox").path) { id in
                calls.ids.append(id)
                guard calls.ids.count == 1 else { throw DiskFull() }
                return firstRequest
            }
            Issue.record("the failed second submission must be reported")
        } catch let partial as MacCrabCtl.PartialRemovalSubmission {
            #expect(partial.queued.map(\.id) == [calls.ids[0]])
            #expect(partial.queued.map(\.request) == [firstRequest])
            #expect(partial.failure is DiskFull)
            let report = MacCrabCtl.unsuppressReport([(calls.ids[0], firstRequest, .pending)], submissionFailure: partial)
            #expect(report.lines.joined().contains(firstRequest.uuidString))
            #expect(report.failure?.contains("after 1 were queued") == true)
            #expect(report.failure?.contains(firstRequest.uuidString) == true)
        }
        #expect(calls.ids.count == 2, "submission stops at the failure")

        // Nothing queued yet: the failure itself is reported, as before.
        do {
            _ = try await MacCrabCtl.removeRuleSuppressions(directory: root.path, ruleId: "fixture.rule",
                processPath: nil, inboxDirectory: root.appendingPathComponent("inbox").path) { _ in throw DiskFull() }
            Issue.record("the failed submission must be reported")
        } catch {
            #expect(error is DiskFull)
        }
    }

    @Test("an unavailable storage directory refuses removal and leaves runtime state unchanged")
    func failedSave() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let manager = SuppressionManager(dataDir: root.path, publishReadableSnapshot: true)
        let entry = Suppression(scope: .rule("fixture.rule"), source: .cli, reason: "Ordinary fixture")
        await manager.add(entry)
        // Represents a volume disappearing after the store was loaded.
        try FileManager.default.removeItem(at: root)
        var failed = false
        do { _ = try await manager.removePersisted(ids: [entry.id]) }
        catch { failed = true }
        #expect(failed)
        let current = await manager.list(includeExpired: true)
        let persistError = await manager.lastPersistError
        #expect(current == [entry])
        #expect(persistError != nil)
    }
}
