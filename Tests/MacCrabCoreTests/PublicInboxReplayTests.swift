import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// A user can keep a link to the console user's request in the 1777 inbox and
/// rename it back in once the engine has consumed it. Public requests must be
/// fresh, and an inode seen once is not accepted again.
@Suite("Public inbox freshness and replay")
struct PublicInboxReplayTests {
    private typealias Inode = DaemonTimers.SeenInboxInodes.Inode

    @Test("a public request must be fresh and new, whoever owns it")
    func freshnessAndReplay() {
        let seen = DaemonTimers.SeenInboxInodes()
        let now: TimeInterval = 1_000_000
        func refusal(_ number: UInt64, age: TimeInterval = 5) -> DaemonTimers.PublicInboxRefusal? {
            DaemonTimers.publicInboxRefusal(
                birthTime: now - age, now: now, inode: Inode(device: 1, number: number), seen: seen)
        }
        #expect(refusal(42) == nil, "a fresh, new request is accepted")
        #expect(refusal(42) == .replayed, "the same inode again is a replay")
        #expect(refusal(43, age: 601) == .stale)
        #expect(refusal(44, age: -61) == .future)
        #expect(refusal(45, age: -59) == nil, "a little clock skew is tolerated")
        // Refused stale and future entries can never be accepted, so they
        // are not recorded.
        #expect(seen.count == 2, "42 and 45 only")
        #expect(refusal(43, age: 5) == nil)
    }

    @Test("old files linked in by the thousand cannot push out a live record")
    func staleFloodCannotEvictARecord() {
        let seen = DaemonTimers.SeenInboxInodes()
        let now: TimeInterval = 2_000_000
        let harvested = Inode(device: 1, number: 7)
        #expect(DaemonTimers.publicInboxRefusal(birthTime: now - 3, now: now, inode: harvested, seen: seen) == nil)
        for number in 1_000..<(1_000 + 4_096) as Range<UInt64> {
            #expect(DaemonTimers.publicInboxRefusal(
                birthTime: now - 3_600, now: now, inode: Inode(device: 1, number: number), seen: seen) == .stale)
        }
        #expect(DaemonTimers.publicInboxRefusal(birthTime: now - 3, now: now + 40, inode: harvested, seen: seen)
                == .replayed)
    }

    @Test("records leave by age, once their file could no longer be fresh")
    func recordsExpireByAge() {
        let seen = DaemonTimers.SeenInboxInodes(retention: 660, capacity: 100_000)
        let now: TimeInterval = 3_000_000
        for number in 0..<100 as Range<UInt64> {
            #expect(!seen.checkAndRecord(Inode(device: 2, number: number), birthTime: now, now: now))
        }
        #expect(seen.count == 100)
        #expect(!seen.checkAndRecord(Inode(device: 2, number: 500), birthTime: now + 700, now: now + 700))
        #expect(seen.count == 1, "the first hundred are past the window")
        // The backstop cap holds even with a stuck clock.
        let capped = DaemonTimers.SeenInboxInodes(retention: 660, capacity: 3)
        for number in 0..<10 as Range<UInt64> {
            _ = capped.checkAndRecord(Inode(device: 3, number: number), birthTime: now, now: now)
        }
        #expect(capped.count == 3)
    }

    @Test("the owner check refuses a stale public request, says why, and keeps other directories unchanged")
    func ownerCheckAppliesFreshness() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-public-inbox-\(UUID().uuidString)").path
        let inbox = base + "/" + InboxDirectories.publicName
        let elsewhere = base + "/elsewhere"
        try FileManager.default.createDirectory(atPath: inbox, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: elsewhere, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: base) }

        let old = Date().addingTimeInterval(-3_600)
        for directory in [inbox, elsewhere] {
            let file = directory + "/reload-rules-\(UUID().uuidString).json"
            #expect(FileManager.default.createFile(atPath: file, contents: Data("{}".utf8)))
            try FileManager.default.setAttributes([.creationDate: old], ofItemAtPath: file)
            let expected = directory == inbox ? -1 : Int(getuid())
            #expect(DaemonTimers.requestOwnerUID(at: file) == expected, "\(directory)")
            let owner = DaemonTimers.requestOwner(at: file)
            if directory == inbox {
                #expect(owner.refusal == .stale)
                #expect(owner.rejectionResult == "refused_stale")
                #expect(owner.auditUID == Int(getuid()), "audited as its real owner")
                #expect(owner.rejectionReason == "Request is more than 10 minutes old")
            } else {
                #expect(owner.refusal == nil)
            }
        }
        let fresh = inbox + "/reload-rules-\(UUID().uuidString).json"
        #expect(FileManager.default.createFile(atPath: fresh, contents: Data("{}".utf8)))
        #expect(DaemonTimers.requestOwnerUID(at: fresh) == Int(getuid()))
        let unauthorized = DaemonTimers.InboxRequestOwner(uid: -1, refusal: nil, fileOwner: 502)
        #expect(unauthorized.rejectionResult == "rejected_uid")
        #expect(unauthorized.auditUID == -1)
        #expect(unauthorized.rejectionReason == "Request owner is not authorized")
    }

    @Test("a request rejected while linked elsewhere cannot be renamed back in")
    func savedLinkIsNotReplayed() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-public-replay-\(UUID().uuidString)").path
        let inbox = base + "/" + InboxDirectories.publicName
        let saved = base + "/saved"
        try FileManager.default.createDirectory(atPath: inbox, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: saved, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: base) }

        let request = inbox + "/trace-dashboard-key-\(UUID().uuidString).json"
        #expect(FileManager.default.createFile(atPath: request, contents: Data("{}".utf8)))
        let link = saved + "/kept.json"
        #expect(Darwin.link(request, link) == 0)
        // The engine sees two links and rejects it; the inode is remembered.
        #expect(DaemonTimers.requestOwnerUID(at: request) == -1)
        DaemonTimers.removeInboxEntry(at: request)
        // The saved link, now the only one, renamed back in under another verb.
        let replay = inbox + "/reload-rules-\(UUID().uuidString).json"
        #expect(rename(link, replay) == 0)
        #expect(DaemonTimers.requestOwner(at: replay).refusal == .replayed)
    }

    @Test("an unclaimed request the poller discards cannot come back under a claimed name")
    func discardedRequestIsRemembered() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-public-discard-\(UUID().uuidString)").path
        let inbox = base + "/" + InboxDirectories.publicName
        let saved = base + "/saved"
        try FileManager.default.createDirectory(atPath: inbox, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: saved, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: base) }

        let unclaimed = inbox + "/no-such-verb-\(UUID().uuidString).json"
        #expect(FileManager.default.createFile(atPath: unclaimed, contents: Data("{}".utf8)))
        let link = saved + "/kept.json"
        #expect(Darwin.link(unclaimed, link) == 0)
        let scan = DaemonTimers.inboxScanBatch(
            scanner: DaemonTimers.InboxDirectoryScanner(path: inbox), inboxDir: inbox)
        #expect(scan.requestNames.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: unclaimed), "discarded")
        let replay = inbox + "/flush-request-\(UUID().uuidString).json"
        #expect(rename(link, replay) == 0)
        #expect(DaemonTimers.requestOwner(at: replay).refusal == .replayed)
    }

    @Test("every handler audits a refused request as its real owner, and answers it with the reason")
    func handlersAuditAndAnswerTheRefusal() throws {
        // Building a DaemonState for one handler is out of reach in a unit
        // test, so each owner check's rejection branch is pinned in the source.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let timers = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"), encoding: .utf8)
        let checks = timers.components(separatedBy: "let owner = requestOwner(at: path)").dropFirst()
        #expect(checks.count == 20, "owner checks: \(checks.count)")
        var answered = 0
        for (index, handler) in checks.enumerated() {
            let audit = try #require(handler.range(of: "uid: owner.auditUID, result: owner.rejectionResult)"),
                                     "owner check \(index + 1) never audits its refusal")
            let branch = handler[..<audit.lowerBound]
            #expect(branch.count < 1_000, "owner check \(index + 1): that audit belongs to a later handler")
            #expect(!branch.contains("result: \"rejected"), "owner check \(index + 1) audits a refusal without its reason")
            if branch.contains("state: .rejected") {
                #expect(branch.contains("owner.rejectionReason"), "owner check \(index + 1) answers without the reason")
                answered += 1
            }
        }
        #expect(answered == 3, "set-daemon-config, remove-suppression and reload-rules answer a refusal")
    }

    @Test("every verb the dashboard queues is one the engine claims, campaign restore included")
    func dashboardVerbsAreClaimed() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let provider = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabApp/V2/Data/V2LiveDataProvider.swift"),
            encoding: .utf8)
        let pattern = try NSRegularExpression(pattern: #"queueInboxMutation\(prefix: "([a-z-]+)""#)
        let ns = provider as NSString
        let verbs = pattern.matches(in: provider, range: NSRange(location: 0, length: ns.length))
            .map { ns.substring(with: $0.range(at: 1)) }
        #expect(verbs.contains("unsuppress-campaign"))
        for verb in Set(verbs) {
            #expect(DaemonTimers.knownInboxRequestPrefixes.contains(verb + "-"), "\(verb) is never handled")
        }
        let timers = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"), encoding: .utf8)
        #expect(timers.contains("await handleUnsuppressCampaignRequests(unsuppressCampaignReqs, inboxDir: inboxDir, state: state)"))
        let handler = try #require(timers.range(of: "private static func handleUnsuppressCampaignRequests("))
        let body = timers[handler.upperBound...].prefix(2_000)
        #expect(body.contains("state.alertStore.unsuppress(campaignId: id)"))
        #expect(body.contains("setSuppressed(id: id, false)"))
        #expect(body.contains("isAuthorizedInboxRequest(uid: uid, rootChannel: isRootInbox(inboxDir))"))
    }
}
