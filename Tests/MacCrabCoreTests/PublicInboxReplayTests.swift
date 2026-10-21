import Foundation
import SystemConfiguration
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// A user can keep a link to the console user's request in the 1777 inbox and
/// rename it back in once the engine has consumed it. Public requests must be
/// fresh, and an inode seen once is not accepted again.
@Suite("Public inbox freshness and replay")
struct PublicInboxReplayTests {
    private typealias Inode = DaemonTimers.SeenInboxInodes.Inode

    @Test("a public request must be fresh and new; only console-user inodes are remembered")
    func freshnessAndReplay() {
        let seen = DaemonTimers.SeenInboxInodes(capacity: 5)
        let now: TimeInterval = 1_000_000
        func refusal(_ number: UInt64, age: TimeInterval = 5, console: Bool = true) -> DaemonTimers.PublicInboxRefusal? {
            DaemonTimers.publicInboxRefusal(
                birthTime: now - age, now: now, inode: Inode(device: 1, number: number),
                ownedByConsoleUser: console, seen: seen)
        }
        #expect(refusal(42) == nil, "a fresh, new console request is accepted")
        #expect(refusal(42) == .replayed, "the same inode again is a replay")
        #expect(refusal(43, age: 601) == .stale)
        #expect(refusal(44, age: -61) == .future)
        #expect(refusal(45, age: -59) == nil, "a little clock skew is tolerated")

        // Another user's files are never recorded, so they cannot push the
        // console user's inodes out of the bounded set.
        #expect(refusal(50, console: false) == nil)
        #expect(refusal(50, console: false) == nil)
        #expect(seen.count == 4, "42-45 are recorded, refused or not; 50 is not")
        #expect(refusal(42) == .replayed)

        // Once full, the oldest record is forgotten first.
        #expect(refusal(46) == nil)
        #expect(refusal(47) == nil)
        #expect(seen.count == 5)
        #expect(refusal(42) == nil, "42 was the oldest record")
        #expect(refusal(44, age: -61) == .replayed, "44 is still remembered")
    }

    @Test("the owner check refuses a stale public request and keeps other directories unchanged")
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
        }
        let fresh = inbox + "/reload-rules-\(UUID().uuidString).json"
        #expect(FileManager.default.createFile(atPath: fresh, contents: Data("{}".utf8)))
        #expect(DaemonTimers.requestOwnerUID(at: fresh) == Int(getuid()))
    }

    @Test("a console-user request rejected while linked elsewhere cannot be renamed back in")
    func savedLinkIsNotReplayed() throws {
        var consoleUID: uid_t = 0
        var group: gid_t = 0
        let store = SCDynamicStoreCreate(nil, "MacCrabReplayTest" as CFString, nil, nil)
        guard let user = SCDynamicStoreCopyConsoleUser(store, &consoleUID, &group),
              (user as String) != "loginwindow", consoleUID == getuid() else {
            return  // Only the console user's inodes are remembered.
        }
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
        #expect(DaemonTimers.requestOwnerUID(at: replay) == -1)
    }
}
