import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// A root-owned file in the 1777 inbox proves nothing: any user can keep a
/// link to an inode the engine later replaces and rename it in. Root requests
/// count only from the root-only inbox.
@Suite("Root-only request inbox")
struct RootInboxChannelTests {
    private func temporaryDirectory() throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-root-inbox-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false)
        return path
    }

    private func chmodACL(_ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = arguments
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    @Test("root's requests go to the root-only inbox; everyone else's to the public one")
    func requestDirectoryFollowsTheUser() {
        #expect(InboxDirectories.requestDirectory(dataDir: "/d", effectiveUID: 0) == "/d/inbox-root")
        #expect(InboxDirectories.requestDirectory(dataDir: "/d", effectiveUID: 501) == "/d/inbox")
        #expect(DaemonTimers.isRootInbox("/Library/Application Support/MacCrab/inbox-root"))
        #expect(!DaemonTimers.isRootInbox("/Library/Application Support/MacCrab/inbox"))
    }

    @Test("an extended ACL closes the root-only inbox, at the engine and for a root writer")
    func extendedACLIsRefused() throws {
        let base = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let inbox = base + "/" + InboxDirectories.rootName
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox))
        #expect(InboxDirectories.isPrivateDirectory(at: inbox))
        #expect(try InboxDirectories.preparedRequestDirectory(dataDir: base, effectiveUID: 0) == inbox)

        // An entry letting another user add a file defeats the 0700 mode.
        #expect(try chmodACL(["+a", "everyone allow add_file", inbox]) == 0)
        #expect(!InboxDirectories.isPrivateDirectory(at: inbox))
        #expect(!DaemonTimers.ensureRootInboxDirectory(at: inbox))
        #expect(throws: (any Error).self) {
            try InboxDirectories.preparedRequestDirectory(dataDir: base, effectiveUID: 0)
        }

        #expect(try chmodACL(["-N", inbox]) == 0)
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox))

        // A widened mode is refused by the writer, narrowed by the engine.
        chmod(inbox, 0o755)
        #expect(!InboxDirectories.isPrivateDirectory(at: inbox))
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox))
        let link = base + "/linked"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: inbox)
        #expect(!InboxDirectories.isPrivateDirectory(at: link))
    }

    @Test("each channel reaches one dispatcher, and every handler authorizes by its channel")
    func pollerWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let timers = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"), encoding: .utf8)
        #expect(timers.contains("let rootInboxDir = state.supportDir + \"/\" + InboxDirectories.rootName"))
        #expect(timers.contains(".filter(isClaimedInboxRequestName)"))
        #expect(timers.contains("Array(rootRequests), inboxDir: rootInboxDir, state: state, rootChannel: true)"))
        #expect(timers.contains("await dispatchInboxRequests(files, inboxDir: inboxDir, state: state, rootChannel: false)"))
        // No handler may authorize without naming its channel.
        #expect(!timers.contains("isAuthorizedInboxRequest(uid: uid)"))
        let byDirectory = timers.components(
            separatedBy: "isAuthorizedInboxRequest(uid: uid, rootChannel: isRootInbox(inboxDir))").count - 1
        let explicit = timers.components(
            separatedBy: "isAuthorizedInboxRequest(uid: uid, rootChannel: rootChannel)").count - 1
        #expect(byDirectory == 18)
        #expect(explicit == 1, "the capability handler uses the dispatcher's channel")
        // The engine's system support directory is the one the CLI writes under.
        let setup = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonSetup.swift"), encoding: .utf8)
        #expect(setup.contains("supportDir = \"/Library/Application Support/MacCrab\""))
    }
}
