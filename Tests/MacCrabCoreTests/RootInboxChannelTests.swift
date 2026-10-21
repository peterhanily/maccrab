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

    @Test("whatever arrived while the root-only inbox was unsafe is discarded, not dispatched")
    func taintedInboxIsPurged() throws {
        let base = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let inbox = base + "/" + InboxDirectories.rootName
        let marker = inbox + ".tainted"
        var discarded: [String] = []
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox) { discarded.append($0) })
        #expect(!FileManager.default.fileExists(atPath: marker))

        // An ACL closes the channel and taints it; a request planted meanwhile
        // is dropped once the ACL is gone, before any dispatch.
        #expect(try chmodACL(["+a", "everyone allow add_file", inbox]) == 0)
        #expect(!DaemonTimers.ensureRootInboxDirectory(at: inbox) { discarded.append($0) })
        #expect(FileManager.default.fileExists(atPath: marker), "the taint survives a restart")
        #expect(FileManager.default.createFile(atPath: inbox + "/reload-rules-a.json", contents: Data("{}".utf8)))
        #expect(try chmodACL(["-N", inbox]) == 0)
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox) { discarded.append($0) })
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox).isEmpty)
        #expect(discarded == ["reload-rules-a.json"])
        #expect(!FileManager.default.fileExists(atPath: marker))

        // A widened mode is narrowed and its entries discarded in the same check.
        chmod(inbox, 0o755)
        #expect(FileManager.default.createFile(atPath: inbox + "/flush-request-b.json", contents: Data("{}".utf8)))
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox) { discarded.append($0) })
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox).isEmpty)
        #expect(discarded == ["reload-rules-a.json", "flush-request-b.json"])

        // A safe directory keeps its requests.
        #expect(FileManager.default.createFile(atPath: inbox + "/reload-rules-c.json", contents: Data("{}".utf8)))
        #expect(DaemonTimers.ensureRootInboxDirectory(at: inbox) { discarded.append($0) })
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox) == ["reload-rules-c.json"])
    }

    @Test("an inbox seen unsafe is purged even when its taint marker cannot be written")
    func unwritableMarkerStillPurges() throws {
        let base = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let inbox = base + "/" + InboxDirectories.rootName
        var discarded: [String] = []
        func ensure() -> Bool {
            DaemonTimers.ensureRootInboxDirectory(at: inbox, writesTaintMarker: false) { discarded.append($0) }
        }
        #expect(ensure())

        // An ACL taints the directory in memory; the planted request is still
        // dropped once the ACL is gone, though no marker was written.
        #expect(try chmodACL(["+a", "everyone allow add_file", inbox]) == 0)
        #expect(!ensure())
        #expect(!FileManager.default.fileExists(atPath: inbox + ".tainted"))
        #expect(FileManager.default.createFile(atPath: inbox + "/reload-rules-a.json", contents: Data("{}".utf8)))
        #expect(try chmodACL(["-N", inbox]) == 0)
        #expect(ensure())
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox).isEmpty)
        #expect(discarded == ["reload-rules-a.json"])

        // A widened mode is purged in the same call, marker or not.
        chmod(inbox, 0o755)
        #expect(FileManager.default.createFile(atPath: inbox + "/flush-request-b.json", contents: Data("{}".utf8)))
        #expect(ensure())
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox).isEmpty)
        #expect(discarded == ["reload-rules-a.json", "flush-request-b.json"])

        // Once purged, a safe directory keeps its requests.
        #expect(FileManager.default.createFile(atPath: inbox + "/reload-rules-c.json", contents: Data("{}".utf8)))
        #expect(ensure())
        #expect(try FileManager.default.contentsOfDirectory(atPath: inbox) == ["reload-rules-c.json"])
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
        #expect(byDirectory == 19, "18 verbs plus the campaign restore")
        #expect(explicit == 1, "the capability handler uses the dispatcher's channel")
        // The root dispatch call itself, and grants handled only through the
        // dispatcher, which sets the audit line's channel.
        #expect(timers.range(of: #"await dispatchInboxRequests\(\s*Array\(rootRequests\)"#,
                              options: .regularExpression) != nil)
        let verbs = try #require(timers.range(of: "private static func dispatchInboxVerbs("))
        let verbsBody = timers[verbs.upperBound...]
        let verbsEnd = verbsBody.range(of: "\n    private static func ")?.lowerBound ?? verbsBody.endIndex
        let grantCalls = timers.components(separatedBy: "handleSetAgentCapabilitiesRequests(").count - 1
        let grantCallsInDispatcher = verbsBody[..<verbsEnd]
            .components(separatedBy: "handleSetAgentCapabilitiesRequests(").count - 1
        #expect(grantCallsInDispatcher == 1)
        #expect(grantCalls == 2, "one declaration and one call, inside the dispatcher")
        #expect(timers.contains("await $inboxAuditChannel.withValue(rootChannel ? \"root\" : \"public\")"))
        #expect(timers.contains("source=inbox\\(channelField) prefix="))
        #expect(timers.contains("root-only request directory is usable again"))
        // A System Extension's stdout is discarded: state changes and refusals
        // reach the unified log.
        #expect(timers.contains("inboxLogger.warning(\"Root-only request directory unavailable"))
        #expect(timers.contains("inboxLogger.notice(\"Root-only request directory is usable again"))
        #expect(timers.contains("inboxLogger.notice(\"Refused inbox request"))
        // `sudo maccrabctl trace …` asks through the inbox its user may write.
        let exchange = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Storage/TraceDashboardKeyExchange.swift"),
            encoding: .utf8)
        let resolve = try #require(exchange.range(of: "public static func resolveEncryption("))
        #expect(exchange[resolve.upperBound...].prefix(1_500)
            .contains("InboxDirectories.preparedRequestDirectory(dataDir: supportDir)"))
        // The engine's system support directory is the one the CLI writes under.
        let setup = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonSetup.swift"), encoding: .utf8)
        #expect(setup.contains("supportDir = \"/Library/Application Support/MacCrab\""))
    }
}
