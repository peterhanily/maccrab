// InboxRefreshRequestTests.swift
// v1.17 pull-refresh-transport: the dashboard "Refresh now" button and
// `maccrabctl intel refresh` now drop a `refresh-intel-<token>.json`
// into the daemon's inbox instead of `pkill -USR1` (which fails EPERM
// cross-uid). These tests pin the file format the daemon's poller
// filters on (prefix `refresh-intel-`, suffix `.json`) and the
// honest-failure contract (write into a non-writable dir returns false).
import Foundation
import Testing
@testable import MacCrabApp

@Suite("Inbox refresh-intel request writer")
struct InboxRefreshRequestTests {
    @Test("writes a refresh-intel-*.json the daemon poller will match")
    func writesMatchingFile() throws {
        let tmp = NSTemporaryDirectory() + "maccrab-refresh-test-" + UUID().uuidString
        let inbox = tmp + "/inbox"
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let ok = V2LiveDataProvider.writeInboxRefreshRequest(inboxDir: inbox)
        #expect(ok)

        let files = (try? FileManager.default.contentsOfDirectory(atPath: inbox)) ?? []
        // The daemon partitions with: hasPrefix("refresh-intel-") && hasSuffix(".json")
        let matched = files.filter { $0.hasPrefix("refresh-intel-") && $0.hasSuffix(".json") }
        #expect(matched.count == 1)

        // Payload is a JSON object the daemon does NOT require an `id`
        // from (refresh is parameterless) but must be valid JSON.
        let data = try Data(contentsOf: URL(fileURLWithPath: inbox + "/" + matched[0]))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["source"] as? String == "MacCrabApp")
        #expect(obj?["queuedAt"] != nil)
    }

    @Test("returns false when the inbox dir cannot be created (honest failure)")
    func honestFailureOnUnwritablePath() {
        // A path under a regular file can never become a directory, so
        // createDirectory + write both fail — the writer must report
        // false rather than a fake success (the core of the bug fix).
        let tmpFile = NSTemporaryDirectory() + "maccrab-not-a-dir-" + UUID().uuidString
        FileManager.default.createFile(atPath: tmpFile, contents: Data("x".utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let ok = V2LiveDataProvider.writeInboxRefreshRequest(inboxDir: tmpFile + "/inbox")
        #expect(!ok)
    }
}
