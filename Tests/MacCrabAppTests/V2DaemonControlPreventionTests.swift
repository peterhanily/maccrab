// V2DaemonControlPreventionTests.swift
// MacCrabAppTests
//
// Prevention control-plane (v1.21.4): the Prevention tab's per-module
// enable/disable toggle can't mutate the root-owned prevention state directly
// (the app runs as uid-501) nor `pkill` the sysext cross-uid (EPERM), so each
// toggle drops a `prevention-config-*.json` request the root engine applies
// live. These tests pin the app-side writer to the EXACT daemon partition
// contract in DaemonTimers.swift — `hasPrefix("prevention-config-") &&
// hasSuffix(".json")` — mirroring the delete-alert / prune-alerts writer tests.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2DaemonControl — prevention-config inbox request writer")
struct V2DaemonControlPreventionTests {

    @Test("writes a prevention-config-*.json the daemon poller will match, carrying the module toggles")
    func writesPreventionRequest() throws {
        let tmp = NSTemporaryDirectory() + "maccrab-prevention-test-" + UUID().uuidString
        let inbox = tmp + "/inbox"
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        #expect(V2DaemonControl.writePreventionConfigRequest(
            inboxDir: inbox,
            payload: ["sinkhole": false, "network_blocker": true]))

        let files = (try? FileManager.default.contentsOfDirectory(atPath: inbox)) ?? []
        // Daemon partition contract (DaemonTimers.swift inbox poller):
        // hasPrefix("prevention-config-") && hasSuffix(".json")
        let matched = files.filter { $0.hasPrefix("prevention-config-") && $0.hasSuffix(".json") }
        #expect(matched.count == 1)

        let data = try Data(contentsOf: URL(fileURLWithPath: inbox + "/" + matched[0]))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        // Module keys must match the daemon handler's expected keys exactly.
        #expect(obj?["sinkhole"] as? Bool == false)
        #expect(obj?["network_blocker"] as? Bool == true)
        #expect(obj?["source"] as? String == "MacCrabApp")
        // A module the caller didn't specify must NOT be present (nil = untouched).
        #expect(obj?["persistence_guard"] == nil)
    }

    @Test("carries only the persistence_guard key when that's the only module toggled")
    func writesSingleModule() throws {
        let tmp = NSTemporaryDirectory() + "maccrab-prevention-single-" + UUID().uuidString
        let inbox = tmp + "/inbox"
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        #expect(V2DaemonControl.writePreventionConfigRequest(
            inboxDir: inbox, payload: ["persistence_guard": true]))

        let files = (try? FileManager.default.contentsOfDirectory(atPath: inbox)) ?? []
        let matched = files.filter { $0.hasPrefix("prevention-config-") && $0.hasSuffix(".json") }
        #expect(matched.count == 1)

        let data = try Data(contentsOf: URL(fileURLWithPath: inbox + "/" + matched[0]))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["persistence_guard"] as? Bool == true)
        #expect(obj?["sinkhole"] == nil)
        #expect(obj?["network_blocker"] == nil)
    }

    @Test("prevention writer reports false on an unwritable path (honest failure)")
    func preventionHonestFailure() {
        let tmpFile = NSTemporaryDirectory() + "maccrab-prevention-notdir-" + UUID().uuidString
        FileManager.default.createFile(atPath: tmpFile, contents: Data("x".utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }
        // A regular file where a directory is expected — createDirectory + write both fail.
        #expect(!V2DaemonControl.writePreventionConfigRequest(
            inboxDir: tmpFile + "/inbox", payload: ["sinkhole": true]))
    }
}
