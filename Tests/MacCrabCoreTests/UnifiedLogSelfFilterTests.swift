import Foundation
import os
import Testing
@testable import MacCrabCore

@Suite("Unified log collector ignores the engine's own log lines")
struct UnifiedLogSelfFilterTests {
    private func entry(pid: Int) -> [String: Any] {
        [
            "subsystem": "com.apple.securityd",
            "category": "integrity",
            "eventMessage": "SecStaticCode validation",
            "processImagePath": "/Library/SystemExtensions/x/com.maccrab.agent",
            "processID": pid,
            "messageType": "Default",
            "timestamp": "2026-10-20 03:00:00.000000+0100",
        ]
    }

    @Test("an entry from the engine's own pid is dropped; others normalise")
    func dropsOwnProcess() {
        let logger = Logger(subsystem: "test", category: "ul")
        #expect(UnifiedLogCollector.normalise(json: entry(pid: 4242), logger: logger, engineProcessID: 4242) == nil)
        #expect(UnifiedLogCollector.normalise(json: entry(pid: 4243), logger: logger, engineProcessID: 4242) != nil)
    }
}
