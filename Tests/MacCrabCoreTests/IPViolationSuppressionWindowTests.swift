import Foundation
import Testing
@testable import MacCrabCore

@Suite("AI network finding suppression has bounded monotonic retention")
struct IPViolationSuppressionWindowTests {
    @Test("Repeated observations do not extend the one-hour deadline")
    func expiry() {
        var window = IPViolationSuppressionWindow(capacity: 4)
        let start = ContinuousClock.now
        let initial = window.shouldSuppress("203.0.113.1", at: start)
        let repeated = window.shouldSuppress("203.0.113.1", at: start.advanced(by: .seconds(3_599)))
        let expired = window.shouldSuppress("203.0.113.1", at: start.advanced(by: .seconds(3_600)))
        #expect(!initial)
        #expect(repeated)
        #expect(!expired)
        #expect(window.count == 1)
        #expect(window.orderedEntryCount == 1)
    }

    @Test("Capacity permits a new finding instead of retaining unlimited history")
    func capacityAndChurn() {
        var window = IPViolationSuppressionWindow(capacity: 3)
        let start = ContinuousClock.now
        for index in 0..<100 {
            let key = "ordinary-destination-\(index)"
            let initial = window.shouldSuppress(key, at: start.advanced(by: .seconds(index)))
            let repeated = window.shouldSuppress(key, at: start.advanced(by: .seconds(index)))
            #expect(!initial)
            #expect(repeated)
            #expect(window.count <= 3)
            #expect(window.orderedEntryCount <= 6)
        }
        let retained = window.shouldSuppress("ordinary-destination-98", at: start.advanced(by: .seconds(100)))
        let forgotten = window.shouldSuppress("ordinary-destination-0", at: start.advanced(by: .seconds(100)))
        let afterExpiry = window.shouldSuppress("after-expiry", at: start.advanced(by: .seconds(3_701)))
        #expect(retained)
        #expect(!forgotten)
        #expect(!afterExpiry)
        #expect(window.count == 1)
        #expect(window.orderedEntryCount == 1)
    }

    @Test("Zero or negative capacity disables suppression without retaining entries", arguments: [0, -1])
    func noRetention(capacity: Int) {
        var window = IPViolationSuppressionWindow(capacity: capacity)
        for _ in 0..<4 {
            let suppressed = window.shouldSuppress("203.0.113.1", at: .now)
            #expect(!suppressed)
        }
        #expect(window.count == 0)
        #expect(window.orderedEntryCount == 0)
    }

    @Test("The production connection path emits again after capacity eviction")
    func connectionPath() async {
        let sandbox = AINetworkSandbox(
            customConfigPath: "/nonexistent/maccrab-private-test.json",
            maxCachedViolations: -1, maxSuppressedIPs: 1
        )
        func check(_ ip: String) async -> AINetworkSandbox.Violation? {
            await sandbox.checkConnection(
                aiToolName: "fixture", processPid: 1234, processPath: "/usr/bin/true",
                destinationIP: ip, destinationPort: 443, destinationDomain: nil
            )
        }
        #expect(await check("203.0.113.1") != nil)
        #expect(await check("203.0.113.1") == nil)
        #expect(await check("203.0.113.2") != nil)
        #expect(await check("203.0.113.1") != nil)
        #expect(await sandbox.getRecentViolations().isEmpty)
    }
}
