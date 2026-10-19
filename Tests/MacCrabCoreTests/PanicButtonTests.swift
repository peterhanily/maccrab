// PanicButtonTests.swift
// Emergency-response coverage — deliberately conservative: we never call
// PanicButton.activate() in tests because its real implementation kills
// processes, issues pfctl rules, locks the screen, and disables
// Bluetooth. Those paths are exercised by manual integration tests.

import Testing
import Foundation
@testable import MacCrabCore

private final class PanicRemovalRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func record() { lock.lock(); defer { lock.unlock() }; count += 1 }
    func snapshot() -> Int { lock.lock(); defer { lock.unlock() }; return count }
}

@Suite("Panic Button")
struct PanicButtonTests {

    @Test("Instance creation succeeds")
    func initialization() async {
        let _ = PanicButton()
        // Just verifying the actor constructs without side effects.
        #expect(true)
    }

    @Test("deactivate() requests cleanup once and reports launch outcome", arguments: [true, false])
    func deactivateSafe(launched: Bool) async {
        let recorder = PanicRemovalRecorder()
        let button = PanicButton(removeEmergencyFirewall: {
            recorder.record()
            return launched
        })
        let actions = await button.deactivate()

        #expect(recorder.snapshot() == 1)
        #expect(actions == [
            launched ? "Emergency firewall rules removed" : "Failed to remove emergency firewall rules",
            "Normal operation restored",
        ])
    }

    @Test("PanicResult struct holds expected fields")
    func resultStruct() {
        let result = PanicButton.PanicResult(
            processesKilled: 3,
            networkBlocked: true,
            screenLocked: true,
            dnsFlush: true,
            timestamp: Date(),
            actions: ["Killed 3 processes", "Firewall activated"]
        )
        #expect(result.processesKilled == 3)
        #expect(result.networkBlocked == true)
        #expect(result.screenLocked == true)
        #expect(result.dnsFlush == true)
        #expect(result.actions.count == 2)
    }

    @Test("Maps to D3FEND D3-PL (Process Lockout)")
    func d3fendRef() {
        #expect(PanicButton.d3fend.id == "D3-PL")
        #expect(PanicButton.d3fend.tactic == .evict)
    }
}
