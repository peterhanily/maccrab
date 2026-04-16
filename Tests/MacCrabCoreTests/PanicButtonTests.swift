// PanicButtonTests.swift
// Emergency-response coverage — deliberately conservative: we never call
// PanicButton.activate() in tests because its real implementation kills
// processes, issues pfctl rules, locks the screen, and disables
// Bluetooth. Those paths are exercised by manual integration tests.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Panic Button")
struct PanicButtonTests {

    @Test("Instance creation succeeds")
    func initialization() async {
        let _ = PanicButton()
        // Just verifying the actor constructs without side effects.
        #expect(true)
    }

    @Test("deactivate() runs to completion without crash")
    func deactivateSafe() async {
        // deactivate() is idempotent — it flushes a pfctl anchor that may
        // or may not exist. It returns the list of cleanup actions taken.
        let button = PanicButton()
        let actions = await button.deactivate()

        // We expect at least one cleanup action was attempted (the
        // firewall flush) regardless of whether panic was ever active.
        #expect(!actions.isEmpty)
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
