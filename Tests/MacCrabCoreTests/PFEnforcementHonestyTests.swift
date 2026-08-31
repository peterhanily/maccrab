// PFEnforcementHonestyTests.swift
//
// v1.21.6-rc.45: a PF path may not claim a block it is not performing.
//
// THE BLOCKER THIS PINS. Every PF control — NetworkBlocker,
// ResponseAction.blockNetwork, ManualResponse.blockDestination, PanicButton,
// TravelMode — enforces with `pfctl -a com.maccrab -f <file>`. That loads rules
// INTO an anchor; macOS evaluates them only if PF is enabled AND the main
// ruleset references the anchor. MacCrab arranges neither: there is no
// `pfctl -e`/`-E` anywhere in the source, and nothing writes /etc/pf.conf.
// `pfctl -f` exits 0 regardless, so all five reported success.
//
// Measured on an installed host, 2026-08-31:
//   pfctl -s info                  ->  Status: Disabled
//   pfctl -s Anchors               ->  com.apple            (com.maccrab absent)
//   pfctl -a com.maccrab -s rules  ->  pfctl: DIOCGETRULES: Invalid argument
//
// The decision is a pure function so the reporting contract is testable without
// pfctl and without root.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("PF enforcement honesty (v1.21.6-rc.45)")
struct PFEnforcementHonestyTests {

    @Test("the shipped host's exact state is reported as NOT enforcing")
    func disabledPFIsNotEnforcing() {
        let s = PFEnforcement.status(pfEnabled: false, anchorReachable: false)
        #expect(!s.enforcing)
        #expect(s.reason.contains("PF is disabled"))
    }

    @Test("a loaded anchor on a running PF still needs to be referenced")
    func unreferencedAnchorIsNotEnforcing() {
        let s = PFEnforcement.status(pfEnabled: true, anchorReachable: false)
        #expect(!s.enforcing, "loading rules into an anchor no ruleset references blocks nothing")
        #expect(s.reason.contains("/etc/pf.conf"))
    }

    @Test("both conditions together are enforcement")
    func bothConditionsEnforce() {
        let s = PFEnforcement.status(pfEnabled: true, anchorReachable: true)
        #expect(s.enforcing)
        #expect(s.reason == "enforcing")
    }

    @Test("every state explains itself")
    func everyStateHasAReason() {
        for pf in [true, false] {
            for anchor in [true, false] {
                let s = PFEnforcement.status(pfEnabled: pf, anchorReachable: anchor)
                #expect(!s.reason.isEmpty)
            }
        }
    }

    @Test("no PF path treats a pfctl exit code as proof of enforcement")
    func noPathTrustsExitCodeAlone() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        func read(_ p: String) throws -> String {
            try String(contentsOf: root.appendingPathComponent(p), encoding: .utf8)
        }
        // Each of the five call sites must consult PFEnforcement.
        for path in [
            "Sources/MacCrabCore/Prevention/NetworkBlocker.swift",
            "Sources/MacCrabCore/Detection/ResponseAction.swift",
            "Sources/MacCrabCore/Prevention/ManualResponse.swift",
            "Sources/MacCrabCore/Prevention/PanicButton.swift",
            "Sources/MacCrabCore/Prevention/TravelMode.swift",
        ] {
            #expect(
                try read(path).contains("PFEnforcement"),
                "\(path) loads a PF anchor without checking whether it enforces"
            )
        }
    }

    @Test("the operator-facing block message says when it is not in effect")
    func operatorCopyIsHonest() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let manual = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabCore/Prevention/ManualResponse.swift"
            ),
            encoding: .utf8
        )
        #expect(
            manual.contains("NOT in effect"),
            "the string returned to the operator after a manual block must not claim a block that did not happen"
        )
    }
}
