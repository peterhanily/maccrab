// PFEnforcementHonestyTests.swift
//
// v1.21.6-rc.45: a PF path may not claim a block it is not performing.
//
// THE BLOCKER THIS PINS. Every PF control — NetworkBlocker,
// ResponseAction.blockNetwork, ManualResponse.blockDestination, PanicButton,
// TravelMode — loads rules with `pfctl -a <feature-anchor> -f <file>`. That loads rules
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

    @Test("both observed prerequisites permit the enforcement status")
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

    @Test("the actual root ruleset must reference each feature anchor", arguments: [
        "com.maccrab", "com.maccrab.response", "com.maccrab.dashboard",
        "com.maccrab.emergency", "com.maccrab.travel",
    ])
    func activeRootAttachment(anchor: String) {
        var calls: [[String]] = []
        let result = PFEnforcement.probe(anchorName: anchor) { args in
            calls.append(args)
            if args == ["-s", "info"] { return (true, "Status: Enabled for 0 days\n") }
            if args == ["-s", "rules"] { return (true, "anchor \"\(anchor)\" all\n") }
            if args == ["-a", anchor, "-s", "rules"] { return (true, "block drop out quick all\n") }
            return nil
        }
        #expect(result.enforcing)
        #expect(calls == [["-s", "info"], ["-s", "rules"], ["-a", anchor, "-s", "rules"]])
    }

    @Test("listing a populated but unattached anchor is not enforcement")
    func populatedAnchorWithoutAttachment() {
        let result = PFEnforcement.probe(anchorName: "com.maccrab") { args in
            if args == ["-s", "info"] { return (true, "Status: Enabled\n") }
            if args == ["-s", "rules"] { return (true, "anchor \"com.apple/*\" all\n") }
            return (true, "block drop out quick all\n")
        }
        #expect(result.pfEnabled)
        #expect(!result.anchorReachable)
        #expect(!result.enforcing)
    }

    @Test("every failed probe remains unverified", arguments: [0, 1, 2])
    func failedCommand(index: Int) {
        var call = 0
        let replies = ["Status: Enabled\n", "anchor \"com.maccrab\" all\n", "block drop out quick all\n"]
        let result = PFEnforcement.probe(anchorName: "com.maccrab") { _ in
            defer { call += 1 }
            return (call != index, replies[call])
        }
        #expect(!result.enforcing)
    }

    @Test("conditional, nested and partial attachment listings remain unverified", arguments: [
        "anchor \"com.maccrab\" out on en0 all\n",
        "anchor \"com.maccrab\" proto tcp from any to any port = 443\n",
        "anchor \"outer\" all {\n  anchor \"com.maccrab\" all\n}\n",
        "anchor \"com.maccrab/*\" all\n",
        "anchor \"com.maccrab.dashboard\" all\n",
        "anchor \"com.maccrab\" all {\n",
    ])
    func unsupportedAttachments(rules: String) {
        #expect(!PFEnforcement.hasUnconditionalRootReference(rules: rules, anchorName: "com.maccrab"))
    }

    @Test("root wildcard evaluates immediate children and quoted braces preserve nesting")
    func wildcardAndInlineRules() {
        #expect(PFEnforcement.hasUnconditionalRootReference(rules: "anchor \"*\" all\n", anchorName: "com.maccrab"))
        #expect(!PFEnforcement.hasUnconditionalRootReference(rules: "anchor \"*\" all\n", anchorName: "parent/com.maccrab"))
        #expect(PFEnforcement.hasUnconditionalRootReference(
            rules: "anchor \"other\" all {\n pass all label \"ordinary { label\"\n}\nanchor \"com.maccrab\" all\n",
            anchorName: "com.maccrab"
        ))
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
            "Sources/MacCrabCore/Detection/TemporaryNetworkBlocks.swift",
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
