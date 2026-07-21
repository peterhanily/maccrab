// WelcomeChecklistTests.swift
// MacCrabAppTests
//
// v1.21.5: the Welcome wizard's live setup-checklist predicate, plus the
// UIMode storage contract the wizard's new mode picker writes into.

import Foundation
import Testing
@testable import MacCrabApp

@Suite("WelcomeChecklist")
struct WelcomeChecklistTests {

    @Test("complete when DB found, rules loaded, FDA granted, sysext activated")
    func allGreen() {
        #expect(WelcomeChecklist.isComplete(
            daemonDBFound: true, ruleCount: 438, fda: .granted, sysext: .activated))
    }

    @Test("unknown FDA probe does not block completion (no-false-alarm treatment)")
    func unknownFDA() {
        #expect(WelcomeChecklist.isComplete(
            daemonDBFound: true, ruleCount: 1, fda: .unknown, sysext: .activated))
    }

    @Test("denied FDA blocks completion")
    func deniedFDA() {
        #expect(!WelcomeChecklist.isComplete(
            daemonDBFound: true, ruleCount: 1, fda: .denied, sysext: .activated))
    }

    @Test("missing daemon DB blocks completion")
    func noDB() {
        #expect(!WelcomeChecklist.isComplete(
            daemonDBFound: false, ruleCount: 1, fda: .granted, sysext: .activated))
    }

    @Test("zero compiled rules blocks completion")
    func noRules() {
        #expect(!WelcomeChecklist.isComplete(
            daemonDBFound: true, ruleCount: 0, fda: .granted, sysext: .activated))
    }

    @Test("every non-activated sysext state blocks completion",
          arguments: [SystemExtensionState.unknown, .notActivated, .activating,
                      .awaitingApproval, .failed("boom")])
    func sysextNotActive(state: SystemExtensionState) {
        #expect(!WelcomeChecklist.isComplete(
            daemonDBFound: true, ruleCount: 1, fda: .granted, sysext: state))
    }
}

@Suite("UIMode storage contract")
struct UIModeStorageTests {

    @Test("storage key is stable — stored preferences must survive upgrades")
    func storageKey() {
        #expect(UIMode.storageKey == "maccrab.ui.mode")
    }

    @Test("raw values are stable — the Welcome picker writes them and every @AppStorage reader parses them")
    func rawValues() {
        #expect(UIMode.basic.rawValue == "basic")
        #expect(UIMode.standard.rawValue == "standard")
        #expect(UIMode.advanced.rawValue == "advanced")
    }

    @Test("no stored value (or garbage) falls back to .advanced, preserving upgrade UX")
    func fallback() {
        // Mirrors the read pattern in SettingsView / V2Sidebar:
        // UIMode(rawValue: storedString) ?? .advanced
        let none: String? = nil
        #expect((none.flatMap(UIMode.init(rawValue:)) ?? .advanced) == .advanced)
        #expect((UIMode(rawValue: "expert") ?? .advanced) == .advanced)
    }

    @Test("wizard-written mode round-trips through UserDefaults")
    func roundTrip() {
        let suite = "maccrab.tests.uimode.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }

        // Fresh install pre-wizard: nothing stored → readers fall back.
        #expect(defaults.string(forKey: UIMode.storageKey) == nil)

        // applySetup() writes the raw value; readers parse it back.
        defaults.set(UIMode.basic.rawValue, forKey: UIMode.storageKey)
        let read = defaults.string(forKey: UIMode.storageKey).flatMap(UIMode.init(rawValue:)) ?? .advanced
        #expect(read == .basic)
    }
}
