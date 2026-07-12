// BTMDetectionTests.swift
// v1.21.4 BTM / SMAppService "ghost login item" coverage.
//
// Three seams, mirroring the way ESCollectorDispatchTests / IntrospectionDetection
// -Tests split a live-only ES path into testable pieces (a raw es_message_t can
// only be built by the kernel at euid 0 + entitlement, so it can't be
// synthesized in a unit test):
//
//   1. ESCollector.btmEnrichments / .btmItemTypeName — the pure dispatch-time
//      enrichment builder that attaches the Sigma BTM* fields the persistence
//      rules resolve. A silent key rename here = dead rules.
//   2. The two Sigma rules, END-TO-END through the REAL RuleEngine: a synthetic
//      BTM Event must dispatch under file_event, resolve BTMItemType/BTMManaged
//      via enrichment passthrough + SignerType via the instigator's codesign,
//      fire on the untrusted shape, and be suppressed for Apple-signed / MDM-
//      managed shapes (the FP guard).
//   3. BTMSnapshotMonitor.parseDumpBTM / .suspiciousRecords — the pure
//      `sfltool dumpbtm` parser + discriminator, driven by captured output.

import Testing
import Foundation
import EndpointSecurity
@testable import MacCrabCore

@Suite("BTM launch-item detection (v1.21.4)")
struct BTMDetectionTests {

    // MARK: - 1. Dispatch enrichment seam

    /// The exact Sigma field set the BTM rules resolve via enrichment passthrough.
    /// A silent rename here would dead-fire the rules while other tests pass.
    private static let expectedKeys: Set<String> = [
        "BTMItemType", "BTMLegacy", "BTMManaged", "BTMExecutablePath",
        "BTMItemURL", "BTMAppURL", "BTMAppSignerType", "BTMAppTeamId",
    ]

    private func esProc(exe: String, team: String = "", signer: SignerType = .unsigned) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1,
            name: (exe as NSString).lastPathComponent, executable: exe, commandLine: exe, args: [exe],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20,
            startTime: Date(),
            codeSignature: CodeSignatureInfo(signerType: signer, teamId: team.isEmpty ? nil : team,
                                             signingId: nil, authorities: [], flags: 0, isNotarized: false),
            ancestors: [], architecture: "arm64", isPlatformBinary: signer == .apple
        )
    }

    @Test("btmEnrichments emits exactly the Sigma keys the BTM rules resolve")
    func emitsExactKeySet() {
        let e = ESCollector.btmEnrichments(
            itemType: ES_BTM_ITEM_TYPE_AGENT, legacy: false, managed: false,
            executablePath: "/tmp/x", itemURL: "file:///tmp/x", appURL: "",
            app: esProc(exe: "/Applications/Foo.app/Contents/MacOS/Foo", team: "ABC123", signer: .devId))
        #expect(Set(e.keys) == Self.expectedKeys)
    }

    @Test("btmItemTypeName maps every ES BTM item type to its stable token")
    func itemTypeMapping() {
        #expect(ESCollector.btmItemTypeName(ES_BTM_ITEM_TYPE_USER_ITEM) == "user_item")
        #expect(ESCollector.btmItemTypeName(ES_BTM_ITEM_TYPE_APP) == "app")
        #expect(ESCollector.btmItemTypeName(ES_BTM_ITEM_TYPE_LOGIN_ITEM) == "login_item")
        #expect(ESCollector.btmItemTypeName(ES_BTM_ITEM_TYPE_AGENT) == "agent")
        #expect(ESCollector.btmItemTypeName(ES_BTM_ITEM_TYPE_DAEMON) == "daemon")
    }

    @Test("btmEnrichments carries item flags and the attributed-app identity")
    func enrichmentValues() {
        let e = ESCollector.btmEnrichments(
            itemType: ES_BTM_ITEM_TYPE_DAEMON, legacy: true, managed: true,
            executablePath: "/Library/PrivilegedHelperTools/h", itemURL: "file:///Library/LaunchDaemons/h.plist",
            appURL: "file:///Applications/Foo.app",
            app: esProc(exe: "/Applications/Foo.app/Contents/MacOS/Foo", team: "9BNSXJN65R", signer: .devId))
        #expect(e["BTMItemType"] == "daemon")
        #expect(e["BTMLegacy"] == "true")
        #expect(e["BTMManaged"] == "true")
        #expect(e["BTMExecutablePath"] == "/Library/PrivilegedHelperTools/h")
        #expect(e["BTMAppTeamId"] == "9BNSXJN65R")
        #expect(e["BTMAppSignerType"] == "devId")
    }

    @Test("btmEnrichments with no attributed app reports unknown signer / empty team")
    func enrichmentNilApp() {
        let e = ESCollector.btmEnrichments(
            itemType: ES_BTM_ITEM_TYPE_LOGIN_ITEM, legacy: false, managed: false,
            executablePath: "", itemURL: "file:///tmp/ghost", appURL: "", app: nil)
        #expect(e["BTMAppSignerType"] == "unknown")
        #expect(e["BTMAppTeamId"] == "")
    }

    // MARK: - 2. Rule fire + FP guard (through the real RuleEngine)

    private func loadRules() async throws -> RuleEngine {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        return engine
    }

    /// Build the Event the normalise() BTM case emits: .file/.creation/"btm_add",
    /// process = the INSTIGATOR (the responsible actor, not the delivering daemon).
    private func btmEvent(
        itemType: String = "agent",
        legacy: String = "false",
        managed: String = "false",
        instigatorSigner: SignerType = .unsigned,
        instigatorPath: String = "/tmp/maccy-installer",
        instigatorTeam: String = ""
    ) -> Event {
        let instigator = esProc(exe: instigatorPath, team: instigatorTeam, signer: instigatorSigner)
        let enrich = ESCollector.btmEnrichments(
            itemType: itemType == "daemon" ? ES_BTM_ITEM_TYPE_DAEMON
                : itemType == "login_item" ? ES_BTM_ITEM_TYPE_LOGIN_ITEM
                : ES_BTM_ITEM_TYPE_AGENT,
            legacy: legacy == "true", managed: managed == "true",
            executablePath: "/Users/t/Library/Application Support/x", itemURL: "file:///x",
            appURL: "", app: nil)
        return Event(eventCategory: .file, eventType: .creation, eventAction: "btm_add",
                     process: instigator, file: FileInfo(path: "/Users/t/Library/Application Support/x", action: .create),
                     enrichments: enrich)
    }

    private func fires(_ matches: [RuleMatch], _ needle: String) -> Bool {
        matches.contains { $0.ruleName.localizedCaseInsensitiveContains(needle) }
    }

    @Test("untrusted (unsigned instigator) BTM agent add FIRES the untrusted rule")
    func untrustedFires() async throws {
        let engine = try await loadRules()
        let m = await engine.evaluate(btmEvent(itemType: "agent", instigatorSigner: .unsigned))
        #expect(fires(m, "BTM Launch Item Added by Untrusted"),
                "expected untrusted BTM detection, got: \(m.map(\.ruleName))")
    }

    @Test("modern (non-legacy) unsigned BTM add ALSO fires the ghost-login-item rule")
    func ghostFires() async throws {
        let engine = try await loadRules()
        let m = await engine.evaluate(btmEvent(itemType: "login_item", legacy: "false", instigatorSigner: .unsigned))
        #expect(fires(m, "Ghost Login Item"),
                "expected ghost-login-item detection, got: \(m.map(\.ruleName))")
    }

    @Test("legacy BTM add does NOT fire the ghost (no-plist) rule")
    func legacyDoesNotFireGhost() async throws {
        let engine = try await loadRules()
        let m = await engine.evaluate(btmEvent(itemType: "daemon", legacy: "true", instigatorSigner: .unsigned))
        #expect(!fires(m, "Ghost Login Item"), "legacy add should not match the modern-only ghost rule")
        // ...but the general untrusted rule still fires on a legacy untrusted add.
        #expect(fires(m, "BTM Launch Item Added by Untrusted"))
    }

    @Test("FP guard: an Apple-signed instigator (System Settings) is suppressed")
    func appleInstigatorSuppressed() async throws {
        let engine = try await loadRules()
        let m = await engine.evaluate(btmEvent(itemType: "login_item", instigatorSigner: .apple,
                                               instigatorPath: "/System/Library/PreferencePanes/x"))
        #expect(!fires(m, "BTM Launch Item Added by Untrusted"), "apple instigator should be filtered")
        #expect(!fires(m, "Ghost Login Item"), "apple instigator should be filtered")
    }

    @Test("FP guard: an MDM-managed item is suppressed")
    func managedSuppressed() async throws {
        let engine = try await loadRules()
        let m = await engine.evaluate(btmEvent(itemType: "daemon", managed: "true", instigatorSigner: .unsigned))
        #expect(!fires(m, "BTM Launch Item Added by Untrusted"), "managed item should be filtered")
        #expect(!fires(m, "Ghost Login Item"), "managed item should be filtered")
    }

    @Test("BTM rule does not cross-match an ordinary file create (no BTM enrichment)")
    func ordinaryFileCreateDoesNotMatch() async throws {
        let engine = try await loadRules()
        let ordinary = Event(eventCategory: .file, eventType: .creation, eventAction: "create",
                             process: esProc(exe: "/tmp/x"),
                             file: FileInfo(path: "/Users/t/Documents/note.txt", action: .create))
        let m = await engine.evaluate(ordinary)
        #expect(!fires(m, "BTM Launch Item"), "an ordinary file create must not match a BTM-gated rule")
        #expect(!fires(m, "Ghost Login Item"))
    }

    // MARK: - 3. dumpbtm parser + discriminator

    // Captured `sfltool dumpbtm` shape: a developer container (not a launch
    // item), an enabled legacy daemon with a Team (trusted), an enabled legacy
    // daemon with NO Team (the ghost signal), a disabled no-team item, and an
    // enabled modern agent with no Team (also a ghost signal).
    private static let sampleDump = """
     Items:

     #1:
                     UUID: AAAA0001-0000-0000-0000-000000000001
                     Name: (null)
                     Type: developer (0x20)
              Disposition: [disabled, allowed, not notified] (0x2)
               Identifier: Unknown Developer
                      URL: (null)

     #2:
                     UUID: BBBB0002-0000-0000-0000-000000000002
                     Name: com.docker.vmnetd
          Team Identifier: 9BNSXJN65R
                     Type: legacy daemon (0x10010)
              Disposition: [enabled, allowed, notified] (0xb)
               Identifier: 16.com.docker.vmnetd
                      URL: file:///Library/LaunchDaemons/com.docker.vmnetd.plist
          Executable Path: /Library/PrivilegedHelperTools/com.docker.vmnetd

     #3:
                     UUID: CCCC0003-0000-0000-0000-000000000003
                     Name: com.evil.helper
                     Type: legacy daemon (0x10010)
              Disposition: [enabled, allowed, notified] (0xb)
               Identifier: 16.com.evil.helper
                      URL: file:///Library/LaunchDaemons/com.evil.helper.plist
          Executable Path: /tmp/evil

     #4:
                     UUID: DDDD0004-0000-0000-0000-000000000004
                     Name: com.dormant.thing
                     Type: agent (0x8)
              Disposition: [disabled, allowed, not notified] (0x2)
               Identifier: com.dormant.thing

     #5:
                     UUID: EEEE0005-0000-0000-0000-000000000005
                     Name: com.ghost.login
                     Type: agent (0x8)
              Disposition: [enabled, allowed, notified] (0xb)
               Identifier: com.ghost.login
                      URL: file:///Applications/Ghost.app
    """

    @Test("parseDumpBTM extracts every record and its key fields")
    func parsesRecords() {
        let recs = BTMSnapshotMonitor.parseDumpBTM(Self.sampleDump)
        #expect(recs.count == 5)
        let docker = recs.first { $0.uuid.hasPrefix("BBBB") }
        #expect(docker?.teamIdentifier == "9BNSXJN65R")
        #expect(docker?.enabled == true)
        #expect(docker?.executablePath == "/Library/PrivilegedHelperTools/com.docker.vmnetd")
        let container = recs.first { $0.uuid.hasPrefix("AAAA") }
        #expect(container?.teamIdentifier == nil)   // "(null)" / absent -> nil
        #expect(container?.enabled == false)
    }

    @Test("suspiciousRecords = enabled launch items with NO Team Identifier")
    func discriminator() {
        let recs = BTMSnapshotMonitor.parseDumpBTM(Self.sampleDump)
        let flagged = BTMSnapshotMonitor.suspiciousRecords(recs)
        let names = Set(flagged.map(\.name))
        // #3 (enabled legacy daemon, no team) and #5 (enabled modern agent, no team)
        #expect(names == ["com.evil.helper", "com.ghost.login"])
        // Trusted (#2 has a Team), the developer container (#1, not a launch
        // item), and the disabled item (#4) are all excluded.
        #expect(!names.contains("com.docker.vmnetd"))
        #expect(!names.contains("com.dormant.thing"))
    }

    @Test("installPath prefers the executable path, then a file:// URL")
    func installPathResolution() {
        let recs = BTMSnapshotMonitor.parseDumpBTM(Self.sampleDump)
        let evil = recs.first { $0.uuid.hasPrefix("CCCC") }!
        #expect(BTMSnapshotMonitor.installPath(evil) == "/tmp/evil")
        // App-scoped record with no Executable Path -> resolve from the item URL.
        let ghost = recs.first { $0.uuid.hasPrefix("EEEE") }!
        #expect(ghost.executablePath == nil)
        #expect(BTMSnapshotMonitor.installPath(ghost) == "/Applications/Ghost.app")
    }
}
