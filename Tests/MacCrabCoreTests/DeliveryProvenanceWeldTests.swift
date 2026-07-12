// DeliveryProvenanceWeldTests.swift
// Phase-5 P0(2) — the Delivery-Provenance Weld.
//
// Encodes the acceptance criteria:
//   * a synthetic download from a FRESH domain whose binary then touches a
//     cookie DB -> the firing alert carries the delivery NARRATIVE (and is
//     flagged suspicious);
//   * a SIGNED app self-delivered to /Applications -> narrative attached but
//     NOT flagged.
// Plus the full FP-gate conjunction, the session novel-origin tracker, the
// trigger-gating contract (no weld on non-trigger rules / no provenance), and
// the Core-side Chromium History origin reader against a synthetic fixture.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("Delivery-Provenance Weld")
struct DeliveryProvenanceWeldTests {

    // MARK: - Fixtures

    /// Stub provenance source so the gate/narrative logic is testable without
    /// live quarantine / Chromium databases.
    struct StubSource: DeliveryProvenanceSource {
        let provenance: DeliveryProvenance?
        func provenance(forExecutable path: String) async -> DeliveryProvenance? { provenance }
    }

    private static func process(
        executable: String,
        startTime: Date,
        signature: CodeSignatureInfo?
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 5150,
            ppid: 100,
            rpid: 5150,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [executable],
            workingDirectory: NSHomeDirectory(),
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: startTime,
            codeSignature: signature
        )
    }

    private static func event(
        executable: String,
        startTime: Date,
        signature: CodeSignatureInfo?
    ) -> Event {
        Event(
            eventCategory: .file,
            eventType: .info,
            eventAction: "open",
            process: process(executable: executable, startTime: startTime, signature: signature),
            file: FileInfo(
                path: NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Cookies",
                action: .open
            )
        )
    }

    private static func triggerAlert(ruleId: String, event: Event) -> Alert {
        Alert(
            ruleId: ruleId,
            ruleTitle: "Browser Cookie Database Accessed by Non-Browser",
            severity: .high,
            eventId: event.id.uuidString,
            processPath: event.process.executable,
            processName: event.process.name,
            description: "Non-browser process read a browser cookie database."
        )
    }

    private static let cookieRule = "d1a2b3c4-0031-4000-a000-000000000031"

    // MARK: - Acceptance: fresh-domain download that touches a cookie DB

    @Test("Fresh-domain download -> cookie-DB alert carries delivery narrative and is flagged")
    func freshDomainDownloadCarriesNarrativeAndFlags() async throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let ranAt = t0.addingTimeInterval(120)  // ran 2 minutes after delivery
        let exe = NSHomeDirectory() + "/Downloads/Installer.app/Contents/MacOS/Installer"
        let ev = Self.event(executable: exe, startTime: ranAt,
                            signature: CodeSignatureInfo(signerType: .unsigned))
        let alert = Self.triggerAlert(ruleId: Self.cookieRule, event: ev)

        let source = StubSource(provenance: DeliveryProvenance(
            deliveringAgent: "com.google.Chrome",
            downloadedAt: t0,
            fileURL: "https://cdn.evil-fresh.example/Installer.dmg",
            originHost: "ads.evil-fresh.example",
            originSource: "chromium"
        ))
        let weld = DeliveryProvenanceWeld(source: source)

        let result = await weld.weld(alert: alert, event: ev)
        let r = try #require(result)
        // Narrative is attached and reads correctly.
        #expect(r.narrative.contains("delivered by Google Chrome"))
        #expect(r.narrative.contains("evil-fresh.example"))
        #expect(r.narrative.contains("run 2m 0s later"))
        // Fresh domain + unsigned + run-in-place from ~/Downloads + tight dwell
        // => the FP conjunction holds.
        #expect(r.flagged == true)
        let welded = r.appended(to: alert.description)
        #expect(welded.contains("Suspicious delivery:"))
        #expect(welded.hasPrefix("Non-browser process read a browser cookie database."))
    }

    // MARK: - Acceptance: signed app self-delivered to /Applications is NOT flagged

    @Test("Signed app self-delivered to /Applications -> narrative attached, NOT flagged")
    func signedAppInApplicationsNotFlagged() async throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let ranAt = t0.addingTimeInterval(60)
        let exe = "/Applications/Acme.app/Contents/MacOS/Acme"
        let sig = CodeSignatureInfo(signerType: .devId, teamId: "ACME123456",
                                    signingId: "com.acme.app", isNotarized: true)
        let ev = Self.event(executable: exe, startTime: ranAt, signature: sig)
        let alert = Self.triggerAlert(ruleId: Self.cookieRule, event: ev)

        let source = StubSource(provenance: DeliveryProvenance(
            deliveringAgent: "com.apple.Safari",
            downloadedAt: t0,
            fileURL: "https://acme.com/downloads/Acme.dmg",
            originHost: "acme.com",
            originSource: "quarantine"
        ))
        let weld = DeliveryProvenanceWeld(source: source)

        let result = await weld.weld(alert: alert, event: ev)
        let r = try #require(result)
        #expect(r.narrative.contains("delivered by Safari"))
        #expect(r.flagged == false)
        #expect(r.appended(to: alert.description).contains("Delivery provenance:"))
    }

    // MARK: - Trigger-gating contract

    @Test("Non-trigger rule -> weld returns nil (no enrichment)")
    func nonTriggerRuleReturnsNil() async {
        let ev = Self.event(executable: NSHomeDirectory() + "/Downloads/x",
                            startTime: Date(),
                            signature: CodeSignatureInfo(signerType: .unsigned))
        let alert = Self.triggerAlert(ruleId: "not-a-trigger-rule", event: ev)
        let source = StubSource(provenance: DeliveryProvenance(
            deliveringAgent: "com.google.Chrome", downloadedAt: Date(),
            fileURL: nil, originHost: "evil.example", originSource: "chromium"))
        let weld = DeliveryProvenanceWeld(source: source)
        #expect(await weld.weld(alert: alert, event: ev) == nil)
        #expect(weld.isTrigger(ruleId: "not-a-trigger-rule") == false)
        #expect(weld.isTrigger(ruleId: Self.cookieRule) == true)
    }

    @Test("No resolvable provenance (no quarantine GUID) -> weld returns nil")
    func noProvenanceReturnsNil() async {
        let ev = Self.event(executable: NSHomeDirectory() + "/Downloads/x",
                            startTime: Date(),
                            signature: CodeSignatureInfo(signerType: .unsigned))
        let alert = Self.triggerAlert(ruleId: Self.cookieRule, event: ev)
        let weld = DeliveryProvenanceWeld(source: StubSource(provenance: nil))
        #expect(await weld.weld(alert: alert, event: ev) == nil)
    }

    @Test("All four trigger rule IDs are recognised")
    func allTriggerRuleIds() {
        let weld = DeliveryProvenanceWeld(source: StubSource(provenance: nil))
        for id in [
            "d1a2b3c4-0031-4000-a000-000000000031",
            "d1a2b3c4-0034-4000-a000-000000000034",
            "a1b2c3d4-0003-4000-a003-000000000003",
            "e1f2a3b4-0009-4000-b000-000000000009",
        ] {
            #expect(weld.isTrigger(ruleId: id))
        }
        #expect(DeliveryProvenanceWeld.triggerRuleIds.count == 4)
    }

    // MARK: - Session novel-origin tracker (G2)

    @Test("Same origin seen twice this session -> second occurrence is not first-seen -> not flagged")
    func sessionNovelOriginTracker() async {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let exe = NSHomeDirectory() + "/Downloads/Tool.app/Contents/MacOS/Tool"
        let ev = Self.event(executable: exe, startTime: t0.addingTimeInterval(90),
                            signature: CodeSignatureInfo(signerType: .unsigned))
        let alert = Self.triggerAlert(ruleId: Self.cookieRule, event: ev)
        let source = StubSource(provenance: DeliveryProvenance(
            deliveringAgent: "com.google.Chrome", downloadedAt: t0,
            fileURL: nil, originHost: "repeat.example", originSource: "chromium"))
        let weld = DeliveryProvenanceWeld(source: source)

        let first = await weld.weld(alert: alert, event: ev)
        #expect(first?.flagged == true)   // first sighting -> novel -> flagged
        let second = await weld.weld(alert: alert, event: ev)
        #expect(second?.flagged == false) // same origin -> not first-seen -> G2 fails
        #expect(second?.narrative.isEmpty == false) // narrative still attached
    }

    // MARK: - FP-gate conjunction (pure)

    private func inputs(
        origin: String? = "evil-fresh.example",
        signer: SignerType? = .unsigned,
        adhoc: Bool = false,
        signingId: String? = nil,
        exe: String? = nil,
        dwell: Double = 120,
        firstSeen: Bool = true,
        mail: Bool = false
    ) -> DeliveryProvenanceGate.Inputs {
        DeliveryProvenanceGate.Inputs(
            originRegistrableDomain: origin,
            signerType: signer,
            isAdhoc: adhoc,
            signingId: signingId,
            executablePath: exe ?? (NSHomeDirectory() + "/Downloads/x"),
            dwellSeconds: dwell,
            originFirstSeenThisSession: firstSeen,
            deliveredViaMessagesOrMail: mail
        )
    }

    @Test("Gate: all conjuncts hold -> flagged")
    func gateAllHold() {
        let d = DeliveryProvenanceGate.evaluate(inputs())
        #expect(d.flagged == true)
        #expect(d.degradedMissingInput == false)
        #expect(d.reasons.count == 4)
    }

    @Test("Gate: missing origin domain -> degrade (no flag)")
    func gateMissingOriginDegrades() {
        let d = DeliveryProvenanceGate.evaluate(inputs(origin: nil))
        #expect(d.flagged == false)
        #expect(d.degradedMissingInput == true)
    }

    @Test("Gate: run from /Applications -> not flagged (G3)")
    func gateApplicationsNotFlagged() {
        let d = DeliveryProvenanceGate.evaluate(inputs(exe: "/Applications/App.app/Contents/MacOS/App"))
        #expect(d.flagged == false)
        #expect(d.degradedMissingInput == false)
    }

    @Test("Gate: stale dwell (ran days after download) -> not flagged (G4)")
    func gateStaleDwellNotFlagged() {
        let d = DeliveryProvenanceGate.evaluate(inputs(dwell: 25 * 3600))
        #expect(d.flagged == false)
    }

    @Test("Gate: signed vendor self-delivery (domain matches signer) -> not flagged (G1)")
    func gateVendorSelfDeliveryNotFlagged() {
        let d = DeliveryProvenanceGate.evaluate(inputs(
            origin: "slack.com", signer: .devId, signingId: "com.slack.Slack"))
        #expect(d.flagged == false)
        #expect(d.degradedMissingInput == false)
    }

    @Test("Gate: signed binary with unknown signer domain -> degrade (no flag on a guess)")
    func gateSignedUnknownSignerDegrades() {
        let d = DeliveryProvenanceGate.evaluate(inputs(
            origin: "github.com", signer: .devId, signingId: nil))
        #expect(d.flagged == false)
        #expect(d.degradedMissingInput == true)
    }

    @Test("Gate: signed binary whose signer domain != origin -> flagged (devId-signed stealer)")
    func gateSignedMismatchFlags() {
        let d = DeliveryProvenanceGate.evaluate(inputs(
            origin: "sketchy-cdn.com", signer: .devId, signingId: "com.evil.tool"))
        #expect(d.flagged == true)
    }

    @Test("Gate: origin not first-seen and not a mail attachment -> not flagged (G2)")
    func gateNotFirstSeenNotFlagged() {
        let d = DeliveryProvenanceGate.evaluate(inputs(firstSeen: false, mail: false))
        #expect(d.flagged == false)
    }

    @Test("Gate: Messages/Mail attachment satisfies G2 even when not first-seen")
    func gateMailAttachmentSatisfiesG2() {
        let d = DeliveryProvenanceGate.evaluate(inputs(firstSeen: false, mail: true))
        #expect(d.flagged == true)
    }

    // MARK: - Pure helpers

    @Test("registrableDomain reduces to eTLD+1 approximation")
    func registrableDomainHelper() {
        #expect(DeliveryProvenanceGate.registrableDomain(ofHost: "www.evil.example.com") == "example.com")
        #expect(DeliveryProvenanceGate.registrableDomain(ofHost: "Evil.Example") == "evil.example")
        #expect(DeliveryProvenanceGate.registrableDomain(ofHost: "localhost") == "localhost")
    }

    @Test("isRunInPlace: Downloads / temp / DMG true; /Applications false")
    func runInPlaceHelper() {
        #expect(DeliveryProvenanceGate.isRunInPlace(NSHomeDirectory() + "/Downloads/x/y") == true)
        #expect(DeliveryProvenanceGate.isRunInPlace("/Volumes/AMOS/AMOS.app/Contents/MacOS/AMOS") == true)
        #expect(DeliveryProvenanceGate.isRunInPlace("/private/tmp/x") == true)
        #expect(DeliveryProvenanceGate.isRunInPlace("/Applications/Slack.app/Contents/MacOS/Slack") == false)
        #expect(DeliveryProvenanceGate.isRunInPlace("/System/Library/CoreServices/x") == false)
    }

    @Test("signerVendorTokens drops generic labels and keeps vendor tokens")
    func vendorTokensHelper() {
        let t = DeliveryProvenanceGate.signerVendorTokens(signingId: "com.google.Chrome")
        #expect(t.contains("google"))
        #expect(t.contains("com") == false)
        #expect(DeliveryProvenanceGate.signerVendorTokens(signingId: nil).isEmpty)
        #expect(DeliveryProvenanceGate.signerVendorTokens(signingId: "single").isEmpty)
    }

    @Test("humanDwell formats seconds compactly")
    func humanDwellHelper() {
        #expect(DeliveryProvenanceWeld.humanDwell(45) == "45s")
        #expect(DeliveryProvenanceWeld.humanDwell(65) == "1m 5s")
        #expect(DeliveryProvenanceWeld.humanDwell(3 * 3600 + 5 * 60) == "3h 5m")
    }

    // MARK: - Core-side Chromium History origin reader (synthetic fixture)

    @Test("ChromiumDownloadOriginReader resolves referrer + redirect origin from a synthetic History")
    func chromiumOriginReaderFixture() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("chromium-weld-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let historyPath = dir.appendingPathComponent("History").path

        var db: OpaquePointer?
        #expect(sqlite3_open(historyPath, &db) == SQLITE_OK)
        let ddl = """
            CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT,
                                    referrer TEXT, start_time INTEGER);
            CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
            INSERT INTO downloads VALUES
                (1, '/Users/x/Downloads/AMOS.dmg', 'https://news.example/article',
                 'https://ads.evil.example/landing', 13350000000000000);
            INSERT INTO downloads_url_chains VALUES
                (1, 0, 'https://ads.evil.example/redirect'),
                (1, 1, 'https://cdn.evil.example/AMOS.dmg');
            """
        #expect(sqlite3_exec(db, ddl, nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        let reader = ChromiumDownloadOriginReader()
        let origin = try #require(reader.origin(historyPath: historyPath, fileName: "AMOS.dmg"))
        #expect(origin.referrer == "https://ads.evil.example/landing")
        #expect(origin.originURL == "https://ads.evil.example/redirect")  // first hop
        #expect(origin.tabURL == "https://news.example/article")

        // Non-matching filename -> nil.
        #expect(reader.origin(historyPath: historyPath, fileName: "Nope.dmg") == nil)
    }
}
