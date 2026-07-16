// AlertSinkTests.swift
// MacCrabCoreTests
//
// Pin the v1.6.19 AlertSink contract: every alert reaches AlertStore through
// AlertSink (single chokepoint) and AlertSink applies AlertDeduplicator
// before insertion. These tests are the regression net for the v1.6.9
// NoiseFilter-layering bug class — if a future change re-introduces a
// direct AlertStore.insert outside the sink, these tests will not catch
// it (that's the job of pre-release-audit.sh in task #10), but they DO
// catch silent breakage of dedup ordering, missing await chains, and
// double-counting bugs.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertSink contract")
struct AlertSinkTests {

    // MARK: - Helpers

    private func makeSink() async throws -> (sink: AlertSink, store: AlertStore, dir: URL) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tempDir.path)
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        let sink = AlertSink(alertStore: store, deduplicator: dedup)
        return (sink, store, tempDir)
    }

    private func makeAlert(
        ruleId: String = "test.rule",
        processPath: String? = "/usr/bin/example",
        severity: Severity = .medium
    ) -> Alert {
        Alert(
            ruleId: ruleId,
            ruleTitle: "Test rule",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: processPath,
            processName: processPath.map { ($0 as NSString).lastPathComponent },
            description: "test description",
            mitreTactics: nil, mitreTechniques: nil,
            suppressed: false
        )
    }

    /// Reuses the global `makeEvent(...)` helper from MacCrabCoreTests.swift.
    private func event(executable: String = "/usr/bin/example", pid: Int32 = 1234) -> Event {
        makeEvent(processName: (executable as NSString).lastPathComponent,
                  processPath: executable,
                  commandLine: executable,
                  pid: pid)
    }

    // MARK: - Tests

    @Test("enrichWithAttribution derives D3FEND defenses + remediation from ATT&CK tactics")
    func enrichDerivesD3FEND() {
        // C2 tactic → outbound filtering + DNS blackholing (FIQ-3).
        let c2 = Alert(
            ruleId: "r", ruleTitle: "t", severity: .high, eventId: "e",
            processPath: "/bin/x", processName: "x", description: "d",
            mitreTactics: "attack.command_and_control", mitreTechniques: nil,
            suppressed: false
        )
        let enriched = AlertSink.enrichWithAttribution(alert: c2, event: event())
        #expect(enriched.d3fendTechniques == ["D3-OTF", "D3-DNSBA"])
        #expect(enriched.remediationHint?.contains("D3-OTF") == true)

        // A tactic with no clean preventive twin → nil (no fabricated hint).
        let disc = Alert(
            ruleId: "r", ruleTitle: "t", severity: .low, eventId: "e",
            processPath: "/bin/x", processName: "x", description: "d",
            mitreTactics: "attack.discovery", mitreTechniques: nil, suppressed: false
        )
        let enrichedDisc = AlertSink.enrichWithAttribution(alert: disc, event: event())
        #expect(enrichedDisc.d3fendTechniques == nil)
        #expect(enrichedDisc.remediationHint == nil)

        // Caller-supplied values are preserved, never overwritten.
        let preset = Alert(
            ruleId: "r", ruleTitle: "t", severity: .high, eventId: "e",
            processPath: "/bin/x", processName: "x", description: "d",
            mitreTactics: "attack.command_and_control", mitreTechniques: nil,
            suppressed: false,
            d3fendTechniques: ["D3-CUSTOM"], remediationHint: "operator note"
        )
        let enrichedPreset = AlertSink.enrichWithAttribution(alert: preset, event: event())
        #expect(enrichedPreset.d3fendTechniques == ["D3-CUSTOM"])
        #expect(enrichedPreset.remediationHint == "operator note")
    }

    @Test("submit(alert:event:) inserts the alert into AlertStore on first call")
    func submitInsertsFirst() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let inserted = try await sink.submit(alert: makeAlert(), event: event())
        #expect(inserted == true)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("submit(alert:event:) suppresses duplicate within the dedup window")
    func submitSuppressesDuplicate() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        let first = try await sink.submit(alert: makeAlert(), event: ev)
        let second = try await sink.submit(alert: makeAlert(), event: ev)
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)

        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 1)
    }

    @Test("submit(alert:event:) does not dedup across different processPaths")
    func submitDistinguishesProcesses() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let eventA = event(executable: "/usr/bin/a")
        let eventB = event(executable: "/usr/bin/b")
        let a = try await sink.submit(alert: makeAlert(), event: eventA)
        let b = try await sink.submit(alert: makeAlert(), event: eventB)
        #expect(a == true)
        #expect(b == true)

        let count = try await store.count()
        #expect(count == 2)
    }

    @Test("submit(alert:) without event uses alert.processPath as dedup key")
    func submitNoEventUsesProcessPath() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(alert: makeAlert(processPath: "/Applications/Foo.app/Contents/MacOS/Foo"))
        let second = try await sink.submit(alert: makeAlert(processPath: "/Applications/Foo.app/Contents/MacOS/Foo"))
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("submit(alert:) falls back to ruleId when processPath is nil")
    func submitNoEventFallsBackToRuleId() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try await sink.submit(alert: makeAlert(processPath: nil))
        let second = try await sink.submit(alert: makeAlert(processPath: nil))
        #expect(first == true)
        #expect(second == false)

        let count = try await store.count()
        #expect(count == 1)
    }

    @Test("insertEngineBatch passes through without re-dedup")
    func insertEngineBatchPassthrough() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Engine path: caller has already filtered + deduped. Sink inserts
        // the batch as-is. This call must not trigger AlertSink's own dedup
        // — that would suppress legitimate engine emissions.
        let alerts = [
            makeAlert(ruleId: "a"),
            makeAlert(ruleId: "b"),
            makeAlert(ruleId: "c"),
        ]
        try await sink.insertEngineBatch(alerts: alerts)

        let count = try await store.count()
        #expect(count == 3)

        // After a passthrough batch, follow-up direct submits with the SAME
        // ruleId should still go through dedup against their (ruleId, path)
        // tuple — engine batch insertion doesn't pollute the dedup table.
        // (insertEngineBatch deliberately bypasses AlertDeduplicator state.)
        let extra = try await sink.submit(alert: makeAlert(ruleId: "a"), event: event())
        #expect(extra == true)
    }

    @Test("insertEngineBatch with empty array is a no-op")
    func insertEngineBatchEmpty() async throws {
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        try await sink.insertEngineBatch(alerts: [])
        let count = try await store.count()
        #expect(count == 0)
    }

    @Test("Concurrent submits with the same key insert exactly one (TOCTOU pin)")
    func concurrentSubmitsAtomic() async throws {
        // Pre-fix, AlertSink called shouldSuppress and recordAlert as two
        // separate actor hops — a TOCTOU window between them allowed two
        // concurrent submits with the same key to both observe "not
        // suppressed" and both insert. Post-fix, shouldSuppressAndRecord is
        // a single atomic actor method. This test pins that behavior:
        // emit 50 concurrent submits with the same key and verify exactly
        // one inserts.
        let (sink, store, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    (try? await sink.submit(alert: self.makeAlert(), event: ev)) ?? false
                }
            }
            var insertedCount = 0
            for await wasInserted in group where wasInserted {
                insertedCount += 1
            }
            #expect(insertedCount == 1)
        }

        let count = try await store.count()
        #expect(count == 1)

        let stats = await sink.stats()
        #expect(stats.inserted == 1)
        #expect(stats.suppressed == 49)
    }

    @Test("stats() reflects inserted and suppressed counts after mixed traffic")
    func statsAccumulate() async throws {
        let (sink, _, dir) = try await makeSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        let ev = event()
        // 1st insert: new
        _ = try await sink.submit(alert: makeAlert(ruleId: "x"), event: ev)
        // 2nd insert: same key → suppressed
        _ = try await sink.submit(alert: makeAlert(ruleId: "x"), event: ev)
        // 3rd insert: different rule → new
        _ = try await sink.submit(alert: makeAlert(ruleId: "y"), event: ev)
        // 4th insert: different processPath fallback (no event) → new
        _ = try await sink.submit(alert: makeAlert(ruleId: "z", processPath: "/bin/z"))

        let stats = await sink.stats()
        #expect(stats.inserted == 3)
        #expect(stats.suppressed == 1)
    }

    // MARK: - Shared alerts-emitted counter (audit #211)

    @Test("shared alert counter increments once per emitted alert across all submit paths (post-dedup)")
    func sharedCounterCountsEveryEmissionPath() async throws {
        // Regression net for the ~16x HEARTBEAT alerts_emitted / Prometheus
        // alerts_total undercount: pre-fix only the single-event rule-match
        // site incremented the counter, so the ~59 direct-emission paths
        // (graph/intent/sequence/campaign/AI-guard/meta) that flow through
        // AlertSink.submit were invisible. The daemon injects the SAME
        // LockedCounter the heartbeat reads; the sink must increment it once
        // per successfully-inserted (post-dedup) alert on EVERY path.
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-alertsink-counter-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let counter = LockedCounter()
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            alertCounter: counter
        )
        let ev = event()

        // Three distinct direct emissions (the non-rule-match submit path that
        // used to bypass the counter entirely).
        _ = try await sink.submit(alert: makeAlert(ruleId: "graph"), event: ev)
        _ = try await sink.submit(alert: makeAlert(ruleId: "intent"), event: ev)
        _ = try await sink.submit(alert: makeAlert(ruleId: "campaign"), event: ev)
        #expect(counter.get() == 3)

        // A dedup-suppressed submit must NOT count (post-dedup semantics).
        let dup = try await sink.submit(alert: makeAlert(ruleId: "graph"), event: ev)
        #expect(dup == false)
        #expect(counter.get() == 3)

        // The event-less submit path also counts.
        _ = try await sink.submit(alert: makeAlert(ruleId: "selfdefense", processPath: "/bin/z"))
        #expect(counter.get() == 4)

        // The engine batch path counts once per inserted alert (this is the
        // rule-match path — the old EventLoop per-match increment was removed,
        // so exactly the batch size is added, no double-count).
        try await sink.insertEngineBatch(alerts: [
            makeAlert(ruleId: "rule.a"),
            makeAlert(ruleId: "rule.b"),
        ])
        #expect(counter.get() == 6)

        // The shared counter agrees with the sink's own inserted tally.
        let stats = await sink.stats()
        #expect(counter.get() == stats.inserted)
    }
}

// MARK: - FP recalibration (v1.19.3)

/// Pin the dev-tooling / self-noise down-weight applied at the AlertSink
/// chokepoint. Contract: noisy attack-chain alerts on trusted dev-tooling
/// lineage (or MacCrab's own processes) are DOWN-WEIGHTED to informational —
/// never dropped — while must-fire credential-theft / honeyfile detections are
/// PRESERVED at full severity. Exercised through `submit(alert:)` and read back
/// from the store so the test covers the real emission path.
@Suite("AlertSink FP recalibration")
struct AlertSinkRecalibrationTests {

    private func storedSeverity(after alert: Alert) async throws -> Severity {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        _ = try await sink.submit(alert: alert)
        let stored = try await store.alerts(forEventId: alert.eventId)
        return stored.first?.severity ?? alert.severity
    }

    private func alert(
        ruleId: String = "test.rule",
        ruleTitle: String = "Test rule",
        severity: Severity,
        processPath: String?,
        mitreTactics: String? = nil,
        parentExecutable: String? = nil
    ) -> Alert {
        Alert(
            ruleId: ruleId, ruleTitle: ruleTitle, severity: severity,
            eventId: UUID().uuidString, processPath: processPath,
            processName: processPath.map { ($0 as NSString).lastPathComponent },
            description: "d", mitreTactics: mitreTactics, mitreTechniques: nil,
            suppressed: false, parentExecutable: parentExecutable
        )
    }

    @Test("dev-tooling attack-chain high → low (visible, not hidden)")
    func devToolingHighDownweighted() async throws {
        let a = alert(
            ruleId: "d1a2b3c4-0506", ruleTitle: "Curl Fetch Then Exec",
            severity: .high,
            processPath: "/Users/x/proj/node_modules/.bin/esbuild",
            mitreTactics: "attack.command_and_control"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("dev-tooling critical credential-access PRESERVED (must-fire)")
    func devToolingCredentialPreserved() async throws {
        let a = alert(
            ruleTitle: "AI Tool Reads Credentials Then Network",
            severity: .critical,
            processPath: "/Users/x/proj/node_modules/.bin/tool",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    @Test("dev-tooling honeyfile PRESERVED (must-fire)")
    func devToolingHoneyfilePreserved() async throws {
        let a = alert(
            ruleTitle: "Honeyfile Accessed", severity: .high,
            processPath: "/opt/homebrew/bin/something",
            mitreTactics: "attack.collection"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("gh reading its own GitHub token → down-weighted (self-credential tool)")
    func ghGitHubTokenDownweighted() async throws {
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed GitHub Token", severity: .high,
            processPath: "/opt/homebrew/Cellar/gh/2.86.0/bin/gh",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("non-dev-tooling high is UNCHANGED")
    func nonDevToolingUnchanged() async throws {
        let a = alert(
            ruleTitle: "Suspicious Exec", severity: .high,
            processPath: "/Applications/Evil.app/Contents/MacOS/Evil",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("MacCrab self-process noise → low")
    func selfNoiseDownweighted() async throws {
        let a = alert(
            ruleTitle: "Cross-Process Attack Chain", severity: .high,
            processPath: "/Applications/MacCrab.app/Contents/Resources/bin/maccrab-mcp",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("Tier-B verified trampoline staging path is self-noise")
    func tierBTrampolineSelfNoise() async throws {
        let a = alert(
            ruleTitle: "Non-System Binary Lacks Notarization", severity: .medium,
            processPath: "/private/var/folders/hf/X/T/maccrab-tier-b-verified-4F4CCE5E",
            mitreTactics: "attack.defense_evasion"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("dev-tooling lineage via PARENT executable down-weights")
    func parentLineageDevToolingDownweighted() async throws {
        let a = alert(
            ruleTitle: "Curl Fetch Then Exec", severity: .high,
            processPath: "/usr/bin/curl",
            mitreTactics: "attack.command_and_control",
            parentExecutable: "/Users/x/proj/node_modules/.bin/esbuild"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("non-dev-tooling credential theft (real infostealer) is UNCHANGED")
    func realCredentialTheftUnchanged() async throws {
        // A *different* process (not gh) reading credentials, off any dev path —
        // exactly what must keep escalating.
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed GitHub Token", severity: .critical,
            processPath: "/tmp/.hidden/stealer",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    // MARK: - Must-fire classes preserved on dev paths (v1.19.3 adversarial review)

    @Test("dev-tooling IMPACT (ransomware / disk wipe) PRESERVED")
    func devToolingImpactPreserved() async throws {
        let a = alert(
            ruleTitle: "Disk Wipe or Overwrite Command", severity: .critical,
            processPath: "/opt/homebrew/lib/node_modules/evil/bin/wipe",
            mitreTactics: "attack.impact"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    @Test("dev-tooling DEFENSE-EVASION (SIP / Gatekeeper disable) PRESERVED")
    func devToolingDefenseEvasionPreserved() async throws {
        let a = alert(
            ruleTitle: "SIP Disabled", severity: .critical,
            processPath: "/opt/homebrew/bin/installer",
            mitreTactics: "attack.defense_evasion"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    @Test("dev-tooling PERSISTENCE (launchd) PRESERVED")
    func devToolingPersistencePreserved() async throws {
        let a = alert(
            ruleTitle: "LaunchAgent Created by Unsigned Process", severity: .high,
            processPath: "/Users/x/proj/node_modules/.bin/postinstall",
            mitreTactics: "attack.persistence"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("dev-tooling EXFILTRATION PRESERVED")
    func devToolingExfiltrationPreserved() async throws {
        let a = alert(
            ruleTitle: "Archive Created and Uploaded", severity: .high,
            processPath: "/Users/x/.local/share/claude/bin/agent",
            mitreTactics: "attack.exfiltration"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    // MARK: - Campaign meta-alerts skip dev-tooling recalibration

    @Test("campaign meta-alert on a dev-tool contributor is NOT down-weighted")
    func campaignMetaAlertPreserved() async throws {
        let a = alert(
            ruleId: "maccrab.campaign.kill_chain", ruleTitle: "Kill Chain Detected",
            severity: .critical,
            processPath: "/opt/homebrew/bin/workerd",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .critical)
    }

    // MARK: - Anti-spoofing (P0): self-noise gate must be path-anchored

    @Test("spoofed /tmp/maccrabd is NOT treated as self-noise")
    func spoofedMaccrabdNotSelfNoise() async throws {
        // An attacker drops a binary literally named maccrabd in a world-writable
        // dir. It is NOT on a dev-tooling path and NOT a real install location, so
        // it must keep its full severity (the pre-anchoring code wrongly hid it).
        #expect(AlertSink.isMacCrabSelfNoise("/tmp/maccrabd") == false)
        #expect(AlertSink.isMacCrabSelfNoise("/var/tmp/maccrab-mcp") == false)
        #expect(AlertSink.isMacCrabSelfNoise("/Users/x/Downloads/maccrabctl") == false)
        let a = alert(
            ruleTitle: "Unsigned Binary Execution from /tmp", severity: .high,
            processPath: "/tmp/maccrabd",
            mitreTactics: "attack.execution"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("spoofed /tmp tier-B path is NOT treated as self-noise")
    func spoofedTierBNotSelfNoise() async throws {
        #expect(AlertSink.isMacCrabSelfNoise("/tmp/maccrab-tier-b-verified-FAKE/payload") == false)
        // Legitimate per-user temp path still matches.
        #expect(AlertSink.isMacCrabSelfNoise("/private/var/folders/hf/X/T/maccrab-tier-b-verified-REAL/bin") == true)
    }

    @Test("real install + dev-build self-noise paths still match")
    func realSelfNoisePathsMatch() async throws {
        #expect(AlertSink.isMacCrabSelfNoise("/Applications/MacCrab.app/Contents/Resources/bin/maccrabd") == true)
        #expect(AlertSink.isMacCrabSelfNoise("/Users/x/maccrab/.build/arm64-apple-macosx/debug/maccrabctl") == true)
        #expect(AlertSink.isMacCrabSelfNoise("/Library/SystemExtensions/ABC/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent") == true)
    }

    // MARK: - Parent lineage lifted from the EVENT (production reorder fix)

    /// Proves the recalibration-after-enrichment reorder: the alert's own path is
    /// benign (/usr/bin/curl), the dev-tool lineage lives ONLY on the triggering
    /// event's parent. Pre-reorder, parentExecutable was nil at recalibration and
    /// this would have stayed high.
    @Test("dev-tooling parent from the triggering event down-weights")
    func parentFromEventDownweights() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-recal-evt-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = try AlertStore(directory: tempDir.path)
        let sink = AlertSink(alertStore: store, deduplicator: AlertDeduplicator(suppressionWindow: 60))
        let a = alert(
            ruleTitle: "Curl Fetch Then Exec", severity: .high,
            processPath: "/usr/bin/curl",
            mitreTactics: "attack.command_and_control"
        )
        let ev = makeEvent(processName: "curl", processPath: "/usr/bin/curl",
                           commandLine: "curl http://x",
                           parentPath: "/Users/x/proj/node_modules/.bin/esbuild")
        _ = try await sink.submit(alert: a, event: ev)
        let stored = try await store.alerts(forEventId: a.eventId)
        #expect(stored.first?.severity == .low)
    }

    // MARK: - Browser self-credential (narrow self-access; system keychain stays loud)

    @Test("trusted browser reading its OWN credential store → low")
    func browserOwnCredentialStoreDownweighted() async throws {
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed Browser Credential Store", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/149/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("browser credential-file access then upload (own-store sync) → low")
    func browserCredFileUploadDownweighted() async throws {
        let a = alert(
            ruleTitle: "Credential File Access Followed by Network Upload", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access,attack.exfiltration"
        )
        #expect(try await storedSeverity(after: a) == .low)
    }

    @Test("browser touching the SYSTEM login.keychain stays LOUD")
    func browserSystemKeychainPreserved() async throws {
        let a = alert(
            ruleTitle: "login.keychain or System.keychain Database Opened by Non-Apple Process",
            severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("browser 'Keychain Database' access stays LOUD")
    func browserKeychainDatabasePreserved() async throws {
        let a = alert(
            ruleTitle: "🦀 AI Tool Accessed Keychain Database", severity: .high,
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }

    @Test("non-browser AI tool (claude CLI) reading creds then network stays LOUD")
    func claudeCliCredentialPreserved() async throws {
        // ~/.local/share/claude is a dev-tooling path but NOT a browser; the
        // dev-tooling must-fire carve-out preserves credential-access. This is
        // the AIGuard's core detection and must keep escalating.
        let a = alert(
            ruleTitle: "AI Tool Reads Credentials Then Makes Network Connection",
            severity: .high,
            processPath: "/Users/x/.local/share/claude/versions/2.1.186/bin/claude",
            mitreTactics: "attack.credential_access"
        )
        #expect(try await storedSeverity(after: a) == .high)
    }
}
