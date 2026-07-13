// TelemetryGapAttributionTests.swift
// MacCrabCore
//
// v1.21.4 Phase-7 Phase-1 "Graceful attribution" — pin the honest-degradation
// path: when lineage/session attribution is UNRESOLVED *because* a kernel
// telemetry gap (ES per-client-queue backpressure) was active for the event's
// window, the event is stamped `.telemetryGap` / "telemetry_gap" instead of a
// silent NULL. A benign orphan during a no-drop window must stay `.unknown`.
//
// Coverage:
//   1. Enum additions are decode-safe (round-trip + old/unknown → .unknown).
//   2. EventEnricher stamps `.telemetryGap` only on the two-part gate
//      (empty ancestry AND an active gap signal); injected stub keeps it
//      deterministic.
//   3. EventStore persists the "telemetry_gap" sentinel to
//      session_launch_source (and NULL when no gap).
//   4. TraceCorrelator emits a `.telemetryGap` evidence under the same gate,
//      and nothing when the gap is off (default) or ancestry is non-empty.
//   5. TelemetryGapProbe rolling-increase semantics.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("Telemetry-gap graceful attribution")
struct TelemetryGapAttributionTests {

    // MARK: - Builders

    private static func makeOrphan(
        pid: Int32 = 999_999,
        ppid: Int32 = 999_998,
        ancestors: [ProcessAncestor] = [],
        session: SessionInfo? = nil
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: pid,
            name: "orphan",
            executable: "/usr/bin/orphan",
            commandLine: "/usr/bin/orphan",
            args: ["/usr/bin/orphan"],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: Date(),
            codeSignature: nil,
            ancestors: ancestors,
            architecture: "arm64",
            isPlatformBinary: false,
            hashes: nil,
            session: session
        )
    }

    private static func makeEvent(process: MacCrabCore.ProcessInfo) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process
        )
    }

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("telemetry-gap-\(UUID().uuidString).db").path
    }

    /// Read back the `session_launch_source` column for a single inserted row.
    /// Returns nil for SQLITE_NULL, the text otherwise.
    private static func readLaunchSource(at path: String) -> String? {
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        guard let db else { return nil }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT session_launch_source FROM events", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }
        if sqlite3_column_type(stmt, 0) == SQLITE_NULL { return nil }
        return String(cString: sqlite3_column_text(stmt, 0))
    }

    private static let gapOn: @Sendable () -> Bool = { true }
    private static let gapOff: @Sendable () -> Bool = { false }

    // MARK: - 1. Decode-safety

    @Test("LaunchSource.telemetryGap has the 'telemetry_gap' sentinel raw value")
    func launchSourceRawValue() {
        #expect(LaunchSource.telemetryGap.rawValue == "telemetry_gap")
        #expect(LaunchSource(rawValue: "telemetry_gap") == .telemetryGap)
    }

    @Test("SessionInfo(launchSource: .telemetryGap) survives a Codable round-trip")
    func launchSourceRoundTrip() throws {
        let session = SessionInfo(launchSource: .telemetryGap)
        let data = try JSONEncoder().encode(session)
        let decoded = try JSONDecoder().decode(SessionInfo.self, from: data)
        #expect(decoded.launchSource == .telemetryGap)
    }

    @Test("AttributionEvidence Source/Confidence telemetryGap raw values")
    func evidenceRawValues() {
        #expect(AttributionEvidence.Source.telemetryGap.rawValue == "telemetry_gap")
        #expect(AttributionEvidence.Confidence.telemetryGap.rawValue == "telemetry_gap")
    }

    @Test("AttributionEvidence telemetryGap survives a JSON round-trip")
    func evidenceRoundTrip() throws {
        let ev = AttributionEvidence(
            source: .telemetryGap,
            confidence: .telemetryGap,
            agentTool: nil,
            traceId: nil,
            spanId: nil,
            parentSpanId: nil,
            matchedPid: 4242
        )
        let json = try #require(ev.jsonString())
        let back = try #require(AttributionEvidence.from(jsonString: json))
        #expect(back.source == .telemetryGap)
        #expect(back.confidence == .telemetryGap)
    }

    @Test("Old-format / unknown Source & Confidence still fall back to .unknown")
    func unknownDecodeFallsBack() {
        // A value written by a future/older writer that this reader doesn't
        // recognize must NOT fail the whole row — it degrades to .unknown.
        let json = #"{"schemaVersion":1,"source":"some_removed_value","confidence":"gone","matchedPid":7}"#
        let ev = AttributionEvidence.from(jsonString: json)
        #expect(ev?.source == .unknown)
        #expect(ev?.confidence == .unknown)
    }

    // MARK: - 2. EventEnricher gate

    @Test("Active gap + empty ancestry → session stamped .telemetryGap")
    func enricherStampsGapOnOrphanDuringGap() async {
        let enricher = EventEnricher(telemetryGapSignal: Self.gapOn)
        let enriched = await enricher.enrich(Self.makeEvent(process: Self.makeOrphan()))
        #expect(enriched.process.session?.launchSource == .telemetryGap)
    }

    @Test("Quiet window (gap off) + empty ancestry → NO telemetry_gap label (stays unresolved)")
    func enricherQuietOrphanStaysUnknown() async {
        let enricher = EventEnricher(telemetryGapSignal: Self.gapOff)
        let enriched = await enricher.enrich(Self.makeEvent(process: Self.makeOrphan()))
        // Unresolved: SessionEnricher returns nil (empty ancestry) and the gap
        // gate declines → session is nil (column will be NULL), never labelled.
        #expect(enriched.process.session?.launchSource != .telemetryGap)
        #expect(enriched.process.session == nil)
    }

    @Test("No gap signal wired (nil) → orphan is never telemetry_gap")
    func enricherNoSignalNeverGaps() async {
        let enricher = EventEnricher() // telemetryGapSignal defaults nil
        let enriched = await enricher.enrich(Self.makeEvent(process: Self.makeOrphan()))
        #expect(enriched.process.session?.launchSource != .telemetryGap)
    }

    @Test("Gap active but ancestry resolves → real launch source wins, not telemetry_gap")
    func enricherRealAncestryWins() async {
        // A terminal ancestor means attribution IS resolvable — the gap gate
        // must not override it. Passed via ProcessInfo.ancestors (lineage graph
        // is empty for this fresh enricher, so `enrich` falls back to them).
        let terminal = ProcessAncestor(
            pid: 500,
            executable: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            name: "Terminal"
        )
        let enricher = EventEnricher(telemetryGapSignal: Self.gapOn)
        let enriched = await enricher.enrich(
            Self.makeEvent(process: Self.makeOrphan(ancestors: [terminal]))
        )
        #expect(enriched.process.session?.launchSource == .terminal)
    }

    // MARK: - 3. EventStore persistence

    @Test("Orphan enriched during a gap persists session_launch_source = 'telemetry_gap'")
    func persistsSentinelDuringGap() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let enricher = EventEnricher(telemetryGapSignal: Self.gapOn)
        let enriched = await enricher.enrich(Self.makeEvent(process: Self.makeOrphan()))
        try await store.insert(event: enriched)

        #expect(Self.readLaunchSource(at: path) == "telemetry_gap")
    }

    @Test("Orphan enriched in a quiet window persists NULL (not the sentinel)")
    func persistsNullWhenQuiet() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        let enricher = EventEnricher(telemetryGapSignal: Self.gapOff)
        let enriched = await enricher.enrich(Self.makeEvent(process: Self.makeOrphan()))
        try await store.insert(event: enriched)

        #expect(Self.readLaunchSource(at: path) == nil)
    }

    // MARK: - 4. TraceCorrelator gate

    private static func identity(pid: pid_t = 4242, path: String = "/usr/bin/orphan") -> ProcessIdentity {
        ProcessIdentity(
            auditIdentity: AuditIdentity(
                auid: 0, euid: 0, egid: 0, ruid: 0, rgid: 0,
                pid: pid, pidversion: 0, asid: 0
            ),
            pathHash: ProcessIdentity.fnv1a64(path),
            pid: pid,
            startTime: 0
        )
    }

    @Test("correlate: gap active + empty ancestry + no attribution → telemetryGap evidence")
    func correlateEmitsGapEvidence() async throws {
        let reg = TraceRegistry()
        let correlation = await TraceCorrelator.correlate(
            identity: Self.identity(),
            ancestors: [],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { _ in nil },
            telemetryGapActive: true
        )
        let c = try #require(correlation)
        #expect(c.evidence.source == .telemetryGap)
        #expect(c.evidence.confidence == .telemetryGap)
        #expect(c.enrichments[TraceCorrelator.EnrichmentKey.confidence] == "telemetry_gap")
        // Not an agent attribution: no tool / trace flattened.
        #expect(c.enrichments[TraceCorrelator.EnrichmentKey.agentTool] == nil)
        #expect(c.enrichments[TraceCorrelator.EnrichmentKey.traceId] == nil)
    }

    @Test("correlate: gap OFF (default) + empty ancestry → nil (unchanged for existing callers)")
    func correlateGapOffReturnsNil() async {
        let reg = TraceRegistry()
        let correlation = await TraceCorrelator.correlate(
            identity: Self.identity(),
            ancestors: [],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { _ in nil }
        )
        #expect(correlation == nil)
    }

    @Test("correlate: gap active but ancestry non-empty → nil (empty-ancestry gate required)")
    func correlateNonEmptyAncestryNoGap() async {
        let reg = TraceRegistry()
        let ancestor = ProcessAncestor(pid: 500, executable: "/bin/zsh", name: "zsh")
        let correlation = await TraceCorrelator.correlate(
            identity: Self.identity(),
            ancestors: [ancestor],
            registry: reg,
            ancestorIdentityResolver: { _ in nil },
            aiToolForPath: { _ in nil }, // no AI tool → no real attribution
            telemetryGapActive: true
        )
        #expect(correlation == nil)
    }

    // MARK: - 5. TelemetryGapProbe rolling semantics

    @Test("TelemetryGapProbe reports true only when the drop count advances")
    func probeRollingIncrease() {
        var count: UInt64 = 0
        let probe = TelemetryGapProbe(read: { count })

        #expect(probe.gapActive() == false) // 0 vs seed 0
        count = 5
        #expect(probe.gapActive() == true)  // advanced
        #expect(probe.gapActive() == false) // no further advance
        count = 6
        #expect(probe.gapActive() == true)  // advanced again
        // The @Sendable signal wraps the same rolling state.
        #expect(probe.signal() == false)
    }
}
