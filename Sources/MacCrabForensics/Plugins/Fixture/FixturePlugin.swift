// FixturePlugin — `com.maccrab.forensics.fixture`. No-op Collector
// that emits a single `fixture.heartbeat` artifact. Exists to:
//   - exercise the full plugin lifecycle (register, validate,
//     construct, invoke, record invocation) without depending on
//     macOS TCC.db or launchd plists,
//   - give the maccrabctl plugin / case subcommands something to
//     run on a fresh case before the real collectors land,
//   - serve as the test fixture for PluginRunner.
//
// Plan reference: §7 v1.13a-1 sub-slice 1 — "a
// com.maccrab.forensics.fixture no-op plugin exists to exercise
// the lifecycle."

import Foundation
import CryptoKit

// DEBUG-only test fixture. A no-op collector used solely to exercise the plugin
// lifecycle and back PluginRunner tests. It must not ship in a release build —
// not registered (Bootstrap is also #if DEBUG) and the type itself is gated so
// its marker string never appears in a release binary. Tests register it
// directly and compile in DEBUG, so they're unaffected.
#if DEBUG
public struct FixturePlugin: Collector {

    public static let manifest = PluginManifest(
        id: "com.maccrab.forensics.fixture",
        version: "1.0.0",
        displayName: "Fixture",
        description: "No-op plugin used to exercise the platform's lifecycle. Emits a single fixture.heartbeat artifact.",
        type: .collector,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [
            InputSpec(
                name: "tickCount",
                description: "Number of fixture.heartbeat artifacts to emit per invocation.",
                type: .integer,
                default: .integer(1),
                required: false
            ),
        ],
        outputs: [
            OutputSpec(
                contentType: "fixture.heartbeat",
                privacyClass: .metadata,
                optInRequired: false
            ),
        ],
        mcpTools: [
            MCPToolDescriptor(
                name: "fixture_emit_heartbeat",
                description: "Emit a single fixture.heartbeat artifact into a case. Useful for end-to-end testing the platform.",
                exposesPrivacyClass: .metadata
            ),
        ],
        schemaVersion: 1,
        stability: .preview
    )

    public init() async throws {}

    public func collect(
        case caseContext: CaseContext,
        window: TimeWindow?,
        output: any CollectorOutput
    ) async throws -> CollectionResult {

        // Read tickCount from inputs is a v1.13a-1.6 follow-up
        // (the CLI parses inputs and the runner forwards them to
        // the plugin — currently inputs are in PluginInvocationInputs
        // but not visible to the plugin). For v1.13a-1 the fixture
        // emits exactly one artifact unconditionally.
        let tickCount = 1
        var committed = 0
        let now = Date()

        for tick in 0..<tickCount {
            let payload: [String: JSONValue] = [
                "tick": .integer(Int64(tick)),
                "case_id": .string(caseContext.caseID),
                "fixture_marker": .string("maccrab-forensics-fixture-v1.13a-1"),
            ]
            // Stable sha256 derived from (caseID, tick) — keeps
            // re-invocations deterministic per tick.
            let stableSeed = "\(caseContext.caseID):tick=\(tick):fixture-v1"
            let digest = SHA256.hash(data: Data(stableSeed.utf8))
            let sha = digest.map { String(format: "%02x", $0) }.joined()

            let record = ArtifactRecord(
                caseID: caseContext.caseID,
                pluginID: Self.manifest.id,
                pluginVersion: Self.manifest.version,
                schemaVersion: Self.manifest.schemaVersion,
                contentType: "fixture.heartbeat",
                sha256: sha,
                observedAt: now,
                capturedAt: now,
                summary: "fixture heartbeat tick \(tick)",
                sizeBytes: 0,
                confidence: .observed,
                privacyClass: .metadata,
                data: payload
            )
            try await output.commit(record)
            committed += 1
        }

        return CollectionResult(
            artifactsCommitted: committed,
            artifactsRejected: 0,
            notes: ["fixture heartbeat emitted at \(now.ISO8601Format())"],
            status: .ok
        )
    }
}
#endif
