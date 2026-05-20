// CodesignResolveEnricher tests — fields shape, idempotency (Pass
// 2026-C invariant), unknown-path fallback.
//
// The system binary paths used here are stable across macOS 13+
// per Apple's SIP rooted /usr/bin and /System layout. Tests run
// against the real Security framework — there's no good way to
// mock SecStaticCode, and the cost is negligible (~1ms per
// evaluate after warmup).

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("CodesignResolveEnricher")
struct CodesignResolveEnricherTests {

    private func subject(forPath path: String) -> EnrichmentSubject {
        .path(URL(fileURLWithPath: path))
    }

    @Test("Resolves an Apple-signed system binary as signing_status=apple")
    func appleSignedSystemBinary() async throws {
        let enricher = try await CodesignResolveEnricher()
        let result = try await enricher.enrich(
            subject(forPath: "/usr/bin/true"),
            stage: .onDemand
        )
        #expect(result.fields["codesign.signing_status"] == .string("apple"))
        // Apple system binaries usually carry no team_id but the
        // field is allowed; just confirm the type when present.
        if let teamID = result.fields["codesign.team_id"] {
            if case .string(let s) = teamID {
                #expect(!s.isEmpty)
            }
        }
        #expect(result.privacyClass == .metadata)
        #expect(result.confidence == .observed)
        #expect(result.pluginID == "com.maccrab.enricher.codesign-resolve")
    }

    @Test("Unknown path yields signing_status=unknown with error=path_not_found")
    func unknownPath() async throws {
        let enricher = try await CodesignResolveEnricher()
        let result = try await enricher.enrich(
            subject(forPath: "/var/empty/no-such-binary-at-all"),
            stage: .onDemand
        )
        #expect(result.fields["codesign.signing_status"] == .string("unknown"))
        #expect(result.fields["codesign.error"] == .string("path_not_found"))
    }

    @Test("Event payload with nil processExecutablePath yields signing_status=unknown")
    func nilExecutablePathYieldsUnknown() async throws {
        let enricher = try await CodesignResolveEnricher()
        let event = EnrichmentEventPayload(
            id: "evt-nil",
            processExecutablePath: nil,
            processPID: nil,
            timestamp: Date(),
            categoryRaw: "process_creation"
        )
        let result = try await enricher.enrich(.event(event), stage: .preDetection)
        #expect(result.fields["codesign.signing_status"] == .string("unknown"))
    }

    @Test("Subject from an event payload uses processExecutablePath")
    func eventSubjectUsesExecPath() async throws {
        let enricher = try await CodesignResolveEnricher()
        let event = EnrichmentEventPayload(
            id: "evt-1",
            processExecutablePath: "/usr/bin/true",
            processPID: 1,
            timestamp: Date(),
            categoryRaw: "process_creation"
        )
        let result = try await enricher.enrich(.event(event), stage: .preDetection)
        #expect(result.fields["codesign.signing_status"] == .string("apple"))
    }
}

@Suite("CodesignResolveEnricher: Pass 2026-C idempotency")
struct CodesignResolveEnricherIdempotencyTests {

    /// The Pass 2026-C invariant: for any (subject, stage), the
    /// emitted Enrichment.fields dictionary is byte-identical
    /// across re-runs. Concretely we re-run twice and assert
    /// dictionary equality. The `producedAt` field is allowed to
    /// drift (it's a per-call timestamp, not a payload value); the
    /// fields are what consumers consume.
    @Test("Re-running enrich(/usr/bin/true, .preDetection) yields identical fields")
    func idempotentOnUsrBinTrue() async throws {
        let enricher = try await CodesignResolveEnricher()
        let s: EnrichmentSubject = .path(URL(fileURLWithPath: "/usr/bin/true"))
        let first = try await enricher.enrich(s, stage: .preDetection)
        let second = try await enricher.enrich(s, stage: .preDetection)
        #expect(first.fields == second.fields)
    }

    @Test("Re-running on a nonexistent path yields identical fields")
    func idempotentOnUnknownPath() async throws {
        let enricher = try await CodesignResolveEnricher()
        let s: EnrichmentSubject = .path(URL(fileURLWithPath: "/var/empty/nope"))
        let first = try await enricher.enrich(s, stage: .preDetection)
        let second = try await enricher.enrich(s, stage: .preDetection)
        #expect(first.fields == second.fields)
    }

    @Test("Different stages on the same path also yield identical fields")
    func stageIndependent() async throws {
        let enricher = try await CodesignResolveEnricher()
        let s: EnrichmentSubject = .path(URL(fileURLWithPath: "/usr/bin/true"))
        let preDetection = try await enricher.enrich(s, stage: .preDetection)
        let onDemand = try await enricher.enrich(s, stage: .onDemand)
        // Stage doesn't change the codesign posture; fields stay
        // identical. (If a future enricher DID consult stage, this
        // test would catch the behavioral split and the manifest
        // would need a corresponding `stage` argument flag.)
        #expect(preDetection.fields == onDemand.fields)
    }
}

@Suite("PluginRunner.runEnricher")
struct PluginRunnerEnricherTests {

    @Test("Run codesign-resolve via the runner emits an Enrichment and an invocation row")
    func runEnricherEndToEnd() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-enricher-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "enricher test")

        // Construct a scoped registry containing the enricher.
        let registry = PluginRegistry()
        try await registry.register(PluginRegistration(
            manifest: CodesignResolveEnricher.manifest,
            factory: { try await CodesignResolveEnricher() }
        ))
        let runner = PluginRunner(registry: registry)

        let (enrichment, invocationID) = try await runner.runEnricher(
            id: "com.maccrab.enricher.codesign-resolve",
            handle: handle,
            subject: .path(URL(fileURLWithPath: "/usr/bin/true")),
            stage: .preDetection
        )
        #expect(invocationID > 0)
        #expect(enrichment.fields["codesign.signing_status"] == .string("apple"))
    }

    @Test("Running an unregistered enricher id throws pluginNotFound")
    func unknownEnricherThrows() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-noenr-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "absent")
        let registry = PluginRegistry()
        let runner = PluginRunner(registry: registry)
        await #expect(throws: PluginRunnerError.self) {
            _ = try await runner.runEnricher(
                id: "com.maccrab.enricher.no.such",
                handle: handle,
                subject: .path(URL(fileURLWithPath: "/usr/bin/true")),
                stage: .preDetection
            )
        }
    }

    @Test("Running a Collector via runEnricher throws pluginKindMismatch")
    func kindMismatchThrows() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-kindmis-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "kindmis")
        let registry = PluginRegistry()
        try await registry.register(PluginRegistration(
            manifest: FixturePlugin.manifest,
            factory: { try await FixturePlugin() }
        ))
        let runner = PluginRunner(registry: registry)
        await #expect(throws: PluginRunnerError.self) {
            _ = try await runner.runEnricher(
                id: "com.maccrab.forensics.fixture",
                handle: handle,
                subject: .path(URL(fileURLWithPath: "/usr/bin/true")),
                stage: .preDetection
            )
        }
    }
}
