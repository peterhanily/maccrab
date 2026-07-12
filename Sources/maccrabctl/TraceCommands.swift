// TraceCommands.swift
// maccrabctl
//
// v1.10 TraceGraph (PR-9) — surfaces the bundle pipeline through
// the CLI: validate, verify, inspect, export, list, show, explain,
// from-agent, from-process, from-process-key, plus debug helpers.
//
// Validate / verify exit codes are stable per §18.9 of the v1.10.0
// spec — `maccrabctl trace validate bundle` is intended to drop into
// CI pipelines.

import Foundation
import MacCrabCore

extension MacCrabCtl {

    // MARK: - Path helpers

    static func tracegraphDBPath() -> String {
        return maccrabDataDir() + "/tracegraph.db"
    }

    private static func openStore() async -> SQLiteCausalGraphStore? {
        let path = tracegraphDBPath()
        if !FileManager.default.fileExists(atPath: path) {
            print("tracegraph.db not found at \(path)")
            print("(Trace materialization runs in the daemon — start it via the system extension, or build a synthetic trace via the Swift API.)")
            return nil
        }
        do {
            return try await SQLiteCausalGraphStore(databasePath: path)
        } catch {
            print("Failed to open tracegraph.db: \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - trace list

    static func traceList(limit: Int = 20) async {
        guard let store = await openStore() else { exit(0) }
        do {
            let traces = try await store.listTraces(limit: limit)
            if traces.isEmpty {
                print("No traces. (Materialization is daemon-driven — check ESCollector + RollingCausalGraph wiring.)")
                await store.close()
                return
            }
            print("MacCrab TraceGraph — \(traces.count) traces (most recent first)")
            print(String(repeating: "─", count: 80))
            // String(format: %s) with Swift String segfaults — use
            // explicit padding helpers instead.
            print("\(pad("id", 36))  \(pad("severity", 10))  \(pad("conf", 7))  \(pad("status", 12))  title")
            print(String(repeating: "─", count: 80))
            for trace in traces {
                let severity = severityFromString(trace.severity)
                let coloredSev = severity?.coloredLabel ?? trace.severity
                let confStr = String(format: "%.2f", trace.confidence)
                print("\(pad(trace.id, 36))  \(pad(coloredSev, 10))  \(pad(confStr, 7))  \(pad(trace.status, 12))  \(trace.title)")
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    // MARK: - trace show

    static func traceShow(id: String) async {
        guard let store = await openStore() else { exit(0) }
        do {
            guard let loaded = try await store.loadTrace(id: id) else {
                print("Trace not found: \(id)")
                await store.close()
                exit(1)
            }
            let trace = loaded.trace
            print("Trace \(trace.id)")
            print(String(repeating: "═", count: 60))
            print("  title:     \(trace.title)")
            print("  severity:  \(trace.severity)")
            print("  confidence: \(String(format: "%.2f", trace.confidence))")
            print("  status:    \(trace.status)")
            print("  anchor:    \(trace.anchorEventId)")
            if let root = trace.rootEntityId {
                print("  root:      \(root)")
            }
            print("  daemon:    \(trace.daemonVersion)")
            print("  ruleset:   \(trace.rulesetVersion)")
            print("  policy:    \(trace.policyId) v\(trace.policyVersion)")
            print("  signing:   \(trace.traceSigningKeyMode)")
            print("  replay:    \(trace.replayScope)")
            print("  override:  \(trace.attributionOverridePolicy)")
            print("  created:   \(trace.createdAt)")
            print("")
            print("  Members (\(loaded.members.count)):")
            let byRole = Dictionary(grouping: loaded.members) { $0.role }
            for role in ["anchor", "root", "critical_path", "context", "evidence", "suppressed"] {
                if let members = byRole[role], !members.isEmpty {
                    print("    \(role): \(members.count)")
                    for member in members.prefix(10) {
                        if let eid = member.entityId {
                            print("      entity: \(eid)")
                        } else if let edgeId = member.edgeId {
                            print("      edge:   \(edgeId)")
                        }
                    }
                    if members.count > 10 {
                        print("      … and \(members.count - 10) more")
                    }
                }
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    // MARK: - trace explain

    static func traceExplain(id: String) async {
        guard let store = await openStore() else { exit(0) }
        do {
            guard let loaded = try await store.loadTrace(id: id) else {
                print("Trace not found: \(id)")
                await store.close()
                exit(1)
            }
            let trace = loaded.trace
            print("\(trace.title)")
            print(String(repeating: "═", count: trace.title.count))
            print("severity: \(trace.severity)  confidence: \(String(format: "%.2f", trace.confidence))")
            print("")
            if let summaryJson = trace.summaryJson,
               let data = summaryJson.data(using: .utf8),
               let explanation = try? JSONDecoder().decode(StructuredExplanation.self, from: data) {
                print("Root cause:")
                print("  \(explanation.rootCause.display)")
                print("  \(explanation.rootCause.trustTransition)")
                if !explanation.criticalPath.isEmpty {
                    print("")
                    print("Critical path: \(explanation.criticalPath.count) edges")
                    for edge in explanation.criticalPath.prefix(20) {
                        print("  \(edge.from) --[\(edge.relation), \(edge.tier)]--> \(edge.to)")
                    }
                }
                if !explanation.severityReasons.isEmpty {
                    print("")
                    print("Why severity \(trace.severity):")
                    for reason in explanation.severityReasons {
                        print("  • \(reason)")
                    }
                }
                if !explanation.confidenceReasons.isEmpty {
                    print("")
                    print("Why confidence \(String(format: "%.2f", trace.confidence)):")
                    for reason in explanation.confidenceReasons {
                        print("  • \(reason)")
                    }
                }
                if !explanation.attackMapping.isEmpty {
                    print("")
                    print("ATT&CK: \(explanation.attackMapping.joined(separator: ", "))")
                }
            } else {
                print("No structured explanation recorded.")
                if let attackJson = trace.attackJson,
                   let data = attackJson.data(using: .utf8),
                   let techniques = try? JSONSerialization.jsonObject(with: data) as? [String] {
                    print("")
                    print("ATT&CK: \(techniques.joined(separator: ", "))")
                }
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    // MARK: - trace graph

    static func traceGraph(id: String, asJson: Bool = false) async {
        guard let store = await openStore() else { exit(0) }
        do {
            guard let loaded = try await store.loadTrace(id: id) else {
                print("Trace not found: \(id)")
                await store.close()
                exit(1)
            }
            // Gather all entities + edges referenced by membership.
            var entityIds = Set<String>()
            var edgeIds = Set<String>()
            for member in loaded.members {
                if let eid = member.entityId { entityIds.insert(eid) }
                if let edgeId = member.edgeId { edgeIds.insert(edgeId) }
            }
            var entities: [TraceEntity] = []
            for eid in entityIds {
                if let e = try await store.entity(id: eid) { entities.append(e) }
            }
            var edges: [TraceEdge] = []
            for edgeId in edgeIds {
                if let e = try await store.edge(id: edgeId) { edges.append(e) }
            }

            if asJson {
                let graph = GraphArtifact(
                    trace: loaded.trace,
                    entities: entities, edges: edges,
                    memberships: loaded.members,
                    rootCauseEntityId: loaded.trace.rootEntityId,
                    anchorEntityId: loaded.members.first(where: { $0.role == "anchor" })?.entityId
                        ?? loaded.trace.anchorEventId
                )
                let encoder = canonicalJSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
                let data = try encoder.encode(graph)
                if let text = String(data: data, encoding: .utf8) {
                    print(text)
                }
            } else {
                print("Trace \(loaded.trace.id) — \(entities.count) entities, \(edges.count) edges")
                print(String(repeating: "─", count: 60))
                for entity in entities.sorted(by: { $0.firstSeen < $1.firstSeen }) {
                    print("  [\(entity.entityType)] \(entity.displayName)  (\(entity.id))")
                }
                print("")
                for edge in edges.sorted(by: { $0.firstSeen < $1.firstSeen }) {
                    let sourceName = entities.first(where: { $0.id == edge.sourceEntityId })?.displayName ?? edge.sourceEntityId
                    let targetName = entities.first(where: { $0.id == edge.targetEntityId })?.displayName ?? edge.targetEntityId
                    print("  \(sourceName) --[\(edge.relation), \(edge.confidenceTier)]--> \(targetName)")
                }
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    // MARK: - trace from-process-key

    static func traceFromProcessKey(_ key: String) async {
        guard let store = await openStore() else { exit(0) }
        let entityId = "process:\(key)"
        do {
            guard let _ = try await store.entity(id: entityId) else {
                print("No process entity with key \(key)")
                await store.close()
                exit(1)
            }
            // Find traces that include this entity as a member.
            let allTraces = try await store.listTraces(limit: 1000)
            var matched: [Trace] = []
            for trace in allTraces {
                if let loaded = try await store.loadTrace(id: trace.id) {
                    if loaded.members.contains(where: { $0.entityId == entityId }) {
                        matched.append(loaded.trace)
                    }
                }
            }
            print("\(matched.count) trace(s) reference process:\(key)")
            for trace in matched {
                print("  \(trace.id)  [\(trace.severity)]  \(trace.title)")
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    // MARK: - trace from-process / from-agent (linear scans)

    static func traceFromProcess(pid: Int32, windowMinutes: Int = 20) async {
        guard let store = await openStore() else { exit(0) }
        do {
            let allTraces = try await store.listTraces(limit: 1000)
            var matched: [Trace] = []
            for trace in allTraces {
                if let loaded = try await store.loadTrace(id: trace.id) {
                    for member in loaded.members {
                        guard let eid = member.entityId,
                              let entity = try await store.entity(id: eid),
                              entity.entityType == ProcessNode.entityType,
                              let data = entity.attributesJson.data(using: .utf8),
                              let proc = try? JSONDecoder.dateMillis().decode(ProcessNode.self, from: data),
                              proc.pid == pid
                        else { continue }
                        matched.append(loaded.trace)
                        break
                    }
                }
            }
            print("\(matched.count) trace(s) reference pid \(pid)")
            for trace in matched {
                print("  \(trace.id)  [\(trace.severity)]  \(trace.title)")
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    static func traceFromAgent(name: String, windowMinutes: Int = 20) async {
        guard let store = await openStore() else { exit(0) }
        do {
            let allTraces = try await store.listTraces(limit: 1000)
            var matched: [Trace] = []
            for trace in allTraces {
                if let loaded = try await store.loadTrace(id: trace.id) {
                    for member in loaded.members {
                        guard let eid = member.entityId,
                              let entity = try await store.entity(id: eid),
                              entity.entityType == AIAgentNode.entityType,
                              let data = entity.attributesJson.data(using: .utf8),
                              let agent = try? JSONDecoder.dateMillis().decode(AIAgentNode.self, from: data),
                              agent.agentName.lowercased().contains(name.lowercased())
                        else { continue }
                        matched.append(loaded.trace)
                        break
                    }
                }
            }
            print("\(matched.count) trace(s) reference agent matching \"\(name)\"")
            for trace in matched {
                print("  \(trace.id)  [\(trace.severity)]  \(trace.title)")
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    // MARK: - trace export

    static func traceExport(
        traceId: String,
        outputDir: URL?,
        includeRawPaths: Bool,
        includeHostname: Bool
    ) async {
        guard let store = await openStore() else { exit(0) }
        do {
            guard let loaded = try await store.loadTrace(id: traceId) else {
                print("Trace not found: \(traceId)")
                await store.close()
                exit(1)
            }

            // A3-04 verify-on-load: check the on-DB continuity chain before
            // exporting. Advisory (non-fatal) — a break here means the local
            // tracegraph.db ledger was mutated/truncated since materialization;
            // we surface it so the operator knows, but still let the export
            // proceed (the exported bundle carries its own signed Merkle root).
            switch try await store.verifyHashChain().status {
            case .ok:
                break
            case .brokenContent(let seq):
                print("WARNING: trace continuity chain integrity check failed (content mismatch at sequence \(seq)); local ledger may have been modified.")
            case .brokenLinkage(let seq):
                print("WARNING: trace continuity chain integrity check failed (broken link at sequence \(seq)); a ledger entry may have been deleted or inserted.")
            }
            // Collect entities + edges from memberships.
            var entityIds = Set<String>()
            var edgeIds = Set<String>()
            for member in loaded.members {
                if let eid = member.entityId { entityIds.insert(eid) }
                if let edgeId = member.edgeId { edgeIds.insert(edgeId) }
            }
            var entities: [TraceEntity] = []
            for eid in entityIds {
                if let e = try await store.entity(id: eid) { entities.append(e) }
            }
            var edges: [TraceEdge] = []
            for edgeId in edgeIds {
                if let e = try await store.edge(id: edgeId) { edges.append(e) }
            }

            // TrustSubstrate from production storage. If unavailable
            // (no signing key generated yet), fall back to the
            // UNSIGNED placeholder so the bundle still exports.
            let signingDir = URL(fileURLWithPath: maccrabDataDir() + "/keys/")
            let storage = FilesystemTrustSubstrateStorage(baseDirectory: signingDir)
            let trustSubstrate = TrustSubstrate(storage: storage)
            let mode = (try? await trustSubstrate.activeMode()) ?? .filesystemDegraded
            print("Signing with TrustSubstrate (\(mode.rawValue))")

            let target = outputDir
                ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                    .appendingPathComponent("\(traceId).maccrabtrace")

            let inputs = BundleExporter.Inputs(
                trace: loaded.trace,
                entities: entities, edges: edges,
                memberships: loaded.members,
                eventsJsonl: [],
                policySnapshotJson: loaded.trace.policySnapshotJson
            )
            var options = BundleExporter.Options()
            options.includeRawPaths = includeRawPaths
            options.includeHostname = includeHostname

            // A3-01(a): wire a real unified-log anchor into every production
            // export so the exporter's chain-head emit actually runs. Without
            // this the subsystem was never written and `verify
            // --check-unified-log` could never find a record. The emitted
            // record is the external OS-managed witness of the signed head.
            let exporter = BundleExporter(
                redactor: BundleRedactor.systemDefault(),
                trustSubstrate: trustSubstrate,
                unifiedLogAnchor: SystemUnifiedLogAnchor()
            )
            try await exporter.export(inputs: inputs, to: target, options: options)
            print("Bundle written: \(target.path)")

            // Tar.gz packaging via /usr/bin/tar.
            let tarPath = target.path + ".tar.gz"
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
            proc.currentDirectoryURL = target.deletingLastPathComponent()
            proc.arguments = ["-czf", tarPath, target.lastPathComponent]
            try proc.run()
            proc.waitUntilExit()
            if proc.terminationStatus == 0 {
                let attrs = try? FileManager.default.attributesOfItem(atPath: tarPath)
                let sizeBytes = (attrs?[.size] as? NSNumber)?.intValue ?? 0
                print("Archive: \(tarPath)  (\(sizeBytes) bytes)")
            } else {
                print("tar exited with status \(proc.terminationStatus); directory left at \(target.path)")
            }
        } catch {
            print("Export failed: \(error.localizedDescription)")
            exit(1)
        }
        await store.close()
    }

    // MARK: - trace validate / inspect / verify

    static func traceValidate(bundlePath: String) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        let outcome = BundleValidator.validate(at: target)
        printOutcome(outcome, label: "validate")
        cleanupExtracted(directory)
        exit(outcome.exitCode)
    }

    static func traceInspect(bundlePath: String) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }
        do {
            let manifestData = try Data(contentsOf: target.appendingPathComponent("manifest.json"))
            let manifest = try canonicalJSONDecoder().decode(BundleManifest.self, from: manifestData)
            print("Bundle: \(bundlePath)")
            print(String(repeating: "═", count: 60))
            print("  format:                \(manifest.format)")
            print("  trace_id:              \(manifest.traceId)")
            print("  title:                 \(manifest.title)")
            print("  severity:              \(manifest.severity)")
            print("  confidence:            \(String(format: "%.2f", manifest.confidence))")
            print("  maccrab_version:       \(manifest.maccrabVersion)")
            print("  ruleset_version:       \(manifest.rulesetVersion)")
            print("  normalization_version: \(manifest.normalizationVersion)")
            print("  created_at:            \(manifest.createdAt)")
            print("  host_redacted:         \(manifest.hostRedacted)")
            print("  trace_signing_mode:    \(manifest.traceSigningKeyMode)")
            print("  replay_scope:          \(manifest.replayScope)")
            print("  override_policy:       \(manifest.attributionOverridePolicy)")
            print("  prov_compliant:        \(manifest.provCompliant)")
            print("  otel_aligned:          \(manifest.otelAligned)")
            print("  otel_convention:       \(manifest.otelConventionVersion)")
            // Graph counts
            if let graphData = try? Data(contentsOf: target.appendingPathComponent("graph.json")),
               let graph = try? canonicalJSONDecoder().decode(GraphArtifact.self, from: graphData) {
                print("  entities:              \(graph.entities.count)")
                print("  edges:                 \(graph.edges.count)")
                print("  memberships:           \(graph.memberships.count)")
            }
            // Integrity
            if let chainData = try? Data(contentsOf: target.appendingPathComponent("integrity/hash_chain.json")),
               let chain = try? canonicalJSONDecoder().decode(HashChainArtifact.self, from: chainData) {
                print("  artifact_count:        \(chain.artifacts.count)")
                print("  merkle_root:           \(chain.merkleRoot)")
            }
            if let sigData = try? Data(contentsOf: target.appendingPathComponent("integrity/chain_head_signature.json")),
               let sig = try? canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: sigData) {
                print("  signing_key_mode:      \(sig.signingKeyMode)")
                print("  signing_key_fingerprint: \(sig.signingKeyFingerprint)")
                print("  signed_at:             \(sig.signedAt)")
                print("  signature:             \(sig.signatureBase64.prefix(40))…")
            }
        } catch {
            print("Inspect failed: \(error.localizedDescription)")
            exit(1)
        }
    }

    static func traceVerify(bundlePath: String, checkUnifiedLog: Bool) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }
        var options = BundleVerifier.Options()
        options.checkUnifiedLog = checkUnifiedLog
        let anchor: UnifiedLogAnchor? = checkUnifiedLog ? SystemUnifiedLogAnchor() : nil

        // storage-01: anchor the signature to a key we trust, not the one the
        // bundle ships. TOFU pin store keyed by trace_id — first verify of a
        // trace_id pins the key it was signed with; a later rewrite-and-resign
        // (attacker swaps the embedded key) then fails with exit 3.
        let pinStore = TraceKeyPinStore()
        let traceId = (try? Data(contentsOf: target.appendingPathComponent("manifest.json")))
            .flatMap { try? canonicalJSONDecoder().decode(BundleManifest.self, from: $0) }?
            .traceId
        if let traceId, let pinned = pinStore.pinnedFingerprint(forTraceId: traceId) {
            options.pinnedKeyFingerprint = pinned
        }

        let outcome = await BundleVerifier.verify(at: target, unifiedLogAnchor: anchor, options: options)

        // TOFU: on a clean first verify, record the key we just trusted.
        if outcome.exitCode == 0, let traceId,
           let sigData = try? Data(contentsOf: target.appendingPathComponent("integrity/chain_head_signature.json")),
           let sig = try? canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: sigData) {
            pinStore.pinIfAbsent(traceId: traceId, fingerprint: sig.signingKeyFingerprint)
        }

        printOutcome(outcome, label: "verify")
        exit(outcome.exitCode)
    }

    // MARK: - trace replay

    static func traceReplay(bundlePath: String, expectedNormalizationVersion: String) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }

        let engine = ReplayEngine()
        var options = ReplayEngine.ReplayOptions()
        options.expectedNormalizationVersion = expectedNormalizationVersion
        do {
            let result = try await engine.replay(bundleAt: target, options: options)
            print("[replay] result=\(result.result.rawValue) deterministic=\(result.deterministic) exit=\(result.exitCode)")
            print("  trace_id:        \(result.traceId)")
            print("  bundle_id:       \(result.bundleId)")
            print("  replay_engine:   \(result.replayEngineVersion)")
            print("  ruleset_sha256:  \(result.rulesetSha256)")
            print("  result_sha256:   \(result.resultSha256)")
            if !result.alerts.isEmpty {
                print("  alerts (\(result.alerts.count)):")
                for alert in result.alerts {
                    print("    [\(alert.severity)] \(alert.ruleId)@\(alert.ruleVersion)")
                }
            }
            if !result.unsupportedEngines.isEmpty {
                print("  unsupported_engines: \(result.unsupportedEngines.joined(separator: ", "))")
                print("  unsupported_rule_ids:")
                for id in result.unsupportedRuleIds {
                    print("    - \(id)")
                }
            }
            if !result.differencesVsOriginal.isEmpty {
                print("  differences_vs_original (\(result.differencesVsOriginal.count)):")
                for diff in result.differencesVsOriginal {
                    var msg = "    \(diff.type): \(diff.ruleId)"
                    if let from = diff.from, let to = diff.to {
                        msg += " (\(from) → \(to))"
                    }
                    print(msg)
                }
            }
            exit(result.exitCode)
        } catch {
            print("Replay failed: \(error.localizedDescription)")
            exit(9)
        }
    }

    // MARK: - trace replay --compare-rules

    /// v1.11.1: run the replay twice with two different ruleset
    /// identifiers and diff the resulting alert sets. Until a real
    /// RuleEngine-backed `RulesetReplayer` lands (the echo replayer
    /// always replays `matched_rules.json` verbatim), the diff is
    /// alert-empty + the only observable change is `result_sha256`.
    /// Once the v1.11.x ruleset replayer ships, the diff becomes
    /// load-bearing for "did rule X change behaviour between v1 and
    /// v2 of the corpus?".
    static func traceReplayCompare(
        bundlePath: String,
        rulesetA: String,
        rulesetB: String,
        expectedNormalizationVersion: String
    ) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }

        var options = ReplayEngine.ReplayOptions()
        options.expectedNormalizationVersion = expectedNormalizationVersion

        let engineA = ReplayEngine(replayer: BundleEmbeddedRulesetReplayer(
            rulesetVersion: rulesetA, normalizationVersion: expectedNormalizationVersion
        ))
        let engineB = ReplayEngine(replayer: BundleEmbeddedRulesetReplayer(
            rulesetVersion: rulesetB, normalizationVersion: expectedNormalizationVersion
        ))

        let resultA: ReplayResult
        let resultB: ReplayResult
        do {
            resultA = try await engineA.replay(bundleAt: target, options: options)
            resultB = try await engineB.replay(bundleAt: target, options: options)
        } catch {
            print("Compare replay failed: \(error.localizedDescription)")
            exit(9)
        }

        // Build alert id sets keyed by "<ruleId>@<ruleVersion>". Diff
        // is symmetric: in A not in B, in B not in A, common count.
        func key(_ alert: ReplayedAlert) -> String { "\(alert.ruleId)@\(alert.ruleVersion)" }
        let setA = Set(resultA.alerts.map(key))
        let setB = Set(resultB.alerts.map(key))
        let onlyA = setA.subtracting(setB).sorted()
        let onlyB = setB.subtracting(setA).sorted()
        let common = setA.intersection(setB).count

        print("[replay-compare] trace=\(resultA.traceId)")
        print("  ruleset A:       \(rulesetA)  sha=\(resultA.rulesetSha256.prefix(12))…")
        print("  ruleset B:       \(rulesetB)  sha=\(resultB.rulesetSha256.prefix(12))…")
        print("  result_sha A:    \(resultA.resultSha256.prefix(12))…")
        print("  result_sha B:    \(resultB.resultSha256.prefix(12))…")
        print("  alerts A:        \(resultA.alerts.count)")
        print("  alerts B:        \(resultB.alerts.count)")
        print("  common:          \(common)")
        print("  only in A (\(onlyA.count)):")
        for k in onlyA { print("    - \(k)") }
        print("  only in B (\(onlyB.count)):")
        for k in onlyB { print("    + \(k)") }

        // Exit non-zero when there's a divergence so this is usable
        // from CI / regression scripts.
        if onlyA.isEmpty && onlyB.isEmpty && resultA.resultSha256 == resultB.resultSha256 {
            print("  verdict:         identical")
            exit(0)
        } else {
            print("  verdict:         diverged")
            exit(20)
        }
    }

#if DEBUG
    // MARK: - trace demo (synthetic-trace seeder)
    //
    // DEBUG-only. This seeder writes fabricated "[DEMO]"-titled traces into the
    // live tracegraph.db. A release build must contain no fake/test/demo data,
    // so the whole seeder (plus its `process()` helper) and the CLI dispatch +
    // help line for `trace demo` are gated out of release.

    /// Materializes a synthetic Fixture-1-style AI-credential-access
    /// trace directly into the user's tracegraph.db, with no daemon
    /// required. Useful for soak-testing the dashboard before
    /// ESCollector → RollingCausalGraph wiring lands in production.
    static func traceDemo(scenario: String?) async {
        let dbPath = tracegraphDBPath()
        // Ensure the parent dir exists (first-run case).
        let parent = (dbPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: parent, withIntermediateDirectories: true
        )

        let store: SQLiteCausalGraphStore
        do {
            store = try await SQLiteCausalGraphStore(databasePath: dbPath)
        } catch {
            print("Failed to open tracegraph.db: \(error.localizedDescription)")
            exit(9)
        }
        defer { Task { await store.close() } }

        let now = Date()
        let materializer = TraceMaterializer(store: store)
        let rollingGraph = RollingCausalGraph(store: store, materializer: materializer)

        let scenarioName = (scenario ?? "fixture1").lowercased()
        do {
            switch scenarioName {
            case "fixture1", "ai-credential", "":
                let traces = try await seedFixture1AICredentialAccess(graph: rollingGraph, now: now)
                try await store.prefixTraceTitles(ids: traces.map { $0.id }, with: Self.demoTitlePrefix)
                print("\(traces.count) demo trace(s) materialized (all titled with \"\(Self.demoTitlePrefix)\").")
                if let primary = traces.first {
                    print("  primary trace_id: \(primary.id)")
                }
                print("")
                print("Open the MacCrabApp dashboard → TraceGraph sidebar entry → click Refresh.")
                print("Demo traces are clearly tagged so they don't get mistaken for real data.")
                print("Remove them anytime with:  maccrabctl trace demo clear")
            case "persistence", "fixture3":
                let trace = try await seedFixture3LaunchAgent(graph: rollingGraph, now: now)
                try await store.prefixTraceTitles(ids: [trace.id], with: Self.demoTitlePrefix)
                print("Demo trace materialized: \(trace.id)  [\(trace.severity)]  \(Self.demoTitlePrefix)\(trace.title)")
                print("Remove with:  maccrabctl trace demo clear")
            case "clear", "remove":
                let removed = try await store.deleteTracesWithTitlePrefix(Self.demoTitlePrefix)
                if removed == 0 {
                    print("No demo traces found in tracegraph.db (nothing to clear).")
                } else {
                    print("Removed \(removed) demo trace(s) from tracegraph.db.")
                    print("Real traces (no \"\(Self.demoTitlePrefix)\" title prefix) are untouched.")
                }
            case "list":
                print("Available demo scenarios:")
                print("  fixture1     — AI credential access (Claude Desktop → MCP → node → zsh → osascript)")
                print("  persistence  — LaunchAgent persistence written by a shell")
                print("  clear        — Remove every \"\(Self.demoTitlePrefix)\"-tagged trace from tracegraph.db")
            default:
                print("Unknown scenario '\(scenarioName)'. Try: maccrabctl trace demo list")
                exit(1)
            }
        } catch {
            print("Demo command failed: \(error.localizedDescription)")
            exit(9)
        }
    }

    /// Title prefix every demo trace carries so the dashboard, CLI,
    /// and the clear-demo path can all identify them unambiguously.
    public static let demoTitlePrefix = "[DEMO] "

    // MARK: - Demo scenario builders

    /// Returns every materialized trace produced during the seed —
    /// the caller titles them all with the demo prefix.
    private static func seedFixture1AICredentialAccess(
        graph: RollingCausalGraph,
        now: Date
    ) async throws -> [Trace] {
        let agent = RollingCausalGraph.AgentEnrichment(
            agentName: "Claude Desktop",
            agentTool: "claude_desktop",
            traceId: "demo-trace-\(UUID().uuidString.prefix(8))",
            confidence: 0.95,
            attributionMethod: .directTraceparent
        )

        // Build the spawn chain: Claude Desktop → mcp-server → node → zsh → osascript
        let chain: [(key: String, path: String, signed: Bool)] = [
            ("demo-claude-desktop",
             "/Applications/Claude.app/Contents/MacOS/Claude", true),
            ("demo-mcp-server",
             "/opt/homebrew/bin/mcp-filesystem-server", false),
            ("demo-node",
             "/opt/homebrew/bin/node", false),
            ("demo-zsh",
             "/bin/zsh", true),
            ("demo-osascript",
             "/usr/bin/osascript", true),
        ]

        for (idx, current) in chain.enumerated() {
            let parent = idx > 0 ? chain[idx - 1] : nil
            let observation = process(
                key: current.key, path: current.path,
                signed: current.signed, pid: Int32(1000 + idx),
                parentKey: parent?.key
            )
            let parentObservation = parent.map {
                process(key: $0.key, path: $0.path, signed: $0.signed,
                        pid: Int32(1000 + idx - 1), parentKey: nil)
            }
            // Only the first event carries agent attribution — the
            // bridge derives the rest by lineage.
            let attachAgent = idx <= 2
            let event = RollingCausalGraph.NormalizedEventInput(
                eventId: "demo-exec-\(idx)",
                timestamp: now.addingTimeInterval(Double(idx) * 0.5),
                category: .process,
                action: .exec,
                process: observation,
                parentProcess: parentObservation,
                agent: attachAgent ? agent : nil
            )
            _ = try await graph.ingest(event)
        }

        // Credential read by osascript.
        let credentialRead = RollingCausalGraph.NormalizedEventInput(
            eventId: "demo-cred-read",
            timestamp: now.addingTimeInterval(3),
            category: .file,
            action: .fileRead,
            process: process(key: "demo-osascript", path: "/usr/bin/osascript",
                             signed: true, pid: 1004, parentKey: "demo-zsh"),
            file: RollingCausalGraph.FileObservation(
                path: ((NSHomeDirectory() as NSString)
                    .appendingPathComponent(".aws/credentials")),
                pathHash: "demo-h-aws-creds"
            ),
            agent: agent
        )
        // External network connection.
        let networkOut = RollingCausalGraph.NormalizedEventInput(
            eventId: "demo-net",
            timestamp: now.addingTimeInterval(3.5),
            category: .network,
            action: .netConnect,
            process: process(key: "demo-osascript", path: "/usr/bin/osascript",
                             signed: true, pid: 1004, parentKey: "demo-zsh"),
            network: RollingCausalGraph.NetworkObservation(
                host: "evil.example.com", ip: "203.0.113.10",
                port: 443, protocolName: "tcp", reputation: .suspicious
            ),
            agent: agent
        )
        // LaunchAgent persistence write.
        let persistence = RollingCausalGraph.NormalizedEventInput(
            eventId: "demo-persist",
            timestamp: now.addingTimeInterval(4),
            category: .file,
            action: .fileCreate,
            process: process(key: "demo-osascript", path: "/usr/bin/osascript",
                             signed: true, pid: 1004, parentKey: "demo-zsh"),
            file: RollingCausalGraph.FileObservation(
                path: ((NSHomeDirectory() as NSString)
                    .appendingPathComponent("Library/LaunchAgents/com.demo.fake-agent.plist")),
                pathHash: "demo-h-launchagent"
            ),
            agent: agent
        )

        // Each of these may produce 1+ anchor traces depending on
        // the AnchorDetector's classification of the event.
        var allTraces: [Trace] = []
        allTraces.append(contentsOf: try await graph.ingest(credentialRead))
        allTraces.append(contentsOf: try await graph.ingest(networkOut))
        allTraces.append(contentsOf: try await graph.ingest(persistence))
        if allTraces.isEmpty {
            // Fallback: trigger an explicit external anchor on osascript.
            let trace = try await graph.recordExternalAnchor(
                anchorEntityId: "process:demo-osascript",
                anchorEventId: "demo-cred-read",
                reason: "Demo: AI-assisted credential access",
                severity: "high", confidence: 0.9,
                observedAt: now.addingTimeInterval(5)
            )
            allTraces.append(trace)
        }
        return allTraces
    }

    private static func seedFixture3LaunchAgent(
        graph: RollingCausalGraph,
        now: Date
    ) async throws -> Trace {
        let event = RollingCausalGraph.NormalizedEventInput(
            eventId: "demo-launchagent",
            timestamp: now,
            category: .file,
            action: .fileCreate,
            process: process(key: "demo-zsh-pers", path: "/bin/zsh",
                             signed: true, pid: 2000, parentKey: nil),
            file: RollingCausalGraph.FileObservation(
                path: ((NSHomeDirectory() as NSString)
                    .appendingPathComponent("Library/LaunchAgents/com.demo.persistence.plist")),
                pathHash: "demo-h-persist-only"
            )
        )
        let traces = try await graph.ingest(event)
        guard let first = traces.first else {
            return try await graph.recordExternalAnchor(
                anchorEntityId: "process:demo-zsh-pers",
                anchorEventId: "demo-launchagent",
                reason: "Demo: LaunchAgent persistence",
                severity: "high", confidence: 0.9,
                observedAt: now.addingTimeInterval(1)
            )
        }
        return first
    }

    private static func process(
        key: String, path: String, signed: Bool,
        pid: Int32, parentKey: String?
    ) -> RollingCausalGraph.ProcessObservation {
        RollingCausalGraph.ProcessObservation(
            processKey: key, pid: pid,
            ppid: parentKey == nil ? 1 : nil,
            executablePath: path,
            isAppleSigned: signed, isNotarized: signed,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            parentProcessKey: parentKey
        )
    }
#endif

    // MARK: - trace replay-batch

    static func traceReplayBatch(
        directoryPath: String,
        reportPath: String?,
        expectedNormalizationVersion: String
    ) async {
        let dir = URL(fileURLWithPath: directoryPath)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else {
            print("Not a directory: \(directoryPath)")
            exit(8)
        }
        let engine = ReplayEngine()
        var options = ReplayEngine.ReplayOptions()
        options.expectedNormalizationVersion = expectedNormalizationVersion
        do {
            let report = try await engine.replayBatch(directoryAt: dir, options: options)
            print("[replay-batch] total=\(report.totalCount) ok=\(report.okCount) fail_closed=\(report.failClosedCount) schema_invalid=\(report.schemaInvalidCount) incompatible=\(report.incompatibleCount) with_diff=\(report.withDifferencesCount)")
            for entry in report.entries.prefix(20) {
                let name = (entry.bundlePath as NSString).lastPathComponent
                print("  \(name): \(entry.result.result.rawValue) (exit \(entry.result.exitCode))")
            }
            if report.entries.count > 20 {
                print("  … and \(report.entries.count - 20) more")
            }
            if let reportPath {
                let html = ReplayBatchReportRenderer.renderHTML(report)
                try html.write(to: URL(fileURLWithPath: reportPath), atomically: true, encoding: .utf8)
                print("HTML report: \(reportPath)")
            }
            // Exit code reflects the worst per-bundle outcome.
            let worstExit = report.entries.map { $0.result.exitCode }.max() ?? 0
            exit(worstExit)
        } catch {
            print("Batch replay failed: \(error.localizedDescription)")
            exit(9)
        }
    }

    // MARK: - trace to-prov / to-otel

    static func traceToProv(bundlePath: String) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }
        do {
            let provData = try Data(contentsOf: target.appendingPathComponent("prov/prov.jsonld"))
            if let text = String(data: provData, encoding: .utf8) {
                print(text)
            }
        } catch {
            print("Failed to read prov/prov.jsonld: \(error.localizedDescription)")
            exit(1)
        }
    }

    static func traceToOtel(bundlePath: String) async {
        let url = URL(fileURLWithPath: bundlePath)
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }
        do {
            let otelData = try Data(contentsOf: target.appendingPathComponent("otel/spans.json"))
            if let text = String(data: otelData, encoding: .utf8) {
                print(text)
            }
        } catch {
            print("Failed to read otel/spans.json: \(error.localizedDescription)")
            exit(1)
        }
    }

    // MARK: - debug entity-merge / trust-substrate

    static func debugEntityMerge(pid: Int32) async {
        // EntityResolver state is daemon-runtime — not persisted. The
        // closest surrogate via tracegraph.db is "what's the canonical
        // process entity for this pid right now?". Print that plus a
        // pointer at the test suite for deeper introspection.
        guard let store = await openStore() else { exit(0) }
        do {
            // Linear scan: find process entities whose attributes contain pid.
            // Future increment can add a pid index column.
            print("Process entities with pid \(pid):")
            // The store doesn't expose a query-by-attribute, so we scan
            // recent traces' members.
            let traces = try await store.listTraces(limit: 50)
            var seen = Set<String>()
            for trace in traces {
                if let loaded = try await store.loadTrace(id: trace.id) {
                    for member in loaded.members {
                        guard let eid = member.entityId,
                              !seen.contains(eid),
                              let entity = try await store.entity(id: eid),
                              entity.entityType == ProcessNode.entityType,
                              let data = entity.attributesJson.data(using: .utf8),
                              let proc = try? JSONDecoder.dateMillis().decode(ProcessNode.self, from: data),
                              proc.pid == pid
                        else { continue }
                        seen.insert(eid)
                        print("  \(entity.id)")
                        print("    processKey: \(proc.processKey)")
                        print("    executable: \(proc.executablePath)")
                        print("    appleSigned: \(proc.isAppleSigned)")
                        print("    startTime: \(proc.startTime)")
                    }
                }
            }
            if seen.isEmpty {
                print("  (no matches in recent 50 traces)")
            }
        } catch {
            print("Query failed: \(error.localizedDescription)")
        }
        await store.close()
    }

    static func debugTrustSubstrate() async {
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: URL(fileURLWithPath: maccrabDataDir() + "/keys/"))
        let trustSubstrate = TrustSubstrate(storage: storage)
        do {
            let mode = try await trustSubstrate.activeMode()
            let pubKey = try await trustSubstrate.publicKey()
            print("MacCrab TrustSubstrate")
            print(String(repeating: "═", count: 60))
            print("  mode:                    \(mode.rawValue)")
            print("  public key fingerprint:  \(pubKey.fingerprint)")
            print("  public key DER bytes:    \(pubKey.derBytes.count)")
            print("  base directory:          \(maccrabDataDir())/keys/")
            print("")
            print("Public key (PEM):")
            print(pubKey.pemString)
        } catch {
            print("TrustSubstrate query failed: \(error.localizedDescription)")
            print("(This is expected when no trust-substrate key has been generated yet — run the daemon once to provision one, or call TrustSubstrate.publicKey() from Swift to bootstrap.)")
        }
    }

    // MARK: - Output helpers

    private static func printOutcome(_ outcome: BundleValidator.Outcome, label: String) {
        let prefix = outcome.exitCode == 0 ? "ok" : "fail"
        print("[\(label)] exit=\(outcome.exitCode) status=\(prefix)")
        switch outcome.kind {
        case .valid:
            print("  (no issues)")
        case .schemaInvalid(let m),
             .redactionPolicyViolation(let m),
             .internalError(let m),
             .manifestClaimMismatch(let m):
            print("  \(m)")
        case .incompatibleMajorVersion(let f, let s):
            print("  found=\(f) supported=\(s)")
        }
        for msg in outcome.messages {
            print("  - \(msg)")
        }
    }

    private static func severityFromString(_ s: String) -> Severity? {
        Severity(rawValue: s.lowercased())
    }

    private static func pad(_ s: String, _ width: Int) -> String {
        if s.count >= width { return String(s.prefix(width)) }
        return s + String(repeating: " ", count: width - s.count)
    }

    /// If the path is a .tar.gz / .maccrabtrace archive, extract to a
    /// temp directory and return the URL. If it's already a directory,
    /// return nil (caller uses the original URL).
    private static func extractIfArchive(_ url: URL) throws -> URL? {
        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir)
        if isDir.boolValue { return nil }

        // Treat as archive — extract via /usr/bin/tar.
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-extract-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        proc.currentDirectoryURL = tempDir
        proc.arguments = ["-xzf", url.path]
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            try? FileManager.default.removeItem(at: tempDir)
            return nil
        }
        // Find the single top-level directory inside the temp dir.
        let contents = try FileManager.default.contentsOfDirectory(at: tempDir, includingPropertiesForKeys: nil)
        if let first = contents.first, contents.count == 1 {
            return first
        }
        return tempDir
    }

    private static func cleanupExtracted(_ url: URL?) {
        guard let url else { return }
        // Walk up to a maccrab-extract-* parent and remove that.
        let path = url.path
        if path.contains("maccrab-extract-") {
            let parent = url.deletingLastPathComponent()
            try? FileManager.default.removeItem(at: parent.path.contains("maccrab-extract-") ? parent : url)
        }
    }
}

// MARK: - JSONDecoder helper

private extension JSONDecoder {
    static func dateMillis() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .millisecondsSince1970
        return d
    }
}
