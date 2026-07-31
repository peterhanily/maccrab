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
        // Set only once we know the bundle root is one WE created (see below),
        // and cleared again once the export completes; the catch block names it
        // so the operator can tell our debris from a directory that was already
        // there.
        var partialBundle: URL?
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
            //
            // The keys dir MUST be writable by the INVOKING uid.
            // `maccrabDataDir()` resolves to the ROOT support dir on a release
            // install (that is where tracegraph.db lives), and
            // /Library/Application Support/MacCrab/keys is `drwx------ root` —
            // so `activeMode()` → `selectMode()` → `saveKeyMode()` EPERM'd and
            // aborted the whole export with "You don't have permission to save
            // the file .tmp-…-trust-substrate.json". That made `trace export`
            // fail deterministically for the ordinary user on the shipped
            // configuration, and since export is the FIRST command of the
            // seven-command bundle pipeline it took validate / inspect / verify
            // / replay / to-prov / to-otel down with it.
            //
            // The CLI can never sign with the root daemon's key anyway (0700,
            // unreadable at uid 501), so fall back to the user-domain keys dir —
            // the same filesystem-mode P256 identity the CLI already uses for
            // plugin install receipts (see maccrabUserWritableDataDir). Running
            // as root still uses the system dir.
            let systemSigningDir = maccrabDataDir() + "/keys/"
            let signingDir = FileManager.default.isWritableFile(atPath: systemSigningDir)
                ? URL(fileURLWithPath: systemSigningDir)
                : URL(fileURLWithPath: maccrabUserWritableDataDir() + "/keys/")
            let storage = FilesystemTrustSubstrateStorage(baseDirectory: signingDir)
            let trustSubstrate = TrustSubstrate(storage: storage)
            // FF-07: PROBE the signer instead of assuming it works. On a release
            // install `/Library/Application Support/MacCrab/keys/` is root-owned
            // and both `trust-substrate.json` and `trace-signing.key` are 0o600,
            // so for uid 501 every signing call fails DEEP INSIDE the exporter:
            // `activeMode()` finds no readable mode record, re-selects one, and
            // `saveKeyMode` -> `writeState` -> `ensureBaseDirectory` blows up with
            // a raw Cocoa "You don't have permission to save the file
            // '.tmp-…-trust-substrate.json' in the folder 'keys'". The whole
            // export aborted and NO bundle was produced — `trace export` was 100%
            // broken for the normal user. Note the pre-existing `try?` on
            // `activeMode()` hid this: it printed "Signing with TrustSubstrate
            // (filesystem_degraded)" and then died several frames later.
            //
            // A one-shot probe signature answers "can this process sign?" up
            // front. The SE key ACL is `.privateKeyUsage` only (no user-presence
            // flag), so the probe never prompts. On failure we fall back to the
            // exporter's DOCUMENTED unsigned placeholder path rather than losing
            // the export, and say so loudly.
            var signer: TrustSubstrate? = trustSubstrate
            do {
                _ = try await trustSubstrate.sign(Data("maccrabctl-export-probe".utf8))
                let mode = (try? await trustSubstrate.activeMode()) ?? .filesystemDegraded
                print("Signing with TrustSubstrate (\(mode.rawValue))")
            } catch {
                signer = nil
                print("WARNING: the trust-substrate signing key under \(signingDir.path) is not usable by this user — \(error.localizedDescription)")
                print("WARNING: exporting UNSIGNED. Re-run as root (`sudo maccrabctl trace export …`) or export from MacCrab.app for a signed bundle.")
            }

            let target = outputDir
                ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                    .appendingPathComponent("\(traceId).maccrabtrace")
            // A mid-export failure (commonly: signing can't write the
            // root-owned keys/ dir as a normal user) left the half-written
            // bundle on disk — every artifact dir present but no signed
            // manifest/Merkle root, so `trace verify` rejects it and the debris
            // is indistinguishable from a tampered bundle. Only clean up what
            // WE created: BundleExporter.export throws .directoryAlreadyExists
            // rather than writing into an existing directory, so anything that
            // pre-existed at `target` is the operator's and must be left alone.
            if !FileManager.default.fileExists(atPath: target.path) { partialBundle = target }

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
                // FF-07: `signer`, not `trustSubstrate` — nil when the probe above
                // proved this uid cannot reach the key, which selects the
                // exporter's UNSIGNED placeholder path instead of throwing.
                trustSubstrate: signer,
                unifiedLogAnchor: SystemUnifiedLogAnchor()
            )
            try await exporter.export(inputs: inputs, to: target, options: options)
            // The bundle is complete and has its chain head from here on, so a
            // later failure (tar, sidecar) must NOT report it as a partial.
            partialBundle = nil
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
                // v1.21.5 Phase 2c: outer-archive digest as a shasum-
                // compatible `<archive>.sha256` sidecar, computed AFTER
                // packaging (replaces the impossible in-bundle
                // bundle_sha256.txt placeholder). Transport-integrity
                // convenience only — the signed Merkle chain inside the
                // bundle remains the tamper evidence, so a hashing
                // failure warns without failing the export.
                if let result = ArchiveDigest.writeSidecar(forArchiveAt: URL(fileURLWithPath: tarPath)) {
                    print("SHA-256: \(result.hex)")
                    print("Sidecar: \(result.sidecar.path)")
                } else {
                    print("WARNING: could not compute/write archive SHA-256 sidecar; the archive itself is unaffected.")
                }
            } else {
                print("tar exited with status \(proc.terminationStatus); directory left at \(target.path)")
            }
        } catch {
            print("Export failed: \(error.localizedDescription)")
            // The exporter writes artifacts incrementally, so an abort partway
            // through leaves a directory that LOOKS like a bundle but has no
            // signed chain head. Name it explicitly rather than letting the
            // operator find it later and mistake it for a usable export.
            // (Named, not deleted: the debris is often the only evidence of why
            // the export died, and `trace validate` rejects it anyway. Gated on
            // `partialBundle`, so a directory that pre-existed this run is never
            // pointed at — and the default `<cwd>/<id>.maccrabtrace` target is
            // covered even when `--out` was not passed.)
            if let partial = partialBundle, FileManager.default.fileExists(atPath: partial.path) {
                print("  A PARTIAL, UNSIGNED bundle may remain at \(partial.path) — do not distribute it; `trace validate` will reject it.")
            }
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

    /// Replay drives the REAL `RuleEngine` over the bundle's events via
    /// `RuleEngineReplayer`, so the alert list is a FRESH result produced by an
    /// actual ruleset. `rulesDirectory` (CLI `--rules <dir>`) names which one;
    /// omitted, it resolves the installed corpus at
    /// `<support-dir>/compiled_rules` — the same rules the engine is running.
    ///
    /// The echo replayer is now the LAST resort, not the default. It ignores
    /// `events` entirely, re-emits `matched_rules.json` verbatim and stamps a
    /// fixed ruleset hash: a determinism proof and nothing more. It cannot tell
    /// you whether today's ruleset still detects what yesterday's did, because
    /// it never runs a rule — yet it was what every shipped `trace replay`
    /// invocation got, so the command's headline output was, in the only sense a
    /// caller cares about, meaningless. It is now reached only when no compiled
    /// corpus can be found or loaded, and the banner says which mode ran and why.
    static func traceReplay(
        bundlePath: String,
        expectedNormalizationVersion: String,
        rulesDirectory: String? = nil
    ) async {
        let url = URL(fileURLWithPath: bundlePath)
        // FF-11: `trace replay` takes a BUNDLE PATH, not a trace id. Without this
        // guard a trace id fell straight through to `extractIfArchive`, which
        // shells out to /usr/bin/tar; tar printed its own
        // "…: m: No such file or directory" to stderr, returned non-zero, and the
        // helper answered `nil` — leaving the engine to report
        // `result=schema_invalid` against a path that never existed. That blames
        // the bundle for what is a usage error. Reuses exit 9 (the existing
        // "replay could not run" code) rather than inventing a new one, so the
        // documented 0/1/6/11 result-code contract is untouched.
        guard FileManager.default.fileExists(atPath: url.path) else {
            print("No such bundle: \(bundlePath)")
            print("Usage: maccrabctl trace replay <bundle-path>   — a .maccrabtrace directory or .tar.gz archive, NOT a trace id.")
            exit(9)
        }
        let directory = try? extractIfArchive(url)
        let target = directory ?? url
        defer { cleanupExtracted(directory) }

        // SU-01: drive the REAL rule engine. An explicitly named ruleset is a
        // hard requirement — failing to load it exits rather than quietly
        // downgrading, because the caller asked a specific question ("does THIS
        // ruleset still detect it?") and the echo replayer cannot answer it.
        // With no `--rules`, resolve the installed corpus; only if that is
        // absent or unloadable do we fall back to echo, saying so.
        let engine: ReplayEngine
        if let rulesDirectory {
            do {
                engine = ReplayEngine(replayer: try RuleEngineReplayer(
                    rulesDirectory: URL(fileURLWithPath: rulesDirectory)))
                print("[replay] mode=rule-engine rules=\(rulesDirectory)")
            } catch {
                print("[replay] cannot load ruleset at \(rulesDirectory): \(error)")
                exit(9)
            }
        } else {
            let installed = maccrabDataDir() + "/compiled_rules"
            if let replayer = try? RuleEngineReplayer(
                rulesDirectory: URL(fileURLWithPath: installed)) {
                engine = ReplayEngine(replayer: replayer)
                print("[replay] mode=rule-engine rules=\(installed) (installed corpus; "
                      + "pass --rules <dir> to replay against a different one)")
            } else {
                engine = ReplayEngine()
                print("[replay] mode=echo — no loadable compiled ruleset at \(installed). "
                      + "Determinism only; NO rule was evaluated. "
                      + "Pass --rules <compiled-rules-dir> to replay against a real ruleset.")
            }
        }
        var options = ReplayEngine.ReplayOptions()
        options.expectedNormalizationVersion = expectedNormalizationVersion
        do {
            let result = try await engine.replay(bundleAt: target, options: options)
            print("[replay] result=\(result.result.rawValue) deterministic=\(result.deterministic) exit=\(result.exitCode)")
            print("  trace_id:        \(result.traceId)")
            print("  bundle_id:       \(result.bundleId)")
            print("  replay_engine:   \(result.replayEngineVersion)")
            print("  ruleset_sha256:  \(result.rulesetSha256)")
            // FF-11: only a COMPLETED replay has a meaningful result hash. On a
            // schema_invalid / incompatible / fail-closed run nothing was
            // evaluated, yet the engine still fills `resultSha256` — printing it
            // invited a caller keying on that field to treat a parse failure as a
            // computed result.
            if result.result == .ok {
                print("  result_sha256:   \(result.resultSha256)")
            } else {
                print("  result_sha256:   (not computed — replay did not complete)")
            }
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

    /// Run the replay twice against two DIFFERENT compiled-rules directories
    /// and diff the resulting alert sets — "did rule X change behaviour between
    /// corpus v1 and v2?".
    ///
    /// `rulesetA` / `rulesetB` are compiled-rules DIRECTORY PATHS (the
    /// `compile_rules.py` output the daemon loads), NOT version labels. They
    /// used to be labels handed to `BundleEmbeddedRulesetReplayer`, which never
    /// evaluates a rule — it re-emits `matched_rules.json` verbatim and hashes
    /// the label STRING. So the alert diff was structurally always empty while
    /// the label-derived `result_sha256` always differed, and the command exited
    /// 20 ("diverged") for ANY two distinct labels: a CI gate wired to it failed
    /// unconditionally and told you nothing about detection either way.
    /// `RuleEngineReplayer` actually loads and runs each ruleset, which is what
    /// makes this diff load-bearing.
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

        let engineA: ReplayEngine
        let engineB: ReplayEngine
        do {
            engineA = ReplayEngine(replayer: try RuleEngineReplayer(
                rulesDirectory: URL(fileURLWithPath: rulesetA)
            ))
            engineB = ReplayEngine(replayer: try RuleEngineReplayer(
                rulesDirectory: URL(fileURLWithPath: rulesetB)
            ))
        } catch {
            print("Compare replay failed: \(error)")
            print("  --compare-rules takes two compiled-rules DIRECTORIES (compile_rules.py output), not version labels.")
            exit(9)
        }

        let resultA: ReplayResult
        let resultB: ReplayResult
        do {
            resultA = try await engineA.replay(bundleAt: target, options: options)
            resultB = try await engineB.replay(bundleAt: target, options: options)
        } catch {
            print("Compare replay failed: \(error.localizedDescription)")
            exit(9)
        }

        // FF-11: a bundle that failed to parse (or is normalization-incompatible)
        // yields two EMPTY alert sets, which the diff below reported as
        // "verdict: identical" and exited 0 — a false green about two rulesets
        // that never evaluated anything. Refuse before comparing, and exit with
        // the replay's own documented code (1 schema / 6 normalization /
        // 11 fail-closed) rather than a compare verdict.
        for (label, r) in [("A", resultA), ("B", resultB)] where r.result != .ok {
            print("[replay-compare] ruleset \(label) did not complete: result=\(r.result.rawValue) exit=\(r.exitCode)")
            print("  No comparison is possible — nothing was evaluated on that side.")
            exit(r.exitCode)
        }

        // Build alert id sets keyed by ruleId ALONE. Diff is symmetric: in A
        // not in B, in B not in A, common count.
        //
        // Deliberately NOT "<ruleId>@<ruleVersion>": `RuleEngineReplayer`
        // derives each alert's `ruleVersion` from the ruleset DIGEST
        // ("ruleset-<sha prefix>"), which differs between A and B by
        // construction whenever the two rulesets differ at all. Keying on it
        // would put every rule in both `onlyA` and `onlyB` and report
        // `common: 0` for every comparison — the diff would be pure noise.
        func key(_ alert: ReplayedAlert) -> String { alert.ruleId }
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
        // Verdict is the ALERT diff only. `result_sha256` deliberately excluded:
        // `rulesetSha256` is an input to that digest, so two different rulesets
        // can never produce equal result digests — including it here is what
        // made this command exit 20 unconditionally. Both digests are still
        // printed above as evidence of which rulesets ran.
        if onlyA.isEmpty && onlyB.isEmpty {
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

    // MARK: - trace reattribute (operator verdict on machine attribution)

    /// Record an operator verdict on an event's machine agent-attribution.
    ///
    /// `AttributionOverrideStore` shipped complete — its own database, table,
    /// two indexes, upsert and stats roll-up — and so did the app-side writer
    /// `AppState.recordAttributionOverride`, but NOTHING called either. The
    /// result was that the "Accuracy among rated" figure in the dashboard's
    /// Agent Traces tab (AgentTracesView.swift:272) and in `maccrabctl status`
    /// (StatusCommand.swift:172) could only ever render `—`, and the
    /// `wrongTool` / `noAgent` verdicts were unreachable — so AI-attribution
    /// quality had no feedback loop at all.
    ///
    /// This closes the loop from the CLI. It writes to the SAME user-writable
    /// `attribution_overrides.db` the dashboard opens, so both surfaces reflect
    /// a verdict immediately.
    ///
    /// The user-domain dir is DELIBERATE: the CLI runs as uid 501 and the root
    /// support dir is not writable by it, so writing there would silently
    /// no-op — exactly the failure `maccrabUserWritableDataDir()` exists to
    /// prevent. Mirrors `AppState.overrideStore()`.
    static func traceReattribute(eventId: String, verdictRaw: String, note: String?) async {
        guard let verdict = AttributionOverride.Verdict(rawValue: verdictRaw) else {
            let valid = AttributionOverride.Verdict.allCases.map(\.rawValue).joined(separator: " | ")
            print("Unknown verdict '\(verdictRaw)'. Valid verdicts: \(valid)")
            exit(1)
        }
        let dir = maccrabUserWritableDataDir()
        let store: AttributionOverrideStore
        do {
            store = try AttributionOverrideStore(directory: dir)
        } catch {
            print("Cannot open attribution_overrides.db under \(dir): \(error)")
            exit(9)
        }
        let now = Date()
        do {
            // machineConfidence is nil: the CLI has no accessor for the event's
            // machine confidence, and the field is a display-time snapshot that
            // does not participate in the accuracy roll-up.
            try await store.record(AttributionOverride(
                eventId: eventId,
                machineConfidence: nil,
                verdict: verdict,
                userNote: note,
                createdAt: now,
                updatedAt: now
            ))
        } catch {
            print("Failed to record verdict: \(error)")
            exit(9)
        }
        print("Recorded verdict '\(verdict.rawValue)' for event \(eventId)")
        print("(Reflected in `maccrabctl status` → Agent Traces accuracy and the dashboard's Agent Traces tab.)")
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
