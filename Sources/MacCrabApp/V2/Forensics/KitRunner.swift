// KitRunner.swift
//
// Runs a Kit end-to-end on a new scan: creates the case, runs
// each plugin in the kit on it sequentially, returns the scan id
// when done. Wired to the "Run" button on each kit card in
// V2ForensicsScansView.
//
// rc.10 changes vs rc.5:
//   - Honors kit.encrypted (rc.5 hard-coded plaintext, which
//     would silently no-op every content-class collector since
//     the store rejects non-metadata in plaintext cases)
//   - Per-plugin do/catch so one collector that's missing FDA
//     doesn't abort the whole kit; failures collected into a
//     `skipped` list reported in the final State
//   - Double-run guard: a second call while a kit is already in
//     flight is a no-op

import Foundation
import MacCrabForensics

@MainActor
public final class KitRunner: ObservableObject {

    public enum State: Sendable {
        case idle
        case starting(kitName: String)
        case running(kitName: String, currentPlugin: String, completed: Int, total: Int, rowsSoFar: Int)
        case done(scanID: String, kitName: String, tally: SeverityTally, skipped: [SkippedPlugin])
        case failed(kitName: String, error: String)
    }

    /// A plugin that didn't contribute artifacts. Surfaced in the
    /// done banner so the operator understands why a kit they
    /// expected to be expansive came back with a small tally.
    public struct SkippedPlugin: Sendable, Equatable {
        public let pluginID: String
        public let reason: String
    }

    /// Outcome of attempting an installed Tier-B plugin, so the caller can
    /// surface WHY a plugin didn't contribute instead of collapsing every
    /// refusal / errored run into a generic "not installed" skip.
    enum TierBRunOutcome: Sendable {
        case ran                    // committed artifacts (status ok / partial)
        case ranWithError(String)   // spawned but errored / no terminal result — the real reason
        case refused(String)        // typed refusal (first-party / sandboxed gate, quarantined, disabled)
        case notInstalled           // genuinely not an installed Tier-B plugin
    }

    @Published public internal(set) var state: State = .idle

    public init() {}

    /// Dismiss the done/failed banner from the view.
    public func reset() { state = .idle }

    /// True while a kit is mid-flight. UI gates the Run button on
    /// this so the operator can't fire the same kit twice in
    /// parallel.
    public var isRunning: Bool {
        switch state {
        case .starting, .running: return true
        default: return false
        }
    }

    /// Runs every plugin in the kit on a fresh scan. Reports
    /// progress via `state`. Idempotent in flight — a second call
    /// while a kit is running is a no-op.
    public func run(_ kit: Kit) async {
        if isRunning { return }
        state = .starting(kitName: kit.name)
        do {
            try await MacCrabForensicsBootstrap.registerBuiltins()

            let mgr = makeCaseManager()
            let scanName = "\(kit.name) — \(Date().formatted(date: .abbreviated, time: .shortened))"
            let handle = try await mgr.createCase(
                name: scanName,
                timeWindow: nil,
                notes: "Auto-created from kit: \(kit.id)",
                encrypted: kit.encrypted
            )
            let runner = PluginRunner()

            let total = kit.plugins.count
            var skipped: [SkippedPlugin] = []

            for (idx, pref) in kit.plugins.enumerated() {
                state = .running(kitName: kit.name,
                                 currentPlugin: pref.pluginID,
                                 completed: idx,
                                 total: total,
                                 rowsSoFar: 0)
                guard let reg = await PluginRegistry.shared.registration(forID: pref.pluginID) else {
                    // Not a Tier-A built-in — try an INSTALLED Tier-B plugin via
                    // the shared two-lane executor (first-party → sandboxed,
                    // fail-closed; untrusted code runs ONLY under the sandbox).
                    let outcome = await Self.runInstalledTierB(
                        pluginID: pref.pluginID, store: handle.store, caseID: handle.caseID)
                    switch outcome {
                    case .ran:
                        break   // contributed artifacts — no skip entry
                    case .notInstalled:
                        skipped.append(SkippedPlugin(
                            pluginID: pref.pluginID,
                            reason: "not a built-in and not an installed Tier-B plugin"))
                    case .ranWithError(let reason), .refused(let reason):
                        skipped.append(SkippedPlugin(pluginID: pref.pluginID, reason: reason))
                    }
                    continue
                }

                // Spawn a poll task that updates rowsSoFar every
                // ~400ms while the plugin runs. count() is a
                // sub-ms SQLite COUNT so polling is cheap. Task
                // is cancelled when the plugin finishes.
                let pollTask = Task<Void, Never> { @MainActor [weak self] in
                    while !Task.isCancelled {
                        try? await Task.sleep(nanoseconds: 400_000_000)
                        if Task.isCancelled { break }
                        let rows = (try? await handle.store.count(
                            caseID: handle.caseID,
                            pluginID: pref.pluginID
                        )) ?? 0
                        if Task.isCancelled { break }
                        guard let self else { break }
                        if case .running(let n, let p, let c, let t, _) = self.state,
                           p == pref.pluginID {
                            self.state = .running(
                                kitName: n,
                                currentPlugin: p,
                                completed: c,
                                total: t,
                                rowsSoFar: rows
                            )
                        } else {
                            break
                        }
                    }
                }

                do {
                    switch reg.manifest.type {
                    case .collector:
                        _ = try await runner.runCollector(
                            id: pref.pluginID,
                            handle: handle
                        )
                    case .analyzer:
                        _ = try await runner.runAnalyzer(
                            id: pref.pluginID,
                            handle: handle
                        )
                    case .enricher, .fingerprinter:
                        // Pipeline plumbing — not directly invoked.
                        pollTask.cancel()
                        continue
                    }
                } catch {
                    skipped.append(SkippedPlugin(
                        pluginID: pref.pluginID,
                        reason: Self.shortReason(error)
                    ))
                }
                pollTask.cancel()
            }

            // Tally what landed in the store. Use a generous limit
            // since high-density collectors (mail, knowledgec)
            // routinely emit thousands of rows.
            let tally: SeverityTally
            do {
                let rows = try await handle.store.query(ArtifactQuery(
                    caseID: handle.caseID, limit: 5000
                ))
                tally = FindingHeuristics.tally(rows)
            } catch {
                tally = .zero
            }
            state = .done(scanID: handle.caseID,
                          kitName: kit.name,
                          tally: tally,
                          skipped: skipped)
        } catch {
            state = .failed(kitName: kit.name, error: Self.shortReason(error))
        }
    }

    private func makeCaseManager() -> CaseManager {
        CaseManager(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            dekVault: KeychainDEKVault()
        )
    }

    /// Trim Swift's default error stringification — surface the
    /// useful sentence to the operator without the type path.
    private static func shortReason(_ error: Error) -> String {
        let s = "\(error)"
        // Most TCC-denied / sqlite-locked errors arrive as a
        // descriptive single sentence already.
        if let firstLine = s.split(separator: "\n").first {
            return String(firstLine)
        }
        return s
    }

    /// Run an INSTALLED Tier-B collector through the shared two-lane executor
    /// (first-party → sandboxed, fail-closed) and commit its artifacts. Returns
    /// false (skip) if the plugin isn't installed or is refused — the kit run is
    /// best-effort per plugin. Untrusted code runs ONLY under the sandbox.
    static func runInstalledTierB(pluginID: String, store: ArtifactStore, caseID: String) async -> TierBRunOutcome {
        let ctx = TierBCollectorExecutor.catalogContextFromEnv()
        let scratch = NSTemporaryDirectory() + "maccrab-tierb-scratch-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: scratch) }
        do {
            let exec = try await TierBCollectorExecutor.runInstalled(
                pluginID: pluginID, scratchDir: scratch,
                officialSource: ctx.officialSource, catalogOverrideActive: ctx.catalogOverrideActive)
            let enc = ((try? await store.fetchCase(id: caseID)) ?? nil)?.encryptionState ?? .plaintext
            let invID = try await store.recordInvocationStart(
                caseID: caseID, pluginID: pluginID, pluginVersion: exec.manifest.version, inputsJSON: "{}")
            let result = await TierBArtifactBridge.commit(
                outcome: exec.outcome, caseID: caseID, manifest: exec.manifest,
                caseAllowsSensitive: enc != .plaintext, output: StoreCollectorOutput(store: store))
            try? await store.recordInvocationEnd(
                id: invID, exitStatus: result.status.rawValue,
                artifactsCommitted: Int64(result.artifactsCommitted),
                artifactsRejected: Int64(result.artifactsRejected),
                errorMessage: result.notes.isEmpty ? nil : result.notes.joined(separator: "; "),
                snapshotHash: nil)
            // Spawned but errored (e.g. a first-party plugin that fell through to
            // the sandboxed lane and "emitted no terminal result") — surface the
            // real reason instead of a silent 0-row contribution.
            if result.status != .ok && result.status != .partial {
                let reason = result.notes.isEmpty
                    ? "ran with status \(result.status.rawValue)"
                    : result.notes.joined(separator: "; ")
                return .ranWithError(reason)
            }
            return .ran
        } catch let e as TierBRegistry.RegistryError {
            if case .notInstalled = e { return .notInstalled }
            return .refused(Self.shortReason(e))   // firstPartyExecutionRefused / sandboxedExecutionRefused / quarantined / …
        } catch {
            return .refused(Self.shortReason(error))
        }
    }
}
