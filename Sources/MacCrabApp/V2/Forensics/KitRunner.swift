// KitRunner.swift
//
// Runs a Kit end-to-end on a new scan: creates the case,
// runs each plugin in the kit on it sequentially, returns the
// scan id when done. Wired to the "Run" button on each kit
// card in V2ForensicsScansView.
//
// rc.4 scope: built-in (Tier A in-process) plugins only — the
// 4 bundled kits all reference plugins MacCrab already ships
// internally (com.maccrab.hosts-collector,
// com.maccrab.launch-agents-collector). rc.7 extends to
// fetch-+-install from rave catalog for kits that reference
// plugins not yet installed.

import Foundation
import MacCrabForensics

@MainActor
public final class KitRunner: ObservableObject {

    public enum State: Sendable {
        case idle
        case starting(kitName: String)
        case running(kitName: String, currentPlugin: String, completed: Int, total: Int)
        case done(scanID: String, kitName: String, tally: SeverityTally)
        case failed(kitName: String, error: String)
    }

    @Published public internal(set) var state: State = .idle

    public init() {}

    /// Dismiss the done/failed banner from the view.
    public func reset() { state = .idle }

    /// Runs every plugin in the kit on a fresh scan. Reports
    /// progress via `state`. On completion, `state.done(scanID:)`
    /// is set; caller jumps to the scan detail view.
    public func run(_ kit: Kit) async {
        state = .starting(kitName: kit.name)
        do {
            // Bootstrap plugin registry if needed.
            try await MacCrabForensicsBootstrap.registerBuiltins()

            // Create the scan (case) — auto-named from kit + now.
            let mgr = makeCaseManager()
            let scanName = "\(kit.name) — \(Date().formatted(date: .abbreviated, time: .shortened))"
            // rc.5 — default kit-driven scans to plaintext so the
            // operator doesn't get Keychain password prompts on
            // every Run click. Built-in kit collectors only emit
            // metadata-class artifacts (TCC inventory, launch agent
            // inventory, /etc/hosts baseline), so the audit Pass
            // 2026-D restriction is naturally satisfied. Operators
            // who want encrypted scans (for content-class kits)
            // can opt in via the future Custom Scan sheet (rc.6).
            let handle = try await mgr.createCase(
                name: scanName,
                timeWindow: nil,
                notes: "Auto-created from kit: \(kit.id)",
                encrypted: false
            )
            let runner = PluginRunner()

            // Iterate the kit's plugins in declared order.
            let total = kit.plugins.count
            var findingCount = 0
            for (idx, pref) in kit.plugins.enumerated() {
                state = .running(kitName: kit.name, currentPlugin: pref.pluginID, completed: idx, total: total)
                guard let reg = await PluginRegistry.shared.registration(forID: pref.pluginID) else {
                    // Plugin not installed; rc.7 will fetch from rave.
                    // For rc.4: skip with a note.
                    continue
                }
                switch reg.manifest.type {
                case .collector:
                    let (result, _) = try await runner.runCollector(
                        id: pref.pluginID,
                        handle: handle
                    )
                    findingCount += result.artifactsCommitted
                case .analyzer:
                    let (findings, _) = try await runner.runAnalyzer(
                        id: pref.pluginID,
                        handle: handle
                    )
                    findingCount += findings.count
                case .enricher, .fingerprinter:
                    // Pipeline plumbing — not directly invoked.
                    continue
                }
            }
            // Compute heuristic tally over what landed in the
            // scan's store so the done banner can say
            // "Inventoried 3, 1 needs review" instead of just
            // counting raw rows.
            let tally: SeverityTally
            do {
                let rows = try await handle.store.query(ArtifactQuery(
                    caseID: handle.caseID, limit: 500
                ))
                tally = FindingHeuristics.tally(rows)
            } catch {
                tally = SeverityTally(routine: findingCount, notable: 0, attention: 0, critical: 0)
            }
            state = .done(scanID: handle.caseID, kitName: kit.name, tally: tally)
        } catch {
            state = .failed(kitName: kit.name, error: "\(error)")
        }
    }

    private func makeCaseManager() -> CaseManager {
        CaseManager(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            dekVault: KeychainDEKVault()
        )
    }
}
