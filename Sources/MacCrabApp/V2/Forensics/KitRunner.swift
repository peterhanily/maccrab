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
        case running(kitName: String, currentPlugin: String, completed: Int, total: Int)
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
                                 total: total)
                guard let reg = await PluginRegistry.shared.registration(forID: pref.pluginID) else {
                    skipped.append(SkippedPlugin(
                        pluginID: pref.pluginID,
                        reason: "not registered in this build"
                    ))
                    continue
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
                        continue
                    }
                } catch {
                    skipped.append(SkippedPlugin(
                        pluginID: pref.pluginID,
                        reason: shortReason(error)
                    ))
                }
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
            state = .failed(kitName: kit.name, error: shortReason(error))
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
    private func shortReason(_ error: Error) -> String {
        let s = "\(error)"
        // Most TCC-denied / sqlite-locked errors arrive as a
        // descriptive single sentence already.
        if let firstLine = s.split(separator: "\n").first {
            return String(firstLine)
        }
        return s
    }
}
