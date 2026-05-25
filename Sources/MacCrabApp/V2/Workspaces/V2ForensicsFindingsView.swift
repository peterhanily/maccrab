// V2ForensicsFindingsView.swift — rc.4 placeholder.
//
// The Findings tab is the operator's actual goal: a merged
// feed across all scans showing what we found, when, why it
// matters, and what to do. Full implementation lands rc.6;
// rc.4 ships the placeholder so the tab itself isn't a dead
// link.

import SwiftUI
import MacCrabForensics

struct V2ForensicsFindingsView: View {
    @State private var findings: [CommittedArtifact] = []
    @State private var loading = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if loading {
                    ProgressView("Loading findings…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if findings.isEmpty {
                    emptyState
                } else {
                    findingsList
                }
            }
            .padding(20)
        }
        .task { await reload() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Findings")
                .font(.title2).fontWeight(.semibold)
            Text("Actionable findings from every scan you've run.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No findings yet.")
                .font(.headline)
            Text("Run a scan from the Scans tab. Findings will appear here when scanners commit them.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var findingsList: some View {
        // rc.4 ships a minimal artifact list. rc.6 turns this
        // into a real severity-sorted findings feed with
        // mark-resolved + investigate actions.
        VStack(alignment: .leading, spacing: 6) {
            ForEach(findings.prefix(50), id: \.id) { f in
                findingRow(f)
                Divider()
            }
            if findings.count > 50 {
                Text("Showing first 50 of \(findings.count) findings. Full filter + sort lands in rc.6.")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                    .padding(.top, 8)
            }
        }
    }

    private func findingRow(_ a: CommittedArtifact) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(a.record.summary ?? a.record.contentType)
                    .font(.system(size: 12, weight: .medium))
                Text(a.record.pluginID)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(a.record.observedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }

    private func reload() async {
        loading = true
        // Aggregate artifacts across operator-visible PLAINTEXT
        // scans only. Encrypted scans require Keychain unlock,
        // which fires a macOS password prompt — we never trigger
        // those from a passive dashboard refresh. The operator
        // unlocks an encrypted scan explicitly by clicking it
        // in the Scans tab.
        var all: [CommittedArtifact] = []
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let scans = OperatorVisibilityFilter.filter(
                try await mgr.listCases().sorted { $0.createdAt > $1.createdAt }
            )
            for scan in scans.prefix(20) where scan.encryptionState == .plaintext {
                let handle = try await mgr.openCase(id: scan.id)
                let rows = try await handle.store.query(ArtifactQuery(
                    caseID: scan.id,
                    limit: 50
                ))
                all.append(contentsOf: OperatorVisibilityFilter.filter(rows))
            }
        } catch {
            all = []
        }
        findings = all.sorted { $0.record.observedAt > $1.record.observedAt }
        loading = false
    }
}
