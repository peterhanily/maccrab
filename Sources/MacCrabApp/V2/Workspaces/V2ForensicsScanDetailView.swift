// V2ForensicsScanDetailView.swift
//
// rc.5 — clicking a scan row in V2ForensicsScansView opens this
// detail view in a sheet. Shows:
//   - Scan name + when it ran + state (plaintext / encrypted)
//   - The plugins this scan ran (derived from artifact pluginID
//     diversity)
//   - The committed evidence (collapsed by default for noisy
//     scans)
//   - "Close" + "Open Findings" actions
//
// Encrypted scans surface an "Unlock" button instead of
// auto-prompting for keychain access. This is the only path
// from the dashboard that should fire a Keychain password
// prompt — it requires an explicit click.

import SwiftUI
import MacCrabForensics

struct V2ForensicsScanDetailView: View {
    let scanID: String
    let scanName: String
    let encryptionState: CaseEncryptionState
    let createdAt: Date
    @Binding var isPresented: Bool

    @State private var loading = true
    @State private var artifacts: [CommittedArtifact] = []
    @State private var error: String? = nil
    @State private var unlocked = false
    @State private var rawEvidenceExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    summary
                    if encryptionState != .plaintext && !unlocked {
                        encryptedNotice
                    } else if loading {
                        ProgressView("Loading…")
                            .frame(maxWidth: .infinity)
                            .padding(20)
                    } else if let err = error {
                        Text(err).foregroundStyle(.red).font(.system(size: 12))
                    } else if artifacts.isEmpty {
                        emptyEvidence
                    } else {
                        pluginsRanCard
                        evidenceCard
                    }
                }
                .padding(20)
            }
        }
        .frame(width: 640, height: 540)
        .task {
            if encryptionState == .plaintext {
                await loadEvidence()
            } else {
                loading = false
            }
        }
    }

    // MARK: - Sections

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(scanName).font(.headline)
                Text(createdAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Close") { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var summary: some View {
        let tally = FindingHeuristics.tally(artifacts)
        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 24) {
                metric("Evidence rows", "\(artifacts.count)")
                metric("Scanners run", "\(distinctPluginIDs.count)")
                metric("State", encryptionState == .plaintext ? "Plaintext (metadata only)" : "Encrypted")
            }
            if !artifacts.isEmpty {
                Text(tally.bannerSummary)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(tally.attention + tally.critical > 0 ? .orange : .secondary)
            }
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value).font(.system(size: 18, weight: .semibold, design: .rounded))
            Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
        }
    }

    private var encryptedNotice: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "lock.fill").foregroundStyle(.tint)
                Text("This scan is encrypted")
                    .font(.system(size: 13, weight: .semibold))
            }
            Text("Unlocking reads the scan's data encryption key from your macOS Keychain. macOS will ask for your password the first time MacCrab accesses it.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Button("Unlock + show evidence") {
                Task {
                    unlocked = true
                    await loadEvidence()
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var emptyEvidence: some View {
        Text("This scan didn't commit any evidence rows. The scanners ran but found nothing to record, or finished before producing output.")
            .font(.system(size: 12))
            .foregroundStyle(.secondary)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
    }

    private var distinctPluginIDs: [String] {
        Array(Set(artifacts.map { $0.record.pluginID })).sorted()
    }

    private var pluginsRanCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Scanners that ran").font(.system(size: 12, weight: .semibold))
            ForEach(distinctPluginIDs, id: \.self) { id in
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.system(size: 11))
                    Text(friendlyScannerName(id))
                        .font(.system(size: 12))
                    Spacer()
                    Text("\(artifacts.filter { $0.record.pluginID == id }.count) rows")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var evidenceCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            DisclosureGroup(isExpanded: $rawEvidenceExpanded) {
                ForEach(artifacts.prefix(50), id: \.id) { a in
                    evidenceRow(a)
                    Divider()
                }
                if artifacts.count > 50 {
                    Text("Showing first 50 of \(artifacts.count).")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                        .padding(.top, 6)
                }
            } label: {
                Text("Raw evidence (\(artifacts.count) rows)")
                    .font(.system(size: 12, weight: .semibold))
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func evidenceRow(_ a: CommittedArtifact) -> some View {
        let sev = FindingHeuristics.severity(for: a)
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: sev.sfSymbol)
                .font(.system(size: 10))
                .foregroundStyle(sevColor(sev))
                .padding(.top, 3)
            VStack(alignment: .leading, spacing: 2) {
                Text(a.record.summary ?? a.record.contentType)
                    .font(.system(size: 12, weight: .medium))
                HStack(spacing: 6) {
                    Text(sev.displayName)
                        .font(.system(size: 9, weight: .medium))
                        .foregroundStyle(sevColor(sev))
                    Text("·").font(.system(size: 10)).foregroundStyle(.tertiary)
                    Text(friendlyScannerName(a.record.pluginID))
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                    Text("·").font(.system(size: 10)).foregroundStyle(.tertiary)
                    Text(a.record.observedAt.formatted(date: .abbreviated, time: .shortened))
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func sevColor(_ s: FindingSeverity) -> Color {
        switch s {
        case .routine:   return .secondary
        case .notable:   return .blue
        case .attention: return .orange
        case .critical:  return .red
        }
    }

    private func friendlyScannerName(_ id: String) -> String {
        ScannerDisplay.name(forPluginID: id)
    }

    // MARK: - Load

    private func loadEvidence() async {
        loading = true
        defer { loading = false }
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let handle = try await mgr.openCase(id: scanID)
            let rows = try await handle.store.query(ArtifactQuery(
                caseID: scanID,
                limit: 500
            ))
            artifacts = OperatorVisibilityFilter.filter(rows)
        } catch {
            self.error = "Could not load evidence: \(error)"
            artifacts = []
        }
    }
}
