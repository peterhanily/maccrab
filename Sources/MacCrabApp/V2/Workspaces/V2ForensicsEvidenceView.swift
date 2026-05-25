// V2ForensicsEvidenceView.swift
// MacCrabApp — v1.17 Forensics → Evidence tab.
//
// Per docs/forensics-ia-redesign-plan.md §3.5. Default scope:
// most-recent completed scan. Bulk export to .maccrabevidence
// (rename of .maccrabtrace) ships in rc.3.

import SwiftUI
import MacCrabForensics

struct V2ForensicsEvidenceView: View {
    @State private var scans: [CaseManifest] = []
    @State private var selectedScanID: String? = nil
    @State private var evidence: [CommittedArtifact] = []
    @State private var loading = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if loading {
                    ProgressView("Loading evidence…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if scans.isEmpty {
                    emptyStateNoScans
                } else {
                    scanPicker
                    if evidence.isEmpty {
                        emptyStateNoEvidence
                    } else {
                        evidenceList
                    }
                }
            }
            .padding(20)
        }
        .task { await reload() }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Evidence")
                    .font(.title2).fontWeight(.semibold)
                Text("Artifacts collected during scans. Export bundles for IR or sharing.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                // rc.3
            } label: {
                Label("Export bundle", systemImage: "square.and.arrow.up")
            }
            .disabled(true)
            .help(".maccrabevidence export lands v1.17.0-rc.3")
        }
    }

    private var scanPicker: some View {
        HStack(spacing: 8) {
            Text("Scan:").font(.system(size: 12)).foregroundStyle(.secondary)
            Picker("", selection: Binding(
                get: { selectedScanID ?? scans.first?.id ?? "" },
                set: { newID in
                    selectedScanID = newID
                    Task { await loadEvidence(for: newID) }
                }
            )) {
                ForEach(scans, id: \.id) { s in
                    Text("\(s.name) · \(s.createdAt.formatted(date: .abbreviated, time: .shortened))")
                        .tag(s.id)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 320)
            Spacer()
        }
    }

    private var emptyStateNoScans: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("No scans yet")
                .font(.headline)
            Text("Evidence comes from running scans. Head to the Scans tab to start one.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var emptyStateNoEvidence: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("This scan has no evidence yet.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Text("Run a plugin on this scan to collect artifacts.")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }

    private var evidenceList: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(evidence, id: \.id) { row in
                evidenceRow(row)
                Divider()
            }
        }
    }

    private func evidenceRow(_ a: CommittedArtifact) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(a.record.summary ?? a.record.contentType)
                    .font(.system(size: 12, weight: .medium))
                HStack(spacing: 8) {
                    Text(a.record.pluginID)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text("· \(a.record.contentType)")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                    Text("· \(plainEnglishDataClass(a.record.privacyClass))")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            Text(a.record.observedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 6)
    }

    private func plainEnglishDataClass(_ pc: PrivacyClass) -> String {
        switch pc {
        case .metadata:          return "Metadata"
        case .content:           return "File content"
        case .personalComms:     return "Private user data"
        case .credentialAdjacent: return "Credential-adjacent"
        case .secret:            return "Secret"
        }
    }

    private func reload() async {
        loading = true
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            scans = try await mgr.listCases().sorted { $0.createdAt > $1.createdAt }
            if let first = scans.first {
                selectedScanID = first.id
                await loadEvidence(for: first.id)
            }
        } catch {
            scans = []
        }
        loading = false
    }

    private func loadEvidence(for scanID: String) async {
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let handle = try await mgr.openCase(id: scanID)
            evidence = try await handle.store.query(ArtifactQuery(
                caseID: scanID,
                limit: 500
            ))
        } catch {
            evidence = []
        }
    }
}
