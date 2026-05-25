// V2ForensicsScansView.swift
// MacCrabApp — v1.17 Forensics → Scans tab.
//
// Per docs/forensics-ia-redesign-plan.md §3.3. Empty-state-first
// design — the most important screen because new operators land
// here. The "Start a scan" wizard ships in rc.3; rc.2 wires the
// CTA stub.

import SwiftUI
import MacCrabForensics

struct V2ForensicsScansView: View {
    @State private var scans: [CaseManifest] = []
    @State private var loading = true
    @State private var showingWizardStub = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if loading {
                    ProgressView("Loading scans…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if scans.isEmpty {
                    emptyState
                } else {
                    scanList
                }
            }
            .padding(20)
        }
        .task { await reload() }
        .sheet(isPresented: $showingWizardStub) {
            wizardStub
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Scans")
                    .font(.title2).fontWeight(.semibold)
                Text("Run, schedule, and review scans of this Mac.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                showingWizardStub = true
            } label: {
                Label("Start a scan", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.system(size: 28))
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text("No scans yet")
                        .font(.headline)
                    Text("Start a scan to check this Mac for signs of compromise, misconfiguration, or unauthorized changes.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            Text("Each scan creates a record you can review, export, or share. Built-in plugins look at TCC permissions, launch agents, codesigning anomalies, and more. Third-party plugins add coverage from the maccrab.com/rave catalog.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .padding(.bottom, 4)
            Button {
                showingWizardStub = true
            } label: {
                Label("Start your first scan", systemImage: "arrow.right.circle.fill")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    // MARK: - Non-empty: scan list

    private var scanList: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(scans, id: \.id) { scan in
                scanRow(scan)
                Divider()
            }
        }
    }

    private func scanRow(_ scan: CaseManifest) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(scan.name)
                    .font(.system(size: 13, weight: .semibold))
                Text("Started \(scan.createdAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                if scan.encryptionState == .plaintext {
                    Text("Plaintext (metadata only)")
                        .font(.system(size: 10))
                        .foregroundStyle(.orange)
                }
            }
            Spacer()
            Text(scan.id.prefix(8) + "…")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Wizard stub (rc.3)

    private var wizardStub: some View {
        VStack(spacing: 16) {
            Image(systemName: "wand.and.stars")
                .font(.system(size: 36))
                .foregroundStyle(.tint)
            Text("Start-a-scan wizard")
                .font(.title2).fontWeight(.semibold)
            Text("The guided wizard lands in v1.17.0-rc.3 alongside the unified plugin catalog. For now, use the CLI:")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 320)
            Text("maccrabctl scan new \"my scan\" --reason routine")
                .font(.system(size: 11, design: .monospaced))
                .padding(8)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(4)
                .textSelection(.enabled)
            Button("Got it") { showingWizardStub = false }
                .keyboardShortcut(.defaultAction)
        }
        .padding(28)
        .frame(width: 420)
    }

    // MARK: - Data

    private func reload() async {
        loading = true
        do {
            let mgr = makeForensicsCaseManager()
            let manifests = try await mgr.listCases()
            scans = manifests
        } catch {
            scans = []
        }
        loading = false
    }

    private func makeForensicsCaseManager() -> CaseManager {
        CaseManager(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            dekVault: KeychainDEKVault()
        )
    }
}
