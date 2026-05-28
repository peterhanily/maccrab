// V2ForensicsPastScansView.swift
//
// rc.12 — dedicated tab for the full scan history.
//
// The "Scans" tab used to carry both the kit picker and the
// scan history; that meant operators had to scroll past the kits
// to see their old scans, and the kit list got pushed to the
// bottom on data-heavy Macs. Splitting it lets each surface have
// its own home:
//   - Scans:      kit picker + currently running + last 3 run
//   - Past scans: full archive (this view) with per-row dismiss

import SwiftUI
import MacCrabForensics

struct V2ForensicsPastScansView: View {
    @State private var scans: [CaseManifest] = []
    @State private var loading = true
    @State private var openScanID: String? = nil
    @State private var query: String = ""

    private var openScan: CaseManifest? {
        guard let id = openScanID else { return nil }
        return scans.first { $0.id == id }
    }

    private var filtered: [CaseManifest] {
        guard !query.isEmpty else { return scans }
        let q = query.lowercased()
        return scans.filter { $0.name.lowercased().contains(q) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if loading {
                    ProgressView("Loading…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if scans.isEmpty {
                    emptyState
                } else {
                    if scans.count > 4 {
                        searchField
                    }
                    listSection
                }
            }
            .padding(20)
        }
        .task { await reload() }
        .sheet(isPresented: Binding(
            get: { openScanID != nil },
            set: { if !$0 { openScanID = nil } }
        )) {
            if let scan = openScan {
                V2ForensicsScanDetailView(
                    scanID: scan.id,
                    scanName: scan.name,
                    encryptionState: scan.encryptionState,
                    createdAt: scan.createdAt,
                    isPresented: Binding(
                        get: { openScanID != nil },
                        set: { if !$0 { openScanID = nil } }
                    )
                )
            }
        }
    }

    // MARK: - Sections

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Past scans")
                    .font(.title2).fontWeight(.semibold)
                Text("Every scan run on this Mac, newest first. Click a scan to open it.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !scans.isEmpty {
                Text("\(scans.count) total")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No scans yet.").font(.headline)
            Text("Run a scan from the Run a scan tab. Each scan you complete will appear here.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
            TextField("Filter by scan name", text: $query)
                .textFieldStyle(.plain)
                .font(.system(size: 12))
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }

    private var listSection: some View {
        VStack(spacing: 0) {
            ForEach(filtered, id: \.id) { scan in
                ForensicsScanRow(
                    scan: scan,
                    onOpen: { openScanID = scan.id },
                    onDismiss: {
                        HiddenScans.hide(scan.id)
                        Task { await reload() }
                    }
                )
                if scan.id != filtered.last?.id {
                    Divider()
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    // MARK: - Load

    private func reload() async {
        loading = true
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let raw = try await mgr.listCases().sorted { $0.createdAt > $1.createdAt }
            scans = OperatorVisibilityFilter.filter(raw)
        } catch {
            scans = []
        }
        loading = false
    }
}

// MARK: - ForensicsScanRow

/// Single past-scan row, reusable from V2ForensicsPastScansView
/// and V2ForensicsScansView (the Recently run section). Carries
/// its own open + dismiss callbacks so callers can wire either
/// to a sheet presentation or a navigation push.
struct ForensicsScanRow: View {
    let scan: CaseManifest
    let onOpen: () -> Void
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Button(action: onOpen) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(scan.name)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.primary)
                        HStack(spacing: 6) {
                            Text(timeAgo(scan.createdAt))
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                            if scan.encryptionState != .plaintext {
                                Image(systemName: "lock.fill")
                                    .font(.system(size: 9))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    Spacer()
                    Text("View")
                        .font(.system(size: 11))
                        .foregroundStyle(.tint)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Menu {
                Button(action: onOpen) {
                    Label("Open", systemImage: "eye")
                }
                Divider()
                Button(role: .destructive, action: onDismiss) {
                    Label("Dismiss from list", systemImage: "eye.slash")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 28)
            .help("Actions")
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .contextMenu {
            Button(action: onOpen) {
                Label("Open", systemImage: "eye")
            }
            Button(role: .destructive, action: onDismiss) {
                Label("Dismiss from list", systemImage: "eye.slash")
            }
        }
    }

    private func timeAgo(_ d: Date) -> String {
        let fmt = RelativeDateTimeFormatter()
        fmt.unitsStyle = .full
        return "Started " + fmt.localizedString(for: d, relativeTo: Date())
    }
}
