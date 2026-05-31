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
    @State private var diskSizes: [String: Int64] = [:]
    @State private var loading = true
    @State private var openScanID: String? = nil
    @State private var query: String = ""
    @State private var pendingDelete: CaseManifest? = nil
    @State private var deleteResult: String? = nil
    // Bulk-delete: a selection mode operators toggle from the header.
    // While on, rows show a checkbox and the row click toggles
    // selection instead of opening the scan.
    @State private var selectionMode = false
    @State private var selectedIDs: Set<String> = []
    @State private var pendingBulkDelete = false

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
                if let msg = deleteResult {
                    deleteToast(msg)
                }
                if loading {
                    ProgressView("Loading…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if scans.isEmpty {
                    emptyState
                } else {
                    if selectionMode {
                        bulkBar
                    }
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
        .alert("Delete this scan permanently?",
               isPresented: Binding(
                   get: { pendingDelete != nil },
                   set: { if !$0 { pendingDelete = nil } }
               ),
               presenting: pendingDelete) { scan in
            Button("Delete \(scan.name)", role: .destructive) {
                deleteScan(scan)
            }
            Button("Cancel", role: .cancel) {
                pendingDelete = nil
            }
        } message: { scan in
            let sizeStr = diskSizes[scan.id].map { bytes -> String in
                let bcf = ByteCountFormatter()
                bcf.countStyle = .file
                return bcf.string(fromByteCount: bytes)
            } ?? "unknown size"
            Text("This removes the scan + its evidence database (\(sizeStr)) from disk. You can't undo this. Exported CSV/JSON files are not affected.")
        }
        .alert("Delete \(selectedIDs.count) scan\(selectedIDs.count == 1 ? "" : "s") permanently?",
               isPresented: $pendingBulkDelete) {
            Button("Delete \(selectedIDs.count) scan\(selectedIDs.count == 1 ? "" : "s")", role: .destructive) {
                bulkDelete()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            let total = selectedIDs.reduce(Int64(0)) { $0 + (diskSizes[$1] ?? 0) }
            Text("This removes the selected scans + their evidence databases (\(formattedBytes(total))) from disk. You can't undo this. Exported CSV/JSON files are not affected.")
        }
    }

    private func formattedBytes(_ bytes: Int64) -> String {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .file
        return bcf.string(fromByteCount: bytes)
    }

    /// Permanently remove the case directory from disk + reload
    /// the list. Used by the row's Delete action after the user
    /// confirms in the alert.
    private func deleteScan(_ scan: CaseManifest) {
        let freed = diskSizes[scan.id] ?? CaseDirectoryLayout(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            caseID: scan.id
        ).diskBytes()
        pendingDelete = nil
        Task {
            // Route through CaseManager.deleteCase so the wrapped DEK is
            // also removed from the keychain (a raw removeItem orphans it
            // for encrypted scans) and the case id is UUID-validated
            // before it ever reaches removeItem.
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            do {
                try await mgr.deleteCase(id: scan.id)
                // Also drop any HiddenScans entry — no point keeping
                // the hide list referring to a dir that's gone.
                HiddenScans.restore(scan.id)
                let bcf = ByteCountFormatter()
                bcf.countStyle = .file
                deleteResult = "Deleted \(scan.name) · freed \(bcf.string(fromByteCount: freed))."
            } catch {
                deleteResult = "Couldn't delete: \(error.localizedDescription)"
            }
            await reload()
        }
    }

    private func toggleSelection(_ id: String) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else {
            selectedIDs.insert(id)
        }
    }

    /// Delete every selected scan. Routes each through
    /// `CaseManager.deleteCase` (same as the single-row path) so the
    /// wrapped DEK is removed from the keychain and the id is
    /// UUID-validated before any removeItem. Reports a combined result.
    private func bulkDelete() {
        let ids = Array(selectedIDs)
        pendingBulkDelete = false
        Task {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            var freed: Int64 = 0
            var ok = 0
            var failed = 0
            for id in ids {
                let bytes = diskSizes[id] ?? CaseDirectoryLayout(
                    casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                    caseID: id
                ).diskBytes()
                do {
                    try await mgr.deleteCase(id: id)
                    HiddenScans.restore(id)
                    freed += bytes
                    ok += 1
                } catch {
                    failed += 1
                }
            }
            let bcf = ByteCountFormatter()
            bcf.countStyle = .file
            if failed == 0 {
                deleteResult = "Deleted \(ok) scan\(ok == 1 ? "" : "s") · freed \(bcf.string(fromByteCount: freed))."
            } else {
                deleteResult = "Deleted \(ok), \(failed) failed · freed \(bcf.string(fromByteCount: freed))."
            }
            selectedIDs = []
            selectionMode = false
            await reload()
        }
    }

    // MARK: - Sections

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Past scans")
                    .font(.title2).fontWeight(.semibold)
                Text(selectionMode
                     ? "Select scans, then Delete selected. Click a row to toggle."
                     : "Every scan run on this Mac, newest first. Click a scan to open it.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !scans.isEmpty {
                if selectionMode {
                    Button("Cancel") {
                        selectionMode = false
                        selectedIDs = []
                    }
                    .buttonStyle(.borderless)
                    .font(.system(size: 12))
                } else {
                    Button("Select") { selectionMode = true }
                        .buttonStyle(.borderless)
                        .font(.system(size: 12))
                    Text("\(scans.count) total")
                        .font(.system(size: 11))
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    /// Bulk action bar shown while in selection mode: select-all toggle,
    /// live selected count, and the destructive delete trigger.
    private var bulkBar: some View {
        HStack(spacing: 12) {
            Button(selectedIDs.count == filtered.count && !filtered.isEmpty ? "Deselect all" : "Select all") {
                if selectedIDs.count == filtered.count {
                    selectedIDs = []
                } else {
                    selectedIDs = Set(filtered.map(\.id))
                }
            }
            .buttonStyle(.borderless)
            .font(.system(size: 12))
            Spacer()
            Text("\(selectedIDs.count) selected")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            Button(role: .destructive) {
                pendingBulkDelete = true
            } label: {
                Label("Delete selected", systemImage: "trash")
                    .font(.system(size: 12))
            }
            .disabled(selectedIDs.isEmpty)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }

    private func deleteToast(_ msg: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: msg.hasPrefix("Deleted") ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(msg.hasPrefix("Deleted") ? .green : .orange)
                .font(.system(size: 13))
            Text(msg)
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
            Spacer()
            Button("Dismiss") {
                deleteResult = nil
            }
            .buttonStyle(.borderless)
            .font(.system(size: 11))
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
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
                    diskBytes: diskSizes[scan.id],
                    selectionMode: selectionMode,
                    isSelected: selectedIDs.contains(scan.id),
                    onToggleSelection: { toggleSelection(scan.id) },
                    onOpen: { openScanID = scan.id },
                    onDismiss: {
                        HiddenScans.hide(scan.id)
                        Task { await reload() }
                    },
                    onDeleteRequested: {
                        pendingDelete = scan
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
            // Disk-size walk is cheap (stat() per file) but still off
            // the main actor — let Task.detached handle it so the list
            // appears immediately and sizes populate as they're computed.
            let casesRoot = CaseDirectoryLayout.defaultCasesRoot
            let scanIDs = scans.map(\.id)
            Task.detached {
                var sizes: [String: Int64] = [:]
                for id in scanIDs {
                    let layout = CaseDirectoryLayout(casesRoot: casesRoot, caseID: id)
                    sizes[id] = layout.diskBytes()
                }
                let computed = sizes
                await MainActor.run { diskSizes = computed }
            }
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
    var diskBytes: Int64? = nil
    /// When true the row renders a leading checkbox and the primary
    /// click toggles selection instead of opening the scan. Defaults
    /// off so the Recently-run caller is unchanged.
    var selectionMode: Bool = false
    var isSelected: Bool = false
    var onToggleSelection: (() -> Void)? = nil
    let onOpen: () -> Void
    let onDismiss: () -> Void
    /// Optional permanent-delete callback. When present, the row
    /// menu adds a destructive "Delete permanently…" entry. The
    /// confirmation alert lives on the parent view (Past Scans /
    /// Recently Run), not inside the row, so the row stays a
    /// pure presentation component.
    var onDeleteRequested: (() -> Void)? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            if selectionMode {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 16))
                    .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
                    .padding(.top, 1)
            }
            Button(action: selectionMode ? { onToggleSelection?() } : onOpen) {
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
                            if let bytes = diskBytes {
                                Text("·")
                                    .font(.system(size: 11))
                                    .foregroundStyle(.tertiary)
                                Text(formatSize(bytes))
                                    .font(.system(size: 11))
                                    .foregroundStyle(bytes > 50 * 1_024 * 1_024 ? .orange : .secondary)
                            }
                        }
                    }
                    Spacer()
                    if !selectionMode {
                        Text("View")
                            .font(.system(size: 11))
                            .foregroundStyle(.tint)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if !selectionMode {
            Menu {
                Button(action: onOpen) {
                    Label("Open", systemImage: "eye")
                }
                Divider()
                Button(role: .destructive, action: onDismiss) {
                    Label("Dismiss from list", systemImage: "eye.slash")
                }
                if let onDelete = onDeleteRequested {
                    Button(role: .destructive, action: onDelete) {
                        Label("Delete permanently…", systemImage: "trash")
                    }
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
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .contextMenu {
            Button(action: onOpen) {
                Label("Open", systemImage: "eye")
            }
            Button(role: .destructive, action: onDismiss) {
                Label("Dismiss from list", systemImage: "eye.slash")
            }
            if let onDelete = onDeleteRequested {
                Button(role: .destructive, action: onDelete) {
                    Label("Delete permanently…", systemImage: "trash")
                }
            }
        }
    }

    private func timeAgo(_ d: Date) -> String {
        let fmt = RelativeDateTimeFormatter()
        fmt.unitsStyle = .full
        return "Started " + fmt.localizedString(for: d, relativeTo: Date())
    }

    private func formatSize(_ bytes: Int64) -> String {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .file
        bcf.allowedUnits = [.useKB, .useMB, .useGB]
        return bcf.string(fromByteCount: bytes)
    }
}
