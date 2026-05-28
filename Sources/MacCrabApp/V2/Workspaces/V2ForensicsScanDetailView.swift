// V2ForensicsScanDetailView.swift — rc.15 lazy-loading rebuild.
//
// Pre-rc.15 the view loaded up to 5000 artifacts upfront and
// held them in memory the whole time the sheet was open. For
// large encrypted scans with mail bodies (~100KB each) that
// could push hundreds of MB of resident memory.
//
// rc.15 strategy:
//   - Initial load fetches CONTENT-TYPE COUNTS only via a cheap
//     SQL GROUP BY. The sidebar renders from counts, not data.
//   - When the operator picks a content type, the artifacts for
//     THAT type are fetched on demand and cached.
//   - Export uses a fresh load (not the lazy cache) so the
//     output is always complete.

import SwiftUI
import MacCrabForensics

struct V2ForensicsScanDetailView: View {
    let scanID: String
    let scanName: String
    let encryptionState: CaseEncryptionState
    let createdAt: Date
    @Binding var isPresented: Bool

    @State private var loading = true
    @State private var error: String? = nil
    @State private var unlocked = false
    @State private var ctCounts: [(contentType: String, count: Int)] = []
    @State private var loadedArtifacts: [String: [CommittedArtifact]] = [:]
    @State private var loadingCT: String? = nil
    @State private var hints: [String: ViewerHint?] = [:]
    @State private var selectedContentType: String? = nil
    @State private var exportStatus: ExportStatus = .idle
    @State private var caseHandle: CaseHandle? = nil

    private enum ExportStatus: Equatable {
        case idle
        case exporting
        case exported(URL)
        case failed(String)
    }

    private var totalRows: Int {
        ctCounts.reduce(0) { $0 + $1.count }
    }

    private var selectedArtifacts: [CommittedArtifact] {
        guard let ct = selectedContentType else { return [] }
        return loadedArtifacts[ct] ?? []
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if encryptionState != .plaintext && !unlocked {
                encryptedNotice.padding(20)
            } else if loading {
                ProgressView("Loading…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let err = error {
                Text(err).foregroundStyle(.red).font(.system(size: 12)).padding(20)
            } else if ctCounts.isEmpty {
                emptyEvidence.padding(20)
            } else {
                summaryCard
                Divider()
                HStack(spacing: 0) {
                    contentTypeSidebar
                        .frame(width: 220)
                    Divider()
                    viewerArea
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .frame(width: 980, height: 680)
        .task {
            if encryptionState == .plaintext {
                await initialLoad()
            } else {
                loading = false
            }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(scanName).font(.headline)
                Text(createdAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !ctCounts.isEmpty {
                exportMenu
            }
            Button("Close") { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var exportMenu: some View {
        Menu {
            Button {
                Task { await exportNow(.csv) }
            } label: {
                Label("Export as CSV", systemImage: "tablecells")
            }
            Button {
                Task { await exportNow(.json) }
            } label: {
                Label("Export as JSON", systemImage: "curlybraces")
            }
            if case .exported(let url) = exportStatus {
                Divider()
                Button {
                    ArtifactExporter.revealInFinder(url)
                } label: {
                    Label("Reveal last export in Finder", systemImage: "doc.text.magnifyingglass")
                }
            }
        } label: {
            Label("Export", systemImage: "square.and.arrow.up")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help("Export the scan's evidence")
        .disabled(exportStatus == .exporting)
    }

    // MARK: - Summary card

    private var summaryCard: some View {
        HStack(spacing: 20) {
            metric("Evidence rows", "\(totalRows)")
            metric("Content types", "\(ctCounts.count)")
            metric("State", encryptionState == .plaintext ? "Plaintext" : "Encrypted")
            Spacer()
            exportStatusView
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value).font(.system(size: 18, weight: .semibold, design: .rounded))
            Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var exportStatusView: some View {
        switch exportStatus {
        case .idle:
            EmptyView()
        case .exporting:
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Exporting…").font(.system(size: 10)).foregroundStyle(.secondary)
            }
        case .exported(let url):
            HStack(spacing: 4) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.system(size: 11))
                Text("Saved to ~/Downloads/\(url.lastPathComponent)")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        case .failed(let msg):
            HStack(spacing: 4) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.system(size: 11))
                Text(msg).font(.system(size: 10)).foregroundStyle(.red)
            }
        }
    }

    // MARK: - Content type sidebar

    private var contentTypeSidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                Text("Content types")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .textCase(.uppercase)
                    .padding(.horizontal, 12).padding(.top, 12).padding(.bottom, 4)
                ForEach(ctCounts, id: \.contentType) { item in
                    sidebarRow(contentType: item.contentType, count: item.count)
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }

    private func sidebarRow(contentType ct: String, count: Int) -> some View {
        let isSelected = (selectedContentType ?? ctCounts.first?.contentType) == ct
        let kind = hints[ct]??.viewer.rawValue ?? "json"
        return Button {
            selectedContentType = ct
            // Lazy-fetch on first selection.
            if loadedArtifacts[ct] == nil {
                Task { await loadCT(ct) }
            }
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(ScannerDisplay.name(forContentType: ct))
                        .font(.system(size: 12, weight: isSelected ? .semibold : .regular))
                        .lineLimit(1)
                    Spacer()
                    Text("\(count)")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 4) {
                    Image(systemName: iconFor(viewer: kind))
                        .font(.system(size: 8))
                        .foregroundStyle(.tertiary)
                    Text(kind)
                        .font(.system(size: 9))
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(isSelected ? Color.accentColor.opacity(0.12) : Color.clear)
            .foregroundStyle(isSelected ? Color.accentColor : .primary)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
    }

    private func iconFor(viewer: String) -> String {
        switch viewer {
        case "table":      return "tablecells"
        case "timeline":   return "clock.arrow.circlepath"
        case "keyvalue":   return "list.bullet.indent"
        case "transcript": return "text.bubble"
        case "layout":     return "rectangle.grid.1x2"
        case "chart":      return "chart.bar.fill"
        default:           return "curlybraces"
        }
    }

    // MARK: - Viewer area

    @ViewBuilder
    private var viewerArea: some View {
        if let ct = selectedContentType ?? ctCounts.first?.contentType {
            if loadingCT == ct && loadedArtifacts[ct] == nil {
                ProgressView("Loading \(ScannerDisplay.name(forContentType: ct))…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ArtifactViewerDispatcher(
                    contentType: ct,
                    artifacts: selectedArtifacts,
                    hint: hints[ct] ?? nil
                )
                .padding(8)
            }
        }
    }

    // MARK: - Encrypted / empty

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
                    await initialLoad()
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

    // MARK: - Loading

    /// Initial load: opens the case, fetches counts only, and
    /// kicks off lazy load for the first content type.
    private func initialLoad() async {
        loading = true
        defer { loading = false }
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let handle = try await mgr.openCase(id: scanID)
            caseHandle = handle
            let counts = try await handle.store.contentTypeCounts(caseID: scanID)
            // Apply operator-visibility filter to drop dev plugins.
            ctCounts = counts.filter {
                OperatorVisibilityFilter.isOperatorVisible(
                    contentType: $0.contentType,
                    pluginID: ""
                )
            }
            hints = await ViewerHintResolver.resolveAll(
                contentTypes: Set(ctCounts.map { $0.contentType })
            )
            if let first = ctCounts.first?.contentType {
                selectedContentType = first
                await loadCT(first)
            }
        } catch {
            self.error = "Could not load evidence: \(error)"
            ctCounts = []
        }
    }

    /// Fetch the artifacts for a single content type. Cached on
    /// first hit so re-selecting a sidebar entry is instant.
    private func loadCT(_ ct: String) async {
        guard let handle = caseHandle else { return }
        if loadedArtifacts[ct] != nil { return }
        loadingCT = ct
        defer { loadingCT = nil }
        do {
            let rows = try await handle.store.query(ArtifactQuery(
                caseID: scanID,
                contentType: ct,
                limit: 5000
            ))
            loadedArtifacts[ct] = OperatorVisibilityFilter.filter(rows)
        } catch {
            loadedArtifacts[ct] = []
        }
    }

    /// Export uses a fresh full-case load to guarantee complete
    /// output (the lazy cache may only hold what the operator
    /// happens to have visited).
    private func exportNow(_ format: ArtifactExporter.Format) async {
        exportStatus = .exporting
        guard let handle = caseHandle else {
            exportStatus = .failed("No open case handle.")
            return
        }
        do {
            let rows = try await handle.store.query(ArtifactQuery(
                caseID: scanID, limit: 50_000
            ))
            let filtered = OperatorVisibilityFilter.filter(rows)
            let url = try ArtifactExporter.export(
                artifacts: filtered,
                scanID: scanID,
                scanName: scanName,
                format: format
            )
            exportStatus = .exported(url)
        } catch {
            exportStatus = .failed("\(error)")
        }
    }
}
