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
    // Content types whose on-demand load hit `perTypeLoadLimit` — the viewer is
    // showing only a prefix of the true (sidebar) count for that type.
    @State private var truncatedCTs: Set<String> = []
    // True when the last export query hit `exportRowCap` (output may be partial).
    @State private var exportTruncated = false

    /// Per-content-type lazy load cap. Kept bounded (rc.15 memory design) — when
    /// a type exceeds it the viewer surfaces a "showing first N" notice and
    /// points the operator at Export for the complete set.
    private let perTypeLoadLimit = 5000
    /// Whole-scan / per-type export row cap. Large but finite so a runaway scan
    /// can't exhaust memory during export; surfaced when reached.
    private let exportRowCap = 50_000

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
                ProgressView(String(localized: "scanDetail.loading", defaultValue: "Loading…"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let err = error {
                Text(err).foregroundStyle(.red).scaledSystem(12).padding(20)
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
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !ctCounts.isEmpty {
                exportMenu
            }
            Button(String(localized: "scanDetail.close", defaultValue: "Close")) { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var exportMenu: some View {
        Menu {
            Button {
                Task { await exportNow(.csv) }
            } label: {
                Label(String(localized: "scanDetail.exportAsCSV", defaultValue: "Export all as CSV"), systemImage: "tablecells")
            }
            Button {
                Task { await exportNow(.json) }
            } label: {
                Label(String(localized: "scanDetail.exportAsJSON", defaultValue: "Export all as JSON"), systemImage: "curlybraces")
            }
            // Per-type export: just the content type the operator is viewing.
            if let ct = selectedContentType ?? ctCounts.first?.contentType {
                Divider()
                Section(String(localized: "scanDetail.exportTypeSection", defaultValue: "This type: \(ScannerDisplay.name(forContentType: ct))")) {
                    Button {
                        Task { await exportNow(.csv, contentType: ct) }
                    } label: {
                        Label(String(localized: "scanDetail.exportTypeCSV", defaultValue: "Export this type as CSV"), systemImage: "tablecells")
                    }
                    Button {
                        Task { await exportNow(.json, contentType: ct) }
                    } label: {
                        Label(String(localized: "scanDetail.exportTypeJSON", defaultValue: "Export this type as JSON"), systemImage: "curlybraces")
                    }
                }
            }
            if case .exported(let url) = exportStatus {
                Divider()
                Button {
                    ArtifactExporter.revealInFinder(url)
                } label: {
                    Label(String(localized: "scanDetail.revealLastExport", defaultValue: "Reveal last export in Finder"), systemImage: "doc.text.magnifyingglass")
                }
            }
        } label: {
            Label(String(localized: "scanDetail.export", defaultValue: "Export"), systemImage: "square.and.arrow.up")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help(String(localized: "scanDetail.exportHelp", defaultValue: "Export the scan's evidence"))
        .disabled(exportStatus == .exporting)
    }

    // MARK: - Summary card

    private var summaryCard: some View {
        HStack(spacing: 20) {
            metric(String(localized: "scanDetail.metricEvidenceRows", defaultValue: "Evidence rows"), "\(totalRows)")
            metric(String(localized: "scanDetail.metricContentTypes", defaultValue: "Content types"), "\(ctCounts.count)")
            metric(String(localized: "scanDetail.metricState", defaultValue: "State"), encryptionState == .plaintext ? String(localized: "scanDetail.statePlaintext", defaultValue: "Plaintext") : String(localized: "scanDetail.stateEncrypted", defaultValue: "Encrypted"))
            Spacer()
            exportStatusView
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(value).scaledSystem(18, weight: .semibold, design: .rounded)
            Text(label).scaledSystem(10).foregroundStyle(.secondary)
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
                Text(String(localized: "scanDetail.exporting", defaultValue: "Exporting…")).scaledSystem(10).foregroundStyle(.secondary)
            }
        case .exported(let url):
            HStack(spacing: 4) {
                Image(systemName: exportTruncated ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .foregroundStyle(exportTruncated ? .orange : .green)
                    .scaledSystem(11)
                Text(exportTruncated
                     ? String(localized: "scanDetail.savedToTruncated", defaultValue: "Saved to ~/Downloads/\(url.lastPathComponent) — capped at \(exportRowCap) rows, may be incomplete")
                     : String(localized: "scanDetail.savedTo", defaultValue: "Saved to ~/Downloads/\(url.lastPathComponent)"))
                    .scaledSystem(10)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        case .failed(let msg):
            HStack(spacing: 4) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .scaledSystem(11)
                Text(msg).scaledSystem(10).foregroundStyle(.red)
            }
        }
    }

    // MARK: - Content type sidebar

    private var contentTypeSidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "scanDetail.contentTypesHeader", defaultValue: "Content types"))
                    .scaledSystem(10, weight: .semibold)
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
                        .scaledSystem(12, weight: isSelected ? .semibold : .regular)
                        .lineLimit(1)
                    Spacer()
                    Text("\(count)")
                        .scaledSystem(10)
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 4) {
                    Image(systemName: iconFor(viewer: kind))
                        .scaledSystem(8)
                        .foregroundStyle(.tertiary)
                    Text(kind)
                        .scaledSystem(9)
                        .foregroundStyle(.tertiary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(isSelected ? Color.accentColor.opacity(0.12) : Color.clear)
            .foregroundStyle(isSelected ? Color.accentColor : .primary)
            .cornerRadius(4)
            .contentShape(Rectangle())
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
                ProgressView(String(localized: "scanDetail.loadingContentType", defaultValue: "Loading \(ScannerDisplay.name(forContentType: ct))…"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    if truncatedCTs.contains(ct) {
                        truncationBanner(for: ct)
                    }
                    ArtifactViewerDispatcher(
                        contentType: ct,
                        artifacts: selectedArtifacts,
                        hint: hints[ct] ?? nil
                    )
                    .padding(8)
                }
            }
        }
    }

    /// Shown above a viewer whose content type has more rows on disk than the
    /// per-type load cap surfaced — the operator would otherwise trust an
    /// incomplete view against a larger sidebar count.
    private func truncationBanner(for ct: String) -> some View {
        let trueCount = ctCounts.first(where: { $0.contentType == ct })?.count ?? 0
        return HStack(spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .scaledSystem(10)
            Text(String(localized: "scanDetail.truncatedType", defaultValue: "Showing up to the first \(perTypeLoadLimit) of \(trueCount) rows for this type — use Export for the complete set."))
                .scaledSystem(10)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
        .background(Color.orange.opacity(0.08))
    }

    // MARK: - Encrypted / empty

    private var encryptedNotice: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "lock.fill").foregroundStyle(.tint)
                Text(String(localized: "scanDetail.encryptedTitle", defaultValue: "This scan is encrypted"))
                    .scaledSystem(13, weight: .semibold)
            }
            Text(String(localized: "scanDetail.encryptedBody", defaultValue: "Unlocking reads the scan's data encryption key from your macOS Keychain. macOS will ask for your password the first time MacCrab accesses it."))
                .scaledSystem(12)
                .foregroundStyle(.secondary)
            Button(String(localized: "scanDetail.unlockShowEvidence", defaultValue: "Unlock + show evidence")) {
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
        Text(String(localized: "scanDetail.emptyEvidence", defaultValue: "This scan didn't commit any evidence rows. The scanners ran but found nothing to record, or finished before producing output."))
            .scaledSystem(12)
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
            self.error = String(localized: "scanDetail.couldNotLoad", defaultValue: "Could not load evidence: \(error)")
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
                limit: perTypeLoadLimit
            ))
            // Raw count (pre-visibility-filter) hitting the cap means more rows
            // exist on disk than we loaded for this type.
            if rows.count >= perTypeLoadLimit { truncatedCTs.insert(ct) }
            loadedArtifacts[ct] = OperatorVisibilityFilter.filter(rows)
        } catch {
            loadedArtifacts[ct] = []
        }
    }

    /// Export uses a fresh full load (not the lazy cache) to guarantee complete
    /// output. Pass `contentType` to export just that type; nil exports the
    /// whole scan. The file name carries the type so per-type exports don't
    /// collide with the whole-scan one.
    private func exportNow(_ format: ArtifactExporter.Format, contentType: String? = nil) async {
        exportStatus = .exporting
        exportTruncated = false
        guard let handle = caseHandle else {
            exportStatus = .failed(String(localized: "scanDetail.noOpenCaseHandle", defaultValue: "No open case handle."))
            return
        }
        do {
            let query: ArtifactQuery = contentType.map {
                ArtifactQuery(caseID: scanID, contentType: $0, limit: exportRowCap)
            } ?? ArtifactQuery(caseID: scanID, limit: exportRowCap)
            let rows = try await handle.store.query(query)
            exportTruncated = rows.count >= exportRowCap
            let filtered = OperatorVisibilityFilter.filter(rows)
            let name = contentType.map { "\(scanName) - \(ScannerDisplay.name(forContentType: $0))" } ?? scanName
            let url = try ArtifactExporter.export(
                artifacts: filtered,
                scanID: scanID,
                scanName: name,
                format: format
            )
            exportStatus = .exported(url)
        } catch {
            exportStatus = .failed("\(error)")
        }
    }
}
