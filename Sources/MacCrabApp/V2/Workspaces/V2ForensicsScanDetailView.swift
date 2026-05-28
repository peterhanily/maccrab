// V2ForensicsScanDetailView.swift — rc.13 rebuild.
//
// Old: flat list of evidence rows, no per-content-type
// rendering, no exports.
//
// New: forensic manifest layout.
//   - Top: scan metadata + severity tally + Export menu
//   - Sidebar: content types present (grouped, with counts)
//   - Main: dispatched viewer for the selected content type
//     (table / timeline / keyvalue / transcript / layout /
//     JSON tree fallback)
//
// The dispatcher reads the plugin's ViewerHint from the registry
// at load time (once); subsequent renders are pure SwiftUI.

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
    @State private var hints: [String: ViewerHint?] = [:]
    @State private var selectedContentType: String? = nil
    @State private var exportStatus: ExportStatus = .idle

    private enum ExportStatus: Equatable {
        case idle
        case exported(URL)
        case failed(String)
    }

    private var contentTypes: [String] {
        Array(Set(artifacts.map { $0.record.contentType })).sorted()
    }

    private var grouped: [String: [CommittedArtifact]] {
        Dictionary(grouping: artifacts) { $0.record.contentType }
    }

    private var visibleArtifacts: [CommittedArtifact] {
        guard let ct = selectedContentType else { return artifacts }
        return grouped[ct] ?? []
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
            } else if artifacts.isEmpty {
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
                await loadEvidence()
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
            if !artifacts.isEmpty {
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
                exportNow(.csv)
            } label: {
                Label("Export as CSV", systemImage: "tablecells")
            }
            Button {
                exportNow(.json)
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
    }

    // MARK: - Summary card

    private var summaryCard: some View {
        let tally = FindingHeuristics.tally(artifacts)
        return HStack(spacing: 20) {
            metric("Evidence rows", "\(artifacts.count)")
            metric("Scanners run", "\(distinctPluginIDs.count)")
            metric("Content types", "\(contentTypes.count)")
            metric("State", encryptionState == .plaintext ? "Plaintext" : "Encrypted")
            Spacer()
            if !artifacts.isEmpty {
                Text(tally.bannerSummary)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(tally.attention + tally.critical > 0 ? .orange : .secondary)
            }
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

    private var distinctPluginIDs: [String] {
        Array(Set(artifacts.map { $0.record.pluginID })).sorted()
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
                ForEach(contentTypes, id: \.self) { ct in
                    sidebarRow(ct)
                }
            }
        }
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }

    private func sidebarRow(_ ct: String) -> some View {
        let count = grouped[ct]?.count ?? 0
        let isSelected = (selectedContentType ?? contentTypes.first) == ct
        let kind = hints[ct]??.viewer.rawValue ?? "json"
        return Button {
            selectedContentType = ct
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
        default:           return "curlybraces"
        }
    }

    // MARK: - Viewer area

    private var viewerArea: some View {
        let ct = selectedContentType ?? contentTypes.first ?? ""
        return ArtifactViewerDispatcher(
            contentType: ct,
            artifacts: visibleArtifacts,
            hint: hints[ct] ?? nil
        )
        .padding(8)
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

    // MARK: - Load + export

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
                limit: 5000
            ))
            artifacts = OperatorVisibilityFilter.filter(rows)
            // Resolve viewer hints for every content type in one pass.
            hints = await ViewerHintResolver.resolveAll(
                contentTypes: Set(artifacts.map { $0.record.contentType })
            )
            if selectedContentType == nil { selectedContentType = contentTypes.first }
        } catch {
            self.error = "Could not load evidence: \(error)"
            artifacts = []
        }
    }

    private func exportNow(_ format: ArtifactExporter.Format) {
        do {
            let url = try ArtifactExporter.export(
                artifacts: artifacts,
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
