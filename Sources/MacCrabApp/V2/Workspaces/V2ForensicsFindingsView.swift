// V2ForensicsFindingsView.swift — rc.6.
//
// Merged feed of findings across all operator-visible plaintext
// scans. Findings are grouped by scan, sorted newest-scan-first
// within each group. Filter by scanner. No Keychain prompts —
// encrypted scans are skipped during this passive refresh
// (open them explicitly via Scans → View to unlock).
//
// rc.6 is a presentation upgrade over rc.4/rc.5; real "severity"
// + "mark resolved" semantics need a Finding type emitted by
// the posture analyzer (v1.18). For now every committed artifact
// renders as a finding.

import SwiftUI
import MacCrabForensics

struct V2ForensicsFindingsView: View {
    @State private var loading = true
    @State private var groups: [ScanGroup] = []
    @State private var scannerFilter: String = "all"
    @State private var severityFilter: FindingSeverity? = nil
    @State private var copiedFindingID: Int64? = nil
    @AppStorage("forensics.seenFindingIDs") private var seenIDsRaw: String = ""

    private var seenIDs: Set<String> {
        get { Set(seenIDsRaw.split(separator: ",").map(String.init)) }
    }
    private func markSeen(_ id: Int64) {
        var s = seenIDs
        s.insert(String(id))
        seenIDsRaw = s.sorted().joined(separator: ",")
    }
    private func isSeen(_ id: Int64) -> Bool { seenIDs.contains(String(id)) }

    /// All distinct scanners across groups, for the filter chip row.
    private var allScanners: [String] {
        var seen = Set<String>()
        var ordered: [String] = []
        for g in groups {
            for f in g.findings where !seen.contains(f.record.pluginID) {
                seen.insert(f.record.pluginID)
                ordered.append(f.record.pluginID)
            }
        }
        return ordered
    }

    private var filteredGroups: [ScanGroup] {
        groups.compactMap { g in
            let filtered = g.findings.filter { a in
                let scannerOK = scannerFilter == "all" || a.record.pluginID == scannerFilter
                let sevOK: Bool = {
                    guard let need = severityFilter else { return true }
                    return FindingHeuristics.severity(for: a) == need
                }()
                return scannerOK && sevOK
            }
            guard !filtered.isEmpty else { return nil }
            return ScanGroup(scanID: g.scanID, scanName: g.scanName, createdAt: g.createdAt, findings: filtered)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if loading {
                    ProgressView("Loading findings…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if groups.isEmpty {
                    emptyState
                } else {
                    severitySummaryCard
                    if !allScanners.isEmpty {
                        scannerFilterBar
                    }
                    ForEach(filteredGroups, id: \.scanID) { g in
                        scanGroupCard(g)
                    }
                }
            }
            .padding(20)
        }
        .task { await reload() }
    }

    // MARK: - Sections

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Findings")
                    .font(.title2).fontWeight(.semibold)
                Text("What scans have found on this Mac, grouped by scan.")
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !groups.isEmpty {
                Text("\(totalCount) total")
                    .scaledSystem(11)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var totalCount: Int {
        filteredGroups.reduce(0) { $0 + $1.findings.count }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No findings yet.").font(.headline)
            Text("Run a scan from the Scans tab. Findings will appear here when scanners commit them.")
                .scaledSystem(12)
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var scannerFilterBar: some View {
        HStack(spacing: 8) {
            chip("All", value: "all")
            ForEach(allScanners, id: \.self) { id in
                chip(friendlyScannerName(id), value: id)
            }
            Spacer()
        }
    }

    private func chip(_ label: String, value: String) -> some View {
        Button {
            scannerFilter = value
        } label: {
            Text(label)
                .scaledSystem(11, weight: .medium)
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(scannerFilter == value ? Color.accentColor.opacity(0.18) : Color.clear)
                .foregroundStyle(scannerFilter == value ? Color.accentColor : .secondary)
                .cornerRadius(4)
        }
        .buttonStyle(.plain)
    }

    private func scanGroupCard(_ g: ScanGroup) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(g.scanName)
                    .scaledSystem(13, weight: .semibold)
                Spacer()
                Text("\(g.findings.count) finding\(g.findings.count == 1 ? "" : "s")")
                    .scaledSystem(11)
                    .foregroundStyle(.tertiary)
                Text("·")
                    .scaledSystem(11)
                    .foregroundStyle(.tertiary)
                Text(g.createdAt.formatted(date: .abbreviated, time: .shortened))
                    .scaledSystem(11)
                    .foregroundStyle(.tertiary)
            }
            Divider()
            ForEach(g.findings.prefix(25), id: \.id) { f in
                findingRow(f)
            }
            if g.findings.count > 25 {
                Text("+ \(g.findings.count - 25) more · open the scan detail to see all")
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
                    .padding(.top, 4)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func findingRow(_ a: CommittedArtifact) -> some View {
        let sev = FindingHeuristics.severity(for: a)
        let seen = isSeen(a.id)
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: sev.sfSymbol)
                .scaledSystem(11)
                .foregroundStyle(color(for: sev))
                .padding(.top, 2)
                // v1.18.1: severity was icon-only here — VoiceOver read the
                // raw symbol name; now it reads the severity it encodes.
                .accessibilityLabel("\(sev.displayName) severity")
            VStack(alignment: .leading, spacing: 2) {
                Text(a.record.summary ?? friendlyContentType(a.record.contentType))
                    .scaledSystem(12, weight: seen ? .regular : .medium)
                    .foregroundStyle(seen ? .secondary : .primary)
                HStack(spacing: 6) {
                    Text(sev.displayName)
                        .scaledSystem(9, weight: .medium)
                        .foregroundStyle(color(for: sev))
                    Text("·").scaledSystem(10).foregroundStyle(.tertiary)
                    Text(friendlyScannerName(a.record.pluginID))
                        .scaledSystem(10)
                        .foregroundStyle(.secondary)
                    Text("·").scaledSystem(10).foregroundStyle(.tertiary)
                    Text(a.record.observedAt.formatted(date: .omitted, time: .shortened))
                        .scaledSystem(10)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            Menu {
                Button {
                    copyAsJSON(a)
                } label: {
                    Label("Copy as JSON", systemImage: "doc.on.clipboard")
                }
                Button {
                    markSeen(a.id)
                } label: {
                    Label(seen ? "Already marked seen" : "Mark seen", systemImage: seen ? "checkmark.circle" : "eye")
                }
                .disabled(seen)
            } label: {
                Image(systemName: "ellipsis.circle")
                    .scaledSystem(13)
                    .foregroundStyle(.secondary)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 28)
            .help("Actions")
        }
        .padding(.vertical, 4)
        .overlay(alignment: .trailing) {
            if copiedFindingID == a.id {
                Text("Copied")
                    .scaledSystem(10, weight: .medium)
                    .foregroundStyle(.green)
                    .padding(.trailing, 36)
            }
        }
    }

    private func color(for sev: FindingSeverity) -> Color {
        switch sev {
        case .routine:   return .secondary
        case .notable:   return .blue
        case .attention: return .orange
        case .critical:  return .red
        }
    }

    private func copyAsJSON(_ a: CommittedArtifact) {
        let dict: [String: Any] = [
            "id": Int(a.id),
            "case_id": a.record.caseID,
            "plugin_id": a.record.pluginID,
            "content_type": a.record.contentType,
            "summary": a.record.summary ?? "",
            "observed_at": ISO8601DateFormatter().string(from: a.record.observedAt),
            "severity": FindingHeuristics.severity(for: a).rawValue,
        ]
        if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
           let s = String(data: data, encoding: .utf8) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(s, forType: .string)
            copiedFindingID = a.id
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                if copiedFindingID == a.id { copiedFindingID = nil }
            }
        }
    }

    private var severitySummaryCard: some View {
        let allFindings = groups.flatMap { $0.findings }
        let t = FindingHeuristics.tally(allFindings)
        return HStack(spacing: 16) {
            severityChip("Critical", t.critical, .red, value: .critical)
            severityChip("Needs review", t.attention, .orange, value: .attention)
            severityChip("Notable", t.notable, .blue, value: .notable)
            severityChip("Inventoried", t.routine, .secondary, value: .routine)
            Spacer()
            if severityFilter != nil {
                Button("Clear filter") { severityFilter = nil }
                    .scaledSystem(11)
                    .buttonStyle(.borderless)
            }
        }
        .padding(12)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func severityChip(_ label: String, _ count: Int, _ color: Color, value: FindingSeverity) -> some View {
        Button {
            severityFilter = (severityFilter == value) ? nil : value
        } label: {
            VStack(alignment: .leading, spacing: 1) {
                Text("\(count)")
                    .scaledSystem(18, weight: .semibold, design: .rounded)
                    .foregroundStyle(count == 0 ? Color.secondary.opacity(0.6) : color)
                Text(label)
                    .scaledSystem(10)
                    .foregroundStyle(.secondary)
            }
            .padding(8)
            .background(severityFilter == value ? color.opacity(0.12) : Color.clear)
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
        .disabled(count == 0)
    }

    // MARK: - Plain-English mappers

    private func friendlyScannerName(_ id: String) -> String {
        ScannerDisplay.name(forPluginID: id)
    }

    private func friendlyContentType(_ ct: String) -> String {
        ScannerDisplay.name(forContentType: ct)
    }

    // Severity now sourced from FindingHeuristics.swift.

    // MARK: - Loading

    struct ScanGroup {
        let scanID: String
        let scanName: String
        let createdAt: Date
        let findings: [CommittedArtifact]
    }

    private func reload() async {
        loading = true
        var collected: [ScanGroup] = []
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let scans = OperatorVisibilityFilter.filter(
                try await mgr.listCases().sorted { $0.createdAt > $1.createdAt }
            )
            // Plaintext scans only — encrypted scans require an
            // explicit Unlock action via Scans → View.
            for scan in scans.prefix(20) where scan.encryptionState == .plaintext {
                let handle = try await mgr.openCase(id: scan.id)
                let rows = try await handle.store.query(ArtifactQuery(
                    caseID: scan.id,
                    limit: 200
                ))
                let filtered = OperatorVisibilityFilter.filter(rows)
                if !filtered.isEmpty {
                    collected.append(ScanGroup(
                        scanID: scan.id,
                        scanName: scan.name,
                        createdAt: scan.createdAt,
                        findings: filtered.sorted { $0.record.observedAt > $1.record.observedAt }
                    ))
                }
            }
        } catch {
            collected = []
        }
        groups = collected
        loading = false
    }
}
