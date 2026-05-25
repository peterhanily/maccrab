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
        guard scannerFilter != "all" else { return groups }
        return groups.compactMap { g in
            let filtered = g.findings.filter { $0.record.pluginID == scannerFilter }
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
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if !groups.isEmpty {
                Text("\(totalCount) total")
                    .font(.system(size: 11))
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
                .font(.system(size: 12))
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
                .font(.system(size: 11, weight: .medium))
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
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                Text("\(g.findings.count) finding\(g.findings.count == 1 ? "" : "s")")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                Text("·")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                Text(g.createdAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }
            Divider()
            ForEach(g.findings.prefix(25), id: \.id) { f in
                findingRow(f)
            }
            if g.findings.count > 25 {
                Text("+ \(g.findings.count - 25) more · open the scan detail to see all")
                    .font(.system(size: 10))
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
        HStack(alignment: .top) {
            Image(systemName: severityIcon(for: a))
                .font(.system(size: 11))
                .foregroundStyle(severityColor(for: a))
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                Text(a.record.summary ?? friendlyContentType(a.record.contentType))
                    .font(.system(size: 12, weight: .medium))
                HStack(spacing: 6) {
                    Text(friendlyScannerName(a.record.pluginID))
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                    Text("·")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                    Text(a.record.observedAt.formatted(date: .omitted, time: .shortened))
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
        }
        .padding(.vertical, 4)
    }

    // MARK: - Plain-English mappers

    private func friendlyScannerName(_ id: String) -> String {
        let map: [String: String] = [
            "com.maccrab.hosts-collector":         "Hosts file baseline",
            "com.maccrab.launch-agents-collector": "Launch agents inventory",
            "com.maccrab.forensics.tcc-lite":      "Privacy permissions",
            "com.maccrab.forensics.launchd-lite":  "Launch items",
            "com.maccrab.forensics.applescript-runtime": "AppleScript activity",
            "com.maccrab.forensics.quarantine":    "Quarantined downloads",
            "com.maccrab.forensics.posture":       "Security posture",
        ]
        return map[id]
            ?? id.split(separator: ".").last.map {
                $0.replacingOccurrences(of: "-", with: " ").capitalized
            } ?? id
    }

    private func friendlyContentType(_ ct: String) -> String {
        let map: [String: String] = [
            "tcc.permission":           "Privacy permission grant",
            "launchd.agent":            "Launch agent",
            "launchd.daemon":           "Launch daemon",
            "applescript.execution":    "AppleScript execution",
            "quarantine.download":      "Quarantined download",
            "mail.body":                "Mail message body",
            "safari.extension":         "Safari extension",
            "facetime.call":            "FaceTime call record",
            "biome.stream":             "Apple Biome activity",
            "posture.finding":          "Security posture finding",
        ]
        return map[ct] ?? ct.replacingOccurrences(of: ".", with: " · ").capitalized
    }

    /// Heuristic severity by content type. Real severities come
    /// from the posture analyzer (v1.18 finding type).
    private func severityIcon(for a: CommittedArtifact) -> String {
        let ct = a.record.contentType.lowercased()
        if ct.contains("posture") || ct.contains("anomaly") {
            return "exclamationmark.triangle.fill"
        }
        if ct.contains("permission") || ct.contains("launchd") || ct.contains("hosts") {
            return "info.circle.fill"
        }
        return "circle.fill"
    }

    private func severityColor(for a: CommittedArtifact) -> Color {
        let ct = a.record.contentType.lowercased()
        if ct.contains("posture") || ct.contains("anomaly") { return .orange }
        if ct.contains("permission") || ct.contains("launchd") || ct.contains("hosts") { return .blue }
        return .secondary
    }

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
