// V2ForensicsScansView.swift — rc.4 rebuild.
//
// Operator-shaped Scans tab. Kit-driven: empty state shows
// 4 bundled kit cards (IR Quickstart / Phishing Triage /
// Supply Chain Audit / AI Agent Posture). "Run" actually
// runs the kit inline via KitRunner. No CLI dependency.
// No modal-pretending-to-be-a-wizard.

import SwiftUI
import MacCrabForensics

struct V2ForensicsScansView: View {
    @StateObject private var runner = KitRunner()
    @State private var scans: [CaseManifest] = []
    @State private var loading = true
    @State private var kits: [Kit] = []
    @State private var openScanID: String? = nil

    private var openScan: CaseManifest? {
        guard let id = openScanID else { return nil }
        return scans.first { $0.id == id }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if case .running = runner.state {
                    runningCard
                } else if case .done(let scanID, let kitName, let tally) = runner.state {
                    doneCard(scanID: scanID, kitName: kitName, tally: tally)
                } else if case .failed(let kitName, let err) = runner.state {
                    failedCard(kitName: kitName, err: err)
                }
                if loading {
                    ProgressView("Loading…")
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
        .onChange(of: runnerStateID) { _ in
            // Reload past-scans list when a scan finishes so it
            // appears in the timeline.
            if case .done = runner.state {
                Task { await reload() }
            }
        }
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

    // Re-derive a stable Identifier from the runner state so
    // onChange fires.
    private var runnerStateID: String {
        switch runner.state {
        case .idle: return "idle"
        case .starting(let n): return "starting:\(n)"
        case .running(let n, let p, let c, let t): return "running:\(n):\(p):\(c)/\(t)"
        case .done(let id, _, let t):
            return "done:\(id):\(t.routine)/\(t.notable)/\(t.attention)/\(t.critical)"
        case .failed(let n, _): return "failed:\(n)"
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Forensics")
                .font(.title2).fontWeight(.semibold)
            Text("Check this Mac for signs of compromise.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Empty state — kit cards

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("You haven't run a scan yet.")
                .font(.headline)
            Text("Pick what kind of scan to run — each one is shaped for a specific situation.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)

            VStack(spacing: 10) {
                ForEach(kits, id: \.id) { kit in
                    kitCard(kit)
                }
            }
            .padding(.top, 6)
        }
    }

    private func kitCard(_ kit: Kit) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: kit.category.sfSymbol)
                .font(.system(size: 24))
                .foregroundStyle(.tint)
                .frame(width: 32, alignment: .center)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(kit.name)
                        .font(.system(size: 14, weight: .semibold))
                    Text(kit.category.displayName)
                        .font(.system(size: 10, weight: .medium))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.accentColor.opacity(0.15))
                        .foregroundStyle(.tint)
                        .cornerRadius(3)
                }
                Text(kit.description)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Text("\(kit.plugins.count) scanner\(kit.plugins.count == 1 ? "" : "s")")
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
            Spacer()
            Button {
                Task { await runner.run(kit) }
            } label: {
                Text("Run")
                    .frame(minWidth: 60)
            }
            .buttonStyle(.borderedProminent)
            .disabled(isRunnerBusy)
        }
        .padding(14)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var isRunnerBusy: Bool {
        switch runner.state {
        case .starting, .running: return true
        default: return false
        }
    }

    // MARK: - Runner status cards

    private var runningCard: some View {
        Group {
            if case .running(let kitName, let currentPlugin, let completed, let total) = runner.state {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Running \(kitName)…").font(.system(size: 13, weight: .semibold))
                    }
                    Text("Scanner \(completed + 1) of \(total): \(friendlyScannerName(currentPlugin))")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.accentColor.opacity(0.08))
                .cornerRadius(8)
            } else if case .starting(let n) = runner.state {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Starting \(n)…").font(.system(size: 13))
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.accentColor.opacity(0.08))
                .cornerRadius(8)
            }
        }
    }

    private func doneCard(scanID: String, kitName: String, tally: SeverityTally) -> some View {
        let headlineColor: Color = tally.critical > 0 ? .red
            : tally.attention > 0 ? .orange
            : .green
        let bgColor: Color = tally.critical > 0 ? Color.red.opacity(0.10)
            : tally.attention > 0 ? Color.orange.opacity(0.10)
            : Color.green.opacity(0.10)
        let iconName: String = tally.critical > 0 ? "exclamationmark.octagon.fill"
            : tally.attention > 0 ? "exclamationmark.triangle.fill"
            : "checkmark.circle.fill"
        return HStack(spacing: 10) {
            Image(systemName: iconName)
                .foregroundStyle(headlineColor)
                .font(.system(size: 18))
            VStack(alignment: .leading, spacing: 2) {
                Text("\(kitName) finished")
                    .font(.system(size: 13, weight: .semibold))
                Text(tally.bannerSummary)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if tally.attention + tally.critical > 0 {
                Button("Open findings") {
                    openScanID = scanID
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
            Button("Dismiss") {
                runner.reset()
            }
            .buttonStyle(.borderless)
        }
        .padding(12)
        .background(bgColor)
        .cornerRadius(8)
    }

    private func failedCard(kitName: String, err: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.system(size: 18))
            VStack(alignment: .leading, spacing: 2) {
                Text("\(kitName) failed")
                    .font(.system(size: 13, weight: .semibold))
                Text(err)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
            Spacer()
            Button("Dismiss") { runner.reset() }
                .buttonStyle(.borderless)
        }
        .padding(12)
        .background(Color.red.opacity(0.08))
        .cornerRadius(8)
    }

    // MARK: - Non-empty — past scans

    private var scanList: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 14) {
                Text("Past scans")
                    .font(.headline)
                ForEach(scans, id: \.id) { scan in
                    pastScanRow(scan)
                    Divider()
                }
            }
            Text("Run another scan")
                .font(.system(size: 12, weight: .medium))
                .padding(.top, 8)
            VStack(spacing: 8) {
                ForEach(kits, id: \.id) { kit in
                    kitCardCompact(kit)
                }
            }
        }
    }

    private func pastScanRow(_ scan: CaseManifest) -> some View {
        Button {
            openScanID = scan.id
        } label: {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(scan.name)
                        .font(.system(size: 13, weight: .semibold))
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
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func kitCardCompact(_ kit: Kit) -> some View {
        HStack(spacing: 12) {
            Image(systemName: kit.category.sfSymbol)
                .foregroundStyle(.tint)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(kit.name).font(.system(size: 12, weight: .medium))
                Text(kit.description)
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Button("Run") { Task { await runner.run(kit) } }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(isRunnerBusy)
        }
        .padding(8)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }

    // MARK: - Helpers

    private func timeAgo(_ d: Date) -> String {
        let fmt = RelativeDateTimeFormatter()
        fmt.unitsStyle = .full
        return "Started " + fmt.localizedString(for: d, relativeTo: Date())
    }

    private func friendlyScannerName(_ id: String) -> String {
        let map: [String: String] = [
            "com.maccrab.hosts-collector":          "Hosts file baseline",
            "com.maccrab.launch-agents-collector":  "Launch agents inventory",
            "com.maccrab.forensics.tcc-lite":       "Privacy permissions",
            "com.maccrab.forensics.launchd-lite":   "Launch items",
            "com.maccrab.forensics.applescript-runtime": "AppleScript activity",
            "com.maccrab.forensics.quarantine":     "Quarantined downloads",
            "com.maccrab.forensics.posture":        "Security posture",
        ]
        return map[id] ?? id.split(separator: ".").last
            .map { $0.replacingOccurrences(of: "-", with: " ").capitalized } ?? id
    }

    private func reload() async {
        loading = true
        kits = KitLoader.loadBundledKits()
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

