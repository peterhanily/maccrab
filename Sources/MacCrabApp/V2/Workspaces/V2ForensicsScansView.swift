// V2ForensicsScansView.swift — rc.9 reordered.
//
// Layout from top to bottom:
//   1. Header
//   2. Active runner banner (if any)
//   3. Past scans (most recent first) — each row has a per-row
//      dismiss action that hides it via HiddenScans
//   4. "Run a new scan" — kit cards
//
// rc.9 changes vs rc.8:
//   - Past scans surface ABOVE the kit picker (operator sees
//     what they already did before being asked what to start)
//   - Per-row dismiss via context menu + hover button
//   - Single source of truth for kit cards (no duplicate render
//     in empty-state vs scan-list state)

import SwiftUI
import MacCrabForensics

struct V2ForensicsScansView: View {
    @StateObject private var runner = KitRunner()
    @State private var scans: [CaseManifest] = []
    @State private var loading = true
    @State private var kits: [Kit] = []
    @State private var openScanID: String? = nil
    @State private var pendingEncryptedKit: Kit? = nil
    @AppStorage("forensics.encryptedKitWarningSeen") private var encryptedWarningSeen = false

    private var openScan: CaseManifest? {
        guard let id = openScanID else { return nil }
        return scans.first { $0.id == id }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if case .running = runner.state {
                    runningCard
                } else if case .starting = runner.state {
                    runningCard
                } else if case .done(let scanID, let kitName, let tally, let skipped) = runner.state {
                    doneCard(scanID: scanID, kitName: kitName, tally: tally, skipped: skipped)
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
                    pastScansSection
                }
                runNewScanSection
            }
            .padding(20)
        }
        .task { await reload() }
        .onChange(of: runnerStateID) { _ in
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
        .alert("Encrypted scan",
               isPresented: Binding(
                   get: { pendingEncryptedKit != nil },
                   set: { if !$0 { pendingEncryptedKit = nil } }
               ),
               presenting: pendingEncryptedKit) { kit in
            Button("Run scan") {
                encryptedWarningSeen = true
                let toRun = kit
                pendingEncryptedKit = nil
                Task { await runner.run(toRun) }
            }
            Button("Cancel", role: .cancel) {
                pendingEncryptedKit = nil
            }
        } message: { kit in
            Text("This kit collects personal data (messages, mail, call history). MacCrab will store it encrypted on disk and the OS will ask for your Keychain password to unlock the encryption key. You'll only be asked once per session.")
        }
    }

    // Re-derive a stable identifier from the runner state so
    // onChange fires.
    private var runnerStateID: String {
        switch runner.state {
        case .idle: return "idle"
        case .starting(let n): return "starting:\(n)"
        case .running(let n, let p, let c, let t): return "running:\(n):\(p):\(c)/\(t)"
        case .done(let id, _, let t, let s):
            return "done:\(id):\(t.routine)/\(t.notable)/\(t.attention)/\(t.critical):\(s.count)"
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

    // MARK: - Empty state (no past scans)

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("You haven't run a scan yet.")
                .font(.headline)
            Text("Pick what kind of scan to run below — each one is shaped for a specific situation.")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .padding(.top, 4)
    }

    // MARK: - Past scans

    private var pastScansSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("Past scans").font(.headline)
                Spacer()
                Text("\(scans.count) total")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }
            VStack(spacing: 0) {
                ForEach(scans, id: \.id) { scan in
                    pastScanRow(scan)
                    if scan.id != scans.last?.id {
                        Divider()
                    }
                }
            }
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
        }
    }

    private func pastScanRow(_ scan: CaseManifest) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Button {
                openScanID = scan.id
            } label: {
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
                Button {
                    openScanID = scan.id
                } label: {
                    Label("Open", systemImage: "eye")
                }
                Divider()
                Button(role: .destructive) {
                    HiddenScans.hide(scan.id)
                    Task { await reload() }
                } label: {
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
            Button {
                openScanID = scan.id
            } label: {
                Label("Open", systemImage: "eye")
            }
            Button(role: .destructive) {
                HiddenScans.hide(scan.id)
                Task { await reload() }
            } label: {
                Label("Dismiss from list", systemImage: "eye.slash")
            }
        }
    }

    // MARK: - Run a new scan (kits)

    private var runNewScanSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(scans.isEmpty ? "Start a scan" : "Run a new scan")
                    .font(.headline)
                Spacer()
                Text("\(kits.count) kit\(kits.count == 1 ? "" : "s")")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }
            VStack(spacing: 10) {
                ForEach(kits, id: \.id) { kit in
                    kitCard(kit)
                }
            }
        }
    }

    private func kitCard(_ kit: Kit) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: kit.category.sfSymbol)
                .font(.system(size: 22))
                .foregroundStyle(.tint)
                .frame(width: 28, alignment: .center)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(kit.name)
                        .font(.system(size: 13, weight: .semibold))
                    Text(kit.category.displayName)
                        .font(.system(size: 10, weight: .medium))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Color.accentColor.opacity(0.15))
                        .foregroundStyle(.tint)
                        .cornerRadius(3)
                    if kit.encrypted {
                        Label("Encrypted", systemImage: "lock.fill")
                            .labelStyle(.titleAndIcon)
                            .font(.system(size: 10, weight: .medium))
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Color.purple.opacity(0.15))
                            .foregroundStyle(.purple)
                            .cornerRadius(3)
                    }
                }
                Text(kit.description)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Text("\(kit.plugins.count) scanner\(kit.plugins.count == 1 ? "" : "s")\(kit.encrypted ? " · asks for your Keychain password" : "")")
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)
            }
            Spacer()
            Button {
                if kit.encrypted && !encryptedWarningSeen {
                    pendingEncryptedKit = kit
                } else {
                    Task { await runner.run(kit) }
                }
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

    private func doneCard(scanID: String, kitName: String, tally: SeverityTally, skipped: [KitRunner.SkippedPlugin]) -> some View {
        let headlineColor: Color = tally.critical > 0 ? .red
            : tally.attention > 0 ? .orange
            : .green
        let bgColor: Color = tally.critical > 0 ? Color.red.opacity(0.10)
            : tally.attention > 0 ? Color.orange.opacity(0.10)
            : Color.green.opacity(0.10)
        let iconName: String = tally.critical > 0 ? "exclamationmark.octagon.fill"
            : tally.attention > 0 ? "exclamationmark.triangle.fill"
            : "checkmark.circle.fill"
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
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
            if !skipped.isEmpty {
                skippedList(skipped)
            }
        }
        .padding(12)
        .background(bgColor)
        .cornerRadius(8)
    }

    private func skippedList(_ skipped: [KitRunner.SkippedPlugin]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(skipped.count) scanner\(skipped.count == 1 ? "" : "s") didn't run:")
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(.secondary)
            ForEach(skipped, id: \.pluginID) { s in
                HStack(spacing: 6) {
                    Image(systemName: "minus.circle")
                        .font(.system(size: 9))
                        .foregroundStyle(.secondary)
                    Text(friendlyScannerName(s.pluginID))
                        .font(.system(size: 10, weight: .medium))
                    Text("— \(s.reason)")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
        }
        .padding(.leading, 28)
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

    // MARK: - Helpers

    private func timeAgo(_ d: Date) -> String {
        let fmt = RelativeDateTimeFormatter()
        fmt.unitsStyle = .full
        return "Started " + fmt.localizedString(for: d, relativeTo: Date())
    }

    private func friendlyScannerName(_ id: String) -> String {
        ScannerDisplay.name(forPluginID: id)
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
