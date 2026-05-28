// V2ForensicsScansView.swift — rc.12 "Run a scan" tab.
//
// Layout top to bottom:
//   1. Header
//   2. FDA banner (only when access is denied)
//   3. Runner status — running / done / failed
//   4. Kit picker (the headline action of this tab)
//   5. Recently run — at most 3 scans, with "See all" link to
//      the Past scans tab
//
// rc.12 split: the full scan archive moved to V2ForensicsPastScansView
// behind a dedicated tab. This view's job is now strictly forward-
// looking: pick what to run, see what's running, peek at what just
// finished.

import SwiftUI
import MacCrabForensics

struct V2ForensicsScansView: View {
    /// Optional jump-to-tab callback supplied by V2ForensicsWorkspace.
    /// Wired to the "See all past scans →" button in the Recently
    /// run section. When nil the link hides.
    var onShowAllScans: (() -> Void)? = nil

    @StateObject private var runner = KitRunner()
    @State private var scans: [CaseManifest] = []
    @State private var loading = true
    @State private var kits: [Kit] = []
    @State private var openScanID: String? = nil
    @State private var pendingEncryptedKit: Kit? = nil
    @State private var detailKit: Kit? = nil
    @State private var fdaStatus: FullDiskAccessStatus = .unknown
    @AppStorage("forensics.encryptedKitWarningSeen") private var encryptedWarningSeen = false
    @AppStorage("forensics.fdaBannerDismissed") private var fdaBannerDismissed = false

    private static let recentlyRunLimit = 3

    private var recentlyRun: [CaseManifest] {
        Array(scans.prefix(Self.recentlyRunLimit))
    }

    private var openScan: CaseManifest? {
        guard let id = openScanID else { return nil }
        return scans.first { $0.id == id }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if fdaStatus == .denied && !fdaBannerDismissed {
                    fdaBanner
                }
                if case .running = runner.state {
                    runningCard
                } else if case .starting = runner.state {
                    runningCard
                } else if case .done(let scanID, let kitName, let tally, let skipped) = runner.state {
                    doneCard(scanID: scanID, kitName: kitName, tally: tally, skipped: skipped)
                } else if case .failed(let kitName, let err) = runner.state {
                    failedCard(kitName: kitName, err: err)
                }
                runNewScanSection
                if loading {
                    ProgressView("Loading…")
                        .frame(maxWidth: .infinity)
                        .padding(20)
                } else if !recentlyRun.isEmpty {
                    recentlyRunSection
                }
            }
            .padding(20)
        }
        .task {
            fdaStatus = PermissionsProbe.fullDiskAccess()
            await reload()
        }
        .onAppear {
            fdaStatus = PermissionsProbe.fullDiskAccess()
        }
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
        .sheet(isPresented: Binding(
            get: { detailKit != nil },
            set: { if !$0 { detailKit = nil } }
        )) {
            if let kit = detailKit {
                V2KitDetailSheet(
                    kit: kit,
                    isPresented: Binding(
                        get: { detailKit != nil },
                        set: { if !$0 { detailKit = nil } }
                    ),
                    onRun: { runOrConfirm(kit) }
                )
            }
        }
    }

    // Re-derive a stable identifier from the runner state so
    // onChange fires.
    private var runnerStateID: String {
        switch runner.state {
        case .idle: return "idle"
        case .starting(let n): return "starting:\(n)"
        case .running(let n, let p, let c, let t, let r): return "running:\(n):\(p):\(c)/\(t):\(r)"
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

    // MARK: - FDA banner

    private var fdaBanner: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 18))
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text("MacCrab doesn't have Full Disk Access")
                    .font(.system(size: 13, weight: .semibold))
                Text("Most scanners read system databases (Messages, Mail, Safari, TCC, KnowledgeC) that macOS protects behind Full Disk Access. Without it your scans will come back with 'X scanners didn't run' for those entries.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button {
                        PermissionsProbe.openSystemSettingsFullDiskAccess()
                    } label: {
                        Label("Open System Settings", systemImage: "arrow.up.right.square")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    Button("Re-check") {
                        fdaStatus = PermissionsProbe.fullDiskAccess()
                    }
                    .font(.system(size: 11))
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    Spacer()
                    Button {
                        fdaBannerDismissed = true
                    } label: {
                        Text("Hide")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .help("Don't show this banner again on this Mac")
                }
                .padding(.top, 4)
            }
        }
        .padding(12)
        .background(Color.orange.opacity(0.10))
        .cornerRadius(8)
    }

    // MARK: - Recently run (max 3)

    private var recentlyRunSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("Recently run").font(.headline)
                Spacer()
                if scans.count > Self.recentlyRunLimit, onShowAllScans != nil {
                    Button {
                        onShowAllScans?()
                    } label: {
                        Text("See all \(scans.count) past scans →")
                            .font(.system(size: 11))
                    }
                    .buttonStyle(.borderless)
                }
            }
            VStack(spacing: 0) {
                ForEach(recentlyRun, id: \.id) { scan in
                    ForensicsScanRow(
                        scan: scan,
                        onOpen: { openScanID = scan.id },
                        onDismiss: {
                            HiddenScans.hide(scan.id)
                            Task { await reload() }
                        }
                    )
                    if scan.id != recentlyRun.last?.id {
                        Divider()
                    }
                }
            }
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
        }
    }

    // MARK: - Run a new scan (kits)

    private var runNewScanSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(scans.isEmpty ? "Pick a kit to start a scan" : "Run a new scan")
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
                detailKit = kit
            } label: {
                Image(systemName: "info.circle")
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("How this kit works")
            Button {
                runOrConfirm(kit)
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

    /// Encrypted-kit confirmation gate: once-per-profile alert
    /// the first time the operator runs a kit that asks for
    /// Keychain access, then direct run thereafter.
    private func runOrConfirm(_ kit: Kit) {
        if kit.encrypted && !encryptedWarningSeen {
            pendingEncryptedKit = kit
        } else {
            Task { await runner.run(kit) }
        }
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
            if case .running(let kitName, let currentPlugin, let completed, let total, let rows) = runner.state {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Running \(kitName)…").font(.system(size: 13, weight: .semibold))
                        Spacer()
                        Text("Scanner \(completed + 1) / \(total)")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass")
                            .font(.system(size: 10))
                            .foregroundStyle(.tint)
                        Text(friendlyScannerName(currentPlugin))
                            .font(.system(size: 11, weight: .medium))
                        if rows > 0 {
                            Text("· \(rows) row\(rows == 1 ? "" : "s") collected so far")
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                        } else {
                            Text("· starting…")
                                .font(.system(size: 11))
                                .foregroundStyle(.tertiary)
                        }
                    }
                    if let sources = scannerSources(currentPlugin), !sources.isEmpty {
                        Text("Reading: \(sources.first ?? "")")
                            .font(.system(size: 10))
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
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

    private func scannerSources(_ pluginID: String) -> [String]? {
        ScannerCatalog.fact(forPluginID: pluginID)?.dataSources
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
