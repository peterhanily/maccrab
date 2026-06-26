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
import MacCrabCore

struct V2ForensicsScansView: View {
    /// Injected so the Catalog's "Run on this Mac" can route a single-scanner
    /// run through this tab's shared runner + the existing consent gate.
    @ObservedObject var state: V2DashboardState

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
    // Issue #3: the full scanner inventory, sectioned built-in vs third-party.
    @State private var builtinScanners: [PluginManifest] = []
    @State private var thirdPartyScanners: [InstalledPlugin] = []
    @State private var thirdPartyManifests: [String: TierBManifest] = [:]
    @State private var detailModel: PluginDetailModel? = nil   // issue #5: tap a scanner → inspector
    @State private var scanBuiltinShowAll = false
    // Built-in scanners are collapsed by default: the curated kits above are the
    // recommended path and already bundle these, so a flat 30+ list read as
    // duplicative clutter. One click expands the à-la-carte individual scanners.
    @State private var scanBuiltinExpanded = false
    private let scannerPageSize = 8
    @AppStorage("forensics.encryptedKitWarningSeen") private var encryptedWarningSeen = false
    @AppStorage("forensics.fdaBannerDismissed") private var fdaBannerDismissed = false
    // Unified inventory (v1.19.3): manage installed plugins here too (was the
    // separate "My Plugins" tab). Re-verify all + per-plugin uninstall + update.
    @State private var pendingUninstall: String? = nil
    @State private var reverifying = false
    // Update surfacing (v1.19.3): catalog current_version per installed id, so a
    // newer version shows an "Update" pill here, not only in the Catalog tab. The
    // update itself reuses the Catalog's verified consent flow (RaveInstallConsentSheet
    // → bundled maccrabctl install --force). Empty when offline / catalog unreachable.
    @State private var availableVersions: [String: String] = [:]
    @State private var installLink: RaveInstallLink? = nil
    @State private var pendingIsUpdate = false
    @State private var pendingInstalledVersion: String? = nil

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
                    ProgressView(String(localized: "scans.loading", defaultValue: "Loading…"))
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
        // Catalog "Run on this Mac" → run the single scanner here, through the
        // SAME consent gate (runOrConfirm). .task(id:) — NOT onChange — because
        // the catalog sets the intent AND switches tabs, so this view is mounted
        // FRESH with the value already set; onChange never sees a nil→id
        // transition and would silently no-op. .task(id:) fires on mount and on
        // change, covering both.
        .task(id: state.pendingForensicsRunPluginID) {
            await consumePendingRun()
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
        .alert(String(localized: "scans.encryptedScanTitle", defaultValue: "Encrypted scan"),
               isPresented: Binding(
                   get: { pendingEncryptedKit != nil },
                   set: { if !$0 { pendingEncryptedKit = nil } }
               ),
               presenting: pendingEncryptedKit) { kit in
            Button(String(localized: "scans.runScan", defaultValue: "Run scan")) {
                encryptedWarningSeen = true
                let toRun = kit
                pendingEncryptedKit = nil
                Task { await runner.run(toRun) }
            }
            Button(String(localized: "scans.cancel", defaultValue: "Cancel"), role: .cancel) {
                pendingEncryptedKit = nil
            }
        } message: { kit in
            Text(String(localized: "scans.encryptedScanMessage", defaultValue: "This kit collects personal data (messages, mail, call history). MacCrab will store it encrypted on disk and the OS will ask for your Keychain password to unlock the encryption key. You'll only be asked once per session."))
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
            Text(String(localized: "scans.headerTitle", defaultValue: "Forensics"))
                .font(.title2).fontWeight(.semibold)
            Text(String(localized: "scans.headerSubtitle", defaultValue: "Check this Mac for signs of compromise."))
                .scaledSystem(11)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - FDA banner

    private var fdaBanner: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.shield.fill")
                .scaledSystem(18)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text(String(localized: "scans.fdaTitle", defaultValue: "MacCrab doesn't have Full Disk Access"))
                    .scaledSystem(13, weight: .semibold)
                Text(String(localized: "scans.fdaBody", defaultValue: "Most scanners read system databases (Messages, Mail, Safari, TCC, KnowledgeC) that macOS protects behind Full Disk Access. Without it your scans will come back with 'X scanners didn't run' for those entries."))
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button {
                        PermissionsProbe.openSystemSettingsFullDiskAccess()
                    } label: {
                        Label(String(localized: "scans.openSystemSettings", defaultValue: "Open System Settings"), systemImage: "arrow.up.right.square")
                            .scaledSystem(11)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    Button(String(localized: "scans.recheck", defaultValue: "Re-check")) {
                        fdaStatus = PermissionsProbe.fullDiskAccess()
                    }
                    .scaledSystem(11)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    Spacer()
                    Button {
                        fdaBannerDismissed = true
                    } label: {
                        Text(String(localized: "scans.hide", defaultValue: "Hide"))
                            .scaledSystem(10)
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .help(String(localized: "scans.hideBannerHelp", defaultValue: "Don't show this banner again on this Mac"))
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
                Text(String(localized: "scans.recentlyRun", defaultValue: "Recently run")).font(.headline)
                Spacer()
                if scans.count > Self.recentlyRunLimit, onShowAllScans != nil {
                    Button {
                        onShowAllScans?()
                    } label: {
                        Text(String(localized: "scans.seeAllPastScans", defaultValue: "See all \(scans.count) past scans →"))
                            .scaledSystem(11)
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
        VStack(alignment: .leading, spacing: 18) {
            // Recommended kits (the curated headline).
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text(scans.isEmpty ? String(localized: "scans.pickKitToStart", defaultValue: "Pick a kit to start a scan") : String(localized: "scans.runNewScan", defaultValue: "Run a new scan"))
                        .font(.headline)
                    Spacer()
                    Text(String(localized: "scans.kitCount", defaultValue: "\(kits.count) kit\(kits.count == 1 ? "" : "s")"))
                        .scaledSystem(11)
                        .foregroundStyle(.tertiary)
                }
                VStack(spacing: 10) {
                    ForEach(kits, id: \.id) { kit in kitCard(kit) }
                }
            }
            // Individual built-in scanners — collapsed by default (the kits above
            // are the recommended path and bundle these). One click to run any à
            // la carte.
            if !builtinScanners.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) { scanBuiltinExpanded.toggle() }
                    } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Image(systemName: scanBuiltinExpanded ? "chevron.down" : "chevron.right")
                                .scaledSystem(10).foregroundStyle(.secondary)
                            Text(String(localized: "scans.builtinScanners", defaultValue: "Built-in scanners")).font(.headline)
                            Text(String(localized: "scans.builtinScannersHint", defaultValue: "run one individually")).scaledSystem(11).foregroundStyle(.tertiary)
                            Spacer()
                            Text(String(localized: "scans.sectionCount", defaultValue: "\(builtinScanners.count)")).scaledSystem(11).foregroundStyle(.tertiary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    if scanBuiltinExpanded {
                        let shown = scanBuiltinShowAll ? builtinScanners : Array(builtinScanners.prefix(scannerPageSize))
                        VStack(spacing: 6) {
                            ForEach(shown, id: \.id) { m in
                                scannerRow(icon: scannerIcon(m.type), name: m.displayName,
                                           subtitle: scannerSubtitle(m),
                                           badge: nil,
                                           detail: { detailModel = .builtIn(m) }) { Task { await runBuiltinScanner(m) } }
                            }
                            if builtinScanners.count > scannerPageSize {
                                Button(scanBuiltinShowAll ? String(localized: "scans.showFewer", defaultValue: "Show fewer") : String(localized: "scans.showAllBuiltins", defaultValue: "Show all \(builtinScanners.count)")) {
                                    withAnimation(.easeInOut(duration: 0.15)) { scanBuiltinShowAll.toggle() }
                                }
                                .buttonStyle(.plain).scaledSystem(11, weight: .medium).foregroundStyle(.tint).padding(.top, 2)
                            }
                        }
                    }
                }
            }
            if !thirdPartyScanners.isEmpty {
                scannerSection(String(localized: "scans.thirdPartyPlugins", defaultValue: "Installed plugins"), count: thirdPartyScanners.count) {
                    ForEach(thirdPartyScanners, id: \.pluginID) { p in
                        let m = thirdPartyManifests[p.pluginID]
                        let upd = updateAvailable(for: p.pluginID)
                        scannerRow(icon: "puzzlepiece.extension", name: m?.displayName ?? p.pluginID,
                                   subtitle: (m?.description.isEmpty == false ? m!.description : String(localized: "scans.thirdPartyPluginSubtitle", defaultValue: "Installed plugin")),
                                   badge: upd
                                       ? String(localized: "scans.updateBadge", defaultValue: "Update → v\(availableVersions[p.pluginID] ?? "")")
                                       : nil,
                                   provenance: provenance(for: p),
                                   detail: { detailModel = thirdPartyDetail(p) }) { runThirdPartyScanner(p) }
                    }
                    Button { Task { await reverifyAll() } } label: {
                        Label(reverifying
                              ? String(localized: "scans.reverifying", defaultValue: "Re-verifying…")
                              : String(localized: "scans.reverifyAll", defaultValue: "Re-verify all installed"),
                              systemImage: "checkmark.shield")
                    }
                    .buttonStyle(.plain).scaledSystem(11).foregroundStyle(.tint).disabled(reverifying)
                    .padding(.top, 2)
                }
            }
        }
        .sheet(item: $detailModel) { m in
            // Unified Run + manage surface: built-ins run only; installed plugins
            // also expose Verify (re-verify all) + Uninstall (was "My Plugins").
            PluginDetailInspector(
                model: m,
                onRun: m.runnable ? { runScanner(id: m.id) } : nil,
                onVerify: m.provenance != .builtIn ? { Task { await reverifyAll() } } : nil,
                onUpdate: (m.provenance != .builtIn && updateAvailable(for: m.id)) ? { updateAction(m.id) } : nil,
                onUninstall: m.provenance != .builtIn ? { pendingUninstall = m.id } : nil)
        }
        .sheet(item: $installLink) { link in
            // Reuse the Catalog tab's verified consent flow for an in-place update.
            RaveInstallConsentSheet(
                link: link,
                onClose: {
                    installLink = nil
                    pendingIsUpdate = false
                    pendingInstalledVersion = nil
                    Task { await reload() }
                },
                isUpdate: pendingIsUpdate,
                installedVersion: pendingInstalledVersion)
        }
        .confirmationDialog(
            String(localized: "scans.uninstall.confirm", defaultValue: "Uninstall this plugin?"),
            isPresented: Binding(get: { pendingUninstall != nil }, set: { if !$0 { pendingUninstall = nil } }),
            presenting: pendingUninstall
        ) { id in
            Button(String(localized: "scans.uninstall.button", defaultValue: "Uninstall"), role: .destructive) {
                Task { await remove(id); pendingUninstall = nil }
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) { pendingUninstall = nil }
        } message: { id in
            Text(String(localized: "scans.uninstall.message", defaultValue: "\(id) will be removed from this Mac. This cannot be undone."))
        }
    }

    private func reverifyAll() async {
        reverifying = true
        _ = await TierBBootstrap().refresh()
        await reload()
        reverifying = false
    }

    /// True when the signed catalog's current_version for `pluginID` is newer
    /// than the installed manifest version (semver). False when offline, not in
    /// the catalog, or already current.
    private func updateAvailable(for pluginID: String) -> Bool {
        guard let current = availableVersions[pluginID],
              let installed = thirdPartyManifests[pluginID]?.version else { return false }
        // satisfiesFloor(running: installed, floor: current) == false ⇒ installed < current.
        return MacCrabSemverCompare.satisfiesFloor(running: installed, floor: current) == false
    }

    /// Drive the Catalog tab's verified consent flow (RaveInstallConsentSheet →
    /// bundled maccrabctl install --force) for an in-place update.
    private func updateAction(_ pluginID: String) {
        pendingIsUpdate = true
        pendingInstalledVersion = thirdPartyManifests[pluginID]?.version
        detailModel = nil
        installLink = RaveInstallLink(kind: .plugin, id: pluginID)
    }

    private func remove(_ pluginID: String) async {
        try? await PluginInstaller().uninstall(pluginID: pluginID)
        await reload()
    }

    /// Build the third-party detail model (provenance from receipts, "added" date
    /// from the install-root creation time).
    /// Provenance for an installed plugin, catalog-corroborated. The signed
    /// install receipt is authoritative, but it can fail to write on some install
    /// paths — so a trusted plugin whose id is present in the live signed catalog
    /// is classified as Store regardless, instead of mislabeling it Sideloaded.
    private func provenance(for p: InstalledPlugin) -> PluginProvenance {
        let receiptsDir = URL(fileURLWithPath: (PluginInstaller().pluginsRootPath as NSString).deletingLastPathComponent)
            .appendingPathComponent("plugin_receipts")
        let receiptProv = PluginProvenance.forInstalled(pluginID: p.pluginID, receiptsDir: receiptsDir)
        if receiptProv == .store { return .store }
        if availableVersions[p.pluginID] != nil { return .store }  // in the signed catalog
        return receiptProv  // .thirdParty (sideloaded)
    }

    private func thirdPartyDetail(_ p: InstalledPlugin) -> PluginDetailModel {
        let prov = provenance(for: p)
        var installed = String(localized: "scans.installed", defaultValue: "Installed")
        if let attrs = try? FileManager.default.attributesOfItem(atPath: p.installRoot),
           let d = attrs[.creationDate] as? Date {
            let f = DateFormatter(); f.dateStyle = .medium
            installed = String(localized: "scans.addedDate", defaultValue: "Added \(f.string(from: d))")
        }
        return .thirdParty(pluginID: p.pluginID, publicKeyHex: p.publicKeyHex,
                           manifest: thirdPartyManifests[p.pluginID], provenance: prov, installedLabel: installed)
    }

    private func runScanner(id: String) {
        if let bm = builtinScanners.first(where: { $0.id == id }) { Task { await runBuiltinScanner(bm) } }
        else if let p = thirdPartyScanners.first(where: { $0.pluginID == id }) { runThirdPartyScanner(p) }
    }

    private func scannerSection<Content: View>(_ title: String, count: Int, @ViewBuilder _ rows: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.headline)
                Spacer()
                Text(String(localized: "scans.sectionCount", defaultValue: "\(count)")).scaledSystem(11).foregroundStyle(.tertiary)
            }
            VStack(spacing: 6) { rows() }
        }
    }

    private func scannerRow(icon: String, name: String, subtitle: String, badge: String?,
                            provenance: PluginProvenance? = nil,
                            detail: @escaping () -> Void, run: @escaping () -> Void) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).scaledSystem(16).foregroundStyle(.tint)
                .frame(width: 22).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(name).scaledSystem(12, weight: .semibold)
                    if let provenance {
                        let c: Color = provenance == .store ? .blue : (provenance == .builtIn ? .green : .orange)
                        Label(provenance.forensicsLabel, systemImage: provenance.symbolName)
                            .labelStyle(.titleAndIcon)
                            .scaledSystem(9, weight: .semibold)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(c.opacity(0.15)).cornerRadius(3)
                            .foregroundStyle(c)
                            .help(provenance.explanation)
                    }
                    if let badge {
                        Text(badge).scaledSystem(9, weight: .medium)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.secondary.opacity(0.15)).cornerRadius(3)
                            .foregroundStyle(.secondary)
                    }
                }
                Text(subtitle).scaledSystem(10).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            Button(String(localized: "scans.details", defaultValue: "Details"), action: detail).buttonStyle(.bordered).controlSize(.small)
            Button(String(localized: "scans.run", defaultValue: "Run"), action: run).buttonStyle(.borderedProminent).controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor)).cornerRadius(6)
        // UX-7: the explicit Details / Run buttons are the affordances; no
        // invisible whole-row tap (it duplicated Details and was unclear).
    }

    private func scannerSubtitle(_ m: PluginManifest) -> String {
        if let p = ScannerCatalog.fact(forPluginID: m.id)?.purpose { return p }
        if !m.description.isEmpty { return m.description }
        return m.type.rawValue.capitalized
    }

    private func scannerIcon(_ type: PluginType) -> String {
        switch type {
        case .collector:     return "tray.and.arrow.down"
        case .analyzer:      return "magnifyingglass"
        case .enricher:      return "sparkles"
        case .fingerprinter: return "barcode.viewfinder"
        }
    }

    @MainActor private func runBuiltinScanner(_ m: PluginManifest) async {
        guard let reg = await PluginRegistry.shared.registration(forID: m.id) else { return }
        runOrConfirm(Kit.adHoc(pluginID: m.id, name: m.displayName, encrypted: deriveEncrypted(reg)))
    }

    private func runThirdPartyScanner(_ p: InstalledPlugin) {
        let m = thirdPartyManifests[p.pluginID]
        let name = m?.displayName ?? p.pluginID
        let encrypted = (m?.consentSummary().derivedHighestPrivacy ?? "metadata") != "metadata"
        runOrConfirm(Kit.adHoc(pluginID: p.pluginID, name: name, encrypted: encrypted))
    }

    private func kitCard(_ kit: Kit) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: kit.category.sfSymbol)
                .scaledSystem(22)
                .foregroundStyle(.tint)
                .frame(width: 28, alignment: .center)
                .accessibilityHidden(true) // decorative — title text follows
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(kit.name)
                        .scaledSystem(13, weight: .semibold)
                    Text(kit.category.displayName)
                        .scaledSystem(10, weight: .medium)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Color.accentColor.opacity(0.15))
                        .foregroundStyle(.tint)
                        .cornerRadius(3)
                    if kit.encrypted {
                        Label(String(localized: "scans.encrypted", defaultValue: "Encrypted"), systemImage: "lock.fill")
                            .labelStyle(.titleAndIcon)
                            .scaledSystem(10, weight: .medium)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(Color.purple.opacity(0.15))
                            .foregroundStyle(.purple)
                            .cornerRadius(3)
                    }
                }
                Text(kit.description)
                    .scaledSystem(12)
                    .foregroundStyle(.secondary)
                Text(String(localized: "scans.kitScannerCount", defaultValue: "\(kit.plugins.count) scanner\(kit.plugins.count == 1 ? "" : "s")\(kit.encrypted ? " · asks for your Keychain password" : "")"))
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
            }
            Spacer()
            Button {
                detailKit = kit
            } label: {
                Image(systemName: "info.circle")
                    .scaledSystem(14)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help(String(localized: "scans.howKitWorksHelp", defaultValue: "How this kit works"))
            .accessibilityLabel(String(localized: "scans.howKitWorks", defaultValue: "How this kit works"))
            Button {
                runOrConfirm(kit)
            } label: {
                Text(String(localized: "scans.runKit", defaultValue: "Run"))
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
    /// Consume the cross-tab "Run on this Mac" intent (set by the Catalog),
    /// run the single scanner through the existing consent gate, then reset the
    /// intent exactly once (after the work, so resetting it — which restarts the
    /// .task(id:) — can't cancel the run mid-flight). No-op when nothing pends.
    @MainActor
    private func consumePendingRun() async {
        guard let id = state.pendingForensicsRunPluginID else { return }
        guard let reg = await PluginRegistry.shared.registration(forID: id) else {
            state.pendingForensicsRunPluginID = nil
            return
        }
        runOrConfirm(Kit.adHoc(
            pluginID: id,
            name: ScannerDisplay.name(forPluginID: id),
            encrypted: deriveEncrypted(reg)
        ))
        state.pendingForensicsRunPluginID = nil
    }

    /// A single scanner has no `kit.encrypted` flag — derive it from the
    /// manifest output privacy classes. Any non-metadata output means the case
    /// MUST be encrypted (a plaintext case rejects those rows at INSERT,
    /// Pass 2026-D), so the encrypted-scan consent must trigger.
    private func deriveEncrypted(_ reg: PluginRegistration) -> Bool {
        reg.manifest.outputs.contains { $0.privacyClass != .metadata }
    }

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
                        Text(String(localized: "scans.runningKit", defaultValue: "Running \(kitName)…")).scaledSystem(13, weight: .semibold)
                        Spacer()
                        Text(String(localized: "scans.scannerProgress", defaultValue: "Scanner \(completed + 1) / \(total)"))
                            .scaledSystem(11)
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 6) {
                        Image(systemName: "magnifyingglass")
                            .scaledSystem(10)
                            .foregroundStyle(.tint)
                        Text(friendlyScannerName(currentPlugin))
                            .scaledSystem(11, weight: .medium)
                        if rows > 0 {
                            Text(String(localized: "scans.rowsCollected", defaultValue: "· \(rows) row\(rows == 1 ? "" : "s") collected so far"))
                                .scaledSystem(11)
                                .foregroundStyle(.secondary)
                        } else {
                            Text(String(localized: "scans.startingDots", defaultValue: "· starting…"))
                                .scaledSystem(11)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    if let sources = scannerSources(currentPlugin), !sources.isEmpty {
                        Text(String(localized: "scans.reading", defaultValue: "Reading: \(sources.first ?? "")"))
                            .scaledSystem(10)
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
                    Text(String(localized: "scans.startingKit", defaultValue: "Starting \(n)…")).scaledSystem(13)
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
                    .scaledSystem(18)
                VStack(alignment: .leading, spacing: 2) {
                    Text(String(localized: "scans.kitFinished", defaultValue: "\(kitName) finished"))
                        .scaledSystem(13, weight: .semibold)
                    Text(tally.bannerSummary)
                        .scaledSystem(11)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if tally.attention + tally.critical > 0 {
                    Button(String(localized: "scans.openFindings", defaultValue: "Open findings")) {
                        openScanID = scanID
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }
                Button(String(localized: "scans.dismiss", defaultValue: "Dismiss")) {
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
            Text(String(localized: "scans.scannersDidntRun", defaultValue: "\(skipped.count) scanner\(skipped.count == 1 ? "" : "s") didn't run:"))
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(.secondary)
            ForEach(skipped, id: \.pluginID) { s in
                HStack(spacing: 6) {
                    Image(systemName: "minus.circle")
                        .scaledSystem(9)
                        .foregroundStyle(.secondary)
                    Text(friendlyScannerName(s.pluginID))
                        .scaledSystem(10, weight: .medium)
                    Text(String(localized: "scans.skippedReason", defaultValue: "— \(s.reason)"))
                        .scaledSystem(10)
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
                .scaledSystem(18)
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "scans.kitFailed", defaultValue: "\(kitName) failed"))
                    .scaledSystem(13, weight: .semibold)
                Text(err)
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
            Spacer()
            Button(String(localized: "scans.dismissFailed", defaultValue: "Dismiss")) { runner.reset() }
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
        // The full scanner inventory (Issue #3): built-in collectors/analyzers +
        // operator-visible third-party plugins (residue filtered via the shared
        // classifier). Kits stay the recommended headline; these are the
        // individually-runnable scanners.
        let mans = await PluginRegistry.shared.manifests()
        builtinScanners = mans
            .filter { $0.type == .collector || $0.type == .analyzer }
            .sorted { $0.displayName < $1.displayName }
        let builtinIDs = Set(mans.map { $0.id })
        let rawInstalled = (try? await PluginInstaller().list()) ?? []
        // Trusted keys let the visibility filter keep a legit first-party STORE
        // install (com.maccrab.* but not a built-in, e.g. posture-pro) instead of
        // dropping it as impersonation residue — otherwise it has no run row.
        let trustedKeys = await PluginInstaller().currentTrustedKeys()
        // A built-in already appears under "Built-in scanners"; never also list it
        // under "Installed plugins" (the duplication the user saw).
        let visible = OperatorVisibilityFilter.filter(rawInstalled, builtinIDs: builtinIDs, trustedKeyHexes: trustedKeys)
            .filter { !builtinIDs.contains($0.pluginID) }
            .sorted { $0.pluginID < $1.pluginID }
        thirdPartyScanners = visible
        var tpm: [String: TierBManifest] = [:]
        for p in visible {
            if let m = try? TierBManifest.load(fromBundlePath: p.installRoot) { tpm[p.pluginID] = m }
        }
        thirdPartyManifests = tpm
        // v1.19.3: surface "update available" — fetch the signed catalog's
        // current_version per id (best-effort; empty when offline so no badges
        // show). The update itself reuses the Catalog tab's verified consent flow.
        if !visible.isEmpty {
            do {
                var av: [String: String] = [:]
                for e in try await RaveCatalogClient().fetchEntries() { av[e.id] = e.currentVersion }
                availableVersions = av
            } catch {
                availableVersions = [:]
            }
        } else {
            availableVersions = [:]
        }
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
