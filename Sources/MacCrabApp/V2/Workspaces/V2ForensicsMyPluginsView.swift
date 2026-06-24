// V2ForensicsMyPluginsView.swift
//
// P5 — the "My Plugins" lifecycle console (5th Forensics tab). The inventory
// home: what scanners this Mac has, where each came from (built-in vs
// third-party vs store), their live verification state, and uninstall.
//
// Surfaces already-built engine plumbing — nothing here re-implements trust:
//   - Built-in (Tier A) scanners        → PluginRegistry.shared.manifests()
//   - Installed (Tier B) verify state   → TierBBootstrap.status()/refresh()
//     (verified / failed / quarantined buckets, green / red / amber)
//   - Provenance badge                  → PluginProvenance.forInstalled(...)
//   - Uninstall                         → PluginInstaller.uninstall(pluginID:)
// "Re-verify all" runs the real signature re-check (TierBBootstrap.refresh,
// which cleans up verified temp binaries internally), so the row state is
// always the true current state — never optimistic-green.

import SwiftUI
import MacCrabForensics

/// PERF-4: registerBuiltins is idempotent (id-keyed) but re-validates ~35
/// built-in manifests on every call. The shared registry persists for the life
/// of the process, so run the bootstrap at most ONCE rather than on every
/// dashboard reload. Internal (not private) so other workspaces that read the
/// registry — e.g. the Overview forensics card — can guarantee it's populated
/// before counting without re-validating per tick.
actor BuiltinBootstrapOnce {
    static let shared = BuiltinBootstrapOnce()
    private var done = false
    func ensure() async {
        guard !done else { return }
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        done = true
    }
}

struct V2ForensicsMyPluginsView: View {
    @State private var builtins: [PluginManifest] = []
    @State private var status: TierBBootstrap.Status? = nil
    /// Tier-B ids that survive the operator-visibility filter (drops dev/test
    /// residue) — the status buckets are intersected with this so bogus rows
    /// never render.
    @State private var visibleInstalledIDs: Set<String> = []
    @State private var loading = true
    @State private var reverifying = false
    @State private var actionMessage: String? = nil
    @State private var detailModel: PluginDetailModel? = nil   // issue #5: tap a plugin → inspector
    @State private var pendingUninstall: String? = nil          // UX-5: confirm before uninstall
    @State private var builtinShowAll = false                   // pagination in the built-in section
    private let builtinPageSize = 8

    private let installer = PluginInstaller()
    private let bootstrap = TierBBootstrap()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if loading {
                        ProgressView().controlSize(.small).padding(.vertical, 40)
                            .frame(maxWidth: .infinity)
                    } else {
                        builtInSection
                        Divider()
                        installedSection
                        let q = visibleQuarantined
                        if !q.isEmpty {
                            Divider()
                            quarantineSection(q)
                        }
                    }
                    if let msg = actionMessage {
                        Text(msg).scaledSystem(12).foregroundStyle(.secondary).padding(.top, 4)
                    }
                }
                .padding(20)
            }
        }
        .task { await reload() }
        .sheet(item: $detailModel) { PluginDetailInspector(model: $0) }
        .confirmationDialog(
            String(localized: "myPlugins.confirmRemove.title", defaultValue: "Remove this plugin?"),
            isPresented: Binding(get: { pendingUninstall != nil },
                                 set: { if !$0 { pendingUninstall = nil } }),
            presenting: pendingUninstall
        ) { id in
            Button(String(localized: "myPlugins.remove", defaultValue: "Remove"), role: .destructive) {
                Task { await remove(id) }
                pendingUninstall = nil
            }
            Button(String(localized: "common.cancel", defaultValue: "Cancel"), role: .cancel) {
                pendingUninstall = nil
            }
        } message: { id in
            Text(String(localized: "myPlugins.confirmRemove.message",
                        defaultValue: "\(friendlyName(id)) will be uninstalled. This cannot be undone."))
        }
    }

    /// Detail model for an installed (verified) plugin — manifest from its bundle,
    /// "added" date from the install-root creation time.
    private func verifiedDetail(_ v: TierBBootstrap.VerifiedSummary) -> PluginDetailModel {
        var installed = "Installed"
        if let attrs = try? FileManager.default.attributesOfItem(atPath: v.bundleRoot),
           let d = attrs[.creationDate] as? Date {
            let f = DateFormatter(); f.dateStyle = .medium
            installed = "Added \(f.string(from: d))"
        }
        return .thirdParty(pluginID: v.pluginID, publicKeyHex: v.publicKeyHex,
                           manifest: try? TierBManifest.load(fromBundlePath: v.bundleRoot),
                           provenance: v.provenance, installedLabel: installed)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "puzzlepiece.extension.fill")
                .scaledSystem(22).foregroundStyle(.tint)
                .padding(8).background(Color.accentColor.opacity(0.12)).cornerRadius(8)
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "myPlugins.title", defaultValue: "My plugins")).font(.title2).fontWeight(.semibold)
                Text(String(localized: "myPlugins.subtitle", defaultValue: "Scanners installed on this Mac, where they came from, and their verification state."))
                    .scaledSystem(11).foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await reverify() }
            } label: {
                if reverifying {
                    ProgressView().controlSize(.small)
                } else {
                    Label(String(localized: "myPlugins.reverifyAll", defaultValue: "Re-verify all"), systemImage: "checkmark.shield")
                }
            }
            .disabled(reverifying)
            .help(String(localized: "myPlugins.reverifyAll.help", defaultValue: "Re-check every installed plugin's signature against the pinned keys."))
        }
        .padding(.horizontal, 20).padding(.vertical, 16)
    }

    // MARK: - Built-in (Tier A)

    private var builtInSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(String(localized: "myPlugins.builtin.header", defaultValue: "Built-in scanners (\(builtins.count))"),
                          String(localized: "myPlugins.builtin.subtitle", defaultValue: "Ship with MacCrab — always available, signed into the app."))
            if builtins.isEmpty {
                emptyHint(String(localized: "myPlugins.builtin.empty", defaultValue: "No built-in scanners registered."))
            } else {
                let shown = builtinShowAll ? builtins : Array(builtins.prefix(builtinPageSize))
                VStack(spacing: 5) {
                    ForEach(shown, id: \.id) { m in
                        pluginRow(name: friendlyName(m.id),
                                  subtitle: scannerSubtitle(m),
                                  icon: scannerIcon(m.type), iconColor: .blue,
                                  remove: nil) { detailModel = .builtIn(m) }
                    }
                }
                if builtins.count > builtinPageSize {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) { builtinShowAll.toggle() }
                    } label: {
                        Text(builtinShowAll
                             ? String(localized: "myPlugins.showFewer", defaultValue: "Show fewer")
                             : String(localized: "myPlugins.showAll", defaultValue: "Show all \(builtins.count)"))
                            .scaledSystem(11, weight: .medium)
                    }
                    .buttonStyle(.plain).foregroundStyle(.tint).padding(.top, 2)
                }
            }
        }
    }

    // MARK: - Installed (Tier B)

    private var visibleVerified: [TierBBootstrap.VerifiedSummary] {
        (status?.verified ?? []).filter { visibleInstalledIDs.contains($0.pluginID) }
    }
    private var visibleFailed: [TierBBootstrap.FailedSummary] {
        (status?.failed ?? []).filter { visibleInstalledIDs.contains($0.pluginID) }
    }
    private var visibleQuarantined: [TierBBootstrap.QuarantinedSummary] {
        (status?.quarantined ?? []).filter { visibleInstalledIDs.contains($0.pluginID) }
    }

    private var installedSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(String(localized: "myPlugins.installed.header", defaultValue: "Installed plugins (\(visibleVerified.count + visibleFailed.count))"),
                          String(localized: "myPlugins.installed.subtitle", defaultValue: "Added via the catalog or a local bundle. Re-verify checks their signatures live."))
            if visibleVerified.isEmpty && visibleFailed.isEmpty {
                emptyHint(String(localized: "myPlugins.installed.empty", defaultValue: "Nothing installed yet. MacCrab ships with the built-in scanners above."))
            } else {
                VStack(spacing: 5) {
                    ForEach(visibleVerified, id: \.pluginID) { v in
                        pluginRow(name: friendlyName(v.pluginID),
                                  subtitle: "Verified · v\(v.version) · \(v.provenance.displayName)",
                                  icon: "checkmark.seal.fill", iconColor: .green,
                                  remove: { pendingUninstall = v.pluginID }) { detailModel = verifiedDetail(v) }
                    }
                    ForEach(visibleFailed, id: \.pluginID) { f in
                        pluginRow(name: friendlyName(f.pluginID),
                                  subtitle: "Failed · \(f.reason)",
                                  icon: "xmark.octagon.fill", iconColor: .red,
                                  remove: { pendingUninstall = f.pluginID }, detail: nil)
                    }
                }
            }
        }
    }

    /// Dense, clear plugin row with explicit Details / Remove buttons (UX-7
    /// removed the invisible whole-row tap — buttons are the only affordance).
    /// `detail` nil → no Details button (failed installs);
    /// `remove` nil → no Remove button (built-ins).
    private func pluginRow(name: String, subtitle: String, icon: String, iconColor: Color,
                           remove: (() -> Void)?, detail: (() -> Void)?) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon).scaledSystem(13).foregroundStyle(iconColor)
                .frame(width: 18).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).scaledSystem(12, weight: .semibold).lineLimit(1)
                Text(subtitle).scaledSystem(10).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            if let detail {
                Button(String(localized: "myPlugins.details", defaultValue: "Details"), action: detail)
                    .buttonStyle(.bordered)
            }
            if let remove {
                Button(role: .destructive, action: remove) {
                    Text(String(localized: "myPlugins.remove", defaultValue: "Remove"))
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.6))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        // UX-7: no whole-row tap — the explicit Details/Remove buttons are the
        // affordances (the invisible row tap was unclear + double with Details).
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

    // MARK: - Quarantine

    private func quarantineSection(_ q: [TierBBootstrap.QuarantinedSummary]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(String(localized: "myPlugins.quarantined.header", defaultValue: "Quarantined (\(q.count))"),
                          String(localized: "myPlugins.quarantined.subtitle", defaultValue: "Revoked or failed verification — held, not run. Remove to clear."))
            ForEach(q, id: \.pluginID) { item in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.octagon.fill")
                        .scaledSystem(12).foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(friendlyName(item.pluginID)).scaledSystem(13, weight: .semibold)
                        Text("\(item.reason) (\(item.code)) · v\(item.installedVersion)")
                            .scaledSystem(10).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        if let url = item.advisoryURL, let u = URL(string: url) {
                            Link(String(localized: "myPlugins.advisory", defaultValue: "Advisory"), destination: u).scaledSystem(10)
                        }
                    }
                    Spacer()
                    Button(role: .destructive) {
                        pendingUninstall = item.pluginID
                    } label: { Text(String(localized: "myPlugins.remove", defaultValue: "Remove")) }
                    .buttonStyle(.borderless).controlSize(.small)
                }
                .padding(.vertical, 4)
                Divider()
            }
        }
    }

    // MARK: - Helpers

    private func sectionHeader(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).scaledSystem(13, weight: .semibold)
            Text(subtitle).scaledSystem(10).foregroundStyle(.secondary)
        }
    }

    private func emptyHint(_ text: String) -> some View {
        Text(text).scaledSystem(11).foregroundStyle(.tertiary).padding(.vertical, 4)
    }

    private func friendlyName(_ id: String) -> String { ScannerDisplay.name(forPluginID: id) }

    // MARK: - Actions

    private func reload() async {
        loading = true
        await BuiltinBootstrapOnce.shared.ensure()   // PERF-4: bootstrap at most once per process
        builtins = await PluginRegistry.shared.manifests()
            .filter { $0.type == .collector || $0.type == .analyzer }
            .sorted { friendlyName($0.id) < friendlyName($1.id) }
        // Real installed set → operator-visibility filter → the id allowlist the
        // status buckets are intersected with.
        let allInstalled = (try? await installer.list()) ?? []
        visibleInstalledIDs = Set(OperatorVisibilityFilter.filter(allInstalled).map(\.pluginID))
        status = await bootstrap.status()
        loading = false
    }

    private func reverify() async {
        reverifying = true
        status = await bootstrap.refresh()
        reverifying = false
        actionMessage = String(localized: "myPlugins.action.reverified", defaultValue: "Re-verified: \(visibleVerified.count) ok, \(visibleFailed.count) failed.")
    }

    private func remove(_ pluginID: String) async {
        do {
            try await installer.uninstall(pluginID: pluginID)
            actionMessage = String(localized: "myPlugins.action.removed", defaultValue: "Removed \(friendlyName(pluginID)).")
            await reload()
        } catch {
            actionMessage = String(localized: "myPlugins.action.removeFailed", defaultValue: "Couldn't remove: \(error.localizedDescription)")
        }
    }
}
