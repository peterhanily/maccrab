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
                ForEach(builtins, id: \.id) { m in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(friendlyName(m.id)).scaledSystem(13, weight: .semibold)
                            Text("\(m.type.rawValue.capitalized) · v\(m.version)")
                                .scaledSystem(10).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        provenanceLabel(.builtIn)
                    }
                    .padding(.vertical, 3)
                    Divider()
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
                ForEach(visibleVerified, id: \.pluginID) { v in
                    installedRow(pluginID: v.pluginID, subtitle: "v\(v.version)",
                                 state: .verified, provenance: v.provenance)
                    Divider()
                }
                ForEach(visibleFailed, id: \.pluginID) { f in
                    installedRow(pluginID: f.pluginID, subtitle: f.reason,
                                 state: .failed, provenance: provenance(for: f.pluginID))
                    Divider()
                }
            }
        }
    }

    private enum RowState { case verified, failed }

    private func installedRow(pluginID: String, subtitle: String, state: RowState, provenance: PluginProvenance) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: state == .verified ? "checkmark.seal.fill" : "xmark.octagon.fill")
                .scaledSystem(12)
                .foregroundStyle(state == .verified ? .green : .red)
            VStack(alignment: .leading, spacing: 3) {
                Text(friendlyName(pluginID)).scaledSystem(13, weight: .semibold)
                Text(subtitle)
                    .scaledSystem(10)
                    .foregroundStyle(state == .verified ? Color.secondary : Color.red)
                    .fixedSize(horizontal: false, vertical: true)
                provenanceLabel(provenance)
            }
            Spacer()
            Button(role: .destructive) {
                Task { await remove(pluginID) }
            } label: {
                Text(String(localized: "myPlugins.remove", defaultValue: "Remove"))
            }
            .buttonStyle(.borderless).controlSize(.small)
        }
        .padding(.vertical, 4)
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
                        Task { await remove(item.pluginID) }
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

    private func provenanceLabel(_ p: PluginProvenance) -> some View {
        Label(p.displayName, systemImage: p.symbolName)
            .scaledSystem(10)
            .foregroundStyle(p == .store ? Color.green : (p == .builtIn ? Color.blue : Color.orange))
    }

    private func provenance(for pluginID: String) -> PluginProvenance {
        let receiptsDir = URL(fileURLWithPath: (installer.pluginsRootPath as NSString).deletingLastPathComponent)
            .appendingPathComponent("plugin_receipts")
        return PluginProvenance.forInstalled(pluginID: pluginID, receiptsDir: receiptsDir)
    }

    // MARK: - Actions

    private func reload() async {
        loading = true
        try? await MacCrabForensicsBootstrap.registerBuiltins()
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
