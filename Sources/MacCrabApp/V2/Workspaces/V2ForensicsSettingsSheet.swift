// V2ForensicsSettingsSheet.swift
//
// rc.6 — operator-facing settings for the Forensics platform.
// Opened via the gear icon on the Forensics workspace tab bar.
// Three sections:
//
//   - Installed scanners — third-party plugins the operator
//     has added. Per row: friendly name, publisher key prefix,
//     install date, Remove button.
//
//   - Trust + revocation — read-only view of trusted +
//     revoked publisher keys. Operator can copy a key or open
//     the keys file in Finder. Trust list mutation stays in
//     CLI (`maccrabctl plugin trust|revoke`) — it's a serious
//     action that benefits from explicit terminal context.
//
//   - Maintenance — a button to remove leftover dev / test
//     residue from the plugins directory. Hidden if no
//     residue detected.

import SwiftUI
import MacCrabForensics

struct V2ForensicsSettingsSheet: View {
    @Binding var isPresented: Bool

    @State private var trustedKeys: [String] = []
    @State private var revokedKeys: [String] = []
    @State private var devResidue: [String] = []
    @State private var loading = true
    @State private var actionMessage: String? = nil
    private let installer = PluginInstaller()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    installedPointerSection
                    Divider()
                    trustSection
                    if !devResidue.isEmpty {
                        Divider()
                        maintenanceSection
                    }
                    Divider()
                    pluginsRootSection
                    if let msg = actionMessage {
                        Text(msg)
                            .scaledSystem(12)
                            .foregroundStyle(.secondary)
                            .padding(.top, 6)
                    }
                }
                .padding(20)
            }
        }
        .frame(width: 600, height: 580)
        .task { await reload() }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Forensics settings").font(.headline)
                Text("Manage installed scanners + trusted publishers.")
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Done") { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: - Sections

    /// Installed-scanner management moved to the "Run a scan" tab (richer:
    /// provenance, live re-verify, quarantine, uninstall). This keeps Settings
    /// focused on trust keys + maintenance and avoids two divergent inventory
    /// views. (Modal sheet → informational pointer, not a navigation.)
    private var installedPointerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            sectionHeader(String(localized: "forensicsSettings.installedScanners", defaultValue: "Installed scanners"), "")
            HStack(spacing: 6) {
                Image(systemName: "puzzlepiece.extension").foregroundStyle(.secondary).scaledSystem(12)
                Text("Manage installed scanners — provenance, live re-verify, and uninstall — in the Run a scan tab.")
                    .scaledSystem(11).foregroundStyle(.secondary)
            }
        }
    }

    private var trustSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader(String(localized: "forensicsSettings.trustedPublishers", defaultValue: "Trusted publishers"),
                          "Read-only. Use `maccrabctl plugin trust <key>` or `revoke <key>` to mutate.")
            if trustedKeys.isEmpty && revokedKeys.isEmpty {
                emptyHint("No publisher keys in trust or revocation list.")
            }
            if !trustedKeys.isEmpty {
                DisclosureGroup("Trusted (\(trustedKeys.count))") {
                    keyList(trustedKeys, tint: .blue)
                }
            }
            if !revokedKeys.isEmpty {
                DisclosureGroup("Revoked (\(revokedKeys.count))") {
                    keyList(revokedKeys, tint: .secondary)
                }
            }
            // Revocation-data freshness (C-E staleness ceiling). When stale/never,
            // the runtime reconcile quarantines third-party plugins (self-heal).
            let fresh = Self.revocationFreshnessLine()
            HStack(spacing: 6) {
                Image(systemName: fresh.stale ? "exclamationmark.triangle.fill" : "checkmark.shield")
                    .foregroundStyle(fresh.stale ? .orange : .secondary).scaledSystem(11)
                Text(fresh.text).scaledSystem(11).foregroundStyle(.secondary)
            }
        }
    }

    /// Revocation-data staleness, read from the persisted trust-state clock.
    static func revocationFreshnessLine() -> (text: String, stale: Bool) {
        let store = RaveTrustStateStore.default(supportDir: RevocationReverifyService.defaultSupportDir().path)
        switch store.revocationFreshness() {
        case .never:
            return (String(localized: "forensicsSettings.revocation.never", defaultValue: "Revocation data never fetched — third-party plugins quarantine until verified."), true)
        case .fresh(let age):
            return (String(localized: "forensicsSettings.revocation.fresh", defaultValue: "Revocation data fresh (verified \(Int(age / 3600))h ago)."), false)
        case .stale(let age):
            return (String(localized: "forensicsSettings.revocation.stale", defaultValue: "Revocation data stale (\(Int(age / 86_400))d) — third-party plugins quarantined pending re-verify."), true)
        }
    }

    private func keyList(_ keys: [String], tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(keys, id: \.self) { k in
                Text(k)
                    .scaledSystem(10, design: .monospaced)
                    .foregroundStyle(tint)
                    .textSelection(.enabled)
                    .padding(.vertical, 2)
            }
        }
    }

    private var maintenanceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader(String(localized: "forensicsSettings.maintenance", defaultValue: "Maintenance"),
                          "Leftover dev / test scanners detected in your plugins directory.")
            VStack(alignment: .leading, spacing: 6) {
                ForEach(devResidue, id: \.self) { id in
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .scaledSystem(11)
                        Text(id)
                            .scaledSystem(12, design: .monospaced)
                            .foregroundStyle(.secondary)
                    }
                }
                Button(role: .destructive) {
                    Task { await cleanupResidue() }
                } label: {
                    Label("Remove all dev / test scanners", systemImage: "trash")
                }
                .padding(.top, 4)
            }
            .padding(10)
            .background(Color.orange.opacity(0.08))
            .cornerRadius(6)
        }
    }

    private var pluginsRootSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            sectionHeader(String(localized: "forensicsSettings.onDiskLocation", defaultValue: "On-disk location"), "")
            Text(installer.pluginsRootPath)
                .scaledSystem(11, design: .monospaced)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Button("Open in Finder") {
                NSWorkspace.shared.open(URL(fileURLWithPath: installer.pluginsRootPath))
            }
            .controlSize(.small)
        }
    }

    // MARK: - Helpers

    private func sectionHeader(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).scaledSystem(13, weight: .semibold)
            if !subtitle.isEmpty {
                Text(subtitle).scaledSystem(11).foregroundStyle(.secondary)
            }
        }
    }

    private func emptyHint(_ s: String) -> some View {
        Text(s).scaledSystem(11).foregroundStyle(.secondary)
            .padding(.vertical, 4)
    }

    // MARK: - Actions

    private func reload() async {
        loading = true
        let allInstalled = (try? await installer.list()) ?? []
        // Removable residue = exactly what the shared classifier hides (decoupled
        // from the display filter), minus .json trust files we must not uninstall.
        let builtinIDs = Set(await PluginRegistry.shared.manifests().map { $0.id })
        devResidue = allInstalled
            .map { $0.pluginID }
            .filter { OperatorVisibilityFilter.isResidue(pluginID: $0, builtinIDs: builtinIDs) && !$0.hasSuffix(".json") }
        let trusted = await installer.currentTrustedKeys()
        let revoked = await installer.currentRevokedKeys()
        trustedKeys = Array(trusted).sorted()
        revokedKeys = Array(revoked).sorted()
        loading = false
    }

    private func cleanupResidue() async {
        var removed = 0
        for id in devResidue {
            if (try? await installer.uninstall(pluginID: id)) != nil {
                removed += 1
            }
        }
        actionMessage = "Removed \(removed) dev / test scanner\(removed == 1 ? "" : "s")."
        await reload()
    }
}
