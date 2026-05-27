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

    @State private var installed: [InstalledPlugin] = []
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
                    installedSection
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
                            .font(.system(size: 12))
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
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Done") { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: - Sections

    private var installedSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Installed scanners",
                          "Third-party scanners you've added via the catalog or local bundle.")
            if loading {
                ProgressView().controlSize(.small)
            } else if installed.isEmpty {
                emptyHint("Nothing installed yet. MacCrab ships with standard scanners built in.")
            } else {
                ForEach(installed, id: \.pluginID) { p in
                    installedRow(p)
                    Divider()
                }
            }
        }
    }

    private func installedRow(_ p: InstalledPlugin) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(friendlyName(p.pluginID))
                    .font(.system(size: 13, weight: .semibold))
                Text("Publisher key: \(p.publicKeyHex.prefix(16))…")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            Button(role: .destructive) {
                Task { await remove(p) }
            } label: {
                Text("Remove")
            }
            .buttonStyle(.borderless)
            .controlSize(.small)
        }
        .padding(.vertical, 4)
    }

    private var trustSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Trusted publishers",
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
        }
    }

    private func keyList(_ keys: [String], tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(keys, id: \.self) { k in
                Text(k)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(tint)
                    .textSelection(.enabled)
                    .padding(.vertical, 2)
            }
        }
    }

    private var maintenanceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Maintenance",
                          "Leftover dev / test scanners detected in your plugins directory.")
            VStack(alignment: .leading, spacing: 6) {
                ForEach(devResidue, id: \.self) { id in
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.system(size: 11))
                        Text(id)
                            .font(.system(size: 12, design: .monospaced))
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
            sectionHeader("On-disk location", "")
            Text(installer.pluginsRootPath)
                .font(.system(size: 11, design: .monospaced))
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
            Text(title).font(.system(size: 13, weight: .semibold))
            if !subtitle.isEmpty {
                Text(subtitle).font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }
    }

    private func emptyHint(_ s: String) -> some View {
        Text(s).font(.system(size: 11)).foregroundStyle(.secondary)
            .padding(.vertical, 4)
    }

    private func friendlyName(_ id: String) -> String {
        ScannerDisplay.name(forPluginID: id)
    }

    // MARK: - Actions

    private func reload() async {
        loading = true
        let allInstalled = (try? await installer.list()) ?? []
        let filtered = OperatorVisibilityFilter.filter(allInstalled)
        installed = filtered
        // Anything that the filter dropped is dev / test residue.
        let visibleIDs = Set(filtered.map { $0.pluginID })
        devResidue = allInstalled
            .map { $0.pluginID }
            .filter { !visibleIDs.contains($0) && !$0.hasSuffix(".json") }
        let trusted = await installer.currentTrustedKeys()
        let revoked = await installer.currentRevokedKeys()
        trustedKeys = Array(trusted).sorted()
        revokedKeys = Array(revoked).sorted()
        loading = false
    }

    private func remove(_ p: InstalledPlugin) async {
        do {
            try await installer.uninstall(pluginID: p.pluginID)
            actionMessage = "Removed \(friendlyName(p.pluginID))."
            await reload()
        } catch {
            actionMessage = "Couldn't remove: \(error)"
        }
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
