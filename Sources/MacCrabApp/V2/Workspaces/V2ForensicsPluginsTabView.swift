// V2ForensicsPluginsTabView.swift
// MacCrabApp — v1.17 Forensics → Plugins (unified).
//
// Per docs/forensics-ia-redesign-plan.md §3.4. Collapses the
// legacy "Forensics · Plugins" (Tier A built-ins) + "Forensics
// · Tier B" (third-party signed) into ONE view with plain-
// English badges. No Tier A / Tier B taxonomy visible to
// operators.
//
// rc.2 ships built-in + installed lists. rc.4 adds the
// "Available in store" tab + browse-store sheet driven by the
// rave catalog at maccrab.com/rave/catalog/.

import SwiftUI
import MacCrabForensics

struct V2ForensicsPluginsTabView: View {
    @State private var builtIns: [PluginManifest] = []
    @State private var installed: [InstalledPlugin] = []
    @State private var tierBStatus: TierBBootstrap.Status? = nil
    @State private var loading = true
    @State private var filter: Filter = .all

    enum Filter: String, CaseIterable, Identifiable {
        case all = "All"
        case builtIn = "Built-in"
        case installed = "Installed"
        case store = "Available in store"
        var id: String { rawValue }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                filterBar
                if loading {
                    ProgressView("Loading plugins…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else {
                    content
                }
            }
            .padding(20)
        }
        .task { await reload() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Plugins")
                    .font(.title2).fontWeight(.semibold)
                Text("What MacCrab can scan; install more from the catalog.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                // rc.4: opens rave store browse sheet.
                // rc.2: hint-only.
            } label: {
                Label("Browse store →", systemImage: "globe")
            }
            .disabled(true)
            .help("Catalog browser lands v1.17.0-rc.4")
        }
    }

    // MARK: - Filter bar

    private var filterBar: some View {
        HStack(spacing: 8) {
            ForEach(Filter.allCases) { f in
                Button {
                    filter = f
                } label: {
                    Text(f.rawValue)
                        .font(.system(size: 11, weight: .medium))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(filter == f ? Color.accentColor.opacity(0.18) : Color.clear)
                        .foregroundColor(filter == f ? .primary : .secondary)
                        .cornerRadius(4)
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        let showBuiltIn = filter == .all || filter == .builtIn
        let showInstalled = filter == .all || filter == .installed
        let showStore = filter == .all || filter == .store
        if showBuiltIn {
            sectionHeader("Built-in")
            if builtIns.isEmpty {
                Text("No built-in plugins.").font(.system(size: 11)).foregroundStyle(.secondary)
            } else {
                ForEach(builtIns, id: \.id) { m in
                    pluginCard(
                        title: m.displayName,
                        id: m.id,
                        description: m.description,
                        badge: "Built-in",
                        badgeColor: .green,
                        dataClass: plainEnglishDataClass(m.outputs.first?.privacyClass)
                    )
                }
            }
        }
        if showInstalled {
            sectionHeader("Installed (third-party)")
            if installed.isEmpty {
                Text("No third-party plugins installed. Drag a .maccrabplugin bundle onto the dashboard (lands v1.18) or run: maccrabctl plugin install <bundle>")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                ForEach(installed, id: \.pluginID) { p in
                    pluginCard(
                        title: p.pluginID,
                        id: "key=" + String(p.publicKeyHex.prefix(16)) + "…",
                        description: "Installed at \(p.installRoot)",
                        badge: tierBStatus?.verified.contains(where: { $0.pluginID == p.pluginID }) == true ? "Verified" : "Sideloaded · Unverified",
                        badgeColor: tierBStatus?.verified.contains(where: { $0.pluginID == p.pluginID }) == true ? .blue : .orange,
                        dataClass: "—"
                    )
                }
            }
        }
        if showStore {
            sectionHeader("Available in store")
            VStack(alignment: .leading, spacing: 6) {
                Text("Store browser lands v1.17.0-rc.4.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Text("The maccrab.com/rave catalog will list verified-community plugins with Sigstore-pinned signing identities. Until then, sideload via `maccrabctl plugin install --local <bundle>`.")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                    .padding(.top, 2)
            }
            .padding(.vertical, 4)
        }
    }

    private func sectionHeader(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.top, 8)
    }

    private func pluginCard(
        title: String,
        id: String,
        description: String,
        badge: String,
        badgeColor: Color,
        dataClass: String
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Text(badge)
                        .font(.system(size: 9, weight: .medium))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(badgeColor.opacity(0.18))
                        .foregroundColor(badgeColor)
                        .cornerRadius(3)
                }
                Text(description).font(.system(size: 11)).foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Text(id)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.tertiary)
                    if dataClass != "—" {
                        Text("· \(dataClass)")
                            .font(.system(size: 10))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            Spacer()
        }
        .padding(10)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }

    // MARK: - Plain-english data class

    private func plainEnglishDataClass(_ pc: PrivacyClass?) -> String {
        switch pc {
        case .none, .metadata?:   return "Metadata only"
        case .content?:           return "Reads file content"
        case .personalComms?:     return "Reads private user data"
        case .credentialAdjacent?: return "Touches credentials"
        case .secret?:            return "Touches secrets"
        }
    }

    // MARK: - Data

    private func reload() async {
        loading = true
        do {
            try await MacCrabForensicsBootstrap.registerBuiltins()
        } catch {
            // Fall through with empty built-ins.
        }
        builtIns = await PluginRegistry.shared.manifests()
        let installer = PluginInstaller()
        installed = (try? await installer.list()) ?? []
        let bootstrap = TierBBootstrap()
        tierBStatus = await bootstrap.status(force: false)
        loading = false
    }
}
