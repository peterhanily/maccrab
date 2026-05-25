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
    /// Plugin ids that passed signature + revocation verification.
    /// Used to distinguish a verified third-party install from an
    /// unverified sideload at render time.
    @State private var installedVerified: Set<String> = []
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

        // Operator-facing filter: only show plugins that an
        // operator runs explicitly — collectors (things that go
        // look at the Mac) and analyzers (things that produce
        // findings from collected artifacts). Enrichers + finger-
        // printers run as plumbing during the collection pipeline;
        // they're not operator-facing actions.
        let operatorScanners = builtIns.filter { $0.type == .collector }
        let operatorAnalyses = builtIns.filter { $0.type == .analyzer }

        if showBuiltIn {
            sectionHeader("Scanners", subtitle: "What MacCrab can look at on this Mac.")
            if operatorScanners.isEmpty {
                emptyHint("No built-in scanners loaded.")
            } else {
                ForEach(operatorScanners, id: \.id) { m in
                    pluginCard(
                        title: friendlyName(m),
                        description: m.description,
                        badge: "Standard",
                        badgeColor: .green,
                        dataClass: plainEnglishDataClass(m.outputs.first?.privacyClass)
                    )
                }
            }

            if !operatorAnalyses.isEmpty {
                sectionHeader("Analyses", subtitle: "Reports run after a scan finishes.")
                ForEach(operatorAnalyses, id: \.id) { m in
                    pluginCard(
                        title: friendlyName(m),
                        description: m.description,
                        badge: "Standard",
                        badgeColor: .green,
                        dataClass: plainEnglishDataClass(m.outputs.first?.privacyClass)
                    )
                }
            }
        }

        if showInstalled {
            sectionHeader("Installed by you", subtitle: "Third-party scanners you've added.")
            if installed.isEmpty {
                emptyHint("Nothing installed yet. Visit the catalog (rc.4) or install a bundle via the CLI: maccrabctl plugin install <bundle>")
            } else {
                ForEach(installed, id: \.pluginID) { p in
                    let isVerified = installedVerified.contains(p.pluginID)
                    pluginCard(
                        title: friendlyPluginID(p.pluginID),
                        description: "Installed at \(shortenPath(p.installRoot))",
                        badge: isVerified ? "Verified" : "Unverified · Sideloaded",
                        badgeColor: isVerified ? .blue : .orange,
                        dataClass: "—"
                    )
                }
            }
        }

        if showStore {
            sectionHeader("From the catalog", subtitle: "Browse new scanners from maccrab.com/rave.")
            VStack(alignment: .leading, spacing: 6) {
                Text("Catalog browser is on the way.")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Text("v1.17.0-rc.4 wires the catalog fetch + per-plugin install flow. The maccrab.com/rave catalog will list community-published scanners with verified signing identities.")
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                    .padding(.top, 2)
            }
            .padding(.vertical, 4)
        }
    }

    private func emptyHint(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .padding(.vertical, 6)
    }

    /// Replace engineering identifiers like
    /// "com.maccrab.forensics.tcc-lite" with operator-readable
    /// names. Falls back to the manifest's displayName if no
    /// override is registered.
    private func friendlyName(_ m: PluginManifest) -> String {
        let map: [String: String] = [
            "com.maccrab.forensics.tcc-lite":         "Privacy permissions inventory",
            "com.maccrab.forensics.launchd-lite":     "Launch agents + daemons",
            "com.maccrab.forensics.applescript-runtime": "AppleScript runtime activity",
            "com.maccrab.forensics.quarantine":       "Quarantined downloads",
            "com.maccrab.forensics.mail-bodies":      "Mail content (opt-in)",
            "com.maccrab.forensics.safari-lite":      "Safari extensions + state",
            "com.maccrab.forensics.facetime":         "FaceTime call history",
            "com.maccrab.forensics.biome":            "Apple Biome activity streams",
            "com.maccrab.forensics.codesigning-graph": "Code-signing relationships",
            "com.maccrab.forensics.office-analyzer":  "Office document analysis",
            "com.maccrab.forensics.pdf-analyzer":     "PDF document analysis",
            "com.maccrab.forensics.dmg-pkg-analyzer": "DMG / PKG installer analysis",
            "com.maccrab.forensics.archive-analyzer": "Archive contents analysis",
            "com.maccrab.forensics.posture":          "Security posture report",
        ]
        if let nice = map[m.id] { return nice }
        return m.displayName
    }

    /// Turn a reverse-DNS plugin id into the human-recognizable
    /// last segment for third-party plugins.
    /// `com.acme.macops.usb-history` → "USB History (com.acme.macops)"
    private func friendlyPluginID(_ id: String) -> String {
        let parts = id.split(separator: ".")
        guard parts.count >= 2 else { return id }
        let last = parts.last!.replacingOccurrences(of: "-", with: " ")
                              .capitalized
        let publisher = parts.dropLast().joined(separator: ".")
        return "\(last) (\(publisher))"
    }

    private func shortenPath(_ path: String) -> String {
        let home = NSHomeDirectory()
        if path.hasPrefix(home) {
            return "~" + String(path.dropFirst(home.count))
        }
        return path
    }

    private func sectionHeader(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
            Text(subtitle)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
        .padding(.top, 10)
        .padding(.bottom, 2)
    }

    private func pluginCard(
        title: String,
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
                Text(description)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                if dataClass != "—" {
                    Text(dataClass)
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
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
        // Compute which installed plugins pass verification so the
        // card can show "Verified" vs "Unverified · Sideloaded".
        let bootstrap = TierBBootstrap()
        let status = await bootstrap.status(force: false)
        installedVerified = Set(status.verified.map { $0.pluginID })
        loading = false
    }
}
