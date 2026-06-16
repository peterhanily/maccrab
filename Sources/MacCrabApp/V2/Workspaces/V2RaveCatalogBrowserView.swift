// V2RaveCatalogBrowserView.swift — rc.9 in-workspace catalog panel.
//
// Bambu-Studio-shape browse experience, now mounted as the third
// Forensics tab (Scans / Findings / Catalog) instead of a buried
// Settings sheet.
//
// Layout:
//   - Hero header with catalog source + refresh
//   - Left sidebar: All / Featured / Categories
//   - Center grid: plugin cards with icon + name + tags
//   - Right detail panel when a card is selected: description,
//     install command
//
// Source data is RaveCatalogClient (Ed25519-verified fetch).
// Rich fields (icon URL, screenshots, long description) are
// optional per the rave catalog schema — we degrade to a
// monogram icon + the description that is in the manifest.

import SwiftUI
import Foundation

struct V2RaveCatalogBrowserView: View {
    @State private var entries: [RaveCatalogEntry] = []
    /// Per-entry resolved install state (trust badges + install-pill gating),
    /// keyed by plugin id. Computed once per reload from the verified index +
    /// revocation list so the UI never re-runs policy on every redraw.
    @State private var stateByID: [String: RaveCatalogEntryState] = [:]
    @State private var loading = true
    @State private var error: String? = nil
    @State private var baseURL: String = ""
    @State private var selectedID: String? = nil
    @State private var selectedCategory: String? = nil  // nil = All
    @State private var showFeaturedOnly = false
    @State private var usingOfficial: Bool = true
    /// S4-X2: the verified install path. Selecting Install presents the SAME
    /// consent sheet the maccrab://install handler drives (resolve-from-pinned-
    /// catalog → version-floor → consent → verified hand-off). nil = no sheet.
    @State private var installLink: RaveInstallLink? = nil

    private let client = RaveCatalogClient()

    private var categories: [String] {
        let set = Set(entries.compactMap { $0.category })
        return set.sorted()
    }

    private var visibleEntries: [RaveCatalogEntry] {
        entries.filter { e in
            if showFeaturedOnly, e.trustTier != "first-party" { return false }
            if let cat = selectedCategory, e.category != cat { return false }
            return true
        }
    }

    private var selectedEntry: RaveCatalogEntry? {
        entries.first { $0.id == selectedID }
    }

    /// Resolved state for an entry, defaulting to a fail-closed
    /// "awaiting signed binary" when (for any reason) we haven't computed one.
    private func state(for entry: RaveCatalogEntry) -> RaveCatalogEntryState {
        stateByID[entry.id] ?? RaveCatalogEntryState(
            entry: entry,
            installability: .awaitingSignedBinary,
            isRevoked: false,
            revocationReason: nil
        )
    }

    var body: some View {
        liveCatalog
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var liveCatalog: some View {
        VStack(spacing: 0) {
            if loading || error != nil || entries.isEmpty {
                // Offline / empty / first-load: the branded ComingSoon panel is
                // the honest fallback when the catalog isn't reachable yet.
                ComingSoonCatalogView()
            } else {
                header
                if !usingOfficial {
                    nonOfficialBanner
                }
                Divider()
                HStack(spacing: 0) {
                    sidebar
                    Divider()
                    grid
                    Divider()
                    detailPanel
                }
            }
        }
        .task { await reload() }
        .sheet(item: $installLink) { link in
            RaveInstallConsentSheet(link: link) { installLink = nil }
        }
    }

    // MARK: - Header

    private var nonOfficialBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .scaledSystem(12)
            VStack(alignment: .leading, spacing: 1) {
                Text("Using a non-official catalog")
                    .scaledSystem(11, weight: .semibold)
                Text("Source: \(baseURL.isEmpty ? "(unknown)" : baseURL) · plugins fetched here haven't been vetted by the official rave team. Use only for local development + testing.")
                    .scaledSystem(10)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            Button("Settings") {
                if let url = URL(string: "maccrab://settings/forensics") {
                    NSWorkspace.shared.open(url)
                }
            }
            .scaledSystem(11)
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(.horizontal, 20).padding(.vertical, 8)
        .background(Color.orange.opacity(0.12))
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shippingbox.fill")
                .scaledSystem(22)
                .foregroundStyle(.tint)
                .padding(8)
                .background(Color.accentColor.opacity(0.12))
                .cornerRadius(8)
            VStack(alignment: .leading, spacing: 2) {
                Text("Plugin catalog")
                    .font(.title2).fontWeight(.semibold)
                Text(baseURL.isEmpty ? "rave.maccrab.com" : baseURL)
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                Task { await reload() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Refresh")
        }
        .padding(.horizontal, 20).padding(.vertical, 16)
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 4) {
            sidebarHeader("Browse")
            sidebarRow("All scanners",
                       icon: "square.grid.2x2",
                       isSelected: selectedCategory == nil && !showFeaturedOnly,
                       count: entries.count) {
                selectedCategory = nil
                showFeaturedOnly = false
            }
            sidebarRow("Featured (first-party)",
                       icon: "sparkles",
                       isSelected: showFeaturedOnly,
                       count: entries.filter { $0.trustTier == "first-party" }.count) {
                showFeaturedOnly.toggle()
                if showFeaturedOnly { selectedCategory = nil }
            }
            if !categories.isEmpty {
                sidebarHeader("Categories").padding(.top, 16)
                ForEach(categories, id: \.self) { cat in
                    sidebarRow(cat.capitalized,
                               icon: categoryIcon(cat),
                               isSelected: selectedCategory == cat,
                               count: entries.filter { $0.category == cat }.count) {
                        selectedCategory = (selectedCategory == cat) ? nil : cat
                        showFeaturedOnly = false
                    }
                }
            }
            Spacer()
        }
        .padding(14)
        .frame(width: 220)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }

    private func sidebarHeader(_ s: String) -> some View {
        Text(s)
            .scaledSystem(10, weight: .semibold)
            .foregroundStyle(.tertiary)
            .textCase(.uppercase)
            .padding(.bottom, 4)
    }

    private func sidebarRow(_ label: String, icon: String, isSelected: Bool, count: Int, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .scaledSystem(11)
                    .frame(width: 14)
                Text(label).scaledSystem(12)
                Spacer()
                Text("\(count)")
                    .scaledSystem(10)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(isSelected ? Color.accentColor.opacity(0.15) : Color.clear)
            .foregroundStyle(isSelected ? Color.accentColor : .primary)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Grid

    private var grid: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 220, maximum: 280), spacing: 14)], spacing: 14) {
                ForEach(visibleEntries, id: \.id) { e in
                    catalogCard(e)
                }
            }
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func catalogCard(_ e: RaveCatalogEntry) -> some View {
        Button {
            selectedID = e.id
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                ZStack {
                    Rectangle()
                        .fill(LinearGradient(
                            colors: [colorFor(category: e.category), colorFor(category: e.category).opacity(0.6)],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        ))
                        .frame(height: 80)
                    Text(monogram(e.id))
                        .scaledSystem(32, weight: .bold, design: .rounded)
                        .foregroundStyle(.white)
                }
                .cornerRadius(6)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(friendlyName(e.id))
                            .scaledSystem(13, weight: .semibold)
                            .lineLimit(1)
                        trustBadge(e.trustTier)
                    }
                    if let cat = e.category {
                        Text(cat.capitalized)
                            .scaledSystem(10)
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 5) {
                        Text("v\(e.currentVersion)")
                            .scaledSystem(10)
                            .foregroundStyle(.tertiary)
                        statusBadge(state(for: e))
                    }
                }
            }
            .padding(10)
            .background(Color(NSColor.controlBackgroundColor))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(selectedID == e.id ? Color.accentColor : Color.clear, lineWidth: 2)
            )
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Detail panel

    private var detailPanel: some View {
        Group {
            if let e = selectedEntry {
                detailContent(e)
            } else {
                placeholderDetail
            }
        }
        .frame(width: 320)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }

    private var placeholderDetail: some View {
        VStack(spacing: 8) {
            Image(systemName: "arrow.left.circle")
                .scaledSystem(30)
                .foregroundStyle(.tertiary)
            Text("Select a scanner")
                .scaledSystem(13, weight: .medium)
                .foregroundStyle(.secondary)
            Text("Click a card on the left to see what it does + how to install.")
                .scaledSystem(11)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func detailContent(_ e: RaveCatalogEntry) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ZStack {
                    Rectangle()
                        .fill(LinearGradient(
                            colors: [colorFor(category: e.category), colorFor(category: e.category).opacity(0.6)],
                            startPoint: .topLeading, endPoint: .bottomTrailing
                        ))
                        .frame(height: 120)
                    Text(monogram(e.id))
                        .scaledSystem(48, weight: .bold, design: .rounded)
                        .foregroundStyle(.white)
                }
                .cornerRadius(8)

                VStack(alignment: .leading, spacing: 6) {
                    Text(friendlyName(e.id))
                        .font(.headline)
                    HStack(spacing: 6) {
                        trustBadge(e.trustTier)
                        channelBadge(e.channel)
                        statusBadge(state(for: e))
                    }
                    Text(e.id)
                        .scaledSystem(10, design: .monospaced)
                        .foregroundStyle(.tertiary)
                        .textSelection(.enabled)
                }

                Divider()
                detailSection(String(localized: "raveDetail.whatItDoes", defaultValue: "What it does"), body: longDescription(e))
                if !e.tags.isEmpty {
                    detailSection(String(localized: "raveDetail.tags", defaultValue: "Tags"), view: tagWrap(e.tags))
                }
                detailSection(String(localized: "raveDetail.version", defaultValue: "Version"), body: "v\(e.currentVersion)")
                if let min = e.minMaccrabVersion {
                    detailSection(String(localized: "raveDetail.requires", defaultValue: "Requires"), body: "MacCrab v\(min) or newer")
                }
                detailSection(String(localized: "raveDetail.signedBy", defaultValue: "Signed by"), body: e.signerIdentity.isEmpty ? "—" : e.signerIdentity)
                trustStateRow(state(for: e))

                Divider()
                installAction(e)
            }
            .padding(18)
        }
    }

    private func detailSection<V: View>(_ title: String, view: V) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).scaledSystem(10, weight: .semibold)
                .foregroundStyle(.tertiary).textCase(.uppercase)
            view
        }
    }

    private func detailSection(_ title: String, body: String) -> some View {
        detailSection(title, view: Text(body).scaledSystem(12))
    }

    private func tagWrap(_ tags: [String]) -> some View {
        FlowLayout(spacing: 4) {
            ForEach(tags, id: \.self) { t in
                Text(t)
                    .scaledSystem(10)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.12))
                    .cornerRadius(3)
            }
        }
    }

    /// Install action — drives the SAME verified path the maccrab://install
    /// deep-link handler uses. The pill is only LIVE for an entry whose state
    /// resolves to `.installable` (real operator-signed binary + version-floor
    /// passes + not revoked). Everything else shows status, not a live pill —
    /// the dashboard never fakes an install.
    private func installAction(_ e: RaveCatalogEntry) -> some View {
        let st = state(for: e)
        return VStack(alignment: .leading, spacing: 6) {
            Text("Install")
                .scaledSystem(10, weight: .semibold)
                .foregroundStyle(.tertiary).textCase(.uppercase)
            if st.showsInstallPill {
                Button {
                    // Construct the id-only install link and let the SAME
                    // consent flow the URL handler uses resolve it from the
                    // pinned catalog (signer pin + version floor + consent +
                    // receipt). No bypass: this only OPENS the verified path.
                    installLink = RaveInstallLink(kind: .plugin, id: e.id)
                } label: {
                    Label("Install", systemImage: "checkmark.shield")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                Text("Opens the verified install path: signer-pin + version-floor checks, then your explicit confirmation.")
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
            } else {
                // Disabled placeholder pill + the honest reason.
                Button {} label: {
                    Label(disabledPillLabel(st), systemImage: disabledPillIcon(st))
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(true)
                if let reason = st.disabledReason {
                    Text(reason)
                        .scaledSystem(10)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private func disabledPillLabel(_ st: RaveCatalogEntryState) -> String {
        switch st.installability {
        case .installable:            return "Install"
        case .awaitingSignedBinary:   return "Operator-signed binary required"
        case .preRelease:             return "Pre-release"
        case .versionFloorBlocked:    return "Unavailable on this MacCrab"
        case .revoked:                return "Revoked"
        case .impersonation:          return "Impersonation — refused"
        }
    }

    private func disabledPillIcon(_ st: RaveCatalogEntryState) -> String {
        switch st.installability {
        case .installable:            return "checkmark.shield"
        case .awaitingSignedBinary:   return "hourglass"
        case .preRelease:             return "clock.badge"
        case .versionFloorBlocked:    return "exclamationmark.triangle"
        case .revoked:                return "xmark.octagon"
        case .impersonation:          return "exclamationmark.shield"
        }
    }

    /// Compact badge for cards + detail header reflecting install state.
    @ViewBuilder
    private func statusBadge(_ st: RaveCatalogEntryState) -> some View {
        switch st.installability {
        case .installable:
            if st.isSignerPinned {
                badge("Pinned", icon: "checkmark.shield.fill", color: .green)
            }
        case .awaitingSignedBinary:
            badge("Coming soon", icon: "hourglass", color: .secondary)
        case .preRelease:
            badge("Pre-release", icon: "clock.badge", color: .orange)
        case .versionFloorBlocked:
            badge("Needs newer MacCrab", icon: "exclamationmark.triangle.fill", color: .orange)
        case .revoked:
            badge("Revoked", icon: "xmark.octagon.fill", color: .red)
        case .impersonation:
            badge("Impersonation", icon: "exclamationmark.shield.fill", color: .red)
        }
    }

    private func badge(_ label: String, icon: String, color: Color) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).scaledSystem(8)
            Text(label).scaledSystem(9, weight: .medium)
        }
        .padding(.horizontal, 5).padding(.vertical, 1)
        .background(color.opacity(0.16))
        .foregroundStyle(color)
        .cornerRadius(3)
    }

    /// Trust-state detail row: signer-pin status + (when blocked/revoked) the
    /// reason. Shown in the detail panel under "Signed by".
    @ViewBuilder
    private func trustStateRow(_ st: RaveCatalogEntryState) -> some View {
        detailSection("Trust state", view: VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 5) {
                Image(systemName: st.isSignerPinned ? "checkmark.shield.fill" : "shield.slash")
                    .scaledSystem(10)
                    .foregroundStyle(st.isSignerPinned ? Color.green : Color.secondary)
                Text(st.isSignerPinned ? "Publisher key pinned" : "Publisher key not yet pinned")
                    .scaledSystem(11)
            }
            if let reason = st.disabledReason {
                Text(reason)
                    .scaledSystem(10)
                    .foregroundStyle(st.isRevoked ? Color.red : Color.secondary)
            }
        })
    }

    // MARK: - Helpers

    private func trustBadge(_ tier: String) -> some View {
        let (label, color): (String, Color) = {
            switch tier {
            case "first-party":         return ("First-party", .green)
            case "verified-community":  return ("Verified", .blue)
            default:                    return ("Unverified", .orange)
            }
        }()
        return Text(label)
            .scaledSystem(9, weight: .medium)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color.opacity(0.18))
            .foregroundStyle(color)
            .cornerRadius(3)
    }

    private func channelBadge(_ ch: String) -> some View {
        Text(ch.capitalized)
            .scaledSystem(9)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(Color.secondary.opacity(0.12))
            .cornerRadius(3)
    }

    private func friendlyName(_ id: String) -> String {
        ScannerDisplay.name(forPluginID: id)
    }

    private func longDescription(_ e: RaveCatalogEntry) -> String {
        // Detail panel text — manifest descriptions live in the
        // plugin manifests once those land in the catalog; for
        // now the friendly name is enough until the rave catalog
        // emits descriptions in its JSON.
        return "\(friendlyName(e.id)) — \(e.category ?? "scanner") published via the rave catalog. Install via the command shown below to add it to this Mac's scanner registry; from there it'll appear in any kit that references its id."
    }

    private func monogram(_ id: String) -> String {
        // Use the last meaningful segment + first letter.
        let parts = id.split(separator: ".")
        guard let last = parts.last else { return "?" }
        let words = last.split(separator: "-")
        if words.count >= 2 {
            return String(words[0].prefix(1) + words[1].prefix(1)).uppercased()
        }
        return String(last.prefix(2)).uppercased()
    }

    private func colorFor(category: String?) -> Color {
        switch category ?? "" {
        case "collector":  return .blue
        case "analyzer":   return .purple
        case "enricher":   return .teal
        case "fingerprinter": return .indigo
        default:           return .accentColor
        }
    }

    private func categoryIcon(_ cat: String) -> String {
        switch cat {
        case "collector":     return "tray.and.arrow.down"
        case "analyzer":      return "chart.bar"
        case "enricher":      return "wand.and.stars"
        case "fingerprinter": return "barcode.viewfinder"
        default:              return "square.grid.2x2"
        }
    }

    // MARK: - Load

    private func reload() async {
        loading = true
        error = nil
        baseURL = await client.baseURL.absoluteString
        usingOfficial = await client.isUsingOfficialSource
        do {
            let fetched = try await client.fetchEntries()

            // Best-effort load of the signed revocation list so revoked
            // entries are badged + their install pills withheld. A failure
            // here (offline / not-yet-published) is non-fatal: the catalog
            // still renders, and the per-entry signer-pin + version-floor
            // gates still apply. fetchAndReconcileRevocations is fail-closed
            // on a BAD signature (throws) — that's the safe outcome.
            let revocations = try? await client.fetchAndReconcileRevocations()

            var states: [String: RaveCatalogEntryState] = [:]
            states.reserveCapacity(fetched.count)
            for e in fetched {
                states[e.id] = RaveCatalogEntryState.compute(
                    entry: e,
                    revocations: revocations,
                    floorCheck: client.checkVersionFloor   // nonisolated, shared policy
                )
            }

            entries = fetched
            stateByID = states
            if selectedID == nil { selectedID = entries.first?.id }
        } catch {
            self.error = "\(error)"
            entries = []
            stateByID = [:]
        }
        loading = false
    }
}

// MARK: - FlowLayout

/// Lightweight wrap layout for tag chips. Lays out children
/// left-to-right, wrapping when out of horizontal space.
struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var lineHeight: CGFloat = 0
        for sv in subviews {
            let size = sv.sizeThatFits(.unspecified)
            if x + size.width > maxWidth {
                x = 0
                y += lineHeight + spacing
                lineHeight = 0
            }
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
        return CGSize(width: maxWidth, height: y + lineHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var lineHeight: CGFloat = 0
        for sv in subviews {
            let size = sv.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX {
                x = bounds.minX
                y += lineHeight + spacing
                lineHeight = 0
            }
            sv.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
    }
}

// MARK: - Coming soon (first-release catalog gate)

/// One cell of the pixel crab — (x, y, w, h) in a 16-wide grid, same
/// scheme the maccrab.com favicon / og-image crab is drawn with.
private struct RaveCrabPixel { let x, y, w, h: CGFloat; let color: Color }

private let raveCrabOrange = Color(red: 1.0,  green: 0.369, blue: 0.227) // #ff5e3a
private let raveNeonCyan   = Color(red: 0.18, green: 0.90,  blue: 1.0)   // #2ee6ff
private let raveNeonPink   = Color(red: 1.0,  green: 0.24,  blue: 0.65)  // #ff3ea5
private let raveNeonGold   = Color(red: 1.0,  green: 0.82,  blue: 0.23)  // #ffd23a
private let raveFrameDark  = Color(red: 0.04, green: 0.04,  blue: 0.05)  // #0a0a0b

/// The maccrab pixel crab body — kept identical to the maccrab.com
/// artwork so it reads as the same character, just dressed for the rave.
private let raveCrabBody: [RaveCrabPixel] = [
    RaveCrabPixel(x: 1, y: 1, w: 3, h: 3, color: raveCrabOrange),
    RaveCrabPixel(x: 0, y: 2, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 4, y: 2, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 2, y: 4, w: 2, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 12, y: 1, w: 3, h: 3, color: raveCrabOrange),
    RaveCrabPixel(x: 11, y: 2, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 15, y: 2, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 12, y: 4, w: 2, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 6, y: 4, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 9, y: 4, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 4, y: 5, w: 8, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 3, y: 6, w: 10, h: 3, color: raveCrabOrange),
    RaveCrabPixel(x: 4, y: 9, w: 8, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 2, y: 10, w: 1, h: 2, color: raveCrabOrange),
    RaveCrabPixel(x: 5, y: 10, w: 1, h: 2, color: raveCrabOrange),
    RaveCrabPixel(x: 10, y: 10, w: 1, h: 2, color: raveCrabOrange),
    RaveCrabPixel(x: 13, y: 10, w: 1, h: 2, color: raveCrabOrange),
    RaveCrabPixel(x: 1, y: 12, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 4, y: 12, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 11, y: 12, w: 1, h: 1, color: raveCrabOrange),
    RaveCrabPixel(x: 14, y: 12, w: 1, h: 1, color: raveCrabOrange),
]

/// Neon rave shades over the crab's eyes (replaces the plain pixels).
private let raveCrabShades: [RaveCrabPixel] = [
    RaveCrabPixel(x: 4,  y: 6, w: 1, h: 1, color: raveFrameDark),
    RaveCrabPixel(x: 5,  y: 6, w: 2, h: 1, color: raveNeonCyan),
    RaveCrabPixel(x: 7,  y: 6, w: 2, h: 1, color: raveFrameDark),
    RaveCrabPixel(x: 9,  y: 6, w: 2, h: 1, color: raveNeonPink),
    RaveCrabPixel(x: 11, y: 6, w: 1, h: 1, color: raveFrameDark),
]

/// Pixel-art crab in the maccrab.com style, wearing neon rave shades,
/// dancing (vertical bob) under twinkling lights with a pulsing glow.
/// Drawn natively so it stays crisp at any size and needs no asset.
private struct RaveCrabView: View {
    var body: some View {
        TimelineView(.animation) { timeline in
            let t = timeline.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                let cols: CGFloat = 16, rows: CGFloat = 13
                let s = min(size.width / cols, size.height / rows)
                let originX = (size.width - cols * s) / 2
                let originY = (size.height - rows * s) / 2
                let bob = CGFloat(sin(t * 2.4)) * s * 0.5   // dance

                // Soft orange glow behind the crab (pulsing).
                let glowR = cols * s * 0.55
                let cx = originX + cols * s / 2
                let cy = originY + rows * s / 2 + bob
                let glowPulse = 0.5 + 0.5 * sin(t * 1.7)
                ctx.fill(
                    Path(ellipseIn: CGRect(x: cx - glowR, y: cy - glowR, width: glowR * 2, height: glowR * 2)),
                    with: .radialGradient(
                        Gradient(colors: [raveCrabOrange.opacity(0.28 * (0.6 + 0.4 * glowPulse)),
                                          raveCrabOrange.opacity(0)]),
                        center: CGPoint(x: cx, y: cy), startRadius: 0, endRadius: glowR))

                func draw(_ pixels: [RaveCrabPixel], dy: CGFloat) {
                    for p in pixels {
                        let r = CGRect(x: originX + p.x * s, y: originY + p.y * s + dy,
                                       width: p.w * s, height: p.h * s)
                        ctx.fill(Path(r), with: .color(p.color))
                    }
                }
                draw(raveCrabBody, dy: bob)
                draw(raveCrabShades, dy: bob)

                // Twinkling rave lights (fixed — they're the room, not the crab).
                let lights: [(x: CGFloat, y: CGFloat, color: Color, phase: Double)] = [
                    (8, 0, raveNeonGold, 0.0), (1, 1, raveNeonCyan, 1.3), (14, 1, raveNeonPink, 2.1),
                    (3, 0, raveNeonPink, 0.7), (13, 0, raveNeonCyan, 1.9),
                ]
                for l in lights {
                    let tw = 0.35 + 0.65 * (0.5 + 0.5 * sin(t * 4 + l.phase))
                    ctx.fill(Path(CGRect(x: originX + l.x * s, y: originY + l.y * s, width: s, height: s)),
                             with: .color(l.color.opacity(tw)))
                }
            }
        }
        .accessibilityHidden(true)
    }
}

/// First-release stand-in for the catalog tab: an intentional, branded
/// "coming soon" in the maccrab.com dark/orange palette, instead of an
/// error-toned "catalog not reachable" panel.
private struct ComingSoonCatalogView: View {
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.04, green: 0.04, blue: 0.043),
                         Color(red: 0.10, green: 0.055, blue: 0.031)],
                startPoint: .topLeading, endPoint: .bottomTrailing)

            VStack(spacing: 18) {
                RaveCrabView()
                    .frame(width: 180, height: 150)
                VStack(spacing: 8) {
                    Text("Rave catalog")
                        .scaledSystem(12, weight: .semibold)
                        .tracking(2)
                        .foregroundStyle(raveCrabOrange)
                    Text("Coming soon")
                        .scaledSystem(30, weight: .bold)
                        .foregroundStyle(Color(red: 0.957, green: 0.957, blue: 0.961)) // #f4f4f5
                    Text("A signed, vetted catalog of forensic plugins you'll browse and install right from MacCrab. We're polishing it for launch — your existing scanners and kits keep working in the meantime.")
                        .scaledSystem(13)
                        .foregroundStyle(Color(red: 0.63, green: 0.63, blue: 0.67)) // #a1a1aa
                        .multilineTextAlignment(.center)
                        .lineSpacing(2)
                        .frame(maxWidth: 430)
                }
            }
            .padding(40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
