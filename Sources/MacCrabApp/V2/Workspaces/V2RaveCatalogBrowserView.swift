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
import MacCrabCore
import MacCrabForensics

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
    /// Phase-0 honest catalog states. Set on each reload so the pane can tell
    /// loading / offline / trust-failure / verified-but-empty / live apart, and
    /// surface the trust the verified fetch already earns (serial + revocation
    /// freshness) instead of collapsing everything to one "Coming Soon" panel.
    @State private var errorIsTrust = false
    @State private var lastGoodFetch: Date? = nil
    @State private var catalogSerial: Int? = nil
    @State private var revFreshness: RaveRevocationFreshness? = nil
    /// Phase-1 discovery + lifecycle. Search/sort over the offered entries, and
    /// the locally-installed plugin id -> version map so cards show Installed /
    /// Update-available state.
    @State private var searchText = ""
    @State private var sortMode: SortMode = .name
    @State private var installedByID: [String: String] = [:]

    private enum SortMode: CaseIterable, Hashable {
        case name, category, firstPartyFirst
        var label: String {
            switch self {
            case .name:            return "Name (A–Z)"
            case .category:        return "Category"
            case .firstPartyFirst: return "First-party first"
            }
        }
    }

    private let client = RaveCatalogClient()

    private var categories: [String] {
        let set = Set(offeredEntries.compactMap { $0.category })
        return set.sorted()
    }

    /// Only entries the store actually offers — status == "active", mirroring the
    /// website's go-live filter (maccrab-rave site/build.sh). Pre-release /
    /// placeholder / not-yet-signed entries are NOT shown as available apps; when
    /// none are active the browser falls back to the ComingSoon panel. This is a
    /// DISPLAY filter only — it does not touch any signature / serial /
    /// installability trust gate (the install path still fail-closes on its own).
    private var offeredEntries: [RaveCatalogEntry] {
        RaveCatalogClient.offeredEntries(entries)
    }

    private var visibleEntries: [RaveCatalogEntry] {
        let filtered = offeredEntries.filter { e in
            if showFeaturedOnly, e.trustTier != "first-party" { return false }
            if let cat = selectedCategory, e.category != cat { return false }
            if !matchesSearch(e) { return false }
            return true
        }
        return sortEntries(filtered)
    }

    private func matchesSearch(_ e: RaveCatalogEntry) -> Bool {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return true }
        let hay = ([friendlyName(e.id), e.id, e.category ?? ""] + e.tags)
            .joined(separator: " ").lowercased()
        return hay.contains(q)
    }

    private func sortEntries(_ list: [RaveCatalogEntry]) -> [RaveCatalogEntry] {
        switch sortMode {
        case .name:
            return list.sorted {
                friendlyName($0.id).localizedCaseInsensitiveCompare(friendlyName($1.id)) == .orderedAscending
            }
        case .category:
            return list.sorted {
                let ca = $0.category ?? "~", cb = $1.category ?? "~"
                if ca != cb { return ca < cb }
                return friendlyName($0.id).localizedCaseInsensitiveCompare(friendlyName($1.id)) == .orderedAscending
            }
        case .firstPartyFirst:
            return list.sorted {
                let fa = $0.trustTier == "first-party" ? 0 : 1
                let fb = $1.trustTier == "first-party" ? 0 : 1
                if fa != fb { return fa < fb }
                return friendlyName($0.id).localizedCaseInsensitiveCompare(friendlyName($1.id)) == .orderedAscending
            }
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
            // Distinct honest states instead of one catch-all "Coming Soon":
            // loading, unreachable (offline), trust-failure (signature/freshness
            // refused — the SAFE outcome), verified-but-empty (catalog signed &
            // verified on this Mac, just no active plugins yet), and the live store.
            switch paneState {
            case .loading:       loadingPane
            case .offline:       offlinePane
            case .trustError:    trustErrorPane
            case .verifiedEmpty: verifiedEmptyPane
            case .live:          liveStore
            }
        }
        .task { await reload() }
        .sheet(item: $installLink) { link in
            RaveInstallConsentSheet(link: link) { installLink = nil }
        }
    }

    private enum PaneState { case loading, offline, trustError, verifiedEmpty, live }

    private var paneState: PaneState {
        if loading { return .loading }
        if error != nil { return errorIsTrust ? .trustError : .offline }
        return offeredEntries.isEmpty ? .verifiedEmpty : .live
    }

    /// The live store chrome (header + sidebar + grid + detail) — shown only
    /// once the catalog verified AND offers at least one active plugin.
    private var liveStore: some View {
        VStack(spacing: 0) {
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
            VStack(alignment: .leading, spacing: 4) {
                Text("Plugin catalog")
                    .font(.title2).fontWeight(.semibold)
                Text(baseURL.isEmpty ? "rave.maccrab.com" : baseURL)
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
                trustStrip
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

    // MARK: - Honest catalog panes (Phase 0)

    /// Shared dark/orange branded backdrop for the non-live catalog panes, so
    /// loading / offline / trust-failure / coming-soon stay visually coherent
    /// in the maccrab.com rave palette.
    private func ravePane<C: View>(@ViewBuilder _ content: () -> C) -> some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.04, green: 0.04, blue: 0.043),
                         Color(red: 0.10, green: 0.055, blue: 0.031)],
                startPoint: .topLeading, endPoint: .bottomTrailing)
            VStack(spacing: 16) { content() }
                .padding(40)
                .frame(maxWidth: 460)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var paneTitleColor: Color { Color(red: 0.957, green: 0.957, blue: 0.961) }   // #f4f4f5
    private var paneSubtitleColor: Color { Color(red: 0.63, green: 0.63, blue: 0.67) }    // #a1a1aa

    private var loadingPane: some View {
        ravePane {
            RaveCrabView().frame(width: 150, height: 125)
            ProgressView().controlSize(.small).tint(raveCrabOrange)
            Text("Checking the signed catalog…")
                .scaledSystem(13)
                .foregroundStyle(paneSubtitleColor)
        }
    }

    private var offlinePane: some View {
        ravePane {
            RaveCrabView().frame(width: 150, height: 125)
            Text("Rave catalog")
                .scaledSystem(12, weight: .semibold).tracking(2)
                .foregroundStyle(raveCrabOrange)
            Text("Can't reach the catalog")
                .scaledSystem(26, weight: .bold)
                .foregroundStyle(paneTitleColor)
            Text(offlineDetailText)
                .scaledSystem(13)
                .foregroundStyle(paneSubtitleColor)
                .multilineTextAlignment(.center)
                .lineSpacing(2)
            Button { Task { await reload() } } label: {
                Label("Retry", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent).tint(raveCrabOrange).controlSize(.large)
        }
    }

    private var trustErrorPane: some View {
        ravePane {
            Image(systemName: "lock.shield.fill")
                .scaledSystem(46)
                .foregroundStyle(raveCrabOrange)
            Text("Rave catalog")
                .scaledSystem(12, weight: .semibold).tracking(2)
                .foregroundStyle(raveCrabOrange)
            Text("Catalog failed verification")
                .scaledSystem(24, weight: .bold)
                .foregroundStyle(paneTitleColor)
            Text("MacCrab refused to show it — the catalog's signature or freshness check didn't pass, so nothing from it is trusted or installable. This is the safe outcome, not a bug. Your installed scanners and kits keep working.")
                .scaledSystem(13)
                .foregroundStyle(paneSubtitleColor)
                .multilineTextAlignment(.center)
                .lineSpacing(2)
            if let error {
                Text(error)
                    .scaledSystem(10, design: .monospaced)
                    .foregroundStyle(paneSubtitleColor.opacity(0.85))
                    .multilineTextAlignment(.center)
                    .lineLimit(4)
                    .textSelection(.enabled)
            }
            Button { Task { await reload() } } label: {
                Label("Try again", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent).tint(raveCrabOrange).controlSize(.large)
        }
    }

    private var verifiedEmptyPane: some View {
        ravePane {
            RaveCrabView().frame(width: 180, height: 150)
            Text("Rave catalog")
                .scaledSystem(12, weight: .semibold).tracking(2)
                .foregroundStyle(raveCrabOrange)
            Text("Coming soon")
                .scaledSystem(30, weight: .bold)
                .foregroundStyle(paneTitleColor)
            Text("A signed, vetted catalog of forensic plugins you'll browse and install right from MacCrab. The catalog is verified on this Mac — we're putting the finishing touches on the first plugins. Your existing scanners and kits keep working in the meantime.")
                .scaledSystem(13)
                .foregroundStyle(paneSubtitleColor)
                .multilineTextAlignment(.center)
                .lineSpacing(2)
            trustStrip
            Button {
                if let url = URL(string: "https://rave.maccrab.com/") {
                    NSWorkspace.shared.open(url)
                }
            } label: {
                Label("Preview on rave.maccrab.com", systemImage: "safari")
            }
            .buttonStyle(.bordered).tint(raveCrabOrange).controlSize(.small)
        }
    }

    // MARK: - Trust strip (surfaces the verification the fetch already earns)

    /// Compact "Signed & verified · serial N · revocations fresh" strip, shown in
    /// the live header AND the coming-soon pane so the trust the client enforces
    /// (Ed25519 verify + anti-rollback serial + revocation freshness) is visible,
    /// not silent. Semantic colors so it reads on the light header + dark panes.
    @ViewBuilder
    private var trustStrip: some View {
        HStack(spacing: 6) {
            trustChip("Signed & verified", icon: "checkmark.seal.fill", color: .green)
            if let s = catalogSerial {
                trustChip("serial \(s)", icon: "number", color: .secondary)
            }
            freshnessChip
        }
    }

    @ViewBuilder
    private var freshnessChip: some View {
        switch revFreshness {
        case .fresh:
            trustChip("revocations fresh", icon: "clock.badge.checkmark", color: .green)
        case .stale:
            trustChip("revocations stale", icon: "clock.badge.exclamationmark", color: .orange)
        case .never, .none:
            trustChip("revocations: pending", icon: "clock", color: .secondary)
        }
    }

    private func trustChip(_ text: String, icon: String, color: Color) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).scaledSystem(8)
            Text(text).scaledSystem(9, weight: .medium)
        }
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(color.opacity(0.16))
        .foregroundStyle(color)
        .cornerRadius(4)
    }

    private var offlineDetailText: String {
        let host = URL(string: baseURL)?.host ?? "the catalog"
        if let when = lastGoodFetch {
            let f = RelativeDateTimeFormatter()
            return "We couldn't reach \(host). Last verified \(f.localizedString(for: when, relativeTo: Date()))."
        }
        return "We couldn't reach \(host). Check your connection and try again."
    }

    /// Classify a fetch failure: a signature / parse / freshness-rollback failure
    /// is a TRUST refusal (the safe outcome → security-toned pane); a reachability
    /// / network failure is "offline". (Per-entry version-floor + config errors
    /// aren't surfaced here.)
    private static func isTrustError(_ error: Error) -> Bool {
        guard let e = error as? RaveCatalogError else { return false }
        switch e {
        case .signatureMismatch, .parseFailed, .noCatalogKey,
             .catalogRollback, .catalogSerialMissing,
             .revocationsSignatureMismatch, .revocationsParseFailed,
             .revocationsRollback, .revocationsSerialMissing:
            return true
        case .noBaseURL, .fetchFailed, .versionFloor:
            return false
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 4) {
            sidebarHeader("Browse")
            sidebarRow("All scanners",
                       icon: "square.grid.2x2",
                       isSelected: selectedCategory == nil && !showFeaturedOnly,
                       count: offeredEntries.count) {
                selectedCategory = nil
                showFeaturedOnly = false
            }
            sidebarRow("Featured (first-party)",
                       icon: "sparkles",
                       isSelected: showFeaturedOnly,
                       count: offeredEntries.filter { $0.trustTier == "first-party" }.count) {
                showFeaturedOnly.toggle()
                if showFeaturedOnly { selectedCategory = nil }
            }
            if !categories.isEmpty {
                sidebarHeader("Categories").padding(.top, 16)
                ForEach(categories, id: \.self) { cat in
                    sidebarRow(cat.capitalized,
                               icon: categoryIcon(cat),
                               isSelected: selectedCategory == cat,
                               count: offeredEntries.filter { $0.category == cat }.count) {
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
        VStack(spacing: 0) {
            gridToolbar
            Divider()
            ScrollView {
                if visibleEntries.isEmpty {
                    noMatchesView
                } else {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 220, maximum: 280), spacing: 14)], spacing: 14) {
                        ForEach(visibleEntries, id: \.id) { e in
                            catalogCard(e)
                        }
                    }
                    .padding(18)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var gridToolbar: some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .scaledSystem(11).foregroundStyle(.secondary)
                TextField("Search scanners", text: $searchText)
                    .textFieldStyle(.plain)
                    .scaledSystem(12)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").scaledSystem(11)
                    }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .help("Clear search")
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(6)
            .frame(maxWidth: 260)

            Text("\(visibleEntries.count) of \(offeredEntries.count)")
                .scaledSystem(10).foregroundStyle(.secondary)
                .monospacedDigit()

            Spacer()

            Picker("Sort", selection: $sortMode) {
                ForEach(SortMode.allCases, id: \.self) { m in
                    Text(m.label).tag(m)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .scaledSystem(11)
            .frame(width: 160)
        }
        .padding(.horizontal, 18).padding(.vertical, 8)
    }

    private var noMatchesView: some View {
        VStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .scaledSystem(28).foregroundStyle(.tertiary)
            Text("No scanners match")
                .scaledSystem(13, weight: .medium).foregroundStyle(.secondary)
            if !searchText.isEmpty {
                Text("Nothing matches “\(searchText)”.")
                    .scaledSystem(11).foregroundStyle(.tertiary)
                Button("Clear search") { searchText = "" }
                    .scaledSystem(11).buttonStyle(.bordered).controlSize(.small)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 60)
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
                        installedBadge(for: e)
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

    /// Installed / Update-available badge from the local plugin inventory.
    /// Absent when the plugin isn't installed.
    @ViewBuilder
    private func installedBadge(for e: RaveCatalogEntry) -> some View {
        if let installedVer = installedByID[e.id] {
            if isUpdateAvailable(installed: installedVer, current: e.currentVersion) {
                badge("Update", icon: "arrow.up.circle.fill", color: .blue)
            } else {
                badge("Installed", icon: "checkmark.circle.fill", color: .green)
            }
        }
    }

    /// True when the catalog's current version is newer than what's installed.
    /// Uses the shared semver policy; an unparseable pair → no update (safe).
    private func isUpdateAvailable(installed: String, current: String) -> Bool {
        MacCrabSemverCompare.satisfiesFloor(running: installed, floor: current) == false
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
        errorIsTrust = false
        baseURL = await client.baseURL.absoluteString
        usingOfficial = await client.isUsingOfficialSource
        // Local plugin inventory (independent of the catalog fetch) so cards can
        // show Installed / Update-available state.
        installedByID = await client.installedPlugins()
        do {
            let fetched = try await client.fetchEntries()

            // Best-effort load of the signed revocation list so revoked
            // entries are badged + their install pills withheld. A failure
            // here (offline / not-yet-published) is non-fatal: the catalog
            // still renders, and the per-entry signer-pin + version-floor
            // gates still apply. fetchAndReconcileRevocations is fail-closed
            // on a BAD signature (throws) — that's the safe outcome.
            let revocations = try? await client.fetchAndReconcileRevocations()

            // First-party display names from the verified catalog — the C-F
            // confusable guard flags a non-first-party entry whose display name
            // is confusably close to one of these (homoglyph / spacing / 1-edit).
            let firstPartyNames = fetched
                .filter { $0.trustTier == "first-party" }
                .map { $0.displayName }

            var states: [String: RaveCatalogEntryState] = [:]
            states.reserveCapacity(fetched.count)
            for e in fetched {
                states[e.id] = RaveCatalogEntryState.compute(
                    entry: e,
                    revocations: revocations,
                    firstPartyDisplayNames: firstPartyNames,
                    floorCheck: client.checkVersionFloor   // nonisolated, shared policy
                )
            }

            entries = fetched
            stateByID = states
            // Surface the trust this verified fetch earned (anti-rollback serial
            // + revocation freshness) for the trust strip, and stamp the last-good
            // time so the offline pane can say "last verified …".
            lastGoodFetch = Date()
            catalogSerial = await client.currentCatalogSerial()
            revFreshness = await client.revocationFreshness()
            // Default the detail selection to the first OFFERED (active) entry,
            // never a hidden pre-release one.
            if selectedID == nil { selectedID = offeredEntries.first?.id }
        } catch {
            self.error = "\(error)"
            self.errorIsTrust = Self.isTrustError(error)
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
