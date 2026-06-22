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
    /// Injected so "Run on this Mac" can hand a single-scanner run to the Scans
    /// tab (set the intent + switch tabs); the Scans tab owns the runner.
    @ObservedObject var state: V2DashboardState
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
    /// Captured once when the pill is tapped so the consent sheet uses the SAME
    /// update-vs-fresh decision the pill showed — never re-resolved at present
    /// time (which could diverge across an async reload between tap and present).
    @State private var pendingIsUpdate = false
    /// The currently-installed version, passed to the consent sheet for an update
    /// so it can disclose the vOLD → vNEW diff (P6.2).
    @State private var pendingInstalledVersion: String?
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
    /// Plugin ids that are registered in THIS build AND runnable (collector /
    /// analyzer) — the local gate for the "Run on this Mac" action. Built-ins
    /// are always runnable regardless of catalog/install state.
    @State private var runnableIDs: Set<String> = []
    /// Synthesized first-party rows for the runnable BUILT-IN scanners, so the
    /// store can browse + run them while the signed third-party catalog is still
    /// coming soon. DISPLAY-ONLY: never merged into `entries`, so they never
    /// touch stateByID / compute / the trust strip / offeredEntries.
    @State private var builtinEntries: [RaveCatalogEntry] = []
    /// "Recent output" preview for the selected scanner — the most-recent ≤3 REAL
    /// artifact rows from a plaintext case (no fake data). nil = loading / not yet
    /// fetched; [] = ran (or never ran) but no real rows. Loaded once per selection
    /// via `.task(id: selectedID)`, keyed by `sampleForID` so case-A's rows never
    /// show under case-B during an in-flight swap.
    @State private var sampleRows: [CommittedArtifact]? = nil
    @State private var sampleForID: String? = nil

    private enum SortMode: CaseIterable, Hashable {
        case name, category, firstPartyFirst
        var label: String {
            switch self {
            case .name:            return String(localized: "raveStore.sort.name", defaultValue: "Name (A–Z)")
            case .category:        return String(localized: "raveStore.sort.category", defaultValue: "Category")
            case .firstPartyFirst: return String(localized: "raveStore.sort.firstPartyFirst", defaultValue: "First-party first")
            }
        }
    }

    private let client = RaveCatalogClient()

    private var categories: [String] {
        let set = Set(displayEntries.compactMap { $0.category })
        return set.sorted()
    }

    /// Only entries the store actually offers — status == "active", mirroring the
    /// website's go-live filter (maccrab-rave site/build.sh). Pre-release /
    /// placeholder / not-yet-signed entries are NOT shown as available apps; when
    /// none are active the browser shows its verified-empty pane. This is a
    /// DISPLAY filter only — it does not touch any signature / serial /
    /// installability trust gate (the install path still fail-closes on its own).
    private var offeredEntries: [RaveCatalogEntry] {
        RaveCatalogClient.offeredEntries(entries)
    }

    /// Built-ins (local first-party scanners) + offered catalog entries, for
    /// DISPLAY only (browse/search/sort/detail). Built-ins are NOT in `entries`,
    /// so they never touch stateByID / compute / the trust strip / the offer set.
    private var displayEntries: [RaveCatalogEntry] {
        // De-dup on id, built-in wins (see mergedDisplayEntries). offeredEntries
        // is untouched, so the verified-catalog accounting is unaffected.
        RaveCatalogClient.mergedDisplayEntries(builtins: builtinEntries, offered: offeredEntries)
    }

    private func isBuiltin(_ e: RaveCatalogEntry) -> Bool {
        builtinEntries.contains { $0.id == e.id }
    }

    private var visibleEntries: [RaveCatalogEntry] {
        let filtered = displayEntries.filter { e in
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
        displayEntries.first { $0.id == selectedID }
    }

    /// Resolved state for an entry, defaulting to a fail-closed
    /// "awaiting signed binary" when (for any reason) we haven't computed one.
    private func state(for entry: RaveCatalogEntry) -> RaveCatalogEntryState {
        if isBuiltin(entry) {
            return RaveCatalogEntryState(
                entry: entry,
                installability: .builtInLocal,
                isRevoked: false,
                revocationReason: nil
            )
        }
        return stateByID[entry.id] ?? RaveCatalogEntryState(
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
            // P6.1: reload installed-state when the sheet closes so a just-installed
            // (or updated) plugin's Installed badge + state refresh in place, with
            // no manual reload. reload() is idempotent, so a cancelled install is a
            // cheap no-op.
            RaveInstallConsentSheet(
                link: link,
                onClose: {
                    installLink = nil
                    Task { await reload() }
                },
                isUpdate: pendingIsUpdate,
                installedVersion: pendingInstalledVersion)
        }
    }

    private enum PaneState { case loading, offline, trustError, verifiedEmpty, live }

    private var paneState: PaneState {
        if loading { return .loading }
        if error != nil { return errorIsTrust ? .trustError : .offline }
        // Built-ins (local, always-available) widen verifiedEmpty → live. They
        // can never reach trustError/offline (those return above), so a
        // verification failure is never masked by showing built-ins.
        return (offeredEntries.isEmpty && builtinEntries.isEmpty) ? .verifiedEmpty : .live
    }

    /// The live store chrome (header + sidebar + grid + detail) — shown only
    /// once the catalog verified AND offers at least one active plugin.
    private var liveStore: some View {
        VStack(spacing: 0) {
            header
            if !usingOfficial {
                nonOfficialBanner
            }
            // Only built-ins are showing — keep the third-party catalog's empty
            // state honest ("coming soon") so built-ins don't read as "the
            // catalog is live."
            if offeredEntries.isEmpty {
                thirdPartyComingSoonBanner
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

    private var thirdPartyComingSoonBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "shippingbox").foregroundStyle(.secondary).scaledSystem(12)
            VStack(alignment: .leading, spacing: 1) {
                Text(String(localized: "raveStore.thirdPartyComingSoon.title", defaultValue: "Third-party catalog — coming soon"))
                    .scaledSystem(11, weight: .semibold)
                Text(String(localized: "raveStore.thirdPartyComingSoon.body", defaultValue: "The signed, vetted plugin catalog is on the way. The built-in scanners below ship inside MacCrab and run on this Mac now — no install needed."))
                    .scaledSystem(10).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 8)
        .background(Color.secondary.opacity(0.08))
    }

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
                // The pane is always a near-black gradient; force dark so
                // semantic colors (e.g. the trust-strip .secondary chips)
                // resolve light and stay legible even in app light mode.
                .environment(\.colorScheme, .dark)
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
                       count: displayEntries.count) {
                selectedCategory = nil
                showFeaturedOnly = false
            }
            sidebarRow("Featured (first-party)",
                       icon: "sparkles",
                       isSelected: showFeaturedOnly,
                       count: displayEntries.filter { $0.trustTier == "first-party" }.count) {
                showFeaturedOnly.toggle()
                if showFeaturedOnly { selectedCategory = nil }
            }
            if !categories.isEmpty {
                sidebarHeader("Categories").padding(.top, 16)
                ForEach(categories, id: \.self) { cat in
                    sidebarRow(cat.capitalized,
                               icon: categoryIcon(cat),
                               isSelected: selectedCategory == cat,
                               count: displayEntries.filter { $0.category == cat }.count) {
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
                TextField(String(localized: "raveStore.searchPlaceholder", defaultValue: "Search scanners"), text: $searchText)
                    .textFieldStyle(.plain)
                    .scaledSystem(12)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").scaledSystem(11)
                    }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .help(String(localized: "raveStore.clearSearch", defaultValue: "Clear search"))
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(6)
            .frame(maxWidth: 260)

            Text("\(visibleEntries.count) of \(displayEntries.count)")
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
            .frame(minWidth: 140)
        }
        .padding(.horizontal, 18).padding(.vertical, 8)
    }

    private var noMatchesView: some View {
        VStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .scaledSystem(28).foregroundStyle(.tertiary)
            Text(String(localized: "raveStore.noMatches.title", defaultValue: "No scanners match"))
                .scaledSystem(13, weight: .medium).foregroundStyle(.secondary)
            if !searchText.isEmpty {
                Text(String(localized: "raveStore.noMatches.detail", defaultValue: "Nothing matches “\(searchText)”."))
                    .scaledSystem(11).foregroundStyle(.tertiary)
                Button(String(localized: "raveStore.clearSearch", defaultValue: "Clear search")) { searchText = "" }
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
                    thumbnailGlyph(e, size: 32)
                }
                .cornerRadius(6)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(friendlyName(e.id))
                            .scaledSystem(13, weight: .semibold)
                            .lineLimit(1)
                        // Built-ins wear the dedicated "Built-in" status badge, not
                        // the green "First-party" trust chip (which means
                        // catalog-signature-verified first-party).
                        if !isBuiltin(e) { trustBadge(e.trustTier) }
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
                    thumbnailGlyph(e, size: 48)
                }
                .cornerRadius(8)

                VStack(alignment: .leading, spacing: 6) {
                    Text(friendlyName(e.id))
                        .font(.headline)
                    HStack(spacing: 6) {
                        if !isBuiltin(e) { trustBadge(e.trustTier) }
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
                recentOutputSection(e)
                if let f = PluginFactsLookup.facts(forPluginID: e.id) {
                    Divider()
                    capabilityChips(f)
                }
                if !e.tags.isEmpty {
                    detailSection(String(localized: "raveDetail.tags", defaultValue: "Tags"), view: tagWrap(e.tags))
                }
                detailSection(String(localized: "raveDetail.version", defaultValue: "Version"), body: "v\(e.currentVersion)")
                if let min = e.minMaccrabVersion {
                    detailSection(String(localized: "raveDetail.requires", defaultValue: "Requires"), body: "MacCrab v\(min) or newer")
                }
                if isBuiltin(e) {
                    detailSection(String(localized: "raveDetail.source", defaultValue: "Source"), view: HStack(spacing: 5) {
                        Image(systemName: PluginProvenance.builtIn.symbolName)
                            .scaledSystem(10).foregroundStyle(.green)
                        Text(String(localized: "raveDetail.source.builtIn", defaultValue: "Built-in — ships inside MacCrab")).scaledSystem(11)
                    })
                } else {
                    detailSection(String(localized: "raveDetail.signedBy", defaultValue: "Signed by"), body: e.signerIdentity.isEmpty ? "—" : e.signerIdentity)
                    trustStateRow(state(for: e))
                }

                if runnableIDs.contains(e.id) {
                    Divider()
                    runOnThisMacAction(e)
                }
                // Built-ins have nothing to install — Run is their only action.
                if !isBuiltin(e) {
                    Divider()
                    installAction(e)
                }
            }
            .padding(18)
        }
        // Lazy, once-per-selection load of the real "Recent output" rows.
        // Re-keyed on selectedID so rapid card switching cancels/replaces the
        // in-flight load (no pile-up) and never shows the wrong scanner's rows.
        .task(id: selectedID) {
            guard let id = selectedID else { return }
            // Skip the store walk entirely for scanners with no metadata fact
            // (encrypted-only / undocumented) — the section is hidden for them
            // anyway, and this avoids any wasted case opens.
            guard ScannerCatalog.fact(forPluginID: id)?.privacyClass == .metadata else {
                // Non-metadata / undocumented: recentOutputSection is hidden for
                // these, so leave sample state untouched (it's never read here).
                return
            }
            sampleForID = id
            sampleRows = nil
            let rows = await SampleOutputLoader.recentRows(forPluginID: id)
            // Guard against a stale completion landing after the selection moved on.
            if sampleForID == id { sampleRows = rows }
        }
    }

    /// "Recent output" — the most-recent real artifact rows this scanner has
    /// produced on THIS Mac (plaintext cases only; no fake data). Shown only for
    /// metadata scanners (the only class that can live in a plaintext case, so no
    /// Keychain prompt is ever triggered). Encrypted-only / undocumented scanners
    /// get no section — the capability chips' "Emits" row still answers "what
    /// you'll see" honestly.
    @ViewBuilder
    private func recentOutputSection(_ e: RaveCatalogEntry) -> some View {
        if ScannerCatalog.fact(forPluginID: e.id)?.privacyClass == .metadata {
            Divider()
            detailSection(
                String(localized: "raveDetail.recentOutput", defaultValue: "Recent output"),
                view: recentOutputBody(e)
            )
        }
    }

    @ViewBuilder
    private func recentOutputBody(_ e: RaveCatalogEntry) -> some View {
        if let rows = sampleRows, sampleForID == e.id {
            if rows.isEmpty {
                Text(String(localized: "raveDetail.recentOutput.notRun",
                            defaultValue: "No recent output on this Mac — run it to see real output."))
                    .scaledSystem(11).foregroundStyle(.tertiary)
            } else {
                ArtifactCompactPreview(artifacts: rows, hint: nil)
            }
        } else {
            ProgressView().controlSize(.small)
        }
    }

    /// "Run on this Mac" — runs this built-in scanner now via the Scans tab's
    /// runner + the existing consent gate. Local and always-available (no
    /// install); shown only for registered, runnable (collector/analyzer) ids.
    private func runOnThisMacAction(_ e: RaveCatalogEntry) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(String(localized: "raveDetail.run.header", defaultValue: "Run"))
                .scaledSystem(10, weight: .semibold)
                .foregroundStyle(.tertiary).textCase(.uppercase)
            Button {
                state.pendingForensicsRunPluginID = e.id
                state.selectedTabs[.forensics] = .forensicsScans
            } label: {
                Label(String(localized: "raveDetail.run.button", defaultValue: "Run on this Mac"), systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            Text(String(localized: "raveDetail.run.caption", defaultValue: "Runs this built-in scanner on your Mac now — no install needed. Results appear under Run a scan."))
                .scaledSystem(10)
                .foregroundStyle(.tertiary)
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

    /// Phase-2 capability chips: what the scanner reads, the TCC it needs, what
    /// it emits, its privacy class, and the honest network/sandbox posture —
    /// sourced from the local ScannerCatalog (first-party), surfaced here instead
    /// of being buried in the kit-detail sheet on another tab.
    @ViewBuilder
    private func capabilityChips(_ f: PluginFacts) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            chipRow("Reads", f.reads)
            if !f.needs.isEmpty { chipRow("Needs", f.needs) }
            chipRow("Emits", f.emits)
            HStack(spacing: 4) {
                Image(systemName: f.isMetadataOnly ? "checkmark.shield" : "lock.fill")
                    .scaledSystem(9)
                    .foregroundStyle(f.isMetadataOnly ? .green : .purple)
                Text(f.privacyLabel).scaledSystem(10).foregroundStyle(.secondary)
            }
            HStack(spacing: 4) {
                Image(systemName: "network.slash").scaledSystem(9).foregroundStyle(.secondary)
                Text(f.networkChip).scaledSystem(10).foregroundStyle(.secondary)
            }
        }
    }

    private func chipRow(_ label: String, _ values: [String]) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label).scaledSystem(10, weight: .medium)
                .foregroundStyle(.tertiary).frame(width: 50, alignment: .trailing)
            VStack(alignment: .leading, spacing: 1) {
                ForEach(values.indices, id: \.self) { i in
                    Text(values[i]).scaledSystem(11).foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
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
                let isUpdate = updateAvailable(for: e)
                Button {
                    // Construct the id-only install link and let the SAME
                    // consent flow the URL handler uses resolve it from the
                    // pinned catalog (signer pin + version floor + consent +
                    // receipt). No bypass: this only OPENS the verified path.
                    // The update case re-installs over the existing copy (--force);
                    // every trust gate is still re-enforced by maccrabctl. Capture
                    // the decision now so the sheet matches what this pill showed.
                    pendingIsUpdate = isUpdate
                    pendingInstalledVersion = isUpdate ? installedByID[e.id] : nil
                    installLink = RaveInstallLink(kind: .plugin, id: e.id)
                } label: {
                    Label(isUpdate ? String(localized: "rave.install.updateTo", defaultValue: "Update to v\(e.currentVersion)")
                                   : String(localized: "rave.install.install", defaultValue: "Install"),
                          systemImage: isUpdate ? "arrow.up.circle" : "checkmark.shield")
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
        case .builtInLocal:           return "Built-in"
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
        case .builtInLocal:           return "shield.lefthalf.filled"
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
        case .builtInLocal:
            badge("Built-in", icon: "shield.lefthalf.filled", color: .green)
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

    /// Whether `e` is an installed plugin with a newer catalog version — i.e. the
    /// install pill should read "Update" and re-install with --force.
    private func updateAvailable(for e: RaveCatalogEntry) -> Bool {
        guard let installedVer = installedByID[e.id] else { return false }
        return isUpdateAvailable(installed: installedVer, current: e.currentVersion)
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
        // Prefer the real per-scanner purpose from the local ScannerCatalog
        // (first-party, keyed by plugin id); fall back to a templated line for
        // ids with no local facts (third-party / not-yet-documented).
        if let f = PluginFactsLookup.facts(forPluginID: e.id) {
            return f.purpose
        }
        if isBuiltin(e) {
            return "\(friendlyName(e.id)) — a \(e.category ?? "scanner") that ships inside MacCrab. Run it on this Mac from here."
        }
        return "\(friendlyName(e.id)) — \(e.category ?? "scanner") published via the rave catalog. Install it to add it to this Mac's scanner registry; from there it'll appear in any kit that references its id."
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

    /// A meaningful SF Symbol for a card / detail thumbnail. Prefers a
    /// per-scanner symbol (recognizable at a glance), then the category icon;
    /// returns nil only when neither is sensible so the caller falls back to the
    /// 2-letter monogram. Keeps the gradient background either way.
    private func thumbnailSymbol(for e: RaveCatalogEntry) -> String? {
        if let s = Self.scannerSymbols[e.id] { return s }
        switch e.category {
        case "collector", "analyzer", "enricher", "fingerprinter":
            return categoryIcon(e.category ?? "")
        default:
            return nil
        }
    }

    /// Card / detail thumbnail glyph: a per-category / per-scanner SF Symbol when
    /// one is sensible, else the 2-letter monogram fallback. Gradient background
    /// is applied by the caller's ZStack.
    @ViewBuilder
    private func thumbnailGlyph(_ e: RaveCatalogEntry, size: CGFloat) -> some View {
        // Guard against a symbol name unavailable on the running OS (it would
        // render blank): fall back to the monogram if the system symbol is
        // absent. NSImage(systemSymbolName:) is nil for an unknown symbol.
        if let symbol = thumbnailSymbol(for: e),
           NSImage(systemSymbolName: symbol, accessibilityDescription: nil) != nil {
            Image(systemName: symbol)
                .scaledSystem(size, weight: .bold)
                .foregroundStyle(.white)
        } else {
            Text(monogram(e.id))
                .scaledSystem(size, weight: .bold, design: .rounded)
                .foregroundStyle(.white)
        }
    }

    /// Per-scanner thumbnail symbols, keyed by plugin id. Chosen to read at a
    /// glance for the first-party built-ins; ids without an entry fall through to
    /// the category icon, then the monogram.
    private static let scannerSymbols: [String: String] = [
        "com.maccrab.forensics.tcc-lite":               "hand.raised.fill",
        "com.maccrab.forensics.launchd-lite":           "gearshape.2.fill",
        "com.maccrab.forensics.quarantine":             "arrow.down.circle.fill",
        "com.maccrab.forensics.safari-lite":            "safari.fill",
        "com.maccrab.forensics.safari-deep":            "safari.fill",
        "com.maccrab.forensics.mail":                   "envelope.fill",
        "com.maccrab.forensics.mail-bodies":            "envelope.open.fill",
        "com.maccrab.forensics.imessage-metadata":      "message.fill",
        "com.maccrab.forensics.imessage-bodies":        "message.fill",
        "com.maccrab.forensics.facetime":               "video.fill",
        "com.maccrab.forensics.knowledgec":             "brain.head.profile",
        "com.maccrab.forensics.biome":                  "waveform.path.ecg",
        "com.maccrab.forensics.applescript-runtime":    "terminal.fill",
        "com.maccrab.forensics.posture-analyzer":       "checkmark.shield.fill",
        "com.maccrab.forensics.codesigning-graph":      "signature",
        "com.maccrab.forensics.macho-analyzer":         "cpu",
        "com.maccrab.forensics.dmg-pkg-analyzer":       "shippingbox.fill",
        "com.maccrab.forensics.plist-analyzer":         "doc.text.fill",
        "com.maccrab.forensics.mobileconfig-inspector": "doc.badge.gearshape",
        "com.maccrab.forensics.shortcuts-analyzer":     "wand.and.rays",
        "com.maccrab.forensics.image-metadata":         "photo.fill",
        "com.maccrab.forensics.archive-walker":         "archivebox.fill",
        "com.maccrab.forensics.document-analyzer":      "doc.richtext.fill",
        "com.maccrab.forensics.office-document-analyzer": "doc.richtext.fill",
        "com.maccrab.forensics.fsevents":               "folder.fill",
    ]

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
        // Registered + runnable (collector/analyzer) ids — the local gate for
        // "Run on this Mac". Built-ins are always runnable, so register them
        // first; this is independent of catalog reachability.
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        let runnableManifests = await PluginRegistry.shared.manifests()
            .filter { $0.type == .collector || $0.type == .analyzer }
        runnableIDs = Set(runnableManifests.map { $0.id })
        // Synthesize display-only first-party rows for the runnable built-ins so
        // the store can browse + run them while the third-party catalog is empty.
        builtinEntries = RaveCatalogClient.builtinEntries(
            from: runnableManifests,
            displayName: { ScannerDisplay.name(forPluginID: $0) }
        )
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
            // Seat the detail selection on the first OFFERED (active) entry when
            // it's unset OR points at one no longer offered (e.g. went inactive
            // on this reload), so the detail panel never shows a card the grid
            // filtered out. Never a hidden pre-release entry.
            if selectedID == nil || !displayEntries.contains(where: { $0.id == selectedID }) {
                selectedID = displayEntries.first?.id
            }
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
