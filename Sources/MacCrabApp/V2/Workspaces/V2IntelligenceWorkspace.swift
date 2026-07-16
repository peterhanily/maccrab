// V2IntelligenceWorkspace.swift
// Spec §7.5 — feeds, IOC matches, package freshness, integrations.

import SwiftUI
import AppKit
import MacCrabCore

public struct V2IntelligenceWorkspace: View {
    @ObservedObject var state: V2DashboardState

    // v1.19.1: the four opt-in network-enrichment flags (off by default). Same
    // `enrich.*` keys Settings + the first-run prompt bind, so all three
    // surfaces stay in sync; changes push to the daemon via the inbox reload.
    @AppStorage("enrich.threatIntel")      private var enrichThreatIntel: Bool = false
    @AppStorage("enrich.vulnScan")         private var enrichVulnScan: Bool = false
    @AppStorage("enrich.packageFreshness") private var enrichPackageFreshness: Bool = false
    @AppStorage("enrich.certTransparency") private var enrichCertTransparency: Bool = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var feeds: [V2MockFeed] = []
    /// Last time any feed actually pulled fresh records — surfaced in
    /// the summary row so the operator can SEE the feeds working
    /// rather than guessing from a frozen IOC count.
    @State private var lastSuccessfulPull: Date? = nil
    @State private var packages: [V2MockPackage] = []
    @State private var selectedPackage: V2MockPackage?
    @State private var packageScanInProgress: Bool = false
    @State private var packageLastScannedAt: Date? = nil
    /// v1.11.0 RC2 ship-blocker fix: integrations tab is now backed
    /// by `state.provider.integrations()` (audit caught it as a
    /// static placeholder in RC1). Refreshed on every workspace tick.
    @State private var integrations: [V2MockIntegration] = []
    /// State for the per-feed configuration sheet — pre-fix the
    /// managed-feeds card showed read-only chips that the user
    /// couldn't click to configure / enable / supply API keys.
    @State private var feedSheet: V2FeedConfig? = nil
    /// Recent IOC-match alerts (part A records each match as an Alert
    /// whose ruleId starts with `maccrab.threat-intel.`). Drives the
    /// IOC-matches table. Loaded from the alert store via the provider
    /// on every workspace tick.
    @State private var matches: [V2MockAlert] = []
    /// Selected IOC-match row — drives the drill-in inspector so a match
    /// is no longer a triage dead-end (was a non-selectable table).
    @State private var selectedMatch: V2MockAlert? = nil

    public init(state: V2DashboardState) { self.state = state }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            V2WorkspaceTabStrip(
                tabs: V2Workspace.intelligence.tabs,
                selected: Binding(
                    get: { state.selectedTabs[.intelligence] ?? .intelligenceThreatIntel },
                    set: { if let v = $0 { state.selectedTabs[.intelligence] = v } }
                )
            )
            tabBody
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") {
            // v1.11.0 RC2: live provider now exposes packages() (via
            // PackageScanner with 5-min cache) and integrations() (via
            // daemon_config.json + notifications.json). Pre-fix the V2
            // panel ignored both readers — packages tab was driven
            // only by the manual "Run scan" button (using the OLD
            // PackageFreshnessChecker, NOT the new PackageScanner),
            // and the integrations tab was a static placeholder. Pull
            // both on every tick; the cache absorbs the cost.
            //
            // v1.12.6 Wave 9E: feeds are read directly via
            // `V2LiveDataProvider.loadFeedsFromCache(preferring:)`
            // rather than through `state.provider.feeds()`. The
            // threat-intel cache file on disk is the source of truth
            // regardless of provider mode — V2MockDataProvider's
            // `feeds()` returned synthetic fixtures (Spamhaus DROP /
            // MITRE ATT&CK / etc.) that weren't wired to anything, and
            // on first appear the workspace would render those mock
            // rows until the mock→live provider flip plus a .task(id:)
            // re-fire overwrote them. User-visible symptom: "feeds
            // don't seem to work right away until you hit refresh".
            // The static helper probes both canonical paths (system +
            // user-home) so the cache is found regardless of which
            // directory `dataDir` resolved to.
            //
            // v1.12.6 Wave 9G: feeds are assigned to @State BEFORE the
            // slower `packages()` / `integrations()` readers resolve.
            // Pre-9G the three reads were combined in one `await (f, p, i)`
            // tuple, blocking `self.feeds = feedsResult` until packages()
            // returned. PackageScanner.scan() shells out to brew + npm +
            // pip3 on cold open and can take 5+ seconds — longer than the
            // dashboard's default 5s auto-refresh tick. `.task(id:)`
            // cancels the running body when the id changes, so on every
            // tick the feeds assignment was canceled before it ran. The
            // user's symptom: "feeds still require a refresh to appear"
            // even with `feed_cache.json` present and populated on disk.
            // Manual refresh worked only because it injects a 6s sleep
            // that lets PackageScanner's 5-min cache warm before the
            // refreshTick bump fires the next task body.
            let dataDirHint = (state.provider as? V2LiveDataProvider)?.dataDir
            // PERF-2: one decode of feed_cache.json returns both rows + pull date
            // (was two separate cachedIOCs decodes of the multi-MB cache per tick).
            let (feedsResult, pullResult) = await Task.detached(priority: .userInitiated) {
                let r = V2LiveDataProvider.loadFeedsAndPull(preferring: dataDirHint)
                return (r.feeds, r.pull)
            }.value
            await MainActor.run {
                self.feeds = feedsResult
                self.lastSuccessfulPull = pullResult
            }

            // IOC matches: alerts whose ruleId carries the
            // `maccrab.threat-intel.` prefix part A writes them under.
            // Reuses the provider's existing off-MainActor decode path.
            // Fetch-then-filter: the provider has no ruleId-prefix query, so
            // pull a wide window (7d, capped) and filter client-side. The cap
            // is 1000 (was 200) so busy hosts with lots of non-match alerts in
            // the 7-day window don't truncate the threat-intel hits out of the
            // fetch and falsely read "none in window". A dedicated server-side
            // matches query (provider) would remove the cap dependency entirely.
            let allAlerts = await state.provider.alerts(limit: 1000)
            let matchRows = allAlerts.filter { $0.ruleId.hasPrefix(Self.iocMatchRulePrefix) || $0.ruleId == "maccrab.dns.threat-intel-match" }
            await MainActor.run { self.matches = matchRows }

            // packages()/integrations() shell out to brew + npm + pip3 and can
            // take 5+ seconds on a cold cache — longer than the 5s auto-refresh
            // tick. The enclosing `.task(id:)` is cancelled when refreshTick
            // bumps, and (as the Wave 9G feeds fix above documents) a cancelled
            // body drops any MainActor assignment that hasn't run yet. Feeds are
            // assigned early to dodge that; the slow readers used to sit AFTER the
            // long `await (p, i)`, so on a busy host they were cancelled every
            // tick and never landed — integrations, which has no manual fallback,
            // stayed empty forever. Run them in an UNSTRUCTURED Task that is not a
            // child of `.task(id:)` and therefore survives the tick's
            // cancellation; PackageScanner's 5-min actor cache keeps overlapping
            // ticks cheap.
            Task {
                async let p = state.provider.packages()
                async let i = state.provider.integrations()
                let (pkgsResult, integResult) = await (p, i)
                await MainActor.run {
                    // Seed/refresh packages from the live provider. A manual
                    // scan uses the richer PackageFreshnessChecker, so let it
                    // WIN briefly (its installed-vs-latest data is more
                    // accurate) — but don't freeze the table for the whole
                    // session: once the manual scan is older than
                    // PackageScanner's 5-min cache TTL, allow the auto path to
                    // land newer background enrichment (typosquat/attestation).
                    // Pre-fix this gated on `== nil`, so the first manual scan
                    // froze the table permanently and no later enrichment ever
                    // appeared.
                    let manualIsFresh = self.packageLastScannedAt
                        .map { Date().timeIntervalSince($0) < 300 } ?? false
                    if !manualIsFresh && !pkgsResult.isEmpty {
                        self.packages = pkgsResult
                    }
                    self.integrations = integResult
                }
            }
        }
    }

    @ViewBuilder
    private var tabBody: some View {
        switch state.selectedTabs[.intelligence] ?? .intelligenceThreatIntel {
        case .intelligenceThreatIntel:      threatIntelTab
        case .intelligencePackageFreshness: packageFreshnessTab
        case .intelligenceIntegrations:     integrationsTab
        default: threatIntelTab
        }
    }

    // MARK: - Threat intel

    private var threatIntelTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let q = state.pendingIntelQuery, !q.isEmpty {
                    intelQueryBanner(q)
                }
                enrichmentCard
                apiKeysHelpCard
                feedsSummaryRow
                feedsTable
                matchesTable
            }
            .padding(16)
        }
    }

    /// D8: the command-palette `ip:<addr>` "Search IOC matches" item hands
    /// a needle in via `state.pendingIntelQuery`. It narrows the IOC-matches
    /// table (`filteredMatches`) to rows mentioning it. Persists on state
    /// until the user clears this banner — mirroring the Events "Investigate"
    /// pre-fill flow. Pre-fix `applyFilters` had no `.intelligence` branch, so
    /// the palette item navigated here but never searched anything.
    private var filteredMatches: [V2MockAlert] {
        guard let q = state.pendingIntelQuery?
                .trimmingCharacters(in: .whitespaces).lowercased(),
              !q.isEmpty else { return matches }
        return matches.filter { m in
            m.title.lowercased().contains(q)
                || m.description.lowercased().contains(q)
                || m.process.lowercased().contains(q)
        }
    }

    private func intelQueryBanner(_ query: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(V2Theme.brand)
                .scaledSystem(12, weight: .semibold)
            Text("Searching IOC matches for")
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.primaryText)
            Text(query)
                .font(V2Theme.mono())
                .foregroundStyle(V2Theme.brand)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Button { state.pendingIntelQuery = nil } label: {
                HStack(spacing: 4) {
                    Image(systemName: "xmark")
                        .scaledSystem(9, weight: .semibold)
                    Text("Clear search")
                        .font(V2Theme.meta())
                }
                .foregroundStyle(V2Theme.mutedText)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(V2Theme.panelBackground)
                .overlay(RoundedRectangle(cornerRadius: 4)
                            .stroke(V2Theme.panelBorder, lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Clear IOC search")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(V2Theme.brand.opacity(0.08))
        .overlay(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.brand.opacity(0.4), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
    }

    private var anyEnrichmentOn: Bool {
        enrichThreatIntel || enrichVulnScan || enrichPackageFreshness || enrichCertTransparency
    }

    /// The built-in abuse.ch feeds only fetch when threat-intel enrichment is
    /// opted in (the daemon gates network egress on `enrich.threatIntel`). The
    /// help/managed-feed copy must not claim "fetched every 4 hours"
    /// unconditionally — that contradicted the opt-in card directly above it.
    private var feedFetchPhrase: String {
        enrichThreatIntel
            ? "fetched every 4 hours"
            : "off by default — opt in to threat-intel enrichment above to fetch every 4 hours (bundled IOCs work offline until then)"
    }

    /// v1.19.1: enrichment opt-in/status card — the FIRST thing on the Threat
    /// Intel tab. Both a status headline (all-off = "on-device only") and the
    /// durable per-feed control. Binds the shared `enrich.*` keys and pushes to
    /// the daemon via the cross-uid-safe inbox reload (stops/starts egress
    /// live). Bare English literals: this V2 workspace is intentionally not
    /// localized (see the note further down this file).
    private var enrichmentCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: anyEnrichmentOn ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash")
                .foregroundStyle(anyEnrichmentOn ? V2Theme.dataAccent : V2Theme.warning)
                .scaledSystem(14)
                .padding(.top, 2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(anyEnrichmentOn ? "Network enrichment" : "Enrichment is off — MacCrab is running on-device only")
                    .font(V2Theme.sectionTitle())
                    .foregroundStyle(V2Theme.primaryText)
                Text("These optional lookups each reach a public service. Off by default — nothing about your Mac leaves it until you turn one on. Local detection (rules, sequences, campaigns, bundled IOCs) is unaffected.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Threat-intel feeds — abuse.ch IOC lists (download-only)", isOn: $enrichThreatIntel)
                        .onChange(of: enrichThreatIntel) { _ in pushEnrichment() }
                    Toggle("Vulnerability scan — osv.dev CVE lookups (sends your software inventory)", isOn: $enrichVulnScan)
                        .onChange(of: enrichVulnScan) { _ in pushEnrichment() }
                    Toggle("Package freshness — npm/PyPI/Homebrew/crates (reveals package names)", isOn: $enrichPackageFreshness)
                        .onChange(of: enrichPackageFreshness) { _ in pushEnrichment() }
                    Toggle("Certificate transparency — crt.sh lookups (reveals domains you visit)", isOn: $enrichCertTransparency)
                        .onChange(of: enrichCertTransparency) { _ in pushEnrichment() }
                }
                .font(V2Theme.body())
                .padding(.top, 2)
            }
            Spacer()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }

    private func pushEnrichment() {
        let requested = V2DaemonControl.applyEnrichmentFlags(
            threatIntel: enrichThreatIntel, vulnScan: enrichVulnScan,
            packageFreshness: enrichPackageFreshness, certTransparency: enrichCertTransparency)
        state.showToast(V2Toast(
            kind: .info,
            title: requested ? "Enrichment updated" : "Saved",
            detail: requested ? "The engine re-read your enrichment settings."
                              : "Will apply on next daemon start."))
    }

    /// Two-card "where do I add things?" panel. Pre-fix the dashboard
    /// gave operators no answer to: "where do I add a custom feed?"
    /// or "where do I drop an API key?". Now both have visible
    /// affordances:
    ///   - Custom IOC drop-file paths are shown with a Reveal-in-Finder
    ///     button that opens the threat_intel dir if the daemon has
    ///     created it, else creates and reveals it.
    ///   - LLM provider keys link to Settings → AI Backend.
    private var apiKeysHelpCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Custom feeds card — file drop pattern.
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "square.stack.3d.up.fill")
                    .foregroundStyle(V2Theme.dataAccent)
                    .scaledSystem(14)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Add custom feeds & IOCs")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text("MacCrab's built-in feeds are abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker) — keyless, \(feedFetchPhrase). To add operator-supplied indicators, drop a text file (one IOC per line) into the threat_intel directory:")
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("• `custom.hashes.txt` — SHA-256 hashes")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                        Text("• `custom.ips.txt` — IPv4/IPv6 addresses")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                        Text("• `custom.domains.txt` — fully-qualified domain names")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                    }
                    HStack(spacing: 8) {
                        V2ActionButton("Import IOCs from file…", icon: "square.and.arrow.down", style: .primary,
                                       tooltip: "Pick a text file (one IOC per line) and copy it into the threat_intel directory under the right category") {
                            importIOCFile()
                        }
                        V2ActionButton("Reveal folder", icon: "folder", style: .secondary,
                                       tooltip: "Open the threat_intel directory in Finder for manual edits") {
                            revealThreatIntelDirectory()
                        }
                        V2ActionButton("Refresh after edit", icon: "arrow.clockwise", style: .ghost,
                                       tooltip: "Signal the daemon (SIGHUP) to re-read drop files") {
                            Task {
                                let ok = await state.provider.refreshThreatIntel()
                                await MainActor.run {
                                    state.showToast(V2Toast(
                                        kind: ok ? .info : .error,
                                        title: ok ? "Refresh signaled" : "Refresh failed",
                                        detail: ok ? "Daemon will re-read drop files within ~5s"
                                                   : (state.provider.lastErrorDescription ?? "no daemon to signal")
                                    ))
                                }
                            }
                        }
                    }
                }
                Spacer()
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .v2Panel()

            // Managed feeds card — what's available + what's roadmap.
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .foregroundStyle(V2Theme.dataAccent)
                    .scaledSystem(14)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Managed feeds")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text("Built-in: abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker) — keyless, \(feedFetchPhrase). See the table below for status. To bring in commercial feeds, drop their IOCs into the threat_intel folder above.")
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 6) {
                        feedChipButton(.urlhaus)
                        feedChipButton(.malwareBazaar)
                        feedChipButton(.feodoTracker)
                    }
                }
                Spacer()
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .v2Panel()

            // API keys card — LLM providers.
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "key.fill")
                    .foregroundStyle(V2Theme.dataAccent)
                    .scaledSystem(14)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("LLM provider API keys")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text("MacCrab's threat-intel feeds don't take an API key — abuse.ch is fully keyless. The only place keys go is the AI Backend (Anthropic, OpenAI, Mistral, Gemini, or remote Ollama). Keys are stored in the macOS Keychain.")
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                    V2ActionButton("Open AI Backend settings", icon: "gearshape", style: .secondary) {
                        V2SettingsBridge.openSettings()
                    }
                }
                Spacer()
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .v2Panel()
        }
    }

    /// Open the daemon's threat_intel cache directory in Finder so
    /// operators can drop their custom.* drop files. Probes both
    /// possible paths (system sysext install vs dev daemon writing
    /// to user-home) and falls back to creating the user-home path
    /// if neither exists yet (it has to exist for Finder to open).
    /// File-picker IOC import flow. Lets the operator pick a text
    /// file (one IOC per line) and a category — hashes / IPs /
    /// domains / URLs — then copies the picked file into
    /// `<threat_intel>/custom.<category>.txt`. The daemon's
    /// ThreatIntelFeed actor re-reads drop files on SIGHUP so we
    /// also signal a refresh after the copy.
    private func importIOCFile() {
        let panel = NSOpenPanel()
        panel.title = "Import IOCs"
        panel.message = "Pick a text file with one indicator per line (hashes, IPs, domains, or URLs)."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.plainText, .text, .data]
        panel.allowsOtherFileTypes = true
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            // Auto-detect category from filename (custom.hashes.txt
            // / custom.ips.txt / etc.) when possible. Fall back to a
            // category prompt otherwise.
            let detected: String? = {
                let n = url.lastPathComponent.lowercased()
                if n.contains("hash")    { return "hashes" }
                if n.contains("ip")      { return "ips" }
                if n.contains("domain")  { return "domains" }
                if n.contains("url")     { return "urls" }
                return nil
            }()
            promptForCategoryIfNeeded(detected: detected) { category in
                guard let category else { return }
                copyIOCFile(url, asCategory: category)
            }
        }
    }

    /// If we auto-detected a category from the filename, use it. Otherwise
    /// pop a small NSAlert with the four standard categories.
    private func promptForCategoryIfNeeded(
        detected: String?,
        completion: @escaping (String?) -> Void
    ) {
        if let detected {
            completion(detected)
            return
        }
        let alert = NSAlert()
        alert.messageText = "What kind of IOCs are these?"
        alert.informativeText = "MacCrab keeps custom IOCs in separate drop files per category. Pick one — you can always edit the file directly later."
        alert.addButton(withTitle: "Hashes (SHA-256)")
        alert.addButton(withTitle: "IPs")
        alert.addButton(withTitle: "Domains")
        alert.addButton(withTitle: "URLs")
        let resp = alert.runModal()
        switch resp {
        case .alertFirstButtonReturn:  completion("hashes")
        case .alertSecondButtonReturn: completion("ips")
        case .alertThirdButtonReturn:  completion("domains")
        // Fourth button uses the implicit alert button index 1003+.
        case NSApplication.ModalResponse(rawValue: 1003): completion("urls")
        default: completion(nil)
        }
    }

    /// Copy the picked file into `<threat_intel>/custom.<category>.txt`,
    /// merging with anything already there. Uses the same path-probe
    /// as `revealThreatIntelDirectory` so the import lands wherever
    /// the daemon writes.
    private func copyIOCFile(_ source: URL, asCategory category: String) {
        let candidates = [
            "/Library/Application Support/MacCrab/threat_intel",
            NSHomeDirectory() + "/Library/Application Support/MacCrab/threat_intel",
        ]
        let dir = candidates.first(where: { FileManager.default.fileExists(atPath: $0) })
            ?? (NSHomeDirectory() + "/Library/Application Support/MacCrab/threat_intel")
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        let dest = dir + "/custom.\(category).txt"
        do {
            // Append-or-create so consecutive imports of multiple
            // files into the same category don't clobber each other.
            let newData = (try? Data(contentsOf: source)) ?? Data()
            if FileManager.default.fileExists(atPath: dest),
               let existing = try? Data(contentsOf: URL(fileURLWithPath: dest)) {
                var merged = existing
                if !merged.isEmpty, merged.last != UInt8(ascii: "\n") {
                    merged.append(UInt8(ascii: "\n"))
                }
                merged.append(newData)
                try merged.write(to: URL(fileURLWithPath: dest))
            } else {
                try newData.write(to: URL(fileURLWithPath: dest))
            }
            state.showToast(V2Toast(
                kind: .success,
                title: "Imported IOCs",
                detail: "→ custom.\(category).txt"
            ))
            // Signal the daemon to re-read.
            Task {
                _ = await state.provider.refreshThreatIntel()
            }
        } catch {
            state.showToast(V2Toast(
                kind: .error,
                title: "Import failed",
                detail: "\(error)"
            ))
        }
    }

    /// Clickable feed chip that opens a read-only detail sheet describing the
    /// built-in (keyless) abuse.ch feed and whether it's currently fetching.
    private func feedChipButton(_ feed: V2FeedConfig) -> some View {
        Button {
            feedSheet = feed
        } label: {
            V2StatusChip(
                feed.label,
                kind: feed.isBuiltIn ? .healthy : .neutral,
                icon: feed.isBuiltIn ? "checkmark.seal" : "clock"
            )
        }
        .buttonStyle(.plain)
        .help(feed.isBuiltIn
              ? "Built-in. Click for details."
              : "Requires an API key. Click for details.")
        .sheet(item: $feedSheet) { selected in
            V2FeedConfigSheet(
                feed: selected,
                onClose: { feedSheet = nil }
            )
        }
    }

    private func revealThreatIntelDirectory() {
        let candidates = [
            "/Library/Application Support/MacCrab/threat_intel",
            NSHomeDirectory() + "/Library/Application Support/MacCrab/threat_intel",
        ]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
            state.showToast(V2Toast(
                kind: .info,
                title: "Opened threat_intel folder",
                detail: path
            ))
            return
        }
        // Fall back to creating the user-home dir + revealing it.
        let userPath = NSHomeDirectory() + "/Library/Application Support/MacCrab/threat_intel"
        try? FileManager.default.createDirectory(
            atPath: userPath, withIntermediateDirectories: true
        )
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: userPath)])
        state.showToast(V2Toast(
            kind: .info,
            title: "Created + opened threat_intel folder",
            detail: userPath
        ))
    }

    /// "Last successful pull" presentation. Reads the cache-backed
    /// `lastSuccessfulPull`: nil → never pulled (only the bundled set
    /// is live); >12h → warn the operator the feeds may be wedged.
    private var lastPullValue: String {
        guard let pull = lastSuccessfulPull else { return "never" }
        return V2TimeFormat.relative(pull)
    }
    private var lastPullTrend: String {
        guard let pull = lastSuccessfulPull else { return "bundled only" }
        return -pull.timeIntervalSinceNow > 12 * 60 * 60 ? "check feeds" : "fresh intel"
    }
    private var lastPullTrendKind: V2ChipKind {
        guard let pull = lastSuccessfulPull else { return .warning }
        return -pull.timeIntervalSinceNow > 12 * 60 * 60 ? .warning : .healthy
    }

    private var feedsSummaryRow: some View {
        // &+ (wrapping): a garbage `entries` value in a corrupt cache must not
        // trap the reducer on Int overflow.
        let totalIOCs = feeds.reduce(0) { $0 &+ max(0, $1.entries) }
        let staleCount = feeds.filter { $0.staleness > 60 * 60 }.count
        let iocText: String = {
            if totalIOCs >= 1_000_000 { return String(format: "%.1fM", Double(totalIOCs) / 1_000_000) }
            if totalIOCs >= 1_000 { return String(format: "%.0fK", Double(totalIOCs) / 1_000) }
            return "\(totalIOCs)"
        }()
        return HStack(spacing: 12) {
            metricCard(title: "Feeds", value: "\(feeds.count)",
                       trend: feeds.isEmpty ? "no feeds" : (staleCount == 0 ? "all healthy" : "\(staleCount) stale"),
                       trendKind: feeds.isEmpty ? .neutral : (staleCount == 0 ? .healthy : .warning),
                       icon: "antenna.radiowaves.left.and.right", iconColor: V2Theme.dataAccent)
            metricCard(title: "Total IOCs", value: iocText,
                       trend: feeds.isEmpty ? "—" : "across \(feeds.count) feeds",
                       trendKind: .info,
                       icon: "shield.checkerboard", iconColor: V2Theme.dataAccent)
            metricCard(title: "Last pull", value: lastPullValue,
                       trend: lastPullTrend,
                       trendKind: lastPullTrendKind,
                       icon: "arrow.down.circle", iconColor: V2Theme.dataAccent)
            metricCard(title: "Stale > 1h", value: "\(staleCount)",
                       trend: staleCount == 0 ? "all fresh" : "review feeds",
                       trendKind: staleCount == 0 ? .healthy : .warning,
                       icon: "clock.arrow.circlepath", iconColor: staleCount == 0 ? V2Theme.healthy : V2Theme.warning)
        }
    }

    private var feedsTable: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Threat intel feeds").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                if !feeds.isEmpty {
                    V2ActionButton("Export…", icon: "square.and.arrow.up", style: .ghost,
                                   tooltip: "Save the feed table as a CSV file") {
                        exportFeedsCSV(feeds)
                    }
                }
                V2ActionButton("Refresh now", icon: "arrow.clockwise", style: .secondary,
                               tooltip: "Queue a refresh for the engine to fetch URLhaus / MalwareBazaar / Feodo") {
                    Task {
                        let ok = await state.provider.refreshThreatIntel()
                        await MainActor.run {
                            if ok {
                                state.showToast(V2Toast(
                                    kind: .info,
                                    title: "Refresh queued",
                                    detail: "Feeds will update within ~10 seconds"
                                ))
                            } else {
                                state.showToast(V2Toast(
                                    kind: .error,
                                    title: "Refresh failed",
                                    detail: state.provider.lastErrorDescription
                                        ?? "no daemon to signal"
                                ))
                            }
                        }
                        // Re-poll feeds in 6s so the table reflects the
                        // post-refresh state once the daemon writes the
                        // new feed_cache.json.
                        try? await Task.sleep(nanoseconds: 6_000_000_000)
                        await MainActor.run { state.refreshTick += 1 }
                    }
                }
            }
            V2DataTable(
                columns: [
                    V2DataColumn(id: "name", title: "Feed", width: .flexible(min: 220),
                                 sortKey: { .text($0.name) }) { f in
                        V2TableCellText(f.name)
                    },
                    V2DataColumn(id: "kind", title: "Kind", width: .fixed(140),
                                 sortKey: { .text($0.kind) }) { f in
                        V2TableCellText(f.kind, primary: false)
                    },
                    V2DataColumn(id: "entries", title: "Entries", width: .fixed(110),
                                 sortKey: { .number(Double($0.entries)) }) { f in
                        V2TableCellText("\(f.entries)", mono: true)
                    },
                    V2DataColumn(id: "fetch", title: "Last fetch", width: .fixed(120),
                                 sortKey: { .date($0.lastFetch) }) { f in
                        V2TableCellText(V2TimeFormat.relative(f.lastFetch), primary: false)
                    },
                    V2DataColumn(id: "status", title: "Status", width: .fixed(110),
                                 sortKey: { .text($0.lastError != nil ? "Failing" : ($0.staleness > 3600 ? "Stale" : "Healthy")) }) { f in
                        let label = f.lastError != nil ? "Failing"
                            : (f.staleness > 60 * 60 ? "Stale" : "Healthy")
                        let kind: V2ChipKind = (f.lastError != nil || f.staleness > 60 * 60)
                            ? .warning : .healthy
                        V2StatusChip(label, kind: kind)
                    },
                    V2DataColumn(id: "error", title: "Last error", width: .flexible(min: 160),
                                 sortKey: { .text($0.lastError ?? "") }) { f in
                        V2TableCellText(f.lastError ?? "—", primary: false)
                    },
                ],
                items: feeds,
                selection: .constant(nil),
                searchPrompt: "Filter feeds…"
            )
            .frame(minHeight: 280)
        }
    }

    /// ruleId prefix part A writes IOC-match alerts under. The match
    /// type (Hash / IP / Domain / URL / DNS) is the suffix after this.
    static let iocMatchRulePrefix = "maccrab.threat-intel."

    /// Map a `maccrab.threat-intel.<suffix>` ruleId to a short IOC type.
    private func iocType(forRuleId ruleId: String) -> String {
        let suffix = ruleId.hasPrefix(Self.iocMatchRulePrefix)
            ? String(ruleId.dropFirst(Self.iocMatchRulePrefix.count))
            : ruleId
        switch suffix {
        case "hash-match":   return "Hash"
        case "ip-match":     return "IP"
        case "domain-match": return "Domain"
        case "url-match":    return "URL"
        case "dns-match", "maccrab.dns.threat-intel-match": return "DNS"
        default:             return suffix
        }
    }

    /// Table of recent IOC matches: what the indicator hit (ruleTitle),
    /// its type, the indicator + source/family (description), the
    /// process it touched, and when. Reads from `matches`, populated
    /// in the workspace `.task` from the alert store.
    private var matchesTable: some View {
        // D8: honor the palette `ip:` "Search IOC matches" pre-filter so the
        // count + empty-state + rows all reflect the searched needle.
        let rows = filteredMatches
        let searching = (state.pendingIntelQuery?.isEmpty == false)
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("IOC matches").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                Text(rows.isEmpty
                     ? (searching ? "no matches for search" : "none in window")
                     : (searching ? "\(rows.count) matching" : "\(rows.count) in last 7d"))
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                if !rows.isEmpty {
                    V2ActionButton("Export…", icon: "square.and.arrow.up", style: .ghost,
                                   tooltip: "Save the IOC matches below as a CSV file") {
                        exportMatchesCSV(rows)
                    }
                }
            }
            if rows.isEmpty {
                Text(searching
                     ? "No IOC matches mention this indicator. Clear the search above to see all recent threat-intel feed matches."
                     : "No threat-intel feed matches recorded. When a process touches a known-bad hash, IP, domain or URL from the loaded feeds, the hit appears here.")
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.mutedText)
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .v2Panel()
            } else {
                // Floating inspector overlay (same pattern as packagesTable):
                // selecting a match slides in a drill-in with the indicator,
                // process, and ATT&CK context so triage isn't a dead end.
                ZStack(alignment: .topTrailing) {
                    V2DataTable(
                        columns: [
                            V2DataColumn(id: "hit", title: "What it hit", width: .flexible(min: 200),
                                         sortKey: { .text($0.title) }) { m in
                                V2TableCellText(m.title)
                            },
                            V2DataColumn(id: "type", title: "Type", width: .fixed(90),
                                         sortKey: { .text(iocType(forRuleId: $0.ruleId)) }) { m in
                                V2StatusChip(iocType(forRuleId: m.ruleId), kind: .data)
                            },
                            V2DataColumn(id: "indicator", title: "Indicator / source", width: .flexible(min: 220),
                                         sortKey: { .text($0.description) }) { m in
                                V2TableCellText(m.description, primary: false, mono: true, lineLimit: 2)
                            },
                            V2DataColumn(id: "process", title: "Process", width: .fixed(180),
                                         sortKey: { .text($0.process) }) { m in
                                V2TableCellText(m.process, primary: false)
                            },
                            V2DataColumn(id: "when", title: "When", width: .fixed(120),
                                         sortKey: { .date($0.timestamp) }) { m in
                                V2TableCellText(V2TimeFormat.relative(m.timestamp), primary: false)
                            },
                        ],
                        items: rows,
                        selection: $selectedMatch,
                        searchPrompt: "Filter matches…"
                    )
                    .frame(minHeight: 220)
                    if let m = selectedMatch {
                        matchInspector(m)
                            .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                            .transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))
                    }
                }
                .animation(V2Motion.inspectorPresent(reduceMotion: reduceMotion), value: selectedMatch?.id)
            }
        }
    }

    /// Drill-in for a selected IOC match. Surfaces the full indicator/source,
    /// the process it touched, severity, and any ATT&CK codes so the operator
    /// can pivot instead of hitting a dead-end row.
    @ViewBuilder
    private func matchInspector(_ m: V2MockAlert) -> some View {
        V2Inspector(title: m.title,
                    subtitle: "\(iocType(forRuleId: m.ruleId)) match",
                    onClose: { selectedMatch = nil }) {
            V2InspectorSection(String(localized: "inspector.match", defaultValue: "Match")) {
                V2InspectorKeyValue("Type", iocType(forRuleId: m.ruleId))
                V2InspectorKeyValue("Severity", m.severity.label)
                V2InspectorKeyValue("When", V2TimeFormat.relative(m.timestamp))
            }
            V2InspectorSection(String(localized: "inspector.indicator", defaultValue: "Indicator / source")) {
                Text(m.description.isEmpty ? "—" : m.description)
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.primaryText)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection(String(localized: "inspector.process", defaultValue: "Process")) {
                V2InspectorKeyValue("Name", m.process.isEmpty ? "—" : m.process)
                if !m.processPath.isEmpty { V2InspectorKeyValue("Path", m.processPath, mono: true) }
                if m.pid > 0 { V2InspectorKeyValue("PID", "\(m.pid)", mono: true) }
                if !m.parent.isEmpty { V2InspectorKeyValue("Parent", m.parent, mono: true) }
            }
            if !m.mitre.isEmpty {
                V2InspectorSection(String(localized: "inspector.attack", defaultValue: "ATT&CK")) {
                    Text(m.mitre.joined(separator: ", "))
                        .font(V2Theme.mono())
                        .foregroundStyle(V2Theme.primaryText)
                        .textSelection(.enabled)
                }
            }
        }
    }

    // MARK: - Package freshness

    private var packageFreshnessTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                packageScanRow
                if packages.isEmpty {
                    // Three distinct empty states: scanning, scanned-but-empty
                    // (a legit "no packages on this machine" result), and
                    // never-scanned. Pre-fix a completed scan that found zero
                    // packages fell through to "No package scan yet", telling
                    // the operator to run a scan they had already run.
                    Group {
                        if packageScanInProgress {
                            V2EmptyState(
                                title: "Scanning installed packages…",
                                body: "Querying npm, PyPI, Homebrew, and Cargo registries for the packages installed on this machine. The first scan can take 30-90 seconds depending on how many packages you have.",
                                icon: "magnifyingglass.circle"
                            )
                        } else if packageLastScannedAt != nil {
                            V2EmptyState(
                                title: "Scan complete — no packages found",
                                body: "MacCrab found no npm, PyPI, Homebrew, or Cargo packages installed on this machine, so there's nothing to check for freshness. Install packages with one of those managers and re-scan.",
                                icon: "checkmark.circle"
                            )
                        } else {
                            V2EmptyState(
                                title: "No package scan yet",
                                body: "Click \"Run scan\" above to query the npm, PyPI, Homebrew, and Cargo registries for the packages installed on this machine. Slopsquatting, dependency-confusion, and freshly-published-malicious-package indicators all surface here.",
                                icon: "shippingbox"
                            )
                        }
                    }
                    .v2Panel()
                } else {
                    packageSummaryRow
                    packagesTable
                }
            }
            .padding(16)
        }
    }

    /// Scan controls — run a fresh package-registry scan and show
    /// when it last completed. Pre-fix the package tab loaded an empty
    /// table with no affordance to populate it; the v1 dashboard had
    /// a Scan button but the v2 design lost it during the rewrite.
    private var packageScanRow: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Package freshness")
                    .font(V2Theme.sectionTitle())
                    .foregroundStyle(V2Theme.primaryText)
                Text(scanStatusLine)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            }
            Spacer()
            if packageScanInProgress {
                ProgressView().controlSize(.small)
                    .padding(.trailing, 4)
            }
            V2ActionButton(
                packageScanInProgress ? "Scanning…" : (packages.isEmpty ? "Run scan" : "Re-scan"),
                icon: "magnifyingglass.circle",
                style: .primary,
                disabled: packageScanInProgress || !enrichPackageFreshness
            ) {
                Task { await runPackageScan() }
            }
        }
        .padding(14)
        .v2Panel()
    }

    private var scanStatusLine: String {
        if packageScanInProgress {
            return "Querying registries… this can take 30-90 s on a fresh scan."
        }
        if !enrichPackageFreshness {
            return "Enable “Package freshness” in the Threat Intel tab to query npm / PyPI / Homebrew / Cargo. A scan uploads installed-package names; off by default."
        }
        if let last = packageLastScannedAt {
            return "Last scan completed \(V2TimeFormat.relative(last)). Click Re-scan to refresh."
        }
        return "No scan run yet. Click Run scan to query npm / PyPI / Homebrew / Cargo for installed packages."
    }

    /// Run a real package scan via PackageFreshnessChecker. Two
    /// parallel passes off-main: (a) the registry scan that returns
    /// each package's `latestVersion` + risk info, and (b) a local
    /// `installedVersions()` snapshot so the table can compare
    /// installed-vs-latest accurately. Pre-fix `installed` and
    /// `latest` were both set to `info.latestVersion` so every row
    /// rendered "Up to date" regardless of actual local state.
    private func runPackageScan() async {
        // Privacy opt-in: a package scan uploads the installed-package inventory
        // names to npm/PyPI/Homebrew/crates. Honor the same
        // `enrich.packageFreshness` opt-in the enrichment card exposes (and the
        // daemon gates on) so nothing leaves the Mac until the user turns it on.
        guard enrichPackageFreshness else {
            state.showToast(V2Toast(
                kind: .warning,
                title: "Package freshness is off",
                detail: "Enable “Package freshness” in the Threat Intel tab to query registries."))
            return
        }
        await MainActor.run { self.packageScanInProgress = true }
        let (scanned, installedMap): ([PackageFreshnessChecker.PackageInfo], [String: String]) =
            await withTaskGroup(of: ScanComponent.self) { group in
                group.addTask(priority: .userInitiated) {
                    let checker = PackageFreshnessChecker()
                    return .scanned(await checker.scanInstalledPackages())
                }
                group.addTask(priority: .userInitiated) {
                    let checker = PackageFreshnessChecker()
                    return .installed(checker.installedVersions())
                }
                var s: [PackageFreshnessChecker.PackageInfo] = []
                var i: [String: String] = [:]
                for await component in group {
                    switch component {
                    case .scanned(let v):   s = v
                    case .installed(let m): i = m
                    }
                }
                return (s, i)
            }

        // v1.12.0 post-audit (H-Int3): pull the typosquat-enriched
        // PackageScanner inventory once so the manual "Run scan" path
        // surfaces the same intelligence fields as the periodic
        // auto-refresh. Pre-fix this mapper omitted the new fields and
        // every "Run scan" click wiped the Supply-chain inspector
        // indicators. Map by `manager:name` key.
        let intelligenceMap: [String: PackageInfo] = await {
            let infos = await Self.scanIntelligenceCache.scan()
            var out: [String: PackageInfo] = [:]
            for info in infos { out[info.id] = info }
            return out
        }()

        let mapped = scanned.map { info -> V2MockPackage in
            let key = "\(info.registry.rawValue):\(info.name)"
            let installedVer = installedMap[key] ?? "—"
            let latestVer = info.latestVersion ?? "—"
            // The v1.12 intelligence fields live on the
            // PackageScanner-provided `PackageInfo` keyed by
            // `<manager>:<name>` — same shape as `info.id`. Map by name
            // since registry namespaces match (npm <-> npm, pypi <-> pip).
            let intelInfo = intelligenceMap[managerKey(registry: info.registry.rawValue, name: info.name)]
            return V2MockPackage(
                id: key,
                name: info.name,
                installed: installedVer,
                latest: latestVer,
                manager: info.registry.rawValue,
                // PackageFreshnessChecker carries no CVE data — `isFresh` is a
                // "freshly published" signal, not a vulnerability count. Storing
                // it here rendered brand-new packages as "Vulns: 1" and offered a
                // bogus CVE lookup. Real vuln counts arrive via the auto-refresh
                // PackageScanner path (currently 0 until OSV.dev wiring lands).
                vulnCount: 0,
                // `staleness` is a TimeInterval in SECONDS (V2TimeFormat.staleness
                // reads it as seconds, matching the auto-refresh path's
                // `stalenessSeconds`). `ageInDays` is DAYS, so scale up — pre-fix a
                // 400-day-old package rendered as "6m".
                staleness: (info.ageInDays ?? 0) * 86400,
                typosquatScore: intelInfo?.typosquatScore,
                typosquatSimilarTo: intelInfo?.typosquatSimilarTo,
                attestationStatus: intelInfo?.attestationStatus,
                contentRedFlags: intelInfo?.contentRedFlags
            )
        }
        await MainActor.run {
            self.packages = mapped
            self.packageScanInProgress = false
            self.packageLastScannedAt = Date()
            state.showToast(V2Toast(
                kind: .success,
                title: "Package scan complete",
                detail: "\(mapped.count) packages inspected"
            ))
        }
    }

    /// Tagged-union return for the parallel scan task group. Used
    /// only inside `runPackageScan` so the registry scan and the
    /// local-version snapshot can complete concurrently.
    private enum ScanComponent: @unchecked Sendable {
        case scanned([PackageFreshnessChecker.PackageInfo])
        case installed([String: String])
    }

    private var packageSummaryRow: some View {
        let total = packages.count
        let outdated = packages.filter { $0.installed != $0.latest }.count
        // &+ (wrapping): guard against Int overflow from a corrupt vulnCount.
        let vulns = packages.reduce(0) { $0 &+ max(0, $1.vulnCount) }
        return HStack(spacing: 12) {
            metricCard(title: "Tracked", value: "\(total)",
                       trend: "brew + npm + pip", trendKind: .info,
                       icon: "shippingbox.fill", iconColor: V2Theme.dataAccent)
            metricCard(title: "Outdated", value: "\(outdated)",
                       trend: "non-blocking", trendKind: .warning,
                       icon: "arrow.clockwise.circle", iconColor: V2Theme.warning)
            metricCard(title: "Vulns", value: "\(vulns)",
                       trend: "review queue", trendKind: .high,
                       icon: "exclamationmark.shield", iconColor: V2Theme.high)
            metricCard(title: "Up to date", value: "\(total - outdated)",
                       trend: "no action", trendKind: .healthy,
                       icon: "checkmark.seal", iconColor: V2Theme.healthy)
        }
    }

    private var packagesTable: some View {
        // v1.12.9: floating inspector overlay (see V2AlertsWorkspace
        // for the rationale). HStack push-layout overflowed the
        // window at the 1180 minimum; ZStack lets the package
        // inspector float over the rightmost ~340 pt of the
        // packages table.
        ZStack(alignment: .topTrailing) {
            V2DataTable(
                columns: [
                    V2DataColumn(id: "name", title: "Package", width: .flexible(min: 200),
                                 sortKey: { .text($0.name) }) { p in
                        V2TableCellText(p.name)
                    },
                    V2DataColumn(id: "manager", title: "Manager", width: .fixed(100),
                                 sortKey: { .text($0.manager) }) { p in
                        V2StatusChip(p.manager, kind: .data)
                    },
                    V2DataColumn(id: "installed", title: "Installed", width: .fixed(120),
                                 sortKey: { .text($0.installed) }) { p in
                        V2TableCellText(p.installed, primary: false, mono: true)
                    },
                    V2DataColumn(id: "latest", title: "Latest", width: .fixed(120),
                                 sortKey: { .text($0.latest) }) { p in
                        V2TableCellText(p.latest, primary: false, mono: true)
                    },
                    V2DataColumn(id: "vuln", title: "Vulns", width: .fixed(80),
                                 sortKey: { .number(Double($0.vulnCount)) }) { p in
                        if p.vulnCount > 0 {
                            V2StatusChip("\(p.vulnCount)", kind: .high)
                        } else {
                            Text("0").foregroundStyle(V2Theme.tertiaryText).font(V2Theme.meta())
                        }
                    },
                    V2DataColumn(id: "stale", title: "Behind", width: .fixed(110),
                                 sortKey: { .number($0.staleness) }) { p in
                        V2TableCellText(V2TimeFormat.staleness(p.staleness), primary: false)
                    },
                ],
                items: packages,
                selection: $selectedPackage,
                searchPrompt: "Filter packages…"
            )
            .frame(minHeight: 360, maxHeight: .infinity)
            if let pkg = selectedPackage {
                packageInspector(pkg)
                    .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                    .transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))
            }
        }
        .animation(V2Motion.inspectorPresent(reduceMotion: reduceMotion), value: selectedPackage?.id)
    }

    @ViewBuilder
    private func packageInspector(_ pkg: V2MockPackage) -> some View {
        V2Inspector(title: pkg.name,
                    subtitle: "\(pkg.manager) · installed \(pkg.installed)",
                    onClose: { selectedPackage = nil }) {
            V2InspectorSection(String(localized: "inspector.status", defaultValue: "Status")) {
                V2InspectorKeyValue("Installed", pkg.installed, mono: true)
                V2InspectorKeyValue("Latest", pkg.latest, mono: true)
                let outdated = pkg.installed != pkg.latest
                V2InspectorKeyValue("State", outdated ? "Outdated" : "Up to date")
                V2InspectorKeyValue("Behind", V2TimeFormat.staleness(pkg.staleness))
                V2InspectorKeyValue("Vulnerabilities", "\(pkg.vulnCount)", mono: true)
            }
            V2InspectorSection(String(localized: "inspector.updateCommand", defaultValue: "Update command")) {
                let cmd = upgradeCommand(for: pkg)
                HStack(spacing: 6) {
                    Text(cmd)
                        .font(V2Theme.mono())
                        .foregroundStyle(V2Theme.primaryText)
                        .textSelection(.enabled)
                        .lineLimit(2)
                    Spacer()
                    V2ActionButton("Copy", icon: "doc.on.doc", style: .ghost) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(cmd, forType: .string)
                        state.showToast(V2Toast(kind: .success, title: "Command copied", detail: nil))
                    }
                }
            }
            if pkg.vulnCount > 0 {
                V2InspectorSection(String(localized: "inspector.cves", defaultValue: "CVEs")) {
                    // `maccrabctl vulns` takes only --hours / --severity — it has
                    // no package positional and ignores any name argument, so
                    // suggest the real command and tell the operator to look for
                    // this package in the (unfiltered) list.
                    Text("List all CVE-scanner vuln alerts via the CLI, then look for “\(pkg.name)”:")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                    HStack(spacing: 6) {
                        Text("maccrabctl vulns")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                            .textSelection(.enabled)
                        Spacer()
                        V2ActionButton("Copy", icon: "doc.on.doc", style: .ghost) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("maccrabctl vulns", forType: .string)
                            state.showToast(V2Toast(kind: .success, title: "Command copied", detail: nil))
                        }
                    }
                }
            }

            // v1.12.0 — supply-chain intelligence section. Only renders
            // when at least one of the four fields is populated. Single
            // section keeps the inspector compact when none of the
            // signals fired; bumps a chip when something is concerning.
            //
            // v1.12.0 post-audit (M-UI1): "Supply chain", "Typosquat",
            // "Attestation", "Content flags" are bare-literal English
            // strings here. The entire V2IntelligenceWorkspace.swift
            // file does not use `String(localized:)`; adding it to
            // only these four would create inconsistency. A workspace-
            // wide localization sweep is queued for v1.12.x — it
            // should pick these up at the same time.
            let hasSupplyChainSignal = pkg.typosquatScore != nil
                || pkg.attestationStatus != nil
                || (pkg.contentRedFlags?.isEmpty == false)
            if hasSupplyChainSignal {
                V2InspectorSection(String(localized: "inspector.supplyChain", defaultValue: "Supply chain")) {
                    if let score = pkg.typosquatScore {
                        V2InspectorKeyValue("Typosquat", typosquatDisplay(score: score, similarTo: pkg.typosquatSimilarTo, isLikely: pkg.isLikelyTyposquat))
                    }
                    if let status = pkg.attestationStatus {
                        V2InspectorKeyValue("Attestation", attestationDisplay(status))
                    }
                    if let flags = pkg.contentRedFlags, !flags.isEmpty {
                        V2InspectorKeyValue("Content flags", flags.joined(separator: ", "))
                    }
                }
            }
        }
    }

    // v1.12.0 post-audit (H-Int3): shared PackageScanner cache used by
    // the manual "Run scan" path so the intelligence fields flow
    // through to V2MockPackage. The 5-minute cache inside PackageScanner
    // absorbs the cost of repeated scans.
    private static let scanIntelligenceCache: PackageScanner = PackageScanner()

    /// Map the PackageFreshnessChecker's `registry` field to the
    /// PackageScanner's `manager:name` id shape.
    private func managerKey(registry: String, name: String) -> String {
        let manager: String
        switch registry.lowercased() {
        case "npm":     manager = "npm"
        case "pypi":    manager = "pip"
        case "homebrew", "brew": manager = "brew"
        default:        manager = registry.lowercased()
        }
        return "\(manager):\(name)"
    }

    // v1.12.0 — helpers extracted from the inspector ViewBuilder so the
    // if/else chains don't get parsed as View construction.
    private func typosquatDisplay(score: Int, similarTo: String?, isLikely: Bool) -> String {
        let similar = similarTo.map { " (similar to `\($0)`)" } ?? ""
        if isLikely {
            return "⚠️ Likely typosquat — score \(score)\(similar)"
        }
        if score > 0 {
            return "Score \(score)\(similar)"
        }
        return "Clean (no top-corpus match within range)"
    }

    private func attestationDisplay(_ status: String) -> String {
        switch status {
        case "verified": return "✓ Verified (Sigstore / PEP 740)"
        case "missing":  return "Not published with provenance"
        case "invalid":  return "⚠️ Builder mismatch vs prior versions"
        default:         return status
        }
    }

    /// Manager-aware upgrade command. Falls back to a brew upgrade for
    /// any unrecognised manager.
    private func upgradeCommand(for pkg: V2MockPackage) -> String {
        switch pkg.manager.lowercased() {
        case "brew", "homebrew":   return "brew upgrade \(pkg.name)"
        case "npm":                return "npm install -g \(pkg.name)@latest"
        case "pip", "pip3":        return "pip3 install --upgrade \(pkg.name)"
        case "cargo":              return "cargo install --force \(pkg.name)"
        case "gem":                return "gem update \(pkg.name)"
        case "go":                 return "go install \(pkg.name)@latest"
        default:                   return "brew upgrade \(pkg.name)"
        }
    }

    // MARK: - Integrations

    private var integrationsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle").foregroundStyle(V2Theme.mutedText)
                    // v1.12.5 fix: Text-in-Text interpolation
                    // (`Text("foo \(Text("bar").bold())")`) doesn't
                    // render the inner view — SwiftUI calls
                    // `description` on the modified Text struct and
                    // splices that dump into the parent, producing
                    // "Modified­Content<Text, _ForegroundStyleModifier
                    // <Color>>(content: …" garbage on screen. Use
                    // markdown-style `**bold**` instead — SwiftUI Text
                    // initialized from LocalizedStringKey renders
                    // `**…**` as bold natively.
                    Text("Two surfaces: **Detected security tools** (other macOS security software MacCrab observed on this machine — Objective-See suite, Little Snitch, commercial EDR, etc.) and **Configured output sinks** (alert destinations you wired into `daemon_config.json` / `notifications.json` — Splunk, Slack, S3, etc.). Status reflects 'configured' / 'running' / 'installed'.")
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .v2Panel()

                if integrations.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: "powerplug").foregroundStyle(V2Theme.mutedText)
                        Text("Nothing to surface yet. MacCrab hasn't detected any third-party security tools on this machine and no output sinks are configured. To wire alerts to Splunk / Slack / S3 / etc., drop a `daemon_config.json` (outputs[]) or `notifications.json` into `/Library/Application Support/MacCrab/`. Discovered tools (BlockBlock, LuLu, KnockKnock, OverSight, Santa, Little Snitch, etc.) appear here automatically after the daemon's next scan (~2 min).")
                            .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .v2Panel()
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Configured integrations & detected tools (\(integrations.count))")
                            .font(V2Theme.sectionTitle())
                            .foregroundStyle(V2Theme.primaryText)
                        VStack(spacing: 6) {
                            ForEach(integrations) { integ in
                                HStack(spacing: 12) {
                                    Image(systemName: iconForIntegration(integ))
                                        .foregroundStyle(integ.status.chipKind.color)
                                        .frame(width: 18)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(integ.name)
                                            .font(V2Theme.body())
                                            .foregroundStyle(V2Theme.primaryText)
                                        Text(integ.detail)
                                            .font(V2Theme.meta())
                                            .foregroundStyle(V2Theme.mutedText)
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                    }
                                    Spacer()
                                    V2StatusChip(integ.kind, kind: .neutral)
                                    V2StatusChip(integ.status.label, kind: integ.status.chipKind)
                                }
                                .padding(.vertical, 8)
                                .padding(.horizontal, 10)
                                .background(V2Theme.panelBackground)
                                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                            }
                        }
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .v2Panel()
                }
            }
            .padding(16)
        }
    }

    private func iconForIntegration(_ integ: V2MockIntegration) -> String {
        switch integ.kind {
        case "webhook":      return "bubble.left.and.bubble.right"
        case "siem":         return "server.rack"
        case "file":         return "doc.text"
        case "object-store": return "archivebox"
        case "telemetry":    return "chart.line.uptrend.xyaxis"
        case "notification": return "bell.badge"
        default:             return "powerplug"
        }
    }

    // MARK: - CSV export

    /// Save the (already-filtered) IOC-match rows as CSV via NSSavePanel.
    private func exportMatchesCSV(_ rows: [V2MockAlert]) {
        let header = ["what_it_hit", "type", "indicator_source", "process", "when"]
        let records = rows.map { m in
            [m.title, iocType(forRuleId: m.ruleId), m.description, m.process,
             Self.csvTimestamp.string(from: m.timestamp)]
        }
        writeCSV(header: header, rows: records, suggestedName: "maccrab-ioc-matches")
    }

    /// Save the feed table as CSV via NSSavePanel.
    private func exportFeedsCSV(_ rows: [V2MockFeed]) {
        let header = ["feed", "kind", "entries", "last_fetch", "status", "last_error"]
        let records = rows.map { f -> [String] in
            let status = f.lastError != nil ? "Failing" : (f.staleness > 60 * 60 ? "Stale" : "Healthy")
            return [f.name, f.kind, "\(f.entries)",
                    Self.csvTimestamp.string(from: f.lastFetch),
                    status, f.lastError ?? ""]
        }
        writeCSV(header: header, rows: records, suggestedName: "maccrab-threat-intel-feeds")
    }

    /// Shared CSV writer: RFC-4180 quoting, off-main write, success/failure
    /// toast. Uses `.data` content type so macOS doesn't append a second
    /// extension (same reason V2AlertsWorkspace's JSONL export does).
    private func writeCSV(header: [String], rows: [[String]], suggestedName: String) {
        let panel = NSSavePanel()
        panel.title = "Export CSV"
        panel.allowedContentTypes = [.data]
        panel.allowsOtherFileTypes = true
        let stamp = Self.csvFilenameStamp.string(from: Date())
        panel.nameFieldStringValue = "\(suggestedName)-\(stamp).csv"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                func esc(_ s: String) -> String {
                    guard s.contains(",") || s.contains("\"") || s.contains("\n") else { return s }
                    return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
                }
                var out = header.map(esc).joined(separator: ",") + "\n"
                for r in rows { out += r.map(esc).joined(separator: ",") + "\n" }
                let ok = (try? out.write(to: url, atomically: true, encoding: .utf8)) != nil
                DispatchQueue.main.async {
                    state.showToast(V2Toast(
                        kind: ok ? .success : .error,
                        title: ok ? "Exported" : "Export failed",
                        detail: ok ? url.lastPathComponent : nil))
                }
            }
        }
    }

    private static let csvTimestamp: ISO8601DateFormatter = ISO8601DateFormatter()
    private static let csvFilenameStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd-HHmm"
        f.timeZone = TimeZone.current
        return f
    }()

    // MARK: - Shared

    private func metricCard(title: String, value: String, trend: String, trendKind: V2ChipKind,
                            icon: String, iconColor: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(iconColor).scaledSystem(11, weight: .semibold)
                Text(title.uppercased()).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.mutedText)
            }
            Text(value).scaledSystem(22, weight: .bold).foregroundStyle(V2Theme.primaryText)
            V2StatusChip(trend, kind: trendKind)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }
}

// MARK: - V2FeedConfig + V2FeedConfigSheet

/// Identity / metadata for the threat-intel feed chips. All shipped feeds are
/// the built-in, keyless abuse.ch sources.
// NOTE: the commercial API-key feeds (VirusTotal / GreyNoise / AlienVault OTX)
// were removed here — they were orphaned: no chip ever rendered them, and any
// key saved to the Keychain was never read by a live consumer (the
// ThreatIntelAPIs actor is never instantiated). See the deep-audit residual
// note to also drop the now-unreferenced ThreatIntelAPIs actor + the
// SecretKey.virusTotalKey/.greyNoiseKey/.alienVaultKey cases in MacCrabCore.
public enum V2FeedConfig: String, Identifiable, CaseIterable {
    case urlhaus
    case malwareBazaar
    case feodoTracker

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .urlhaus:        return "abuse.ch URLhaus"
        case .malwareBazaar:  return "abuse.ch MalwareBazaar"
        case .feodoTracker:   return "abuse.ch Feodo Tracker"
        }
    }

    /// All shipped feeds are built-in (keyless). Retained as a property so the
    /// chip / sheet styling reads intent, and so a future keyed feed can flip it.
    public var isBuiltIn: Bool { true }

    public var description: String {
        switch self {
        case .urlhaus:
            return "abuse.ch URLhaus — community-curated malicious URL feed. Keyless and download-only (nothing about your machine is uploaded). OFF by default — opt in to threat-intel enrichment to fetch every 4 hours; bundled IOCs work offline until then."
        case .malwareBazaar:
            return "abuse.ch MalwareBazaar — SHA-256 hashes for known-bad samples. Keyless, download-only. OFF by default — opt in to threat-intel enrichment to fetch every 4 hours."
        case .feodoTracker:
            return "abuse.ch Feodo Tracker — IP addresses of active C2 infrastructure for Emotet, Dridex, TrickBot and similar bankers. Keyless, download-only. OFF by default — opt in to threat-intel enrichment to fetch every 4 hours."
        }
    }
}

/// Modal sheet describing a built-in threat-intel feed. Read-only: every
/// shipped feed is a keyless abuse.ch source, so there is no API-key form.
public struct V2FeedConfigSheet: View {
    let feed: V2FeedConfig
    let onClose: () -> Void

    // The built-in feeds only fetch when threat-intel enrichment is opted in
    // (the daemon gates egress on this key), so the status chip reflects that
    // rather than claiming "always-on" — which contradicted the opt-in card.
    @AppStorage("enrich.threatIntel") private var enrichThreatIntel: Bool = false

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "checkmark.seal.fill")
                    .foregroundStyle(V2Theme.healthy)
                    .scaledSystem(18, weight: .semibold)
                Text(feed.label)
                    .font(V2Theme.workspaceTitle())
                    .foregroundStyle(V2Theme.primaryText)
                Spacer()
                Button {
                    onClose()
                } label: {
                    Image(systemName: "xmark")
                        .scaledSystem(11, weight: .semibold)
                        .foregroundStyle(V2Theme.mutedText)
                        .frame(width: 26, height: 26)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.cancelAction)
            }

            if enrichThreatIntel {
                V2StatusChip("Built-in · active — fetched every 4h", kind: .healthy, icon: "checkmark.seal")
            } else {
                V2StatusChip("Built-in · opt in to enable fetching", kind: .info, icon: "checkmark.seal")
            }

            Text(feed.description)
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(20)
        .frame(width: 460)
    }
}
