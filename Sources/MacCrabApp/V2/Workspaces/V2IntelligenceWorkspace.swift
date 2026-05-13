// V2IntelligenceWorkspace.swift
// Spec §7.5 — feeds, IOC matches, package freshness, integrations.

import SwiftUI
import AppKit
import MacCrabCore

public struct V2IntelligenceWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @State private var feeds: [V2MockFeed] = []
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
            async let f = state.provider.feeds()
            async let p = state.provider.packages()
            async let i = state.provider.integrations()
            let (feedsResult, pkgsResult, integResult) = await (f, p, i)
            await MainActor.run {
                self.feeds = feedsResult
                // Only seed packages from the live provider when the
                // user hasn't run an explicit scan (which uses the
                // older PackageFreshnessChecker for richer data).
                // Manual scan results win over auto-refresh.
                if self.packageLastScannedAt == nil && !pkgsResult.isEmpty {
                    self.packages = pkgsResult
                }
                self.integrations = integResult
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
                apiKeysHelpCard
                feedsSummaryRow
                feedsTable
            }
            .padding(16)
        }
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
                    .font(.system(size: 14))
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Add custom feeds & IOCs")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text("MacCrab's built-in feeds are abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker) — keyless, fetched every 4 hours. To add operator-supplied indicators, drop a text file (one IOC per line) into the threat_intel directory:")
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
                    .font(.system(size: 14))
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Managed feeds")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text("Built-in: abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker) — keyless, fetched every 4 hours, see the table below for status. To bring in commercial feeds, drop the IOCs into the threat_intel folder above; native VirusTotal / GreyNoise / OTX integrations are on the v1.11 roadmap (filed at github.com/peterhanily/maccrab/issues — comment with the feed you need most).")
                        .font(V2Theme.body())
                        .foregroundStyle(V2Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 6) {
                        feedChipButton(.urlhaus)
                        feedChipButton(.malwareBazaar)
                        feedChipButton(.feodoTracker)
                        feedChipButton(.virusTotal)
                        feedChipButton(.greyNoise)
                        feedChipButton(.alienVaultOTX)
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
                    .font(.system(size: 14))
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

    /// Clickable feed chip with config sheet on click. Built-in
    /// feeds show a read-only "always-on" sheet; roadmap feeds show
    /// an API-key form that stores the key in Keychain via
    /// SecretsStore so the v1.11 integration can pick it up.
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
              : "Coming in v1.11. Click to save your API key now.")
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

    private var feedsSummaryRow: some View {
        let totalIOCs = feeds.reduce(0) { $0 + $1.entries }
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
            metricCard(title: "Matches (24h)", value: "—",
                       trend: "intel matches",
                       trendKind: .neutral,
                       icon: "burst.fill", iconColor: V2Theme.dataAccent)
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
                V2ActionButton("Refresh now", icon: "arrow.clockwise", style: .secondary,
                               tooltip: "Signal the daemon (SIGHUP) to fetch URLhaus / MalwareBazaar / Feodo immediately") {
                    Task {
                        let ok = await state.provider.refreshThreatIntel()
                        await MainActor.run {
                            if ok {
                                state.showToast(V2Toast(
                                    kind: .info,
                                    title: "Refresh signaled",
                                    detail: "Feeds will update within ~5 seconds"
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
                    V2DataColumn(id: "name", title: "Feed", width: .flexible(min: 220)) { f in
                        V2TableCellText(f.name)
                    },
                    V2DataColumn(id: "kind", title: "Kind", width: .fixed(140)) { f in
                        V2TableCellText(f.kind, primary: false)
                    },
                    V2DataColumn(id: "entries", title: "Entries", width: .fixed(110)) { f in
                        V2TableCellText("\(f.entries)", mono: true)
                    },
                    V2DataColumn(id: "fetch", title: "Last fetch", width: .fixed(120)) { f in
                        V2TableCellText(V2TimeFormat.relative(f.lastFetch), primary: false)
                    },
                    V2DataColumn(id: "status", title: "Status", width: .fixed(110)) { f in
                        V2StatusChip(
                            f.staleness > 60 * 60 ? "Stale" : "Healthy",
                            kind: f.staleness > 60 * 60 ? .warning : .healthy
                        )
                    },
                ],
                items: feeds,
                selection: .constant(nil)
            )
            .frame(minHeight: 280)
        }
    }

    // MARK: - Package freshness

    private var packageFreshnessTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                packageScanRow
                if packages.isEmpty {
                    V2EmptyState(
                        title: packageScanInProgress
                            ? "Scanning installed packages…"
                            : "No package scan yet",
                        body: packageScanInProgress
                            ? "Querying npm, PyPI, Homebrew, and Cargo registries for the packages installed on this machine. The first scan can take 30-90 seconds depending on how many packages you have."
                            : "Click \"Run scan\" above to query the npm, PyPI, Homebrew, and Cargo registries for the packages installed on this machine. Slopsquatting, dependency-confusion, and freshly-published-malicious-package indicators all surface here.",
                        icon: packageScanInProgress
                            ? "magnifyingglass.circle"
                            : "shippingbox"
                    )
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
                disabled: packageScanInProgress
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

        let mapped = scanned.map { info -> V2MockPackage in
            let key = "\(info.registry.rawValue):\(info.name)"
            let installedVer = installedMap[key] ?? "—"
            let latestVer = info.latestVersion ?? "—"
            return V2MockPackage(
                id: key,
                name: info.name,
                installed: installedVer,
                latest: latestVer,
                manager: info.registry.rawValue,
                vulnCount: info.isFresh ? 1 : 0,
                staleness: info.ageInDays ?? 0
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
        let vulns = packages.reduce(0) { $0 + $1.vulnCount }
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
        HStack(alignment: .top, spacing: 0) {
            V2DataTable(
                columns: [
                    V2DataColumn(id: "name", title: "Package", width: .flexible(min: 200)) { p in
                        V2TableCellText(p.name)
                    },
                    V2DataColumn(id: "manager", title: "Manager", width: .fixed(100)) { p in
                        V2StatusChip(p.manager, kind: .data)
                    },
                    V2DataColumn(id: "installed", title: "Installed", width: .fixed(120)) { p in
                        V2TableCellText(p.installed, primary: false, mono: true)
                    },
                    V2DataColumn(id: "latest", title: "Latest", width: .fixed(120)) { p in
                        V2TableCellText(p.latest, primary: false, mono: true)
                    },
                    V2DataColumn(id: "vuln", title: "Vulns", width: .fixed(80)) { p in
                        if p.vulnCount > 0 {
                            V2StatusChip("\(p.vulnCount)", kind: .high)
                        } else {
                            Text("0").foregroundStyle(V2Theme.tertiaryText).font(V2Theme.meta())
                        }
                    },
                    V2DataColumn(id: "stale", title: "Behind", width: .fixed(110)) { p in
                        V2TableCellText(V2TimeFormat.staleness(p.staleness), primary: false)
                    },
                ],
                items: packages,
                selection: $selectedPackage
            )
            .frame(minHeight: 360, maxHeight: .infinity)
            if let pkg = selectedPackage {
                packageInspector(pkg)
            }
        }
    }

    @ViewBuilder
    private func packageInspector(_ pkg: V2MockPackage) -> some View {
        V2Inspector(title: pkg.name,
                    subtitle: "\(pkg.manager) · installed \(pkg.installed)",
                    onClose: { selectedPackage = nil }) {
            V2InspectorSection("Status") {
                V2InspectorKeyValue("Installed", pkg.installed, mono: true)
                V2InspectorKeyValue("Latest", pkg.latest, mono: true)
                let outdated = pkg.installed != pkg.latest
                V2InspectorKeyValue("State", outdated ? "Outdated" : "Up to date")
                V2InspectorKeyValue("Behind", V2TimeFormat.staleness(pkg.staleness))
                V2InspectorKeyValue("Vulnerabilities", "\(pkg.vulnCount)", mono: true)
            }
            V2InspectorSection("Update command") {
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
                V2InspectorSection("CVEs") {
                    Text("Vulnerability detail is available via the CLI:")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                    HStack(spacing: 6) {
                        Text("maccrabctl vulns \(pkg.name)")
                            .font(V2Theme.mono())
                            .foregroundStyle(V2Theme.primaryText)
                            .textSelection(.enabled)
                        Spacer()
                        V2ActionButton("Copy", icon: "doc.on.doc", style: .ghost) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("maccrabctl vulns \(pkg.name)", forType: .string)
                            state.showToast(V2Toast(kind: .success, title: "Command copied", detail: nil))
                        }
                    }
                }
            }
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
                    Text("Configured external sinks. Edit in Settings → Integrations or `daemon_config.json`. v1.11.0 wires the live read; per-sink health reporting lands in v1.11.x — for now status reflects 'configured', not last-call success.")
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .v2Panel()

                if integrations.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: "powerplug").foregroundStyle(V2Theme.mutedText)
                        Text("No integrations configured. Drop a notifications.json or daemon_config.json with an outputs[] entry into the support directory.")
                            .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .v2Panel()
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Configured integrations (\(integrations.count))")
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

    // MARK: - Shared

    private func metricCard(title: String, value: String, trend: String, trendKind: V2ChipKind,
                            icon: String, iconColor: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(iconColor).font(.system(size: 11, weight: .semibold))
                Text(title.uppercased()).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.mutedText)
            }
            Text(value).font(.system(size: 22, weight: .bold)).foregroundStyle(V2Theme.primaryText)
            V2StatusChip(trend, kind: trendKind)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }
}

// MARK: - V2FeedConfig + V2FeedConfigSheet

/// Identity / metadata for the threat-intel feed chips. Encodes
/// whether a feed is built-in (keyless, always-on) or roadmap
/// (needs an API key + a v1.11 integration). The Keychain key is
/// shared with `SecretsStore.SecretKey` so the daemon side picks
/// up any keys the user paste here.
public enum V2FeedConfig: String, Identifiable, CaseIterable {
    case urlhaus
    case malwareBazaar
    case feodoTracker
    case virusTotal
    case greyNoise
    case alienVaultOTX

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .urlhaus:        return "abuse.ch URLhaus"
        case .malwareBazaar:  return "abuse.ch MalwareBazaar"
        case .feodoTracker:   return "abuse.ch Feodo Tracker"
        case .virusTotal:     return "VirusTotal"
        case .greyNoise:      return "GreyNoise"
        case .alienVaultOTX:  return "AlienVault OTX"
        }
    }

    public var isBuiltIn: Bool {
        switch self {
        case .urlhaus, .malwareBazaar, .feodoTracker: return true
        case .virusTotal, .greyNoise, .alienVaultOTX: return false
        }
    }

    public var description: String {
        switch self {
        case .urlhaus:
            return "abuse.ch URLhaus — community-curated malicious URL feed. Keyless, fetched every 4 hours by the daemon's ThreatIntelFeed actor. Always-on; can't be disabled per-feed (turn off the entire intel layer in Settings if needed)."
        case .malwareBazaar:
            return "abuse.ch MalwareBazaar — SHA-256 hashes for known-bad samples. Keyless, fetched every 4 hours. Always-on."
        case .feodoTracker:
            return "abuse.ch Feodo Tracker — IP addresses of active C2 infrastructure for Emotet, Dridex, TrickBot and similar bankers. Keyless, fetched every 4 hours. Always-on."
        case .virusTotal:
            return "Multi-engine malware scanner with billions of samples + URL / domain / IP intel. Requires a free or paid API key from virustotal.com."
        case .greyNoise:
            return "Internet-wide noise scanner. Tells you whether an IP is mass-scanning or targeted. Requires a free community or paid commercial API key from greynoise.io."
        case .alienVaultOTX:
            return "Open Threat Exchange — community-driven IOC sharing platform. Free API key from otx.alienvault.com."
        }
    }

    /// Where to point the user for an API key.
    public var keyURL: String? {
        switch self {
        case .virusTotal:    return "https://www.virustotal.com/gui/my-apikey"
        case .greyNoise:     return "https://viz.greynoise.io/account/"
        case .alienVaultOTX: return "https://otx.alienvault.com/api"
        default: return nil
        }
    }

    /// Maps to the on-disk SecretKey used by SecretsStore. Built-in
    /// feeds return nil because they don't store a key.
    public var secretKey: SecretKey? {
        switch self {
        case .virusTotal:    return .virusTotalKey
        case .greyNoise:     return .greyNoiseKey
        case .alienVaultOTX: return .alienVaultKey
        default: return nil
        }
    }
}

/// Modal sheet for configuring (or describing) a managed feed.
/// Built-in feeds show a read-only descriptive view; roadmap feeds
/// show an API-key field with Save / Clear actions.
public struct V2FeedConfigSheet: View {
    let feed: V2FeedConfig
    let onClose: () -> Void

    @State private var apiKey: String = ""
    @State private var keyExists: Bool = false
    @State private var saved: Bool = false
    @State private var errorMessage: String? = nil

    private let secrets = SecretsStore()

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: feed.isBuiltIn ? "checkmark.seal.fill" : "clock.badge")
                    .foregroundStyle(feed.isBuiltIn ? V2Theme.healthy : V2Theme.dataAccent)
                    .font(.system(size: 18, weight: .semibold))
                Text(feed.label)
                    .font(V2Theme.workspaceTitle())
                    .foregroundStyle(V2Theme.primaryText)
                Spacer()
                Button {
                    onClose()
                } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(V2Theme.mutedText)
                        .frame(width: 26, height: 26)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.cancelAction)
            }

            if feed.isBuiltIn {
                V2StatusChip("Built-in · always-on", kind: .healthy, icon: "checkmark.seal")
            } else {
                V2StatusChip("Coming in v1.11 · accepting API keys now", kind: .info, icon: "clock")
            }

            Text(feed.description)
                .font(V2Theme.body())
                .foregroundStyle(V2Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)

            if let secretKey = feed.secretKey {
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("API key")
                            .font(V2Theme.cardTitle())
                            .foregroundStyle(V2Theme.mutedText)
                        Spacer()
                        if let url = feed.keyURL {
                            Link("Get a key →", destination: URL(string: url)!)
                                .font(V2Theme.meta())
                        }
                    }
                    SecureField(keyExists ? "•••••••••••• (saved — replace to change)" : "Paste your API key…",
                                text: $apiKey)
                        .textFieldStyle(.plain)
                        .padding(8)
                        .background(V2Theme.panelBackground)
                        .overlay(RoundedRectangle(cornerRadius: 6)
                                    .stroke(V2Theme.panelBorder, lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                    if let err = errorMessage {
                        Text(err)
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.critical)
                    }
                    if saved {
                        Text("Saved to Keychain. The v1.11 integration will pick it up automatically when it ships.")
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.healthy)
                    }
                    HStack {
                        Spacer()
                        if keyExists {
                            Button {
                                clearKey(secretKey)
                            } label: {
                                Text("Clear saved key")
                                    .font(V2Theme.meta())
                                    .foregroundStyle(V2Theme.critical)
                            }
                            .buttonStyle(.plain)
                        }
                        V2ActionButton("Save", icon: "key.fill", style: .primary,
                                       disabled: apiKey.trimmingCharacters(in: .whitespaces).isEmpty) {
                            saveKey(secretKey)
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(width: 460)
        .onAppear {
            if let secretKey = feed.secretKey {
                let stored = (try? secrets.get(secretKey)) ?? nil
                keyExists = (stored?.isEmpty == false)
            }
        }
    }

    private func saveKey(_ secretKey: SecretKey) {
        let trimmed = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        do {
            try secrets.set(secretKey, value: trimmed)
            saved = true
            keyExists = true
            errorMessage = nil
            apiKey = ""
        } catch {
            errorMessage = "Couldn't save: \(error.localizedDescription)"
        }
    }

    private func clearKey(_ secretKey: SecretKey) {
        do {
            try secrets.set(secretKey, value: "")
            keyExists = false
            saved = false
            apiKey = ""
        } catch {
            errorMessage = "Couldn't clear: \(error.localizedDescription)"
        }
    }
}
