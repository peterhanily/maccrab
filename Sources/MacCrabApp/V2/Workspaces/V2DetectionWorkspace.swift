// V2DetectionWorkspace.swift
// Spec §7.4 — rules + AI Guard + browser + MCP + prevention.

import SwiftUI

public struct V2DetectionWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @State private var selectedRule: V2MockRule?
    /// Cached lowercased haystack per rule, computed once when
    /// `rules` is loaded. Each rule's haystack is the concat of
    /// (id, title, category, mitre joined). Pre-fix the rulesTable
    /// rebuilt this concatenation + lowercased per row × 427 rules
    /// per keystroke — that's 1700+ string allocations per char
    /// typed in the search box. Now: precompute once + cheap
    /// `contains(q)` per row per keystroke.
    @State private var rulesHaystack: [String: String] = [:]
    @State private var filteredRules: [V2MockRule] = []
    /// Debounced query — driven by ruleQuery via .task(id:). Pre-fix
    /// the filter ran inline in body, so every keystroke re-filtered
    /// 427 rules synchronously on @MainActor. Now the filter result
    /// is cached, filterTask coalesces fast typing.
    @State private var debouncedRuleQuery: String = ""
    @State private var presentingNewRule = false
    @State private var rules: [V2MockRule] = []
    @State private var extensions: [V2MockExtension] = []
    @State private var selectedExtension: V2MockExtension? = nil
    @State private var mcpServers: [V2MockMCP] = []

    public init(state: V2DashboardState) { self.state = state }

    private var ruleQuery: Binding<String> {
        Binding(get: { state.ruleSearchQuery },
                set: { state.ruleSearchQuery = $0 })
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            V2WorkspaceTabStrip(
                tabs: V2Workspace.detection.tabs,
                selected: Binding(
                    get: { state.selectedTabs[.detection] ?? .detectionRules },
                    set: { if let v = $0 { state.selectedTabs[.detection] = v } }
                )
            )
            tabBody
        }
        // Debounce + filter task. Drives both:
        //   - debouncedRuleQuery (delayed mirror of ruleQuery)
        //   - filteredRules (precomputed filter result cached off-main)
        // The .task(id:) cancellation semantics mean fast typing
        // discards in-flight filter computations from prior
        // keystrokes — only the last one's result lands.
        .task(id: state.ruleSearchQuery) {
            let q = state.ruleSearchQuery
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            // 200 ms debounce window. Less than EventStream's 300 ms
            // because the rule filter is in-memory + cheap.
            try? await Task.sleep(nanoseconds: 200_000_000)
            guard !Task.isCancelled else { return }
            // Snapshot current rules + haystack on the actor.
            let snapshot = self.rules
            let haystack = self.rulesHaystack
            let result: [V2MockRule] = await Task.detached(priority: .userInitiated) {
                if q.isEmpty { return snapshot }
                return snapshot.filter { (haystack[$0.id] ?? "").contains(q) }
            }.value
            await MainActor.run {
                self.debouncedRuleQuery = q
                self.filteredRules = result
            }
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") {
            let r = await state.provider.rules()
            let x = await state.provider.extensions()
            let m = await state.provider.mcpServers()
            // Precompute the lowercase haystack so the filter is a
            // single string `contains` per row instead of 4 concats
            // + lowercase per row per keystroke.
            let haystack = await Task.detached(priority: .userInitiated) {
                Dictionary(uniqueKeysWithValues: r.map { rule -> (String, String) in
                    let h = (rule.id + " " + rule.title + " " + rule.category + " "
                             + rule.mitre.joined(separator: " ")).lowercased()
                    return (rule.id, h)
                })
            }.value
            await MainActor.run {
                self.rules = r
                self.extensions = x
                self.mcpServers = m
                self.rulesHaystack = haystack
                // Re-apply current query with the new ruleset.
                let q = self.debouncedRuleQuery
                self.filteredRules = q.isEmpty
                    ? r
                    : r.filter { (haystack[$0.id] ?? "").contains(q) }
                // Cross-workspace deep-link: alerts → rule. The Alert
                // Open inspector's "Open rule" button sets entityId on
                // the destination; we pick it up here and pre-select
                // the matching rule in the inspector.
                let candidateKeys = ["detection:detectionRules", "detection"]
                for key in candidateKeys {
                    if let pendingId = state.selectedEntities[key],
                       let match = r.first(where: { $0.id == pendingId }) {
                        self.selectedRule = match
                        state.selectedEntities[key] = nil
                        break
                    }
                }
            }
        }
        // Cross-workspace intent — Overview's "Create rule" quick
        // action bumps presentNewRuleTick after navigating here.
        .onChange(of: state.presentNewRuleTick) { _ in
            presentingNewRule = true
        }
        .sheet(isPresented: $presentingNewRule) {
            RuleWizard()
                .frame(minWidth: 720, minHeight: 560)
        }
    }

    @ViewBuilder
    private var tabBody: some View {
        switch state.selectedTabs[.detection] ?? .detectionRules {
        case .detectionRules:       rulesTab
        case .detectionAIGuard:     aiGuardTab
        case .detectionBrowser:     browserTab
        case .detectionMCP:         mcpTab
        default: rulesTab
        }
    }

    // MARK: - Rules

    /// Open a rule's YAML source in the user's default editor.
    /// Searches:
    ///   1. App-bundled rules at MacCrab.app/Contents/Resources/rules/
    ///   2. The dev-tree at <repo>/Rules/<tactic>/<id>.yml — fall back
    ///      via shell `find` since rules can live in any tactic dir.
    /// On failure, fires an error toast pointing the user to the CLI.
    private func openRuleYAML(_ rule: V2MockRule) {
        let candidates: [String] = [
            // Bundled rules in the .app
            Bundle.main.path(forResource: rule.id, ofType: "yml", inDirectory: "rules"),
            Bundle.main.path(forResource: rule.id, ofType: "yml"),
            // Dev tree — common case
            FileManager.default.currentDirectoryPath + "/Rules/\(rule.category.lowercased().replacingOccurrences(of: " ", with: "_"))/\(rule.id).yml",
        ].compactMap { $0 }

        for path in candidates where FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.open(URL(fileURLWithPath: path))
            state.showToast(V2Toast(
                kind: .info,
                title: "Opened \(rule.id).yml",
                detail: path
            ))
            return
        }

        // Last resort: shell out to `find` rooted at the cwd. Cheap;
        // fewer than 500 rule files.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/find")
        task.arguments = ["Rules", "-name", "\(rule.id).yml"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            if let data = try? pipe.fileHandleForReading.readToEnd(),
               let out = String(data: data, encoding: .utf8) {
                let lines = out.split(separator: "\n").map(String.init)
                if let path = lines.first {
                    NSWorkspace.shared.open(URL(fileURLWithPath: path))
                    state.showToast(V2Toast(
                        kind: .info,
                        title: "Opened \(rule.id).yml",
                        detail: path
                    ))
                    return
                }
            }
        } catch { /* fall through to error toast */ }

        state.showToast(V2Toast(
            kind: .error,
            title: "Couldn't find \(rule.id).yml",
            detail: "Try: maccrabctl rules list | grep \(rule.id)"
        ))
    }

    private var rulesTab: some View {
        HStack(alignment: .top, spacing: 0) {
            VStack(alignment: .leading, spacing: 16) {
                rulesStatsRow
                rulesSearchBar
                rulesTable
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let rule = selectedRule {
                ruleInspector(rule)
            }
        }
    }

    private var rulesStatsRow: some View {
        let total = rules.count
        let enabled = rules.filter { $0.isEnabled }.count
        let custom = rules.filter { $0.isCustom }.count
        let firedRecently = rules.reduce(0) { $0 + $1.firesLastWeek }
        return HStack(spacing: 12) {
            metricCard(title: "Rules loaded", value: "\(total)",
                       trend: total == 0 ? "no rules" : "\(enabled) enabled",
                       trendKind: total == 0 ? .neutral : .info,
                       icon: "shield.lefthalf.filled", iconColor: V2Theme.dataAccent)
            metricCard(title: "Custom rules", value: "\(custom)",
                       trend: custom == 0 ? "none yet" : "user-authored",
                       trendKind: .neutral,
                       icon: "wrench.and.screwdriver.fill", iconColor: V2Theme.aiAccent)
            metricCard(title: "Fired (7d)", value: "\(firedRecently)",
                       trend: firedRecently == 0 ? "quiet" : "review alerts",
                       trendKind: firedRecently == 0 ? .healthy : .warning,
                       icon: "bolt.fill", iconColor: firedRecently == 0 ? V2Theme.healthy : V2Theme.high)
        }
    }

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

    private var rulesSearchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(V2Theme.mutedText).font(.system(size: 12))
                TextField("Filter rules (id, MITRE, category)…", text: ruleQuery)
                    .textFieldStyle(.plain).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(V2Theme.panelBackground)
            .overlay(
                RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius)
                    .stroke(V2Theme.panelBorder, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            Spacer()
            V2ActionButton("New rule", icon: "plus", style: .primary,
                           tooltip: "Open the rule wizard") {
                presentingNewRule = true
            }
            V2ActionButton("Reload", icon: "arrow.clockwise", style: .secondary,
                           tooltip: "Send SIGHUP to the detection engine") {
                let ok = V2DaemonControl.reloadDetectionRules()
                state.showToast(V2Toast(
                    kind: ok ? .success : .warning,
                    title: ok ? "Reload signal sent"
                              : "Daemon not running",
                    detail: ok ? "SIGHUP delivered to com.maccrab.agent / maccrabd"
                              : "No matching MacCrab process found"
                ))
            }
        }
    }

    private var rulesTable: some View {
        // `filteredRules` is updated by a debounced `.task(id:)`
        // inside `tabBody` so we don't re-filter on every keystroke.
        // When the query is empty, fall back to `rules` directly to
        // avoid waiting for the .task to update filteredRules on
        // first mount.
        let items = debouncedRuleQuery.isEmpty ? rules : filteredRules
        return V2DataTable(
            columns: [
                V2DataColumn(id: "on", title: "On", width: .fixed(50)) { r in
                    Image(systemName: r.isEnabled ? "circle.fill" : "circle")
                        .foregroundStyle(r.isEnabled ? V2Theme.healthy : V2Theme.tertiaryText)
                        .font(.system(size: 8))
                },
                V2DataColumn(id: "title", title: "Rule", width: .flexible(min: 240)) { r in
                    VStack(alignment: .leading, spacing: 1) {
                        V2TableCellText(r.title)
                        V2TableCellText(r.id, primary: false, mono: true)
                    }
                },
                V2DataColumn(id: "category", title: "Category", width: .fixed(140)) { r in
                    V2TableCellText(r.category, primary: false)
                },
                V2DataColumn(id: "sev", title: "Severity", width: .fixed(96)) { r in
                    V2StatusChip(r.severity.label, kind: r.severity.chipKind)
                },
                V2DataColumn(id: "mitre", title: "MITRE", width: .fixed(110)) { r in
                    Text(r.mitre.first ?? "—")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.mutedText)
                },
                V2DataColumn(id: "fires", title: "Fires (7d)", width: .fixed(90)) { r in
                    V2TableCellText("\(r.firesLastWeek)", primary: false, mono: true)
                },
                V2DataColumn(id: "custom", title: "Source", width: .fixed(80)) { r in
                    V2StatusChip(r.isCustom ? "Custom" : "Builtin",
                                 kind: r.isCustom ? .ai : .neutral)
                },
            ],
            items: items,
            selection: $selectedRule
        )
    }

    @ViewBuilder
    private func ruleInspector(_ r: V2MockRule) -> some View {
        V2Inspector(title: r.title, subtitle: r.id, onClose: { selectedRule = nil }) {
            HStack(spacing: 8) {
                V2StatusChip(r.severity.label, kind: r.severity.chipKind)
                V2StatusChip(r.isEnabled ? "Enabled" : "Disabled",
                             kind: r.isEnabled ? .healthy : .neutral)
                if r.isCustom { V2StatusChip("Custom", kind: .ai) }
            }
            V2InspectorSection("Description") {
                Text(r.description).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection("Logic") {
                Text(mockYAML(for: r))
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.neutral)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(V2Theme.sidebarBackground.opacity(0.6))
                    .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                    .textSelection(.enabled)
            }
            V2InspectorSection("MITRE") {
                ForEach(r.mitre, id: \.self) { code in
                    HStack(spacing: 6) {
                        Image(systemName: "doc.plaintext").font(.system(size: 11))
                            .foregroundStyle(V2Theme.mutedText)
                        Text(code).font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                    }
                }
            }
            V2InspectorSection("Activity") {
                V2InspectorKeyValue("Last fired",
                                    r.lastFired.map(V2TimeFormat.relative) ?? "—")
                V2InspectorKeyValue("Fires (7d)", "\(r.firesLastWeek)")
                V2InspectorKeyValue("Category", r.category)
            }
            V2InspectorSection("Actions") {
                V2ActionButton("Edit YAML", icon: "pencil", style: .secondary,
                               tooltip: "Open the rule's source YAML in your default editor") {
                    openRuleYAML(r)
                }
                V2ActionButton("View fires", icon: "list.bullet", style: .secondary) {
                    state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsHistory))
                }
            }
        }
    }

    private func mockYAML(for r: V2MockRule) -> String {
        """
        title: \(r.title)
        id: \(r.id)
        level: \(r.severity.rawValue)
        tags:\n  - \(r.mitre.joined(separator: "\n  - "))
        detection:
          selection:
            ProcessName|contains: \(r.id.split(separator: "_").last ?? "—")
            FileAction: write
          condition: selection
        """
    }

    // MARK: - AI Guard

    private var aiGuardTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                aiGuardOverview
                aiGuardToolsTable
                aiGuardLineageCard
            }
            .padding(16)
        }
    }

    private var aiGuardOverview: some View {
        HStack(spacing: 12) {
            metricCard(title: "MCP servers", value: "\(mcpServers.count)",
                       trend: mcpServers.isEmpty ? "none configured" : "discovered configs",
                       trendKind: mcpServers.isEmpty ? .neutral : .ai,
                       icon: "server.rack", iconColor: V2Theme.medium)
            metricCard(title: "Tracked tools", value: "—",
                       trend: "via daemon",
                       trendKind: .neutral,
                       icon: "brain.head.profile", iconColor: V2Theme.aiAccent)
            metricCard(title: "Tool calls (24h)", value: "—",
                       trend: "via daemon",
                       trendKind: .neutral,
                       icon: "wand.and.stars", iconColor: V2Theme.aiAccent)
            metricCard(title: "AI alerts (7d)", value: "—",
                       trend: "via daemon",
                       trendKind: .neutral,
                       icon: "exclamationmark.shield.fill", iconColor: V2Theme.aiAccent)
        }
    }

    private var aiGuardToolsTable: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("AI tools observed").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            HStack(spacing: 8) {
                Image(systemName: "wand.and.stars").foregroundStyle(V2Theme.aiAccent)
                Text("AI tool inventory is collected by the daemon's AIGuard pipeline. The dashboard surface for it is not yet wired — inspect `~/Library/Application Support/MacCrab/agent_lineage.json` directly to view the captured tool calls.")
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .v2Panel()
        }
    }

    private var aiGuardLineageCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Recent AI lineage").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
            HStack(spacing: 8) {
                Image(systemName: "link").foregroundStyle(V2Theme.aiAccent)
                Text("AI lineage chains (terminal → AI tool → command) are captured by the daemon's AgentLineageService and persisted to `<dataDir>/agent_lineage.json`. Open the file directly to inspect; a dedicated dashboard surface is planned.")
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
            }
            .padding(12)
            .background(V2Theme.panelBackground)
            .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
        }
        .v2Panel()
    }

    // MARK: - Browser

    private var browserTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Browser extensions across Chrome, Firefox, Brave, Edge, and Arc. Risk score factors permission breadth, dangerous APIs, and dev-mode/unpacked status. Click a row for the full permission set and the manifest path.")
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                browserSummaryRow
                HStack(alignment: .top, spacing: 0) {
                    V2DataTable(
                        columns: [
                            V2DataColumn(id: "name", title: "Extension", width: .flexible(min: 200)) { x in
                                V2TableCellText(x.name)
                            },
                            V2DataColumn(id: "browser", title: "Browser", width: .fixed(100)) { x in
                                V2StatusChip(x.browser, kind: .data)
                            },
                            V2DataColumn(id: "version", title: "Version", width: .fixed(90)) { x in
                                V2TableCellText(x.version, primary: false, mono: true)
                            },
                            V2DataColumn(id: "perms", title: "Permissions", width: .fixed(110)) { x in
                                Text("\(x.permissions.count)")
                                    .font(V2Theme.mono())
                                    .foregroundStyle(V2Theme.mutedText)
                            },
                            V2DataColumn(id: "signed", title: "Signed", width: .fixed(80)) { x in
                                V2StatusChip(x.signed ? "Yes" : "No",
                                             kind: x.signed ? .healthy : .high)
                            },
                            V2DataColumn(id: "risk", title: "Risk", width: .fixed(80)) { x in
                                riskPill(x.riskScore)
                            },
                        ],
                        items: extensions,
                        selection: $selectedExtension
                    )
                    .frame(minHeight: 320, maxHeight: .infinity)
                    if let ext = selectedExtension {
                        extensionInspector(ext)
                    }
                }
            }
            .padding(16)
        }
    }

    /// 4-card summary above the extensions table. Pre-fix the
    /// browser tab was just a bare table — no aggregate counts, no
    /// signal about dev-mode extensions or dangerous-permission
    /// outliers. These four metrics are the operator-relevant
    /// distillation.
    @ViewBuilder
    private var browserSummaryRow: some View {
        let total = extensions.count
        let highRisk = extensions.filter { $0.riskScore >= 60 }.count
        let unsigned = extensions.filter { !$0.signed }.count
        let perBrowser = Dictionary(grouping: extensions, by: { $0.browser })
            .mapValues { $0.count }
        let topBrowser = perBrowser.max { $0.value < $1.value }?.key ?? "—"
        HStack(spacing: 12) {
            metricCard(title: "Tracked", value: "\(total)",
                       trend: total == 0 ? "no extensions" : "\(perBrowser.count) browser\(perBrowser.count == 1 ? "" : "s")",
                       trendKind: total == 0 ? .neutral : .info,
                       icon: "puzzlepiece.extension", iconColor: V2Theme.dataAccent)
            metricCard(title: "High risk",  value: "\(highRisk)",
                       trend: highRisk == 0 ? "none ≥ 60" : "review queue",
                       trendKind: highRisk == 0 ? .healthy : .high,
                       icon: "exclamationmark.shield", iconColor: V2Theme.high)
            metricCard(title: "Unsigned / dev", value: "\(unsigned)",
                       trend: unsigned == 0 ? "all signed" : "review",
                       trendKind: unsigned == 0 ? .healthy : .warning,
                       icon: "lock.open", iconColor: unsigned == 0 ? V2Theme.healthy : V2Theme.warning)
            metricCard(title: "Most installed in",
                       value: topBrowser,
                       trend: total == 0 ? "—" : "browser w/ most extensions",
                       trendKind: .info,
                       icon: "globe",
                       iconColor: V2Theme.dataAccent)
        }
    }

    /// Inspector for a selected extension. Surfaces the full
    /// permissions list, manifest version, dev-mode flag, dangerous-
    /// permissions sub-list, and the on-disk path with a Reveal-in-
    /// Finder button.
    @ViewBuilder
    private func extensionInspector(_ ext: V2MockExtension) -> some View {
        V2Inspector(
            title: ext.name,
            subtitle: "\(ext.browser) · \(ext.version)",
            onClose: { selectedExtension = nil }
        ) {
            HStack(spacing: 8) {
                V2StatusChip(ext.browser, kind: .data)
                if ext.signed {
                    V2StatusChip("Signed", kind: .healthy, icon: "checkmark.seal")
                } else {
                    V2StatusChip("Unsigned / dev mode", kind: .warning, icon: "exclamationmark.shield")
                }
                riskPill(ext.riskScore)
            }
            V2InspectorSection("Permissions (\(ext.permissions.count))") {
                if ext.permissions.isEmpty {
                    Text("No declared permissions (or manifest unreadable, e.g. Firefox .xpi).")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                } else {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(ext.permissions, id: \.self) { perm in
                            HStack(spacing: 6) {
                                Image(systemName: dangerousPermissions.contains(perm)
                                      ? "exclamationmark.triangle.fill"
                                      : "checkmark.circle")
                                    .foregroundStyle(dangerousPermissions.contains(perm)
                                                     ? V2Theme.high
                                                     : V2Theme.mutedText)
                                    .font(.system(size: 10))
                                Text(perm)
                                    .font(V2Theme.mono())
                                    .foregroundStyle(V2Theme.primaryText)
                            }
                        }
                    }
                }
            }
            V2InspectorSection("Risk score") {
                Text(riskExplanation(for: ext))
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection("Identity") {
                V2InspectorKeyValue("ID", String(ext.id.split(separator: ":").last ?? ""), mono: true)
                V2InspectorKeyValue("Version", ext.version, mono: true)
            }
        }
    }

    private static let dangerousPermissions: Set<String> = [
        "webRequest", "webRequestBlocking", "cookies", "clipboardRead",
        "clipboardWrite", "nativeMessaging", "debugger", "management",
        "proxy", "<all_urls>", "http://*/*", "https://*/*", "tabs",
        "history", "downloads",
    ]

    private var dangerousPermissions: Set<String> { Self.dangerousPermissions }

    private func riskExplanation(for ext: V2MockExtension) -> String {
        let dangerous = ext.permissions.filter { Self.dangerousPermissions.contains($0) }
        var parts: [String] = []
        parts.append("Score \(ext.riskScore)/100.")
        parts.append("Base 30 for any installed extension.")
        if !dangerous.isEmpty {
            parts.append("+\(dangerous.count * 10) for \(dangerous.count) dangerous permission\(dangerous.count == 1 ? "" : "s") (\(dangerous.joined(separator: ", "))).")
        }
        if ext.permissions.contains("<all_urls>") {
            parts.append("+20 for `<all_urls>` host access.")
        }
        if ext.permissions.contains("nativeMessaging") {
            parts.append("+20 for nativeMessaging (can spawn host processes).")
        }
        if !ext.signed {
            parts.append("+20 for unsigned / dev-mode extension.")
        }
        if ext.riskScore < 50 {
            parts.append("Below review threshold (50).")
        } else {
            parts.append("Above review threshold — recommend a manual permission audit.")
        }
        return parts.joined(separator: " ")
    }

    private func riskPill(_ score: Int) -> some View {
        let kind: V2ChipKind = score >= 70 ? .critical : (score >= 50 ? .high : (score >= 30 ? .medium : .healthy))
        return V2StatusChip("\(score)", kind: kind)
    }

    // MARK: - MCP

    private var mcpTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("MCP servers reachable from this device. Tool inflation and unsigned new servers raise trust scores.")
                    .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                V2DataTable(
                    columns: [
                        V2DataColumn(id: "name", title: "Server", width: .flexible(min: 180)) { m in
                            V2TableCellText(m.name)
                        },
                        V2DataColumn(id: "host", title: "Host", width: .fixed(140)) { m in
                            V2TableCellText(m.host, mono: true)
                        },
                        V2DataColumn(id: "tools", title: "Tools", width: .fixed(80)) { m in
                            V2TableCellText("\(m.toolCount)", mono: true)
                        },
                        V2DataColumn(id: "known", title: "Known to", width: .flexible(min: 160)) { m in
                            V2TableCellText(m.knownTo.joined(separator: " · "), primary: false)
                        },
                        V2DataColumn(id: "trust", title: "Trust", width: .fixed(120)) { m in
                            V2StatusChip(m.trust.label, kind: m.trust.chipKind)
                        },
                        V2DataColumn(id: "used", title: "Last used", width: .fixed(110)) { m in
                            V2TableCellText(V2TimeFormat.relative(m.lastUsed), primary: false)
                        },
                    ],
                    items: mcpServers,
                    selection: .constant(nil)
                )
                .frame(minHeight: 280)
            }
            .padding(16)
        }
    }

}
