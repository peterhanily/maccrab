// V2DetectionWorkspace.swift
// Spec §7.4 — rules + AI Guard + browser + MCP + prevention.

import SwiftUI
// v1.12.0: CompiledRule is used by the user-rule override path to
// re-serialize the bundled rule JSON with `enabled: false` (and other
// override fields, post-v1.12.1).
import MacCrabCore

public struct V2DetectionWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selectedRule: V2MockRule?
    /// Cached lowercased haystack per rule, computed once when
    /// `rules` is loaded. Each rule's haystack is the concat of
    /// (id, title, category, mitre joined, description) — so an operator
    /// can find a rule by its id, its name/title (= the alert name), its
    /// MITRE tag, OR free text from its description. Pre-fix the rulesTable
    /// rebuilt this concatenation + lowercased per row × the loaded rules
    /// per keystroke — that's 1700+ string allocations per char
    /// typed in the search box. Now: precompute once + cheap
    /// `contains(q)` per row per keystroke.
    @State private var rulesHaystack: [String: String] = [:]
    @State private var filteredRules: [V2MockRule] = []
    /// Debounced query — driven by ruleQuery via .task(id:). Pre-fix
    /// the filter ran inline in body, so every keystroke re-filtered
    /// the loaded rules synchronously on @MainActor. Now the filter result
    /// is cached, filterTask coalesces fast typing.
    @State private var debouncedRuleQuery: String = ""
    @State private var presentingNewRule = false
    @State private var rules: [V2MockRule] = []
    @State private var extensions: [V2MockExtension] = []
    @State private var selectedExtension: V2MockExtension? = nil
    @State private var mcpServers: [V2MockMCP] = []
    @State private var agentSessions: [V2AgentSession] = []
    /// v1.12.0: in-app YAML viewer sheet. Replaces the v1.11.x
    /// external-editor opener which exposed the read-only bundled
    /// YAML in TextEdit and confused users when Cmd+S failed.
    @State private var yamlViewerRule: V2MockRule?
    /// v1.12.0 RC16: in-app YAML editor sheet. Save compiles the
    /// edited YAML via the bundled Python compiler and writes the
    /// resulting JSON to user_rules/<uuid>.json, then touches
    /// .reload_tick so the daemon's mtime watcher picks it up.
    @State private var yamlEditorRule: V2MockRule?
    /// IDs of rules the user has overridden to disabled via
    /// /Library/Application Support/MacCrab/user_rules/<id>.json.
    /// Refreshed at .task and after each Disable / Enable action.
    @State private var userDisabledRuleIDs: Set<String> = []
    /// Sequence + graph (composite) rule id → title, lowercased keys.
    /// An alert can deep-link a composite-rule id into the search box;
    /// those rules aren't single-event Sigma and never appear in
    /// `rules`, so without this the table just goes blank. Loaded in
    /// the rules-load task. See `builtInDetectionNote`.
    @State private var compositeRuleLabels: [String: String] = [:]

    init(state: V2DashboardState, appState: AppState) {
        self.state = state
        self.appState = appState
    }

    /// Lowercased search haystack for one rule — id + title (= the alert
    /// name) + category + MITRE + description. The single source of truth
    /// for the rule search box, used by BOTH the precomputed cache and the
    /// not-yet-built fallback so the two can't drift. Extracted as a pure
    /// function so the searchable-field set is unit-testable.
    nonisolated static func ruleSearchHaystack(for rule: V2MockRule) -> String {
        (rule.id + " " + rule.title + " " + rule.category + " "
            + rule.mitre.joined(separator: " ") + " " + rule.description).lowercased()
    }

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
                // Fall back to an inline field concat when the precomputed
                // haystack hasn't been built yet (it's populated late in the
                // rules-load task, after extensions()/mcpServers()). Without
                // this fallback an early search runs against an empty haystack
                // and returns zero matches until the next ~5s refresh tick —
                // i.e. the filter looks broken. Mirrors the haystack formula.
                return snapshot.filter { rule in
                    let h = haystack[rule.id]
                        ?? V2DetectionWorkspace.ruleSearchHaystack(for: rule)
                    return h.contains(q)
                }
            }.value
            await MainActor.run {
                self.debouncedRuleQuery = q
                self.filteredRules = result
            }
        }
        .task(id: "\(state.provider.mode):\(state.refreshTick)") {
            // v1.12.6 Wave 9P: write each piece of @State as soon as
            // its await resolves. Pre-9P all four fields were gated
            // behind one trailing MainActor.run after four awaits —
            // and `rules()` alone reads the compiled-rule JSON files
            // + parses each, which can exceed the 5s refreshTick on
            // cold cache. Same shape as Wave 9G in V2Intelligence.
            //
            // Filter handling: if there's no active filter query, the
            // rule table renders the full list as soon as rules load —
            // the haystack is only needed for filtered queries. If a
            // filter IS active, filteredRules updates again once the
            // detached haystack build completes.
            let r = await state.provider.rules()
            await MainActor.run {
                self.rules = r
                // Default (no filter): show all rules immediately.
                if self.debouncedRuleQuery.isEmpty {
                    self.filteredRules = r
                }
                // Cross-workspace deep-link: alerts → rule.
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

            let x = await state.provider.extensions()
            await MainActor.run { self.extensions = x }

            let m = await state.provider.mcpServers()
            await MainActor.run { self.mcpServers = m }

            // Wave-3 recorder: durable AI-agent sessions.
            let sess = await state.provider.agentSessions(limit: 50)
            await MainActor.run { self.agentSessions = sess }

            // Composite (sequence + graph) rule labels — for the
            // empty-table explanation when an alert deep-links a
            // non-single-event detection id.
            let comp = await state.provider.compositeRuleLabels()
            await MainActor.run { self.compositeRuleLabels = comp }

            // Precompute the lowercase haystack so the filter is a
            // single string `contains` per row instead of rebuilding the
            // field concat + lowercase per row per keystroke. Detached so
            // the string work doesn't block main.
            let haystack = await Task.detached(priority: .userInitiated) {
                Dictionary(uniqueKeysWithValues: r.map { rule -> (String, String) in
                    let h = V2DetectionWorkspace.ruleSearchHaystack(for: rule)
                    return (rule.id, h)
                })
            }.value
            await MainActor.run {
                self.rulesHaystack = haystack
                // Re-apply filter if one is active.
                let q = self.debouncedRuleQuery
                if !q.isEmpty {
                    self.filteredRules = r.filter { (haystack[$0.id] ?? "").contains(q) }
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

    // MARK: - User-rule overrides (v1.12.0)

    /// System-wide override dir. Written by the dashboard, read by the
    /// daemon at boot and on its `.reload_tick` mtime watcher. Lives
    /// alongside the bundled `compiled_rules/` tree but is NEVER touched
    /// by `RuleBundleInstaller` on Sparkle updates — so user overrides
    /// persist across version bumps.
    private static let userRulesDir = "/Library/Application Support/MacCrab/user_rules"
    private static let reloadTickPath = userRulesDir + "/.reload_tick"

    /// Refresh `userDisabledRuleIDs` from on-disk overrides so the
    /// Disable / Enable button shows the right label after a fresh
    /// workspace open or after another window's edit. Cheap: at most a
    /// few-hundred-byte directory scan.
    private func refreshUserDisabledRuleIDs() {
        var ids: Set<String> = []
        if let urls = try? FileManager.default.contentsOfDirectory(
            at: URL(fileURLWithPath: Self.userRulesDir),
            includingPropertiesForKeys: nil
        ) {
            for url in urls where url.pathExtension == "json" {
                guard let data = try? Data(contentsOf: url) else { continue }
                struct StubRule: Decodable { let id: String; let enabled: Bool }
                if let stub = try? JSONDecoder().decode(StubRule.self, from: data),
                   !stub.enabled {
                    ids.insert(stub.id)
                }
            }
        }
        userDisabledRuleIDs = ids
    }

    /// Toggle a rule between bundled-default and user-override disabled.
    /// First disable in a session bootstraps the override directory
    /// (admin prompt). Subsequent toggles write directly — the dir is
    /// chmod'd 0775 root:admin during bootstrap so any admin user can
    /// edit overrides without re-prompting.
    private func toggleRuleDisabled(_ rule: V2MockRule) async {
        // Built-in maccrab.* rules: enable/disable (mute) via the inbox IPC —
        // the root daemon owns builtin_rules_settings.json. Detection + any
        // protective action still run; only the alert is muted.
        if rule.id.hasPrefix("maccrab.") {
            appState.setBuiltinRuleEnabled(ruleId: rule.id, enabled: !rule.isEnabled)
            state.showToast(V2Toast(
                kind: .info,
                title: rule.isEnabled ? "Built-in rule muted" : "Built-in rule enabled",
                detail: rule.title + " — applies in ~5 s (detection still runs)"
            ))
            return
        }
        // v1.18: sequence + graph (composite) rules are loaded by the
        // SequenceEngine / TraceGraph engine from compiled_rules/{sequences,
        // graph}/, not via the single-event user_rules overlay — so a disable
        // override here would be silently ignored by the engine. List them
        // read-only rather than offer a toggle that does nothing.
        if rule.category == "Sequence" || rule.category == "Graph" {
            state.showToast(V2Toast(
                kind: .info,
                title: "Read-only rule",
                detail: rule.title + " — multi-step rules are managed in their rule files"
            ))
            return
        }
        let currentlyDisabled = userDisabledRuleIDs.contains(rule.id) || !rule.isEnabled
        if currentlyDisabled {
            await removeUserOverride(rule: rule)
        } else {
            await writeDisabledOverride(rule: rule)
        }
        refreshUserDisabledRuleIDs()
    }

    /// Locate the bundled compiled JSON for a rule and return the
    /// in-memory `CompiledRule`. Used to clone the canonical rule
    /// definition before mutating fields for an override.
    ///
    /// v1.12.0 RC30 fix: bundled compiled JSONs are slug-named (e.g.
    /// `maccrab_tamper_attempt.json`), not UUID-named — only the YAMLs
    /// are duplicated under both keys in build-release.sh. The old
    /// UUID-by-filename lookup failed every Disable click. Fall back to
    /// a one-time scan of compiled_rules/ that indexes UUID → path by
    /// each JSON's internal `id` field.
    private func loadBundledCompiledRule(id: String) -> CompiledRule? {
        guard let data = bundledCompiledRuleData(id: id) else { return nil }
        return try? JSONDecoder().decode(CompiledRule.self, from: data)
    }

    /// Raw JSON Data variant of the lookup above — v1.18.1: the severity
    /// override patches the raw dict (CompiledRule.level is a `let`, and
    /// raw patching keeps MacCrabCore untouched for a UI feature).
    private func bundledCompiledRuleData(id: String) -> Data? {
        // Fast path: UUID-named file (works if build-release.sh has
        // started shipping UUID copies in a later release).
        let direct: [String?] = [
            Bundle.main.path(forResource: id, ofType: "json", inDirectory: "compiled_rules"),
            Bundle.main.path(forResource: id, ofType: "json"),
        ]
        for path in direct.compactMap({ $0 }) {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
               (try? JSONDecoder().decode(CompiledRule.self, from: data)) != nil {
                return data
            }
        }
        // Slow path: scan compiled_rules/ and match by internal `id`.
        guard let dir = Bundle.main.resourcePath.map({ $0 + "/compiled_rules" }),
              let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
            return nil
        }
        for entry in entries where entry.hasSuffix(".json") && entry != "manifest.json" {
            let path = dir + "/" + entry
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let rule = try? JSONDecoder().decode(CompiledRule.self, from: data) else {
                continue
            }
            if rule.id == id { return data }
        }
        return nil
    }

    /// An existing user override for this rule, if one is on disk
    /// (root-owned but world-readable). Used so a new override builds on
    /// the previous one — e.g. disabling a rule keeps its severity
    /// override, and a severity change keeps the disabled flag. Also the
    /// only source for rules the USER installed (no bundled copy exists).
    private func existingUserOverrideData(id: String) -> Data? {
        try? Data(contentsOf: URL(fileURLWithPath: Self.userRulesDir + "/\(id).json"))
    }

    /// Ensure the override directory exists and is writable. Returns
    /// true if writable after the call. First time through fires an
    private func writeDisabledOverride(rule: V2MockRule) async {
        // v1.18.1: build on an existing user override so disabling a rule
        // keeps its severity override, and patch the raw JSON dict (see
        // bundledCompiledRuleData for why not CompiledRule).
        guard let data = existingUserOverrideData(id: rule.id) ?? bundledCompiledRuleData(id: rule.id),
              var obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            state.showToast(V2Toast(
                kind: .error,
                title: "Couldn't load rule definition",
                detail: "Rule \(rule.id) wasn't found in the .app bundle or user_rules."
            ))
            return
        }
        obj["enabled"] = false
        guard let out = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
              let json = String(data: out, encoding: .utf8) else {
            state.showToast(V2Toast(kind: .error, title: "Couldn't encode override", detail: rule.id))
            return
        }
        // Route through the privileged inbox: the ROOT daemon writes the override
        // into the secure root-owned user_rules dir (the engine's secure-dir gate
        // refuses a user-writable dir, so the app can't write it itself — that
        // mismatch was why disabling a rule appeared to work but the rule kept
        // firing). yaml omitted: a disable override is JSON-only.
        let result = UserRuleInstaller.dropInboxRequest(
            verb: "install-rule", payload: ["ruleId": rule.id, "json": json])
        switch result {
        case .success:
            state.showToast(V2Toast(kind: .info, title: "Rule disabled",
                                    detail: rule.title + " — applies in ~5 s"))
        case .failure(let msg):
            state.showToast(V2Toast(kind: .error, title: "Couldn't disable rule", detail: msg))
        }
    }

    private func removeUserOverride(rule: V2MockRule) async {
        // Route the removal through the daemon's remove-rule inbox verb (same
        // reason — the app can't mutate the root-owned user_rules dir).
        let result = UserRuleInstaller.dropInboxRequest(
            verb: "remove-rule", payload: ["ruleId": rule.id])
        switch result {
        case .success:
            state.showToast(V2Toast(kind: .info, title: "Rule re-enabled",
                                    detail: rule.title + " — applies in ~5 s"))
        case .failure(let msg):
            state.showToast(V2Toast(kind: .error, title: "Couldn't re-enable rule", detail: msg))
        }
    }

    /// v1.18.1: change a rule's effective severity WITHOUT the YAML
    /// round-trip. Built-ins route through the builtin-settings inbox verb;
    /// single-event Sigma rules get a user-rule override (raw JSON `level`
    /// patch via the same install-rule verb the disable flow uses);
    /// sequence/graph rules are read-only (their engines don't read the
    /// user_rules overlay).
    private func setSeverityOverride(_ rule: V2MockRule, severityRaw: String?) async {
        if rule.id.hasPrefix("maccrab.") {
            appState.setBuiltinRuleSeverity(ruleId: rule.id, severityRaw: severityRaw)
            state.showToast(V2Toast(
                kind: .info,
                title: severityRaw == nil ? "Severity reverted to default" : "Severity override sent",
                detail: rule.title + " — applies in ~5 s"
            ))
            return
        }
        if rule.category == "Sequence" || rule.category == "Graph" {
            state.showToast(V2Toast(
                kind: .info,
                title: "Read-only rule",
                detail: rule.title + " — multi-step rules are managed in their rule files"
            ))
            return
        }
        guard let data = existingUserOverrideData(id: rule.id) ?? bundledCompiledRuleData(id: rule.id),
              var obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            state.showToast(V2Toast(
                kind: .error,
                title: "Couldn't load rule definition",
                detail: "Rule \(rule.id) wasn't found in the .app bundle or user_rules."
            ))
            return
        }
        let wasDisabled = userDisabledRuleIDs.contains(rule.id) || !rule.isEnabled
        if let severityRaw {
            obj["level"] = severityRaw
        } else {
            // Revert to the bundled default. If the rule is also disabled,
            // keep a disable-only override; otherwise drop the override file.
            guard let bundled = bundledCompiledRuleData(id: rule.id),
                  let bundledObj = (try? JSONSerialization.jsonObject(with: bundled)) as? [String: Any] else {
                // User-installed rule: there is no bundled default to revert to.
                state.showToast(V2Toast(
                    kind: .info,
                    title: "No bundled default",
                    detail: rule.title + " — edit this custom rule's YAML to change its severity"
                ))
                return
            }
            if !wasDisabled {
                let result = UserRuleInstaller.dropInboxRequest(
                    verb: "remove-rule", payload: ["ruleId": rule.id])
                switch result {
                case .success:
                    state.showToast(V2Toast(kind: .info, title: "Severity reverted to default",
                                            detail: rule.title + " — applies in ~5 s"))
                case .failure(let msg):
                    state.showToast(V2Toast(kind: .error, title: "Couldn't revert severity", detail: msg))
                }
                return
            }
            obj = bundledObj
        }
        if wasDisabled { obj["enabled"] = false }
        guard let out = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
              let json = String(data: out, encoding: .utf8) else {
            state.showToast(V2Toast(kind: .error, title: "Couldn't encode override", detail: rule.id))
            return
        }
        let result = UserRuleInstaller.dropInboxRequest(
            verb: "install-rule", payload: ["ruleId": rule.id, "json": json])
        switch result {
        case .success:
            state.showToast(V2Toast(
                kind: .info,
                title: severityRaw == nil ? "Severity reverted to default" : "Severity set to \(severityRaw!)",
                detail: rule.title + " — applies in ~5 s"
            ))
        case .failure(let msg):
            state.showToast(V2Toast(kind: .error, title: "Couldn't set severity", detail: msg))
        }
    }

    /// Severity chip that opens an override menu (v1.18.1 — inline severity
    /// without opening the YAML). Sequence/Graph rules render a plain chip.
    @ViewBuilder
    private func severityControl(for r: V2MockRule) -> some View {
        if r.category == "Sequence" || r.category == "Graph" {
            V2StatusChip(r.severity.label, kind: r.severity.chipKind)
        } else {
            Menu {
                Button("Critical") { Task { await setSeverityOverride(r, severityRaw: "critical") } }
                Button("High")     { Task { await setSeverityOverride(r, severityRaw: "high") } }
                Button("Medium")   { Task { await setSeverityOverride(r, severityRaw: "medium") } }
                Button("Low")      { Task { await setSeverityOverride(r, severityRaw: "low") } }
                Button("Info")     { Task { await setSeverityOverride(r, severityRaw: "informational") } }
                Divider()
                Button("Default")  { Task { await setSeverityOverride(r, severityRaw: nil) } }
            } label: {
                HStack(spacing: 3) {
                    V2StatusChip(r.severity.label, kind: r.severity.chipKind)
                    Image(systemName: "chevron.down")
                        .scaledSystem(7, weight: .semibold)
                        .foregroundStyle(V2Theme.mutedText)
                }
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Change this rule's effective severity")
            .accessibilityLabel("Severity \(r.severity.label). Activate to change.")
        }
    }

    private var rulesTab: some View {
        // v1.12.9: floating inspector overlay (see V2AlertsWorkspace
        // for the rationale). HStack push-layout overflowed the
        // window at the 1180 minimum; ZStack lets the rule inspector
        // float over the rightmost ~340 pt of the rules table.
        ZStack(alignment: .topTrailing) {
            VStack(alignment: .leading, spacing: 16) {
                rulesStatsRow
                rulesSearchBar
                if builtInDetectionSearchUnmatched {
                    builtInDetectionNote
                }
                rulesTable
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let rule = selectedRule {
                ruleInspector(rule)
                    .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                    .transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))
            }
        }
        .animation(V2Motion.inspectorPresent(reduceMotion: reduceMotion), value: selectedRule?.id)
        .sheet(item: $yamlViewerRule) { rule in
            RuleYAMLViewerSheet(rule: rule, onClose: { yamlViewerRule = nil })
        }
        .sheet(item: $yamlEditorRule) { rule in
            RuleYAMLEditorSheet(
                rule: rule,
                onClose: { yamlEditorRule = nil },
                onSaved: {
                    yamlEditorRule = nil
                    refreshUserDisabledRuleIDs()
                    state.showToast(V2Toast(
                        kind: .info,
                        title: "Rule saved",
                        detail: rule.title + " — daemon will reload in ~5 s"
                    ))
                },
                onError: { detail in
                    state.showToast(V2Toast(
                        kind: .error,
                        title: "Save failed",
                        detail: detail
                    ))
                }
            )
        }
        .task { refreshUserDisabledRuleIDs() }
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
                Image(systemName: icon).foregroundStyle(iconColor).scaledSystem(11, weight: .semibold)
                Text(title.uppercased()).font(V2Theme.cardTitle()).foregroundStyle(V2Theme.mutedText)
            }
            Text(value).scaledSystem(22, weight: .bold).foregroundStyle(V2Theme.primaryText)
            V2StatusChip(trend, kind: trendKind)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .v2Panel()
    }

    private var rulesSearchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(V2Theme.mutedText).scaledSystem(12)
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

    /// True when the operator searched a rule id that looks like one of
    /// MacCrab's built-in (non-Sigma) detection engines and nothing in the
    /// Sigma rules list matched. Alerts deep-link their ruleId into this
    /// search box, so an AI-Guard / campaign / behavioral / threat-intel
    /// alert lands the operator on an empty table — explain why.
    private var builtInDetectionSearchUnmatched: Bool {
        let q = debouncedRuleQuery.lowercased()
        guard !q.isEmpty else { return false }
        guard filteredRules.isEmpty else { return false }
        // Two families of detection deep-link a ruleId here but have
        // nothing editable in this single-event Sigma list:
        //   1. Programmatic built-in engines — ai-guard, campaign,
        //      behavior, correlator, forensic, dns, threat-intel, … —
        //      every one emits an id under the `maccrab.` namespace.
        //   2. Composite rules — sequence + graph — whose ids (UUIDs and
        //      `maccrab_` slugs) live in compiled_rules/{sequences,graph}/
        //      and are evaluated by separate engines, so they never load
        //      into this list. Pre-fix only family (1) was covered, so an
        //      alert from a sequence/graph rule landed on a blank table.
        return q.hasPrefix("maccrab.") || compositeRuleLabels[q] != nil
    }

    private var builtInDetectionNote: some View {
        let compositeTitle = compositeRuleLabels[debouncedRuleQuery.lowercased()]
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle")
                .foregroundStyle(V2Theme.mutedText)
            VStack(alignment: .leading, spacing: 3) {
                Text("No editable rule matches “\(debouncedRuleQuery)”.")
                    .scaledSystem(12, weight: .medium)
                Text(compositeTitle.map {
                    "“\($0)” is a multi-step correlation detection — a sequence or trace-graph rule evaluated across several events, not a single-event Sigma rule. There's nothing to edit or tune for it on this screen."
                } ?? "Alerts with a `maccrab.*` ID (e.g. AI Guard, campaign correlation, behavioral scoring, threat intel, forensic scanners, cross-process correlation, DNS analysis) come from MacCrab's built-in detection engines — not Sigma YAML rules, so there's nothing to edit or tune here.")
                    .scaledSystem(11)
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(10)
        .background(V2Theme.panelBackground)
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
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
                V2DataColumn(id: "on", title: "On", width: .fixed(50),
                             sortKey: { .number($0.isEnabled ? 0 : 1) }) { r in
                    // v1.18.1: the static status dot is now the toggle —
                    // enable/disable without opening the inspector.
                    // toggleRuleDisabled routes builtin/user/read-only
                    // rules correctly and toasts the outcome.
                    Button {
                        Task { await toggleRuleDisabled(r) }
                    } label: {
                        Image(systemName: r.isEnabled ? "circle.fill" : "circle")
                            .foregroundStyle(r.isEnabled ? V2Theme.healthy : V2Theme.tertiaryText)
                            .scaledSystem(8)
                            .frame(width: 22, height: 22)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(r.isEnabled ? "Enabled — click to disable" : "Disabled — click to enable")
                    .accessibilityLabel(r.isEnabled
                        ? "Rule enabled. Activate to disable."
                        : "Rule disabled. Activate to enable.")
                },
                V2DataColumn(id: "title", title: "Rule", width: .flexible(min: 240),
                             sortKey: { .text($0.title) }) { r in
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 6) {
                            V2TableCellText(r.title)
                            if r.isDeprecated {
                                V2StatusChip("Deprecated", kind: .warning)
                            }
                        }
                        V2TableCellText(r.id, primary: false, mono: true)
                    }
                },
                V2DataColumn(id: "category", title: "Category", width: .fixed(140),
                             sortKey: { .text($0.category) }) { r in
                    V2TableCellText(r.category, primary: false)
                },
                V2DataColumn(id: "sev", title: "Severity", width: .fixed(110),
                             sortKey: { .number(Double($0.severity.sortOrder)) }) { r in
                    severityControl(for: r)
                },
                V2DataColumn(id: "mitre", title: "MITRE", width: .fixed(110),
                             sortKey: { .text($0.mitre.first ?? "") }) { r in
                    Text(r.mitre.first ?? "—")
                        .font(V2Theme.mono()).foregroundStyle(V2Theme.mutedText)
                },
                V2DataColumn(id: "fires", title: "Fires (7d)", width: .fixed(90),
                             sortKey: { .number(Double($0.firesLastWeek)) }) { r in
                    V2TableCellText("\(r.firesLastWeek)", primary: false, mono: true)
                },
                V2DataColumn(id: "custom", title: "Source", width: .fixed(80),
                             sortKey: { .text($0.isCustom ? "Custom" : "Builtin") }) { r in
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
                if r.isDeprecated { V2StatusChip("Deprecated", kind: .warning) }
                if r.isCustom { V2StatusChip("Custom", kind: .ai) }
            }
            if r.isDeprecated {
                Text("This detection is deprecated — retained so its history and existing suppressions stay valid, but it ships disabled and does not fire.")
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection(String(localized: "inspector.description", defaultValue: "Description")) {
                Text(r.description).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection(String(localized: "inspector.logic", defaultValue: "Logic")) {
                Text(mockYAML(for: r))
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.neutral)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(V2Theme.sidebarBackground.opacity(0.6))
                    .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
                    .textSelection(.enabled)
            }
            V2InspectorSection(String(localized: "inspector.mitre", defaultValue: "MITRE")) {
                ForEach(r.mitre, id: \.self) { code in
                    HStack(spacing: 6) {
                        Image(systemName: "doc.plaintext").scaledSystem(11)
                            .foregroundStyle(V2Theme.mutedText)
                        Text(code).font(V2Theme.mono()).foregroundStyle(V2Theme.primaryText)
                    }
                }
            }
            V2InspectorSection(String(localized: "inspector.activity", defaultValue: "Activity")) {
                V2InspectorKeyValue("Last fired",
                                    r.lastFired.map(V2TimeFormat.relative) ?? "—")
                V2InspectorKeyValue("Fires (7d)", "\(r.firesLastWeek)")
                V2InspectorKeyValue("Category", r.category)
            }
            if r.id.hasPrefix("maccrab.") {
                // Built-in detection: logic isn't editable, but it can be muted
                // or have its severity overridden (applied at the daemon's
                // AlertSink chokepoint via the inbox IPC).
                BuiltinRuleSettingsSection(rule: r, appState: appState, state: state)
                V2InspectorSection(String(localized: "inspector.actions", defaultValue: "Actions")) {
                    // v1.18.1: compact action bar (paired equal-width row)
                    // instead of intrinsic-width buttons stacked vertically.
                    HStack(spacing: 8) {
                        V2ActionButton(
                            r.isEnabled ? "Mute rule" : "Enable rule",
                            icon: r.isEnabled ? "minus.circle" : "checkmark.circle",
                            style: .secondary,
                            fullWidth: true,
                            tooltip: "Built-in rule: mute the alert (the detection + any protective action still run)."
                        ) {
                            Task { await toggleRuleDisabled(r) }
                        }
                        V2ActionButton("View fires", icon: "list.bullet", style: .secondary, fullWidth: true) {
                            state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsHistory))
                        }
                    }
                }
            } else {
                // v1.18.1: severity is editable here too — no YAML round-trip.
                V2InspectorSection(String(localized: "inspector.settings", defaultValue: "Settings")) {
                    HStack {
                        Text("Effective severity")
                            .font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                        Spacer()
                        severityControl(for: r)
                    }
                    Text("Changing severity writes a user-rule override (survives updates). \"Default\" reverts to the bundled value.")
                        .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                V2InspectorSection(String(localized: "inspector.actions", defaultValue: "Actions")) {
                    // v1.18.1: compact 2×2 action bar (paired equal-width
                    // rows) instead of four stacked intrinsic-width buttons.
                    VStack(spacing: 8) {
                        HStack(spacing: 8) {
                            V2ActionButton("View YAML", icon: "doc.text", style: .secondary, fullWidth: true,
                                           tooltip: "Show the rule's source YAML in-app") {
                                yamlViewerRule = r
                            }
                            V2ActionButton("Edit YAML", icon: "pencil", style: .secondary, fullWidth: true,
                                           tooltip: "Open the YAML in an in-app editor. Save writes a user-rule override that survives Sparkle updates.") {
                                yamlEditorRule = r
                            }
                        }
                        let isDisabled = userDisabledRuleIDs.contains(r.id) || !r.isEnabled
                        HStack(spacing: 8) {
                            V2ActionButton(
                                isDisabled ? "Enable rule" : "Disable rule",
                                icon: isDisabled ? "checkmark.circle" : "minus.circle",
                                style: .secondary,
                                fullWidth: true,
                                tooltip: isDisabled
                                    ? "Re-enable this rule (removes the user override)"
                                    : "Disable this rule without editing the bundled YAML. First disable in this session may prompt for your admin password to create the override directory; subsequent disables don't."
                            ) {
                                Task { await toggleRuleDisabled(r) }
                            }
                            V2ActionButton("View fires", icon: "list.bullet", style: .secondary, fullWidth: true) {
                                state.goto(V2NavigationDestination(workspace: .alerts, tab: .alertsHistory))
                            }
                        }
                    }
                }
            }
        }
    }

    /// Severity-override control for a built-in maccrab.* rule. The picker sends
    /// the chosen severity (or clears the override) through the inbox; the chip
    /// above already shows the current EFFECTIVE severity.
    private struct BuiltinRuleSettingsSection: View {
        let rule: V2MockRule
        @ObservedObject var appState: AppState
        @ObservedObject var state: V2DashboardState
        @State private var severitySel = "default"

        var body: some View {
            V2InspectorSection(String(localized: "inspector.builtInSettings", defaultValue: "Built-in settings")) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("This detection's logic isn't editable. You can override its severity or mute it; the detection still runs.")
                        .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Text("Override severity").font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                        Spacer()
                        Picker("", selection: $severitySel) {
                            Text("Default").tag("default")
                            Text("Critical").tag("critical")
                            Text("High").tag("high")
                            Text("Medium").tag("medium")
                            Text("Low").tag("low")
                            Text("Info").tag("informational")
                        }
                        .labelsHidden()
                        .frame(width: 140)
                        .onChange(of: severitySel) { new in
                            appState.setBuiltinRuleSeverity(ruleId: rule.id, severityRaw: new == "default" ? nil : new)
                            state.showToast(V2Toast(
                                kind: .info,
                                title: new == "default" ? "Severity reverted to default" : "Severity override sent",
                                detail: rule.title + " — applies in ~5 s"
                            ))
                        }
                    }
                }
            }
            // Seed the Picker from the live override so an already-overridden
            // built-in shows its real severity instead of "Default". Without
            // this the @State default ("default") always wins on first render
            // even when rule.severityOverrideRaw is set.
            .onAppear {
                severitySel = rule.severityOverrideRaw ?? "default"
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
            HStack {
                Text("Agent sessions").font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                if !agentSessions.isEmpty {
                    Text("\(agentSessions.count)").font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
            }
            if agentSessions.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "wand.and.stars").foregroundStyle(V2Theme.aiAccent)
                    Text("No AI-agent sessions recorded yet. Sessions appear once the engine observes a coding agent (Claude Code, Cursor, …) and its descendant activity.")
                        .font(V2Theme.body()).foregroundStyle(V2Theme.mutedText)
                }
                .padding(12)
                .background(V2Theme.panelBackground)
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            } else {
                VStack(spacing: 0) {
                    ForEach(agentSessions.prefix(20)) { s in
                        HStack(spacing: 10) {
                            Image(systemName: "terminal").foregroundStyle(V2Theme.aiAccent)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.tool).font(V2Theme.body()).foregroundStyle(V2Theme.primaryText)
                                Text(s.projectDir ?? s.id)
                                    .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("\(s.eventCount) events").font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                                Text(s.lastSeen, style: .relative).font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                            }
                        }
                        .padding(.vertical, 6).padding(.horizontal, 12)
                    }
                }
                .background(V2Theme.panelBackground)
                .clipShape(RoundedRectangle(cornerRadius: V2Theme.smallCornerRadius))
            }
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
                            V2DataColumn(id: "name", title: "Extension", width: .flexible(min: 200),
                                         sortKey: { .text($0.name) }) { x in
                                V2TableCellText(x.name)
                            },
                            V2DataColumn(id: "browser", title: "Browser", width: .fixed(100),
                                         sortKey: { .text($0.browser) }) { x in
                                V2StatusChip(x.browser, kind: .data)
                            },
                            V2DataColumn(id: "version", title: "Version", width: .fixed(90),
                                         sortKey: { .text($0.version) }) { x in
                                V2TableCellText(x.version, primary: false, mono: true)
                            },
                            V2DataColumn(id: "perms", title: "Permissions", width: .fixed(110),
                                         sortKey: { .number(Double($0.permissions.count)) }) { x in
                                Text("\(x.permissions.count)")
                                    .font(V2Theme.mono())
                                    .foregroundStyle(V2Theme.mutedText)
                            },
                            V2DataColumn(id: "signed", title: "Signed", width: .fixed(80),
                                         sortKey: { .text($0.signed ? "Yes" : "No") }) { x in
                                V2StatusChip(x.signed ? "Yes" : "No",
                                             kind: x.signed ? .healthy : .high)
                            },
                            V2DataColumn(id: "risk", title: "Risk", width: .fixed(80),
                                         sortKey: { .number(Double($0.riskScore)) }) { x in
                                riskPill(x.riskScore)
                            },
                        ],
                        items: extensions,
                        selection: $selectedExtension,
                        searchPrompt: "Filter extensions…"
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
            V2InspectorSection(String(localized: "inspector.permissionsExtPermissionsCount", defaultValue: "Permissions (\(ext.permissions.count))")) {
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
                                    .scaledSystem(10)
                                Text(perm)
                                    .font(V2Theme.mono())
                                    .foregroundStyle(V2Theme.primaryText)
                            }
                        }
                    }
                }
            }
            V2InspectorSection(String(localized: "inspector.riskScore", defaultValue: "Risk score")) {
                Text(riskExplanation(for: ext))
                    .font(V2Theme.body())
                    .foregroundStyle(V2Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            V2InspectorSection(String(localized: "inspector.identity", defaultValue: "Identity")) {
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

/// In-dashboard read-only YAML viewer (v1.12.0).
/// Replaces v1.11.x's external-editor opener — that path exposed the
/// signed, read-only bundled YAML file in TextEdit and confused users
/// when Cmd+S failed. View-only here is honest about the constraint:
/// to actually customise a rule, use the inspector's "Disable rule"
/// override. Full raw-YAML editing with user-rules is targeted for
/// v1.12.1, which needs a Swift port of compile_rules.py.
private struct RuleYAMLViewerSheet: View {
    let rule: V2MockRule
    let onClose: () -> Void

    @State private var content: String = ""
    @State private var sourcePath: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(rule.title)
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text(rule.id)
                        .font(V2Theme.mono())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(content, forType: .string)
                } label: {
                    Label("Copy YAML", systemImage: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .disabled(content.isEmpty)
                Button("Close", action: onClose)
                    .keyboardShortcut(.cancelAction)
            }
            .padding(16)
            Divider()
            ScrollView {
                Text(content.isEmpty ? "Loading…" : content)
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.primaryText)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
                    .textSelection(.enabled)
            }
            .background(V2Theme.sidebarBackground.opacity(0.4))
            if !sourcePath.isEmpty {
                HStack {
                    Text("Source: \(sourcePath)")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                        .textSelection(.enabled)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
            }
        }
        .frame(minWidth: 700, minHeight: 500)
        .task { load() }
    }

    private func load() {
        // Prefer the UUID-named copy bundled by build-release.sh; fall
        // back to a slug-named lookup. Dev tree probe stays for `swift
        // run MacCrabApp` workflows where cwd is the repo root.
        let candidates: [String?] = [
            Bundle.main.path(forResource: rule.id, ofType: "yml", inDirectory: "rules"),
            Bundle.main.path(forResource: rule.id, ofType: "yml"),
            FileManager.default.currentDirectoryPath + "/Rules/\(rule.category.lowercased().replacingOccurrences(of: " ", with: "_"))/\(rule.id).yml",
        ]
        for path in candidates.compactMap({ $0 }) where FileManager.default.fileExists(atPath: path) {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
               let text = String(data: data, encoding: .utf8) {
                content = text
                sourcePath = path
                return
            }
        }
        content = "# Couldn't find YAML for \(rule.id)\n# This usually means the .app was built without the rules/ bundle step."
    }
}

/// In-dashboard YAML editor (v1.12.0 RC16).
/// Loads the bundled rule's YAML into a TextEditor; the Save button
/// writes the edited YAML to `/Library/Application Support/MacCrab/
/// user_rules/<uuid>.yml`, spawns the bundled Python compiler with a
/// vendored PyYAML on PYTHONPATH to produce `<uuid>.json` alongside,
/// then touches `<dir>/.reload_tick` to trigger the daemon's mtime
/// watcher (DaemonSetup.swift). User overrides live under user_rules/
/// which RuleBundleInstaller never touches, so they survive Sparkle
/// updates. First save in a session may prompt for admin to create
/// the dir at 0775 root:admin; subsequent saves don't need elevation.
private struct RuleYAMLEditorSheet: View {
    let rule: V2MockRule
    let onClose: () -> Void
    let onSaved: () -> Void
    let onError: (String) -> Void

    @State private var content: String = ""
    @State private var sourcePath: String = ""
    @State private var saving: Bool = false
    @State private var validating: Bool = false
    /// Most recent compile error, surfaced inline so the user can fix
    /// YAML / Sigma mistakes without dismissing the editor. Cleared on
    /// successful Validate or Save.
    @State private var lastError: String = ""
    /// v1.12.0 RC27 audit fix (UX-B1): track the original content
    /// loaded at task time so Cancel can warn before discarding edits.
    @State private var originalContent: String = ""
    @State private var showDiscardConfirm: Bool = false

    private static let userRulesDir = "/Library/Application Support/MacCrab/user_rules"

    /// True when the user has typed edits that aren't yet saved.
    /// `originalContent` is populated by `load()`; if save() succeeds
    /// it gets updated so the user can keep editing without re-prompts.
    private var hasUnsavedChanges: Bool {
        !originalContent.isEmpty && content != originalContent
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Edit YAML — \(rule.title)")
                        .font(V2Theme.sectionTitle())
                        .foregroundStyle(V2Theme.primaryText)
                    Text(rule.id)
                        .font(V2Theme.mono())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
                // v1.12.0 RC29 audit fix (UX-M2): in-app help link to
                // Sigma syntax docs. Pre-fix a user hitting a compile
                // error had no in-app path to look up correct YAML.
                Button {
                    if let url = URL(string: "https://sigmahq.io/docs/basics/rules.html") {
                        NSWorkspace.shared.open(url)
                    }
                } label: {
                    Image(systemName: "questionmark.circle")
                        .scaledSystem(14)
                }
                .buttonStyle(.borderless)
                .help("Open Sigma rule reference (sigmahq.io)")
                Button("Cancel") {
                    if hasUnsavedChanges {
                        showDiscardConfirm = true
                    } else {
                        onClose()
                    }
                }
                .keyboardShortcut(.cancelAction)
                Button {
                    Task { await save() }
                } label: {
                    if saving {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Save")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || content.isEmpty || !hasUnsavedChanges)
            }
            .padding(16)
            Divider()
            TextEditor(text: $content)
                .font(V2Theme.mono())
                .scrollContentBackground(.hidden)
                .background(V2Theme.sidebarBackground.opacity(0.4))
                .padding(8)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            HStack {
                // v1.12.0 RC28 audit fix (UX-M2): show a "Saving…"
                // indicator while the Python compile subprocess is in
                // flight. Editor save is 65-160ms wall-clock; without
                // feedback the user can't tell saved vs. hung.
                if saving {
                    ProgressView().controlSize(.small)
                    Text("Compiling rule…")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                } else {
                    Text("Saves to \(Self.userRulesDir)/\(rule.id).{yml,json} — survives Sparkle updates.")
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                }
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        .frame(minWidth: 800, minHeight: 600)
        .task { load() }
        .confirmationDialog(
            "Discard unsaved changes?",
            isPresented: $showDiscardConfirm,
            titleVisibility: .visible
        ) {
            Button("Discard changes", role: .destructive) { onClose() }
            Button("Keep editing", role: .cancel) {}
        } message: {
            Text("Your YAML edits to \(rule.title) haven't been saved. Closing now will discard them.")
        }
    }

    private func load() {
        // Prefer an existing user override (so the user can iterate on
        // their own edits). Fall back to the bundled rule.
        let userPath = Self.userRulesDir + "/\(rule.id).yml"
        if FileManager.default.fileExists(atPath: userPath),
           let data = try? Data(contentsOf: URL(fileURLWithPath: userPath)),
           let text = String(data: data, encoding: .utf8) {
            content = text
            originalContent = text
            sourcePath = userPath
            return
        }
        let candidates: [String?] = [
            Bundle.main.path(forResource: rule.id, ofType: "yml", inDirectory: "rules"),
            Bundle.main.path(forResource: rule.id, ofType: "yml"),
        ]
        for path in candidates.compactMap({ $0 }) where FileManager.default.fileExists(atPath: path) {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
               let text = String(data: data, encoding: .utf8) {
                content = text
                originalContent = text
                sourcePath = path
                return
            }
        }
        content = "# Couldn't find YAML for \(rule.id)\n# Edit + save will create a new user override at \(Self.userRulesDir)/\(rule.id).yml"
        originalContent = content
    }

    @MainActor
    private func save() async {
        saving = true
        defer { saving = false }
        // v1.18: delegate to the shared installer (same path the rule wizard
        // uses) so the two never drift on how a rule is compiled + installed.
        let result = await UserRuleInstaller.install(ruleId: rule.id, yaml: content)
        switch result {
        case .success:
            // v1.12.0 RC27: re-baseline originalContent so a follow-up
            // Cancel doesn't warn about edits we just persisted.
            originalContent = content
            onSaved()
        case .failure(let message):
            // Keep the YAML on disk so the user doesn't lose their work,
            // but warn that the daemon won't see it until they fix the
            // YAML and save again (or delete the broken file via CLI).
            onError("Compiler error: \(message)")
        }
    }

}
