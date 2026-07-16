// V2CommandPalette.swift
// Universal command palette per spec §3.4.1.
//
// Phase 3 features:
//   - Keyboard navigation (up/down/enter) via hidden shortcuts
//   - Recent items at the top when query is empty
//   - Doc-article rows (searchable Docs, deep-linked into the Docs workspace)
//   - Entity prefix lookup: alert:<id>, rule:<id>, ip:<addr>, trace:<id>
//   - Verbs always shown
//   - Deep-link rows

import AppKit
import SwiftUI

public struct V2CommandPalette: View {

    @ObservedObject var state: V2DashboardState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var query: String = ""
    @State private var selectedIndex: Int = 0
    @FocusState private var fieldFocused: Bool

    public init(state: V2DashboardState) { self.state = state }

    public var body: some View {
        VStack(spacing: 0) {
            queryRow
            Divider().background(V2Theme.panelBorder)
            results
            Divider().background(V2Theme.panelBorder)
            footer
        }
        .frame(width: 600)
        .background(V2Theme.sidebarBackground)
        .overlay(
            RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                .stroke(V2Theme.panelBorder, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: V2Theme.cornerRadius))
        .shadow(color: Color.black.opacity(0.45), radius: 24, x: 0, y: 8)
        .background(keyboardHandlers)
        .onAppear {
            fieldFocused = true
            selectedIndex = 0
        }
        .task {
            // Populate the live entity caches so alert:/rule:/trace: work the
            // moment the palette opens (no-op cost in mock mode).
            await state.refreshPaletteEntities()
        }
        .onChange(of: query) { _ in
            selectedIndex = 0
            // VoiceOver can't see the visual result list shrink/grow.
            let count = flatten(groupedItems).count
            announce(count == 0
                ? String(localized: "palette.ax.noResults", defaultValue: "No matches")
                : String(localized: "palette.ax.results", defaultValue: "\(count) results"))
        }
        .accessibilityLabel(String(localized: "palette.ax.label", defaultValue: "Command palette"))
    }

    // MARK: - Subviews

    private var queryRow: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .scaledSystem(14, weight: .medium)
                .foregroundStyle(V2Theme.mutedText)
            TextField("Jump to anything (workspaces, tabs, verbs, alert: rule: ip: trace:…)",
                      text: $query)
                .textFieldStyle(.plain)
                .scaledSystem(14)
                .foregroundStyle(V2Theme.primaryText)
                .focused($fieldFocused)
                .onSubmit { applySelected() }
                .accessibilityLabel(String(localized: "palette.ax.field",
                                           defaultValue: "Search commands, workspaces, and entities"))
            shortcutHint("Esc")
        }
        .padding(14)
        .background(V2Theme.panelBackground)
    }

    private var results: some View {
        ScrollViewReader { reader in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    let groups = groupedItems
                    if groups.isEmpty {
                        Text("No matches.")
                            .font(V2Theme.body())
                            .foregroundStyle(V2Theme.mutedText)
                            .padding(20)
                    } else {
                        let flat = flatten(groups)
                        ForEach(groups, id: \.title) { group in
                            section(title: group.title)
                            ForEach(group.items) { item in
                                row(item: item, isSelected: flat.firstIndex(of: item) == selectedIndex)
                                    .id(item.id)
                            }
                        }
                    }
                }
            }
            .frame(maxHeight: 420)
            .onChange(of: selectedIndex) { idx in
                let flat = flatten(groupedItems)
                if idx >= 0, idx < flat.count {
                    withAnimation(V2Motion.paletteScroll(reduceMotion: reduceMotion)) {
                        reader.scrollTo(flat[idx].id, anchor: .center)
                    }
                }
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 14) {
            footerHint(label: "Navigate", icons: ["↑", "↓"])
            footerHint(label: "Open", icons: ["↵"])
            footerHint(label: "Close", icons: ["Esc"])
            Spacer()
            Text("\(flatten(groupedItems).count) results")
                .font(V2Theme.micro())
                .foregroundStyle(V2Theme.tertiaryText)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(V2Theme.sidebarBackground)
    }

    private func footerHint(label: String, icons: [String]) -> some View {
        HStack(spacing: 4) {
            ForEach(icons, id: \.self) { shortcutHint($0) }
            Text(label).font(V2Theme.micro()).foregroundStyle(V2Theme.tertiaryText)
        }
    }

    private func shortcutHint(_ s: String) -> some View {
        Text(s)
            .font(V2Theme.micro())
            .foregroundStyle(V2Theme.tertiaryText)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(V2Theme.hoverBackground)
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }

    private func section(title: String) -> some View {
        Text(title.uppercased())
            .font(V2Theme.micro())
            .foregroundStyle(V2Theme.tertiaryText)
            .padding(.horizontal, 14)
            .padding(.top, 8)
            .padding(.bottom, 2)
            .accessibilityAddTraits(.isHeader)
    }

    private func row(item: V2PaletteItem, isSelected: Bool) -> some View {
        Button { apply(item) } label: {
            HStack(spacing: 12) {
                Image(systemName: item.icon)
                    .scaledSystem(13, weight: .medium)
                    .foregroundStyle(isSelected ? V2Theme.primaryText : V2Theme.mutedText)
                    .frame(width: 22, alignment: .center)
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.title)
                        .scaledSystem(13, weight: isSelected ? .semibold : .medium)
                        .foregroundStyle(V2Theme.primaryText)
                        .lineLimit(1)
                    if let subtitle = item.subtitle {
                        Text(subtitle)
                            .font(V2Theme.meta())
                            .foregroundStyle(V2Theme.mutedText)
                            .lineLimit(1)
                    }
                }
                Spacer()
                if let shortcut = item.shortcut { shortcutHint(shortcut) }
                Text(item.category.label.uppercased())
                    .font(V2Theme.micro())
                    .foregroundStyle(V2Theme.tertiaryText)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(isSelected ? V2Theme.brand.opacity(0.15) : Color.clear)
            .overlay(
                Rectangle().fill(isSelected ? V2Theme.brand : .clear).frame(width: 2),
                alignment: .leading
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : [.isButton])
    }

    // MARK: - Keyboard handlers

    @ViewBuilder
    private var keyboardHandlers: some View {
        ZStack {
            Button { moveSelection(by: -1) } label: { Color.clear }
                .keyboardShortcut(.upArrow, modifiers: [])
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
            Button { moveSelection(by: 1) } label: { Color.clear }
                .keyboardShortcut(.downArrow, modifiers: [])
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
            Button { applySelected() } label: { Color.clear }
                .keyboardShortcut(.return, modifiers: [])
                .frame(width: 0, height: 0).opacity(0).accessibilityHidden(true)
        }
        .frame(width: 0, height: 0)
    }

    private func moveSelection(by delta: Int) {
        let flat = flatten(groupedItems)
        guard !flat.isEmpty else { return }
        var next = selectedIndex + delta
        if next < 0 { next = flat.count - 1 }
        if next >= flat.count { next = 0 }
        selectedIndex = next
        // The hidden-button arrow shortcuts move a purely visual highlight;
        // tell VoiceOver where it landed.
        announce(flat[next].title)
    }

    /// VoiceOver announcement helper — macOS-13-compatible (SwiftUI's
    /// AccessibilityNotification.Announcement needs macOS 14).
    private func announce(_ text: String) {
        guard NSWorkspace.shared.isVoiceOverEnabled else { return }
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                .announcement: text,
                .priority: NSAccessibilityPriorityLevel.high.rawValue,
            ]
        )
    }

    private func applySelected() {
        let flat = flatten(groupedItems)
        guard selectedIndex >= 0, selectedIndex < flat.count else { return }
        apply(flat[selectedIndex])
    }

    private func apply(_ item: V2PaletteItem) {
        // The "Open Settings" verb opens the real (v1) Settings window —
        // the same thing ⌘, does (V2DashboardShell). Its destination points
        // at the preview-only System › Settings tab, so navigating there
        // instead of opening the window contradicted the advertised ⌘,
        // shortcut. Intercept it here so the palette row and the shortcut do
        // the same thing.
        if item.id == "verb:settings" {
            state.paletteOpen = false
            V2SettingsBridge.openSettings()
            return
        }
        state.goto(item.destination)
    }

    // MARK: - Items

    private var groupedItems: [V2PaletteSection] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let qLower = q.lowercased()

        // Entity prefix lookup
        if let entity = entityLookup(q) {
            return [V2PaletteSection(title: "Match", items: entity)]
        }

        var sections: [V2PaletteSection] = []

        if q.isEmpty {
            let recents = state.recentDestinations.prefix(5).map(V2PaletteItem.fromDestination)
            if !recents.isEmpty {
                sections.append(V2PaletteSection(title: "Recent", items: recents))
            }
            sections.append(V2PaletteSection(title: "Workspaces", items: V2PaletteItem.workspaceItems()))
            sections.append(V2PaletteSection(title: "Actions", items: V2PaletteItem.verbItems()))
            return sections
        }

        let workspace = filter(V2PaletteItem.workspaceItems(), q: qLower)
        let tabs      = filter(V2PaletteItem.tabItems(),       q: qLower)
        let verbs     = filter(V2PaletteItem.verbItems(),      q: qLower)
        let docs      = filter(V2PaletteItem.docItems(),       q: qLower)
        let recents   = filter(state.recentDestinations.map(V2PaletteItem.fromDestination), q: qLower)

        if !recents.isEmpty   { sections.append(V2PaletteSection(title: "Recent",     items: recents)) }
        if !workspace.isEmpty { sections.append(V2PaletteSection(title: "Workspaces", items: workspace)) }
        if !tabs.isEmpty      { sections.append(V2PaletteSection(title: "Tabs",       items: tabs)) }
        if !verbs.isEmpty     { sections.append(V2PaletteSection(title: "Actions",    items: verbs)) }
        if !docs.isEmpty      { sections.append(V2PaletteSection(title: "Docs",       items: docs)) }
        return sections
    }

    private func filter(_ items: [V2PaletteItem], q: String) -> [V2PaletteItem] {
        items.filter { item in
            let haystack = (item.title + " " + (item.subtitle ?? "") + " "
                            + item.keywords.joined(separator: " ")).lowercased()
            return haystack.contains(q)
        }
    }

    private func flatten(_ groups: [V2PaletteSection]) -> [V2PaletteItem] {
        groups.flatMap { $0.items }
    }

    private func entityLookup(_ raw: String) -> [V2PaletteItem]? {
        guard let colon = raw.firstIndex(of: ":") else { return nil }
        let prefix = String(raw[..<colon]).lowercased()
        let needle = String(raw[raw.index(after: colon)...])
            .trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else {
            // Bare prefix → list everything in that namespace.
            return entityLookup(prefix: prefix, needle: nil)
        }
        return entityLookup(prefix: prefix, needle: needle)
    }

    private func entityLookup(prefix: String, needle: String?) -> [V2PaletteItem]? {
        // In LIVE mode read the synchronous caches V2DashboardState refreshes on
        // palette open; in a DEBUG mock build use the static fixtures. (Previously
        // this hard-returned [] in live mode, so alert:/rule:/trace: were dead on
        // every real install — the one feature that only worked in the demo.)
        #if DEBUG
        let isMock = state.provider.mode == .mock
        #endif
        // `ip:` needs no entity data — it's a pure IOC-search nav hint — so it
        // works in both modes (handled before any source lookup).
        if prefix == "ip" {
            return [
                V2PaletteItem(
                    id: "entity:ip:\(needle ?? "")",
                    title: "Search IOC matches for \(needle ?? "an IP")",
                    subtitle: "intel · IOC lookup",
                    icon: "globe.americas.fill",
                    shortcut: nil,
                    keywords: ["ip", "ioc", needle ?? ""],
                    category: .entity,
                    destination: V2NavigationDestination(
                        workspace: .intelligence, tab: .intelligenceThreatIntel,
                        filters: needle.map { ["q": $0] } ?? [:]
                    )
                )
            ]
        }
        #if DEBUG
        let alertSource = isMock ? V2MockRepository.alerts : state.paletteAlerts
        let ruleSource = isMock ? V2MockRepository.rules : state.paletteRules
        let traceSource = isMock ? V2MockRepository.traces : state.paletteTraces
        #else
        let alertSource = state.paletteAlerts
        let ruleSource = state.paletteRules
        let traceSource = state.paletteTraces
        #endif
        switch prefix {
        case "alert":
            return alertSource
                .filter { match($0.id, $0.title, $0.ruleId, needle: needle) }
                .map { alert in
                    V2PaletteItem(
                        id: "entity:alert:\(alert.id)",
                        title: alert.title,
                        subtitle: "alert · \(alert.id) · \(alert.ruleId)",
                        icon: "bell.fill",
                        shortcut: nil,
                        keywords: [alert.id, alert.ruleId],
                        category: .entity,
                        destination: V2NavigationDestination(
                            workspace: .alerts, tab: .alertsOpen, entityId: alert.id
                        )
                    )
                }
        case "rule":
            return ruleSource
                .filter { match($0.id, $0.title, needle: needle) }
                .map { rule in
                    V2PaletteItem(
                        id: "entity:rule:\(rule.id)",
                        title: rule.title,
                        subtitle: "rule · \(rule.id) · \(rule.category)",
                        icon: "shield.lefthalf.filled",
                        shortcut: nil,
                        keywords: [rule.id, rule.category],
                        category: .entity,
                        destination: V2NavigationDestination(
                            workspace: .detection, tab: .detectionRules, entityId: rule.id
                        )
                    )
                }
        case "trace":
            return traceSource
                .filter { match($0.id, $0.title, needle: needle) }
                .map { trace in
                    V2PaletteItem(
                        id: "entity:trace:\(trace.id)",
                        title: trace.title,
                        subtitle: "trace · \(trace.id)",
                        icon: "point.3.connected.trianglepath.dotted",
                        shortcut: nil,
                        keywords: [trace.id],
                        category: .entity,
                        destination: V2NavigationDestination(
                            workspace: .investigation, tab: .investigationTraceGraph,
                            entityId: trace.id
                        )
                    )
                }
        default:
            return nil
        }
    }

    private func match(_ haystacks: String..., needle: String?) -> Bool {
        guard let needle, !needle.isEmpty else { return true }
        return haystacks.contains { $0.lowercased().contains(needle) }
    }
}

// MARK: - Sections

public struct V2PaletteSection {
    public let title: String
    public let items: [V2PaletteItem]
}

// MARK: - Items

public struct V2PaletteItem: Identifiable, Equatable {
    public let id: String
    public let title: String
    public let subtitle: String?
    public let icon: String
    public let shortcut: String?
    public let keywords: [String]
    public let category: Category
    public let destination: V2NavigationDestination

    public enum Category: String { case workspace, tab, verb, doc, entity, recent
        var label: String {
            switch self {
            case .workspace: return "workspace"
            case .tab:       return "tab"
            case .verb:      return "action"
            case .doc:       return "doc"
            case .entity:    return "entity"
            case .recent:    return "recent"
            }
        }
    }

    public static func == (lhs: V2PaletteItem, rhs: V2PaletteItem) -> Bool {
        lhs.id == rhs.id
    }

    public static func workspaceItems() -> [V2PaletteItem] {
        V2Workspace.allCases.map { wk in
            V2PaletteItem(
                id: "workspace:\(wk.rawValue)",
                title: "Go to \(wk.title)",
                subtitle: wk.subtitle,
                icon: wk.systemImage,
                shortcut: "⌘\(wk.keyboardIndex)",
                keywords: ["go", wk.title],
                category: .workspace,
                destination: V2NavigationDestination(workspace: wk)
            )
        }
    }

    public static func tabItems() -> [V2PaletteItem] {
        V2WorkspaceTab.allCases.map { tab in
            V2PaletteItem(
                id: "tab:\(tab.rawValue)",
                title: "Go to \(tab.workspace.title) › \(tab.title)",
                subtitle: nil,
                icon: tab.workspace.systemImage,
                shortcut: nil,
                keywords: [tab.title, tab.workspace.title],
                category: .tab,
                destination: V2NavigationDestination(workspace: tab.workspace, tab: tab)
            )
        }
    }

    public static func verbItems() -> [V2PaletteItem] {
        [
            V2PaletteItem(
                id: "verb:create-rule",
                title: "Create Detection Rule",
                subtitle: "Detection › Rules › New",
                icon: "plus.shield",
                shortcut: nil,
                keywords: ["new", "rule", "detection"],
                category: .verb,
                destination: V2NavigationDestination(
                    workspace: .detection, tab: .detectionRules,
                    filters: ["modal": "new"]
                )
            ),
            V2PaletteItem(
                id: "verb:hunt",
                title: "Search events",
                subtitle: "Events workspace · FTS5",
                icon: "magnifyingglass",
                shortcut: nil,
                keywords: ["hunt", "search", "find", "events", "fts"],
                category: .verb,
                destination: V2NavigationDestination(workspace: .events)
            ),
            V2PaletteItem(
                id: "verb:settings",
                title: "Open Settings",
                subtitle: "System › Settings",
                icon: "gearshape.fill",
                shortcut: "⌘,",
                keywords: ["preferences", "config", "settings"],
                category: .verb,
                destination: V2NavigationDestination(workspace: .system, tab: .systemSettings)
            ),
            V2PaletteItem(
                id: "verb:permissions",
                title: "Recheck Permissions",
                subtitle: "System › Permissions",
                icon: "lock.shield",
                shortcut: nil,
                keywords: ["tcc", "permissions", "fda"],
                category: .verb,
                destination: V2NavigationDestination(workspace: .system, tab: .systemPermissions)
            ),
        ]
    }

    /// Doc-article rows. Each deep-links into the Docs workspace with the
    /// article slug as the entity id (V2DocsWorkspace resolves it to the
    /// selected article), so Docs is searchable from the palette and the
    /// previously-dead `.doc` category is now used.
    public static func docItems() -> [V2PaletteItem] {
        V2DocEntry.allCases.map { entry in
            V2PaletteItem(
                id: "doc:\(entry.rawValue)",
                title: "Docs › \(entry.title)",
                subtitle: entry.subtitle,
                icon: entry.icon,
                shortcut: nil,
                keywords: ["docs", "help", "reference", entry.title],
                category: .doc,
                destination: V2NavigationDestination(
                    workspace: .docs, entityId: entry.rawValue
                )
            )
        }
    }

    public static func fromDestination(_ dest: V2NavigationDestination) -> V2PaletteItem {
        let path = dest.workspace.title + (dest.tab.map { " › \($0.title)" } ?? "")
        let entityNote = dest.entityId.map { " · \($0)" } ?? ""
        return V2PaletteItem(
            id: "recent:\(V2DeepLink.url(for: dest)?.absoluteString ?? UUID().uuidString)",
            title: path + entityNote,
            subtitle: V2DeepLink.url(for: dest)?.absoluteString,
            icon: dest.workspace.systemImage,
            shortcut: nil,
            keywords: [dest.workspace.title, dest.tab?.title ?? ""],
            category: .recent,
            destination: dest
        )
    }
}
