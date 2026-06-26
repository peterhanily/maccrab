// V2OverviewLayoutStore.swift
// Customizable Overview dashboard: the catalog of available widgets + the
// user's persisted layout (which widgets are shown, in what order, at what
// size). The Protection banner is pinned (always shown, always first) and is
// intentionally NOT part of this model — a security tool should never let the
// user hide whether they're protected.

import SwiftUI

/// The widgets the Overview dashboard can host, in their default order.
/// `rawValue` is the stable id persisted to disk.
enum V2OverviewWidget: String, CaseIterable {
    case kpiSecurityGrade
    case kpiOpenAlerts
    case kpiActiveCampaigns
    case kpiAIGuard
    case kpiEventRate
    case kpiThreatIntel
    case alertHistogram
    case recentActivity
    case quickActions
    case forensics

    /// User-facing name shown in the Customize controls.
    var displayName: String {
        switch self {
        case .kpiSecurityGrade:   return String(localized: "overview.widget.securityGrade", defaultValue: "Security Grade")
        case .kpiOpenAlerts:      return String(localized: "overview.widget.openAlerts", defaultValue: "Open Alerts")
        case .kpiActiveCampaigns: return String(localized: "overview.widget.activeCampaigns", defaultValue: "Active Campaigns")
        case .kpiAIGuard:         return String(localized: "overview.widget.aiGuard", defaultValue: "AI Guard")
        case .kpiEventRate:       return String(localized: "overview.widget.eventRate", defaultValue: "Event Rate")
        case .kpiThreatIntel:     return String(localized: "overview.widget.threatIntel", defaultValue: "Threat Intel")
        case .alertHistogram:     return String(localized: "overview.widget.alertVolume", defaultValue: "Alert Volume")
        case .recentActivity:     return String(localized: "overview.widget.recentActivity", defaultValue: "Recent Activity")
        case .quickActions:       return String(localized: "overview.widget.quickActions", defaultValue: "Quick Actions")
        case .forensics:          return String(localized: "overview.widget.forensics", defaultValue: "Forensics & Plugins")
        }
    }

    /// Column spans the widget may snap to, on the dashboard's 4-column grid.
    /// KPI tiles are 1–2 columns; content cards are 2 or 4 (half / full width).
    var allowedSpans: [Int] {
        switch self {
        case .kpiSecurityGrade, .kpiOpenAlerts, .kpiActiveCampaigns,
             .kpiAIGuard, .kpiEventRate, .kpiThreatIntel:
            return [1, 2]
        case .alertHistogram, .forensics:
            return [2, 4]
        case .recentActivity, .quickActions:
            return [2, 4]
        }
    }

    var defaultSpan: Int {
        switch self {
        case .alertHistogram, .forensics: return 4
        case .recentActivity, .quickActions: return 2
        default: return 1
        }
    }

    /// True for the fixed-height KPI tiles (so the grid can normalise their height).
    var isKPITile: Bool { allowedSpans == [1, 2] }

    /// Nearest allowed span to `n` (used when migrating a persisted span that is
    /// no longer valid, e.g. after the allowed set changes).
    func clampSpan(_ n: Int) -> Int {
        allowedSpans.min(by: { abs($0 - n) < abs($1 - n) }) ?? defaultSpan
    }
}

/// The persisted layout: visibility + order + per-widget size. Mutations save
/// immediately to UserDefaults. Unknown ids are dropped and newly-added catalog
/// widgets are appended on load, so upgrades never lose or crash the layout.
/// All mutations are UI-driven (button actions, drop callbacks) and therefore
/// already run on the main thread.
final class V2OverviewLayoutStore: ObservableObject {

    struct Item: Codable, Equatable, Identifiable {
        var id: String
        var visible: Bool
        var span: Int

        init(id: String, visible: Bool, span: Int) {
            self.id = id; self.visible = visible; self.span = span
        }

        private enum CodingKeys: String, CodingKey { case id, visible, span }

        /// Resilient decode: a missing or wrong-typed field defaults instead of
        /// throwing, so a layout written by a DIFFERENT app version (a field
        /// added/removed later) still decodes. A hard decode failure here would
        /// otherwise discard the user's entire saved layout on upgrade.
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.id = (try? c.decode(String.self, forKey: .id)) ?? ""
            self.visible = (try? c.decode(Bool.self, forKey: .visible)) ?? true
            self.span = (try? c.decode(Int.self, forKey: .span)) ?? 1
        }
    }

    /// Versioned on-disk envelope. New saves write this; `load` still accepts the
    /// legacy bare `[Item]` array written by v1.20 builds. The `version` anchors
    /// any future schema migration.
    private struct StoredLayout: Codable { var version: Int; var items: [Item] }
    private static let schemaVersion = 1

    /// Retired widget id → its replacement, so RENAMING a widget in a future
    /// version preserves the user's saved order / visibility / size instead of
    /// dropping the old id and re-appending the new one at the end. Empty today;
    /// add an entry whenever a `V2OverviewWidget.rawValue` changes.
    static let renamedWidgetIDs: [String: String] = [:]

    @Published private(set) var items: [Item]

    private static let userDefaultsKey = "v2.overview.layout"
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        items = Self.load(from: defaults) ?? Self.defaults()
    }

    // MARK: Defaults

    private static func defaults() -> [Item] {
        V2OverviewWidget.allCases.map { Item(id: $0.rawValue, visible: true, span: $0.defaultSpan) }
    }

    // MARK: Derived

    struct VisibleWidget: Identifiable {
        let widget: V2OverviewWidget
        let span: Int
        var id: String { widget.rawValue }
    }

    /// Visible widgets, in display order, resolved to their catalog case + span.
    var visibleOrdered: [VisibleWidget] {
        items.compactMap { item in
            guard item.visible, let w = V2OverviewWidget(rawValue: item.id) else { return nil }
            return VisibleWidget(widget: w, span: item.span)
        }
    }

    /// Hidden widgets (catalog order) — offered in the "Add widget" menu.
    var hiddenWidgets: [V2OverviewWidget] {
        let hidden = Set(items.filter { !$0.visible }.map { $0.id })
        return V2OverviewWidget.allCases.filter { hidden.contains($0.rawValue) }
    }

    var allHidden: Bool { items.allSatisfy { !$0.visible } }

    func span(for id: String) -> Int {
        items.first(where: { $0.id == id })?.span ?? (V2OverviewWidget(rawValue: id)?.defaultSpan ?? 1)
    }

    // MARK: Mutations

    /// Move `id` to just before `target` in display order (drag-reorder).
    /// Does NOT persist — a single drag fires this on every hover step, so the
    /// caller persists once at drag-end via `commit()`, keeping synchronous
    /// UserDefaults writes off the animation path.
    func move(_ id: String, before target: String) {
        guard id != target,
              let from = items.firstIndex(where: { $0.id == id }) else { return }
        let moved = items.remove(at: from)
        guard let to = items.firstIndex(where: { $0.id == target }) else {
            items.insert(moved, at: from)   // target vanished — undo
            return
        }
        items.insert(moved, at: to)
    }

    /// Persist the current order (called once when a drag ends).
    func commit() { save() }

    /// Cycle a widget to its next allowed span (the resize control).
    func cycleSpan(_ id: String) {
        guard let idx = items.firstIndex(where: { $0.id == id }),
              let w = V2OverviewWidget(rawValue: id) else { return }
        let spans = w.allowedSpans
        let current = spans.firstIndex(of: items[idx].span) ?? 0
        items[idx].span = spans[(current + 1) % spans.count]
        save()
    }

    func hide(_ id: String) {
        guard let idx = items.firstIndex(where: { $0.id == id }) else { return }
        items[idx].visible = false
        save()
    }

    /// Re-show a hidden widget (appended to the end, so it's easy to find).
    func show(_ id: String) {
        guard let from = items.firstIndex(where: { $0.id == id }) else { return }
        var item = items.remove(at: from)
        item.visible = true
        items.append(item)
        save()
    }

    func reset() {
        items = Self.defaults()
        save()
    }

    // MARK: Persistence

    private func save() {
        let stored = StoredLayout(version: Self.schemaVersion, items: items)
        guard let data = try? JSONEncoder().encode(stored) else { return }
        defaults.set(data, forKey: Self.userDefaultsKey)
    }

    /// Decode + migrate, tolerant of cross-version drift. Reads either the
    /// versioned envelope or the legacy bare `[Item]` array; decodes each row
    /// independently so one bad row never discards the whole layout; applies any
    /// id rename; keeps known ids in their stored order with clamped spans; and
    /// appends catalog widgets the stored layout doesn't know about.
    private static func load(from defaults: UserDefaults) -> [Item]? {
        guard let data = defaults.data(forKey: userDefaultsKey),
              let root = try? JSONSerialization.jsonObject(with: data) else { return nil }
        // Envelope {version, items:[…]} OR the legacy bare [...] array.
        let rawItems: [Any]
        if let obj = root as? [String: Any], let arr = obj["items"] as? [Any] {
            rawItems = arr
        } else if let arr = root as? [Any] {
            rawItems = arr
        } else {
            return nil
        }
        let decoder = JSONDecoder()
        var migrated: [Item] = []
        var seen = Set<String>()
        for raw in rawItems {
            // Decode each row independently — skip a corrupt row, keep the rest.
            // A row MUST be a JSON object: `JSONSerialization.data(withJSONObject:)`
            // raises an *uncatchable* NSObjC exception (not a Swift error `try?`
            // can swallow) on a scalar/array/null top-level value, so guard the
            // type FIRST rather than crash the app on a tampered/garbled plist.
            guard let dict = raw as? [String: Any],
                  let rowData = try? JSONSerialization.data(withJSONObject: dict),
                  var item = try? decoder.decode(Item.self, from: rowData) else { continue }
            if let renamed = renamedWidgetIDs[item.id] { item.id = renamed }   // rename migration
            guard let w = V2OverviewWidget(rawValue: item.id), !seen.contains(item.id) else { continue }
            seen.insert(item.id)
            migrated.append(Item(id: item.id, visible: item.visible, span: w.clampSpan(item.span)))
        }
        // Append catalog widgets missing from the stored layout (visible by default).
        for w in V2OverviewWidget.allCases where !seen.contains(w.rawValue) {
            migrated.append(Item(id: w.rawValue, visible: true, span: w.defaultSpan))
        }
        return migrated.isEmpty ? nil : migrated
    }
}
