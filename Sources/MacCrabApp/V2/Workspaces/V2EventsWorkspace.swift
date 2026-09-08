// V2EventsWorkspace.swift
// Top-level Events workspace.
//
// The v2 sidebar surfaces Events as its own destination (between
// Alerts and Investigation) rather than burying it as a sub-tab. We
// reuse the v1 EventStream view because it already has the full
// feature set users expect: time-range picker, FTS5 search, hourly
// histogram, "Load older" keyset pagination, and aggregate-mode
// drilldown for ranges past 24h. Wrapping it in v2 chrome keeps the
// look consistent without re-implementing battle-tested code.

import SwiftUI

struct V2EventsWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @State private var visibilityOwner = UUID()
    @StateObject private var querySession: EventQuerySession

    init(state: V2DashboardState, appState: AppState) {
        self.state = state
        self.appState = appState
        _querySession = StateObject(wrappedValue: EventQuerySession(reader: appState))
    }

    var body: some View {
        VStack(spacing: 0) {
            // Pre-fix this was gated on `.mock`, a mode a RELEASE build can
            // never reach (V2DashboardState picks V2OfflineDataProvider under
            // #if !DEBUG), so the fresh-install / sysext-not-yet-approved user
            // the banner was written for saw nothing — an empty table with
            // working-looking filters and no explanation. Also gated on
            // didProbeLiveData so the launch-time probe window can't flash it
            // at a healthy machine.
            if state.didProbeLiveData, state.provider.mode != .live {
                noLiveDataBanner
            }
            // Banner that surfaces the active "Investigate in Events"
            // pre-fill so the user (a) understands why the events list
            // is filtered and (b) has a one-click clear. Pre-fix the
            // .id() + auto-clear pattern raced: setting
            // pendingEventsFilter→.id-changes EventStream-rebuilds
            // with filter→.onAppear-clears-pendingEventsFilter→.id-
            // changes-AGAIN→EventStream-rebuilds-WITHOUT filter, and
            // the prefill was lost ~1 frame after it landed.
            if let pending = state.pendingEventsFilter, !pending.isEmpty {
                investigateBanner(filter: pending, centerTime: state.pendingEventsCenterTime)
            }
            EventStream(
                appState: appState,
                querySession: querySession,
                initialFilterText: state.pendingEventsFilter ?? "",
                initialCenterTime: state.pendingEventsCenterTime,
                centerHalfWindowSeconds: state.pendingEventsHalfWindowSeconds
            )
            .id("events:\(state.pendingEventsFilter ?? "default"):\(state.pendingEventsCenterTime?.timeIntervalSince1970 ?? 0)")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        // Register the workspace, not the EventStream whose filter-driven .id
        // changes can overlap old/new appear callbacks. Owners are per window;
        // the shared poll keeps one reader while any Events workspace remains.
        .onAppear { appState.setEventsWorkspaceVisible(true, owner: visibilityOwner, session: querySession) }
        .onDisappear { appState.setEventsWorkspaceVisible(false, owner: visibilityOwner) }
    }

    /// "Filtered by <X> ± <window> at <time>" banner. Pre-fix this
    /// only showed the filter string; if a navigation set a center
    /// time the user couldn't tell why the table looked tighter than
    /// "Last 24h". Now shows the centred-on time + window so the
    /// constraint is explicit and dismissable.
    private func investigateBanner(filter: String, centerTime: Date?) -> some View {
        let centreLabel: String? = centerTime.map { time in
            let tf = DateFormatter()
            tf.dateStyle = .short
            tf.timeStyle = .short
            let halfMin = Int(state.pendingEventsHalfWindowSeconds / 60)
            return "\(tf.string(from: time)) ± \(halfMin)m"
        }
        return HStack(spacing: 8) {
            Image(systemName: "scope")
                .foregroundStyle(V2Theme.brand)
                .scaledSystem(12, weight: .semibold)
            Text(String(localized: "ui.V2EventsWorkspace.filtered.to.events.matching", defaultValue: "Filtered to events matching"))
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.primaryText)
            // WCAG 1.4.3: `brand` as body text is 3.90:1 on the light canvas /
            // 3.65:1 on a panel. This is the literal search string the filter
            // banner echoes back, so it must be readable. `brandText` swaps in
            // the dim variant for light only (6.83:1) and is unchanged in dark.
            Text("\"\(filter)\"")
                .font(V2Theme.mono())
                .foregroundStyle(V2Theme.brandText)
                .lineLimit(1)
                .truncationMode(.middle)
            if let centreLabel {
                Text(String(localized: "ui.V2EventsWorkspace.around", defaultValue: "around"))
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
                Text(centreLabel)
                    .font(V2Theme.mono())
                    .foregroundStyle(V2Theme.brand)
            }
            Spacer()
            Button {
                state.pendingEventsFilter = nil
                state.pendingEventsCenterTime = nil
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: "xmark")
                        .scaledSystem(9, weight: .semibold)
                    Text(String(localized: "ax.clearFilter", defaultValue: "Clear filter"))
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
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(V2Theme.brand.opacity(0.08))
        .overlay(
            Rectangle()
                .fill(V2Theme.brand.opacity(0.4))
                .frame(height: 1),
            alignment: .bottom
        )
    }

    /// Surface a clear "you are not looking at live data" warning, mode-aware
    /// the way V2SystemWorkspace.dataSourceCard already is. The offline copy
    /// drops the `swift run maccrabd` dev jargon the old string carried, per
    /// the same end-user rewrite V2OverviewWorkspace got in v1.21.5.
    private var noLiveDataBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(V2Theme.warning)
                .scaledSystem(12, weight: .semibold)
            Text(state.provider.mode == .mock
                 ? String(localized: "events.bannerMock", defaultValue: "Sample / mock data (dev build) — start the daemon, then Reconnect to see live events.")
                 : String(localized: "events.bannerOffline", defaultValue: "No daemon data yet — approve the System Extension in System Settings, then Reconnect to see live events."))
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.primaryText)
            Spacer()
            V2ActionButton(String(localized: "system.reconnect", defaultValue: "Reconnect"), icon: "arrow.triangle.2.circlepath", style: .secondary) {
                Task { await state.connectLiveData() }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(V2Theme.warning.opacity(0.12))
        .overlay(
            Rectangle()
                .fill(V2Theme.warning.opacity(0.4))
                .frame(height: 1),
            alignment: .bottom
        )
    }
}
