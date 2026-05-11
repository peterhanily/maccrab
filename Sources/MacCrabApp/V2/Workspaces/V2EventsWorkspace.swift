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

    init(state: V2DashboardState, appState: AppState) {
        self.state = state
        self.appState = appState
    }

    var body: some View {
        VStack(spacing: 0) {
            if state.provider.mode == .mock {
                mockBanner
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
                initialFilterText: state.pendingEventsFilter ?? "",
                initialCenterTime: state.pendingEventsCenterTime,
                centerHalfWindowSeconds: state.pendingEventsHalfWindowSeconds
            )
            .id("events:\(state.pendingEventsFilter ?? "default"):\(state.pendingEventsCenterTime?.timeIntervalSince1970 ?? 0)")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
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
                .font(.system(size: 12, weight: .semibold))
            Text("Filtered to events matching")
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.primaryText)
            Text("\"\(filter)\"")
                .font(V2Theme.mono())
                .foregroundStyle(V2Theme.brand)
                .lineLimit(1)
                .truncationMode(.middle)
            if let centreLabel {
                Text("around")
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
                        .font(.system(size: 9, weight: .semibold))
                    Text("Clear filter")
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

    /// Surface a clear "this is mock data" warning when no daemon is
    /// detected, mirroring the System workspace's data-source banner.
    /// Without this banner the v1 EventStream chrome looks identical
    /// in mock and live mode and users can't tell the difference.
    private var mockBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(V2Theme.warning)
                .font(.system(size: 12, weight: .semibold))
            Text("Mock data — no daemon detected. Start the System Extension or `swift run maccrabd` to see live events.")
                .font(V2Theme.meta())
                .foregroundStyle(V2Theme.primaryText)
            Spacer()
            V2ActionButton("Reconnect", icon: "arrow.triangle.2.circlepath", style: .secondary) {
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
