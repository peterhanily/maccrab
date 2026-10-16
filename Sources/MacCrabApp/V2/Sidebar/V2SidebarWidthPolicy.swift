import SwiftUI

/// A rendering budget, not a stored-preference update. The 960-point workspace
/// preserves the existing 1180-point window / 220-point default-sidebar layout
/// (928 points for a workspace table after its two 16-point outer insets).
enum V2SidebarWidthPolicy {
    static let collapsed: CGFloat = 56
    static let minimum: CGFloat = 180
    static let maximum: CGFloat = 360
    static let defaultWidth: CGFloat = 220
    static let workspaceMinimum: CGFloat = 960

    static func preference(_ stored: Double) -> CGFloat {
        guard stored.isFinite else { return defaultWidth }
        return min(max(CGFloat(stored), minimum), maximum)
    }

    static func rendered(stored: Double, collapsed isCollapsed: Bool, availableWidth: CGFloat) -> CGFloat {
        guard !isCollapsed else { return collapsed }
        return min(preference(stored), maximumRendered(availableWidth: availableWidth))
    }

    static func maximumRendered(availableWidth: CGFloat) -> CGFloat {
        let available = availableWidth.isFinite ? max(0, availableWidth) : 0
        return min(maximum, max(minimum, available - workspaceMinimum))
    }

    /// Explicit input starts at the visible handle, not an offscreen preference.
    /// Drag translations are cumulative from one fixed gesture-start width.
    static func resized(startWidth: CGFloat, translation: CGFloat, availableWidth: CGFloat) -> Double {
        let start = startWidth.isFinite ? startWidth : defaultWidth
        let delta = translation.isFinite ? translation : 0
        return Double(min(max(start + delta, minimum), maximumRendered(availableWidth: availableWidth)))
    }
}

/// Shared with private geometry fixtures so they exercise the real allocation
/// without constructing the dashboard, its preferences, providers or AppState.
struct V2SidebarContentLayout<Sidebar: View, Content: View>: View {
    let sidebar: (CGFloat) -> Sidebar
    let content: Content

    init(@ViewBuilder sidebar: @escaping (CGFloat) -> Sidebar,
         @ViewBuilder content: () -> Content) {
        self.sidebar = sidebar
        self.content = content()
    }

    var body: some View {
        GeometryReader { viewport in
            HStack(spacing: 0) {
                sidebar(viewport.size.width)
                content.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}
