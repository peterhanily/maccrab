// V2AXIdentifier.swift
// v1.21.4 — UI-test harness foundation.
//
// The dashboard shipped with ZERO `.accessibilityIdentifier`s, which makes it
// impossible for XCUITest to target anything. Rather than force every call-site
// to supply one, the shared components take an optional `axId` and apply it via
// this helper only when present — so identifiers are opt-in, invisible to users,
// and cost nothing where unused. Pair with the MACCRAB_DATA_DIR fixture-DB seam
// (AppState.dataDir) + the `-ui-testing` launch arg (MacCrabApp) for
// deterministic, daemon-free UI tests.

import SwiftUI

extension View {
    /// Apply an accessibility identifier only when non-nil.
    @ViewBuilder
    func v2AXID(_ id: String?) -> some View {
        if let id { self.accessibilityIdentifier(id) } else { self }
    }
}
