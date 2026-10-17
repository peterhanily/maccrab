import SwiftUI

/// Metadata on one existing visible leaf, never an extra diagnostic label.
/// Keep the leaf's useful label, value, action and selected trait unchanged.
/// The identifier already carries the phase; raw phases are not spoken values.
/// Reports accepted published state, not paint completion. Packaged external AX
/// exposure still requires validation independently of presentation tests.
private struct UIContentReadinessMarker: ViewModifier {
    let readiness: UIContentReadiness?

    @ViewBuilder
    func body(content: Content) -> some View {
        if let readiness {
            content.accessibilityIdentifier(readiness.accessibilityIdentifier)
        } else {
            content
        }
    }
}

extension View {
    /// Apply to a Text or Button leaf, not a container whose children could
    /// inherit the identifier. Nil leaves non-carrier siblings unmodified.
    func contentReadiness(_ readiness: UIContentReadiness?) -> some View {
        modifier(UIContentReadinessMarker(readiness: readiness))
    }
}
