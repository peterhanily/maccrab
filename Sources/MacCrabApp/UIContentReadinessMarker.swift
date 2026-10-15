import AppKit
import SwiftUI

/// Place once in the visible workspace header, outside combined table rows.
/// Direct native AX metadata avoids dependence on localized SwiftUI hints or
/// combined-child exposure. Packaged AX visibility still requires validation.
/// This reports published content state, never pixel/paint completion.
struct UIContentReadinessMarker: NSViewRepresentable {
    let readiness: UIContentReadiness

    func makeNSView(context: Context) -> NSTextField {
        let label = NSTextField(labelWithString: "")
        label.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        label.textColor = .secondaryLabelColor
        label.isSelectable = false
        label.setContentHuggingPriority(.required, for: .horizontal)
        label.setAccessibilityElement(true)
        label.setAccessibilityRole(.staticText)
        label.setAccessibilityLabel("Workspace content status")
        apply(to: label)
        return label
    }

    func updateNSView(_ label: NSTextField, context: Context) {
        apply(to: label)
    }

    private func apply(to label: NSTextField) {
        // These values have no arbitrary String entry point. A page may show
        // its own localized error detail elsewhere, never in this AX marker.
        label.stringValue = readiness.phase.displayText
        label.setAccessibilityIdentifier(readiness.accessibilityIdentifier)
        label.setAccessibilityValue(readiness.phase.rawValue)
    }
}
