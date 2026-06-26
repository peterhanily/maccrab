// V2OverviewWidgetTile.swift
// Wraps each Overview widget. In normal mode it's a passthrough (the card stays
// fully interactive). In Customize ("edit") mode it adds: a dashed outline, a
// full-card drag source + drop target for reordering, and corner controls to
// resize (cycle column span) and hide the widget. The card's own buttons are
// suppressed in edit mode so a drag never accidentally navigates away.

import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct V2OverviewWidgetTile<Content: View>: View {
    let widget: V2OverviewWidget
    let editing: Bool
    @ObservedObject var store: V2OverviewLayoutStore
    @Binding var draggingID: String?
    @ViewBuilder var content: () -> Content
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var isDragging: Bool { draggingID == widget.rawValue }

    var body: some View {
        content()
            .overlay { if editing { editChrome } }
            .overlay {
                if editing {
                    RoundedRectangle(cornerRadius: V2Theme.cornerRadius)
                        .strokeBorder(
                            V2Theme.dataAccent.opacity(isDragging ? 0.9 : 0.45),
                            style: StrokeStyle(lineWidth: 1, dash: [4, 3])
                        )
                }
            }
            .opacity(isDragging ? 0.4 : 1)
            // Honor Reduce Motion — no opacity-lift animation for users who opt out.
            .animation(reduceMotion ? nil : .easeInOut(duration: 0.15), value: isDragging)
            // Grab/move cursor while customizing, so it's obvious the card is draggable.
            .onHover { inside in
                guard editing else { NSCursor.arrow.set(); return }
                (inside ? NSCursor.openHand : NSCursor.arrow).set()
            }
            // VoiceOver / keyboard can't drag — expose reorder/resize/hide as
            // accessibility actions while customizing.
            .accessibilityActions {
                if editing {
                    Button(String(localized: "overview.customize.a11yMoveEarlier", defaultValue: "Move \(widget.displayName) earlier")) {
                        store.moveEarlier(widget.rawValue)
                    }
                    Button(String(localized: "overview.customize.a11yMoveLater", defaultValue: "Move \(widget.displayName) later")) {
                        store.moveLater(widget.rawValue)
                    }
                    if widget.allowedSpans.count > 1 {
                        Button(String(localized: "overview.customize.resize", defaultValue: "Resize")) { store.cycleSpan(widget.rawValue) }
                    }
                    Button(String(localized: "overview.customize.hide", defaultValue: "Hide")) { store.hide(widget.rawValue) }
                }
            }
    }

    private var editChrome: some View {
        ZStack(alignment: .top) {
            // Full-card catcher: intercepts taps (so card buttons don't fire),
            // is the drag source, and is the drop target for live reordering.
            Color.black.opacity(0.001)
                .contentShape(Rectangle())
                .onDrag {
                    draggingID = widget.rawValue
                    return NSItemProvider(object: widget.rawValue as NSString)
                }
                .onDrop(
                    of: [UTType.text],
                    delegate: WidgetReorderDropDelegate(target: widget.rawValue, store: store, draggingID: $draggingID)
                )

            HStack(spacing: 6) {
                // Visible drag affordance (left) — signals the whole card is draggable.
                // Decorative: hit-testing off so it doesn't block the drag catcher beneath.
                Image(systemName: "arrow.up.and.down.and.arrow.left.and.right")
                    .scaledSystem(11, weight: .semibold)
                    .foregroundStyle(V2Theme.mutedText)
                    .frame(width: 22, height: 22)
                    .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 5))
                    .overlay(RoundedRectangle(cornerRadius: 5).stroke(V2Theme.panelBorder, lineWidth: 1))
                    .help(String(localized: "overview.customize.dragHint", defaultValue: "Drag anywhere on this card to move it"))
                    .allowsHitTesting(false)
                Spacer()
                if widget.allowedSpans.count > 1 {
                    chromeButton(
                        "arrow.left.and.right.square",
                        help: String(localized: "overview.customize.resize", defaultValue: "Resize")
                    ) { withAnimation(.easeInOut(duration: 0.15)) { store.cycleSpan(widget.rawValue) } }
                }
                chromeButton(
                    "eye.slash",
                    help: String(localized: "overview.customize.hide", defaultValue: "Hide")
                ) { withAnimation(.easeInOut(duration: 0.15)) { store.hide(widget.rawValue) } }
            }
            .padding(7)
        }
    }

    private func chromeButton(_ icon: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .scaledSystem(12, weight: .semibold)
                .foregroundStyle(V2Theme.primaryText)
                .frame(width: 22, height: 22)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(V2Theme.panelBorder, lineWidth: 1))
        }
        .buttonStyle(.plain)
        .help(help)
    }
}

/// Live drag-reorder: as the dragged card hovers over a target, move it just
/// before the target so the grid shuffles in real time.
private struct WidgetReorderDropDelegate: DropDelegate {
    let target: String
    let store: V2OverviewLayoutStore
    @Binding var draggingID: String?

    func dropEntered(info: DropInfo) {
        guard let dragged = draggingID, dragged != target else { return }
        withAnimation(.easeInOut(duration: 0.18)) { store.move(dragged, before: target) }
    }

    func dropUpdated(info: DropInfo) -> DropProposal? { DropProposal(operation: .move) }

    func performDrop(info: DropInfo) -> Bool {
        store.commit()          // persist the reorder once, at drag-end
        draggingID = nil
        return true
    }
}
