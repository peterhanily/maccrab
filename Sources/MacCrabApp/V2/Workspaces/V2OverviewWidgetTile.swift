// V2OverviewWidgetTile.swift
// Wraps each Overview widget. In normal mode it's a passthrough (the card stays
// fully interactive). In Customize ("edit") mode it adds: a dashed outline, a
// full-card drag source + drop target for reordering, and corner controls to
// resize (cycle column span) and hide the widget. The card's own buttons are
// suppressed in edit mode so a drag never accidentally navigates away.

import SwiftUI
import UniformTypeIdentifiers

struct V2OverviewWidgetTile<Content: View>: View {
    let widget: V2OverviewWidget
    let editing: Bool
    @ObservedObject var store: V2OverviewLayoutStore
    @Binding var draggingID: String?
    @ViewBuilder var content: () -> Content

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
            .animation(.easeInOut(duration: 0.15), value: isDragging)
    }

    private var editChrome: some View {
        ZStack(alignment: .topTrailing) {
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
        draggingID = nil
        return true
    }
}
