import SwiftUI

/// Keeps a notice's wrapped layout slot when its message is absent. The caller
/// still owns every freshness/error predicate; an absent notice says nothing
/// about whether the underlying data is current.
struct StableNoticeText: View {
    let reservedMessages: [Text]
    let visibleIndex: Int?

    init(reservedMessages: [Text], visibleIndex: Int?) {
        precondition(visibleIndex.map { reservedMessages.indices.contains($0) } ?? true,
                     "A visible notice must be one of its reserved messages")
        self.reservedMessages = reservedMessages
        self.visibleIndex = visibleIndex
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            // Measure every known variant at the current width and font. A
            // fixed one-line height would clip longer/localized warnings.
            ForEach(reservedMessages.indices, id: \.self) { index in
                reservedMessages[index]
                    .hidden()
                    .accessibilityHidden(true)
                    .allowsHitTesting(false)
            }
            if let visibleIndex {
                reservedMessages[visibleIndex]
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
