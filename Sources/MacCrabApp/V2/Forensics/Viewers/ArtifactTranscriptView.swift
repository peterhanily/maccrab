// ArtifactTranscriptView — chat-bubble layout for any content
// type that naturally reads as a sequence of messages between
// parties. Used for iMessage threads, Mail message bodies,
// AppleScript invocation history.
//
// Requires .sender + .timestamp + .body field roles. If
// .body is missing, falls back to artifact.summary. If
// .sender is a bool (is_from_me), bubbles align right when
// true and left when false; otherwise grouped by sender value.

import SwiftUI
import MacCrabForensics

struct ArtifactTranscriptView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    private var timestampField: String {
        FieldResolver.field(forRole: .timestamp, in: hint) ?? "observed_at"
    }
    private var senderField: String? {
        FieldResolver.field(forRole: .sender, in: hint)
    }
    private var bodyField: String? {
        FieldResolver.field(forRole: .body, in: hint)
    }

    private var sortedArtifacts: [CommittedArtifact] {
        artifacts.sorted { a, b in
            let ta = FieldResolver.resolve(a, field: timestampField).asDate ?? a.record.observedAt
            let tb = FieldResolver.resolve(b, field: timestampField).asDate ?? b.record.observedAt
            return ta < tb
        }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                // The older end is truncated, so the note belongs at the top.
                if artifacts.count > 300 {
                    Text("Showing the most recent 300 of \(artifacts.count). Older messages above are truncated. Newest at the bottom.")
                        .scaledSystem(10)
                        .foregroundStyle(.tertiary)
                        .padding(.bottom, 4)
                }
                // Keep the NEWEST 300 (suffix of the ascending sort) since recency
                // dominates in forensics; they still render oldest→newest so the
                // most-recent message sits at the bottom, matching the note.
                ForEach(sortedArtifacts.suffix(300), id: \.id) { a in
                    messageBubble(a)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func messageBubble(_ a: CommittedArtifact) -> some View {
        let isFromMe = self.isFromMe(a)
        let sender = self.senderLabel(a)
        let ts = FieldResolver.resolve(a, field: timestampField).asDate ?? a.record.observedAt
        let body = self.bodyText(a)

        return HStack {
            if isFromMe { Spacer(minLength: 60) }
            VStack(alignment: isFromMe ? .trailing : .leading, spacing: 3) {
                Text(sender)
                    .scaledSystem(10, weight: .medium)
                    .foregroundStyle(.secondary)
                Text(body)
                    .scaledSystem(12)
                    .padding(.horizontal, 10).padding(.vertical, 7)
                    .background(isFromMe ? Color.accentColor.opacity(0.20) : Color.secondary.opacity(0.15))
                    .foregroundStyle(.primary)
                    .cornerRadius(10)
                    .frame(maxWidth: 480, alignment: isFromMe ? .trailing : .leading)
                    .textSelection(.enabled)
                Text(ts.formatted(date: .abbreviated, time: .shortened))
                    .scaledSystem(9)
                    .foregroundStyle(.tertiary)
            }
            if !isFromMe { Spacer(minLength: 60) }
        }
    }

    private func isFromMe(_ a: CommittedArtifact) -> Bool {
        guard let sf = senderField else { return false }
        let v = FieldResolver.resolve(a, field: sf)
        if case .bool(let b) = v { return b }
        // Common conventions
        if case .string(let s) = v {
            let lower = s.lowercased()
            if lower == "me" || lower == "self" { return true }
        }
        return false
    }

    private func senderLabel(_ a: CommittedArtifact) -> String {
        guard let sf = senderField else { return "—" }
        let v = FieldResolver.resolve(a, field: sf)
        switch v {
        case .bool(let b): return b ? "Me" : "Them"
        case .string(let s) where !s.isEmpty: return s
        case .int(let i): return "Handle \(i)"
        default: return "—"
        }
    }

    private func bodyText(_ a: CommittedArtifact) -> String {
        if let bf = bodyField {
            let v = FieldResolver.resolve(a, field: bf)
            if !v.isEmpty { return v.displayString() }
        }
        return a.record.summary ?? a.record.contentType
    }
}
