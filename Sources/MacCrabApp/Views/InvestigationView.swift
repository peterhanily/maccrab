// InvestigationView.swift
// MacCrabApp
//
// Phase 4 Investigation panel. Renders a structured LLMInvestigation
// (verdict, confidence, evidence chain, MITRE reasoning, suggested
// actions) inside an alert's detail view. Suggested actions show their
// exact previewCommand before the operator confirms — nothing
// auto-executes from here.

import SwiftUI
import MacCrabCore

// MARK: - InvestigationSection (top-level, dropped into AlertDetailView)

struct InvestigationSection: View {
    let investigation: LLMInvestigation

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                header
                summaryBlock
                confidenceBar
                if !investigation.mitreReasoning.isEmpty {
                    mitreReasoningBlock
                }
                if !investigation.evidenceChain.isEmpty {
                    evidenceBlock
                }
                if !investigation.suggestedActions.isEmpty {
                    suggestedActionsBlock
                }
                if !investigation.confidencePenalties.isEmpty {
                    penaltyBlock
                }
                footer
            }
            .padding(4)
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "brain.head.profile")
                    .accessibilityHidden(true)
                Text("Investigation")
                    .font(.headline)
            }
        }
    }

    // MARK: - Sections

    private var header: some View {
        HStack(spacing: 10) {
            verdictBadge
            Spacer()
            Text(String(format: "%.0f%% confidence", investigation.confidence * 100))
                .font(.caption).foregroundColor(.secondary)
        }
    }

    private var verdictBadge: some View {
        HStack(spacing: 4) {
            Image(systemName: verdictIcon)
                .font(.caption)
                .accessibilityHidden(true)
            Text(verdictLabel)
                .font(.caption)
                .fontWeight(.semibold)
        }
        .padding(.horizontal, 8).padding(.vertical, 3)
        .foregroundColor(verdictColor)
        .background(verdictColor.opacity(0.15))
        .clipShape(Capsule())
    }

    private var summaryBlock: some View {
        Text(investigation.summary)
            .font(.body)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
    }

    private var confidenceBar: some View {
        VStack(alignment: .leading, spacing: 2) {
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Color.secondary.opacity(0.2))
                    RoundedRectangle(cornerRadius: 2)
                        .fill(verdictColor)
                        .frame(width: geo.size.width * CGFloat(investigation.confidence))
                }
            }
            .frame(height: 4)
        }
    }

    private var mitreReasoningBlock: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("MITRE reasoning").font(.caption).fontWeight(.semibold)
            ForEach(Array(investigation.mitreReasoning.enumerated()), id: \.offset) { _, m in
                HStack(alignment: .top, spacing: 6) {
                    Text((m.tacticId ?? m.techniqueId) ?? "—")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.orange)
                    Text(m.reasoning)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private var evidenceBlock: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(investigation.evidenceChain.enumerated()), id: \.offset) { _, e in
                    HStack(alignment: .top, spacing: 6) {
                        Text(e.kind.rawValue)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.blue)
                            .padding(.horizontal, 4).padding(.vertical, 1)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(3)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(e.id)
                                .font(.system(.caption2, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text(e.note)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .padding(.top, 4)
        } label: {
            Text("Evidence chain (\(investigation.evidenceChain.count))")
                .font(.caption).fontWeight(.semibold)
        }
    }

    private var suggestedActionsBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Suggested actions")
                .font(.caption).fontWeight(.semibold)
            ForEach(Array(investigation.suggestedActions.enumerated()), id: \.offset) { _, a in
                SuggestedActionRow(action: a)
            }
        }
    }

    private var penaltyBlock: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Confidence caveats")
                .font(.caption).fontWeight(.semibold)
                .foregroundColor(.orange)
            ForEach(investigation.confidencePenalties, id: \.self) { p in
                HStack(alignment: .top, spacing: 4) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.caption2).foregroundColor(.orange)
                        .accessibilityHidden(true)
                    Text(p).font(.caption2).foregroundColor(.secondary)
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("model: \(investigation.modelVersion)")
                .font(.caption2).foregroundColor(.secondary.opacity(0.8))
            Spacer()
            Text(Self.relativeTime(investigation.generatedAt))
                .font(.caption2).foregroundColor(.secondary.opacity(0.8))
        }
    }

    // MARK: - Derived

    private var verdictLabel: String {
        switch investigation.verdict {
        case .likelyMalicious:      return "Likely malicious"
        case .likelyBenign:         return "Likely benign"
        case .needsHuman:           return "Needs human"
        case .insufficientEvidence: return "Insufficient evidence"
        }
    }

    private var verdictIcon: String {
        switch investigation.verdict {
        case .likelyMalicious:      return "exclamationmark.shield.fill"
        case .likelyBenign:         return "checkmark.shield.fill"
        case .needsHuman:           return "person.fill.questionmark"
        case .insufficientEvidence: return "questionmark.diamond"
        }
    }

    private var verdictColor: Color {
        switch investigation.verdict {
        case .likelyMalicious:      return .red
        case .likelyBenign:         return .green
        case .needsHuman:           return .orange
        case .insufficientEvidence: return .gray
        }
    }

    private static func relativeTime(_ date: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - SuggestedActionRow

struct SuggestedActionRow: View {
    let action: SuggestedAction

    @State private var confirmed: Bool = false
    @State private var dismissed: Bool = false
    @State private var showingPreview: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: kindIcon)
                    .font(.caption)
                    .foregroundColor(blastColor)
                    .accessibilityHidden(true)

                Text(action.title)
                    .font(.caption).fontWeight(.semibold)

                Spacer()

                blastBadge
                if let d3 = action.d3fendRef {
                    Text(d3).font(.caption2)
                        .padding(.horizontal, 4).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15))
                        .cornerRadius(3)
                        .foregroundColor(.secondary)
                }
            }

            Text(action.rationale)
                .font(.caption2).foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 6) {
                if let _ = action.previewCommand {
                    Button {
                        showingPreview.toggle()
                    } label: {
                        Label("Preview", systemImage: "eye")
                            .font(.caption2)
                    }
                    .buttonStyle(.bordered).controlSize(.small)
                }

                if confirmed {
                    Text("✓ Confirmed").font(.caption2).foregroundColor(.green)
                } else if dismissed {
                    Text("✕ Dismissed").font(.caption2).foregroundColor(.secondary)
                } else if action.requiresConfirmation {
                    Button {
                        confirmed = true
                    } label: {
                        Label("Confirm", systemImage: "checkmark.circle")
                            .font(.caption2)
                    }
                    .buttonStyle(.borderedProminent).controlSize(.small)

                    Button {
                        dismissed = true
                    } label: {
                        Label("Dismiss", systemImage: "xmark.circle")
                            .font(.caption2)
                    }
                    .buttonStyle(.bordered).controlSize(.small)
                }
            }

            if showingPreview, let preview = action.previewCommand {
                Text(preview)
                    .font(.system(.caption2, design: .monospaced))
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(4)
                    .textSelection(.enabled)
            }
        }
        .padding(6)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(6)
    }

    private var kindIcon: String {
        switch action.kind {
        case .document:         return "pencil"
        case .suppress:         return "eye.slash"
        case .quarantine:       return "archivebox.fill"
        case .blockNetwork:     return "network.slash"
        case .containProcess:   return "hand.raised.fill"
        case .revokeTCC:        return "lock.slash"
        case .rotateCredential: return "key.fill"
        case .escalate:         return "bell.and.waves.left.and.right"
        }
    }

    private var blastColor: Color {
        switch action.blastRadius {
        case .low:    return .green
        case .medium: return .yellow
        case .high:   return .red
        }
    }

    private var blastBadge: some View {
        Text(action.blastRadius.rawValue.uppercased())
            .font(.caption2).fontWeight(.semibold)
            .padding(.horizontal, 4).padding(.vertical, 1)
            .background(blastColor.opacity(0.15))
            .foregroundColor(blastColor)
            .cornerRadius(3)
    }
}
