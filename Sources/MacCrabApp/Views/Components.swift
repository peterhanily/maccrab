// Components.swift
// MacCrabApp
//
// Reusable small view components used across the application:
// SeverityChip, AlertRow, AlertMenuItem, SignerBadge, RuleRow.

import SwiftUI

// MARK: - SeverityChip

/// A colored pill-shaped button for filtering by severity level.
struct SeverityChip: View {
    let severity: Severity
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(severity.label)
                .font(.caption)
                .fontWeight(isSelected ? .bold : .regular)
                .minimumScaleFactor(0.8)
                .lineLimit(1)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(isSelected ? severity.color.opacity(0.25) : Color.clear)
                .foregroundColor(isSelected ? severity.color : .secondary)
                .clipShape(Capsule())
                .overlay(
                    Capsule()
                        .strokeBorder(severity.color.opacity(isSelected ? 0.8 : 0.3), lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(severity.label) severity filter")
    }
}

// MARK: - AlertRow

/// A single row in the alert dashboard list.
struct AlertRow: View {
    let alert: AlertViewModel
    let onSuppress: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Severity indicator bar — grey for suppressed
            RoundedRectangle(cornerRadius: 2)
                .fill(alert.suppressed ? Color.secondary.opacity(0.3) : alert.severityColor)
                .frame(width: 4)
                .padding(.vertical, 2)
                .accessibilityLabel(Text(alert.suppressed ? "Suppressed" : "\(alert.severity.rawValue) severity"))

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    if alert.suppressed {
                        Image(systemName: "eye.slash.fill")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .accessibilityHidden(true)
                    }
                    Text(alert.ruleTitle)
                        .font(.headline)
                        .lineLimit(2)
                        .minimumScaleFactor(0.8)
                        .foregroundColor(alert.suppressed ? .secondary : .primary)
                    if alert.suppressed {
                        Text(String(localized: "alerts.suppressed", defaultValue: "Suppressed"))
                            .font(.caption2)
                            .foregroundColor(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.secondary)
                            .clipShape(Capsule())
                    }
                    Spacer()
                    Text(alert.dateTimeString)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Text(alert.description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .lineLimit(3)
                    .minimumScaleFactor(0.85)

                HStack(spacing: 12) {
                    Label(alert.severity.label, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundColor(alert.suppressed ? .secondary : alert.severityColor)

                    Label(alert.processName, systemImage: "gearshape")
                        .font(.subheadline)
                        .foregroundColor(.secondary)

                    if !alert.mitreTechniques.isEmpty {
                        Label(alert.mitreTechniques, systemImage: "shield")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    if !alert.suppressed {
                        Button(String(localized: "components.suppress", defaultValue: "Suppress")) {
                            onSuppress()
                        }
                        .font(.caption)
                        .buttonStyle(.borderless)
                    }
                }
            }
        }
        .padding(.vertical, 6)
        .padding(.horizontal, alert.suppressed ? 4 : 0)
        .background(alert.suppressed ? Color.secondary.opacity(0.05) : Color.clear)
        .cornerRadius(6)
        .opacity(alert.suppressed ? 0.65 : 1.0)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - AlertMenuItem

/// A compact alert representation for the status bar dropdown menu.
struct AlertMenuItem: View {
    let alert: AlertViewModel

    var body: some View {
        Button {
            NSApplication.shared.activate(ignoringOtherApps: true)
        } label: {
            HStack(spacing: 8) {
                Circle()
                    .fill(alert.severityColor)
                    .frame(width: 8, height: 8)
                    .accessibilityLabel(Text("\(alert.severity.rawValue) severity"))

                VStack(alignment: .leading, spacing: 1) {
                    Text(alert.ruleTitle)
                        .font(.system(.body))
                        .lineLimit(1)
                    Text("\(alert.processName) -- \(alert.timeString)")
                        .font(.system(.caption))
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

// MARK: - SignerBadge

/// A small colored badge indicating the code-signing status of a binary.
struct SignerBadge: View {
    let signerType: String

    private var label: String {
        switch signerType {
        case "apple":    return "Apple"
        case "appStore": return "App Store"
        case "devId":    return "Dev ID"
        case "adHoc":    return "Ad Hoc"
        case "unsigned": return "Unsigned"
        default:         return signerType
        }
    }

    private var color: Color {
        switch signerType {
        case "apple":    return .green
        case "appStore": return .blue
        case "devId":    return .teal
        case "adHoc":    return .orange
        case "unsigned": return .red
        default:         return .secondary
        }
    }

    var body: some View {
        Text(label)
            .font(.caption2)
            .fontWeight(.medium)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundColor(color)
            .clipShape(Capsule())
            .accessibilityLabel("Signed by \(signerType)")
    }
}

// MARK: - RuleRow

/// A single row in the rule browser list.
struct RuleRow: View {
    let rule: RuleViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Circle()
                    .fill(levelColor)
                    .frame(width: 8, height: 8)
                Text(rule.title)
                    .font(.headline)
                    .lineLimit(1)
                Spacer()
                if !rule.enabled {
                    Text(String(localized: "rules.disabled", defaultValue: "Disabled"))
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.2))
                        .clipShape(Capsule())
                }
                Text(rule.level.capitalized)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(levelColor)
            }

            Text(rule.description)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)

            HStack(spacing: 6) {
                ForEach(rule.techniqueIds, id: \.self) { technique in
                    Text(technique)
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.accentColor.opacity(0.1))
                        .clipShape(Capsule())
                }

                ForEach(tacticTags, id: \.self) { tactic in
                    Text(tactic)
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.purple.opacity(0.1))
                        .foregroundColor(.purple)
                        .clipShape(Capsule())
                }
            }
        }
        .padding(.vertical, 4)
        .opacity(rule.enabled ? 1.0 : 0.5)
    }

    private var levelColor: Color {
        switch rule.level.lowercased() {
        case "critical":      return .red
        case "high":          return .orange
        case "medium":        return Color(red: 0.67, green: 0.37, blue: 0.0)  // Dark amber — WCAG AA compliant (~4.8:1 on white)
        case "low":           return .blue
        case "informational": return .secondary
        default:              return .secondary
        }
    }

    private var tacticTags: [String] {
        rule.tags
            .filter { $0.lowercased().hasPrefix("attack.") && !$0.lowercased().hasPrefix("attack.t") }
            .map { String($0.dropFirst("attack.".count)).replacingOccurrences(of: "_", with: " ").capitalized }
    }
}

// MARK: - ConnectionStatusBadge

/// Small indicator showing daemon connection status.
struct ConnectionStatusBadge: View {
    let isConnected: Bool

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(isConnected ? Color.green : Color.red)
                .frame(width: 6, height: 6)
            Text(isConnected
                ? String(localized: "status.connected", defaultValue: "Connected")
                : String(localized: "status.disconnected", defaultValue: "Disconnected"))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }
}

