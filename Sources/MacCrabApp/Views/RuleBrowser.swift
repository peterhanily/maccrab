// RuleBrowser.swift
// MacCrabApp
//
// Rule browser grouped by MITRE ATT&CK tactic. Shows a sidebar with tactic
// categories and a detail list of rules that can be searched and toggled.

import SwiftUI

// MARK: - RuleBrowser

struct RuleBrowser: View {
    @ObservedObject var appState: AppState
    @State private var searchText: String = ""
    @State private var selectedTactic: String? = nil
    @State private var showRuleWizard: Bool = false
    @State private var selectedRule: RuleViewModel? = nil

    /// Unique tactic groups derived from the loaded rules.
    private var tactics: [TacticGroup] {
        var groupMap: [String: Int] = [:]
        for rule in appState.rules {
            let tactic = rule.tacticName
            groupMap[tactic, default: 0] += 1
        }
        return groupMap
            .map { TacticGroup(id: $0.key.lowercased(), name: $0.key, ruleCount: $0.value) }
            .sorted { $0.name < $1.name }
    }

    /// Rules filtered by the currently selected tactic and search text.
    private var displayedRules: [RuleViewModel] {
        var results = appState.rules

        // Filter by selected tactic
        if let tactic = selectedTactic {
            results = results.filter { $0.tacticName.lowercased() == tactic.lowercased() }
        }

        // Filter by search text
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            results = results.filter { rule in
                rule.title.lowercased().contains(query)
                    || rule.description.lowercased().contains(query)
                    || rule.id.lowercased().contains(query)
                    || rule.tags.joined(separator: " ").lowercased().contains(query)
            }
        }

        return results
    }

    var body: some View {
        HSplitView {
            // Tactic sidebar
            VStack(alignment: .leading, spacing: 0) {
                Text(String(localized: "rules.tactics", defaultValue: "Tactics"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.top, 12)
                    .padding(.bottom, 4)

                List(selection: $selectedTactic) {
                    // "All" row
                    HStack {
                        Image(systemName: "shield")
                            .foregroundColor(.accentColor)
                        Text(String(localized: "rules.allRules", defaultValue: "All Rules"))
                        Spacer()
                        Text("\(appState.rules.count)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .tag(nil as String?)
                    .onTapGesture { selectedTactic = nil }

                    Divider()

                    // Tactic groups
                    ForEach(tactics) { tactic in
                        HStack {
                            Image(systemName: tacticIcon(for: tactic.name))
                                .foregroundColor(.accentColor)
                                .frame(width: 16)
                            Text(tactic.name)
                            Spacer()
                            Text("\(tactic.ruleCount)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .tag(tactic.name as String?)
                        .accessibilityLabel("\(tactic.name), \(tactic.ruleCount) rules")
                    }
                }
            }
            .frame(minWidth: 200, idealWidth: 220, maxWidth: 280)

            // Rules list
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 12) {
                    Text(String(localized: "rules.title", defaultValue: "Rules"))
                        .font(.title2)
                        .fontWeight(.bold)

                    Text("\(displayedRules.count)")
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.2))
                        .clipShape(Capsule())

                    if let tactic = selectedTactic {
                        Text(tactic)
                            .font(.caption)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Color.purple.opacity(0.15))
                            .foregroundColor(.purple)
                            .clipShape(Capsule())

                        Button {
                            selectedTactic = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                    }

                    Spacer()

                    Button {
                        showRuleWizard = true
                    } label: {
                        Label(String(localized: "rules.createRule", defaultValue: "Create Rule"), systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    TextField("Search rules...", text: $searchText)
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 150, idealWidth: 200, maxWidth: 300)
                        .accessibilityLabel("Search rules")
                }
                .padding()
                .sheet(isPresented: $showRuleWizard) {
                    RuleWizard()
                }

                Divider()

                if displayedRules.isEmpty {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "shield.slash")
                            .font(.system(size: 48))
                            .foregroundColor(.secondary.opacity(0.5))
                        Text(String(localized: "rules.noMatch", defaultValue: "No rules matching current filters"))
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    HStack(spacing: 0) {
                        List(displayedRules, selection: $selectedRule) { rule in
                            RuleRow(rule: rule)
                                .tag(rule)
                                .contentShape(Rectangle())
                                .onTapGesture { selectedRule = rule }
                        }

                        // Rule detail — only when selected
                        if let rule = selectedRule {
                            Divider()
                            RuleDetailPanel(rule: rule)
                                .frame(width: 420)
                                .transition(.move(edge: .trailing))
                        }
                    }
                    .animation(.easeInOut(duration: 0.2), value: selectedRule)
                }
            }
        }
        .task {
            await appState.loadRules()
        }
    }

    // MARK: Private

    /// Returns an appropriate SF Symbol for each MITRE ATT&CK tactic.
    private func tacticIcon(for tactic: String) -> String {
        switch tactic.lowercased() {
        case "initial access":       return "door.left.hand.open"
        case "execution":            return "terminal"
        case "persistence":          return "pin"
        case "privilege escalation": return "arrow.up.circle"
        case "defense evasion":      return "eye.slash"
        case "credential access":    return "key"
        case "discovery":            return "magnifyingglass"
        case "lateral movement":     return "arrow.left.arrow.right"
        case "collection":           return "tray.full"
        case "command and control":  return "antenna.radiowaves.left.and.right"
        case "exfiltration":         return "arrow.up.doc"
        case "impact":               return "bolt.slash"
        default:                     return "questionmark.circle"
        }
    }
}

// MARK: - Rule Detail Panel

import MacCrabCore
import AppKit

private struct RuleDetailPanel: View {
    let rule: RuleViewModel
    @State private var isEditing = false
    @State private var editedJSON = ""
    @State private var saveStatus: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                // Header
                HStack {
                    Text(rule.title).font(.title3).fontWeight(.bold)
                    Spacer()
                    SeverityLabel(level: rule.level)
                }

                // Status
                HStack {
                    Label(rule.enabled
                        ? String(localized: "rules.enabled", defaultValue: "Enabled")
                        : String(localized: "rules.disabled", defaultValue: "Disabled"),
                        systemImage: rule.enabled ? "checkmark.circle" : "xmark.circle")
                        .foregroundColor(rule.enabled ? .green : .red)
                        .font(.caption)
                    Spacer()
                }

                // Description
                if !rule.description.isEmpty {
                    GroupBox(String(localized: "ruleDetail.description", defaultValue: "Description")) {
                        Text(rule.description).font(.body).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
                    }
                }

                // MITRE ATT&CK
                if !rule.techniqueIds.isEmpty {
                    GroupBox(String(localized: "ruleDetail.mitreAttack", defaultValue: "MITRE ATT&CK")) {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: "shield.fill").foregroundColor(.purple).font(.caption)
                                Text("Tactic: \(rule.tacticName)").font(.subheadline)
                            }
                            ForEach(rule.techniqueIds, id: \.self) { tech in
                                HStack {
                                    Image(systemName: "chevron.right").font(.caption2).foregroundColor(.secondary)
                                    Text(tech).font(.system(.body, design: .monospaced))
                                    Spacer()
                                    Link("MITRE", destination: URL(string: "https://attack.mitre.org/techniques/\(tech.replacingOccurrences(of: ".", with: "/"))/")!)
                                        .font(.caption)
                                }
                            }
                        }.padding(4)
                    }
                }

                // Tags
                if !rule.tags.isEmpty {
                    GroupBox(String(localized: "ruleDetail.tags", defaultValue: "Tags")) {
                        FlowLayout(spacing: 4) {
                            ForEach(rule.tags, id: \.self) { tag in
                                Text(tag)
                                    .font(.caption2)
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(Color.accentColor.opacity(0.1))
                                    .clipShape(Capsule())
                            }
                        }.padding(4)
                    }
                }

                // Metadata
                GroupBox(String(localized: "ruleDetail.metadata", defaultValue: "Metadata")) {
                    VStack(alignment: .leading, spacing: 6) {
                        RuleDetailRow(label: String(localized: "ruleDetail.ruleId", defaultValue: "Rule ID"), value: rule.id)
                        RuleDetailRow(label: String(localized: "ruleDetail.severity", defaultValue: "Severity"), value: rule.level.capitalized)
                        RuleDetailRow(label: String(localized: "ruleDetail.status", defaultValue: "Status"), value: rule.enabled
                            ? String(localized: "rules.enabled", defaultValue: "Enabled")
                            : String(localized: "rules.disabled", defaultValue: "Disabled"))
                    }.padding(4)
                }

                // Response Actions config
                GroupBox(String(localized: "ruleDetail.responseActions", defaultValue: "Response Actions")) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(String(localized: "ruleDetail.configureInActions", defaultValue: "Configure in actions.json:")).font(.caption).foregroundColor(.secondary)
                        Text("""
                        {
                          "rules": {
                            "\(rule.id)": [
                              {"action": "notify", "minimumSeverity": "high"},
                              {"action": "kill", "minimumSeverity": "critical"}
                            ]
                          }
                        }
                        """)
                        .font(.system(.caption, design: .monospaced))
                        .padding(6)
                        .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                        .textSelection(.enabled)
                    }.padding(4)
                }

                // Actions
                HStack(spacing: 10) {
                    Button {
                        NSPasteboard.general.clearContents()
                        let text = "Rule: \(rule.title)\nID: \(rule.id)\nSeverity: \(rule.level)\nTactic: \(rule.tacticName)\nTechniques: \(rule.techniqueIds.joined(separator: ", "))\nDescription: \(rule.description)"
                        NSPasteboard.general.setString(text, forType: .string)
                    } label: {
                        Label(String(localized: "ruleDetail.copyDetails", defaultValue: "Copy Details"), systemImage: "doc.on.doc")
                    }.controlSize(.large)

                    Button {
                        // Open the compiled JSON file for this rule
                        let possiblePaths = [
                            NSHomeDirectory() + "/Library/Application Support/MacCrab/compiled_rules/",
                            FileManager.default.currentDirectoryPath + "/.build/debug/compiled_rules/",
                        ]
                        for dir in possiblePaths {
                            if let files = try? FileManager.default.contentsOfDirectory(atPath: dir) {
                                for file in files where file.hasSuffix(".json") {
                                    let path = dir + file
                                    if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                                       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                                       json["id"] as? String == rule.id {
                                        NSWorkspace.shared.open(URL(fileURLWithPath: path))
                                        return
                                    }
                                }
                            }
                        }
                    } label: {
                        Label(String(localized: "ruleDetail.openJSON", defaultValue: "Open JSON"), systemImage: "doc.text")
                    }.controlSize(.large)

                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(rule.id, forType: .string)
                    } label: {
                        Label(String(localized: "ruleDetail.copyId", defaultValue: "Copy ID"), systemImage: "number")
                    }.controlSize(.large)
                }

                if let status = saveStatus {
                    Text(status).font(.caption).foregroundColor(.green)
                }

                Spacer()
            }.padding()
        }.background(Color(nsColor: .controlBackgroundColor))
    }
}

private struct SeverityLabel: View {
    let level: String
    var color: Color {
        switch level.lowercased() {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        case "low": return .blue
        default: return .secondary
        }
    }
    var body: some View {
        Text(level.capitalized)
            .font(.caption).fontWeight(.bold)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.15))
            .foregroundColor(color)
            .clipShape(Capsule())
    }
}

private struct RuleDetailRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack(alignment: .top) {
            Text(label).font(.caption).foregroundColor(.secondary).frame(width: 60, alignment: .trailing)
            Text(value).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
        }
    }
}

private struct FlowLayout: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = layout(proposal: proposal, subviews: subviews)
        return result.size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = layout(proposal: proposal, subviews: subviews)
        for (index, position) in result.positions.enumerated() {
            subviews[index].place(at: CGPoint(x: bounds.minX + position.x, y: bounds.minY + position.y), proposal: .unspecified)
        }
    }

    private func layout(proposal: ProposedViewSize, subviews: Subviews) -> (size: CGSize, positions: [CGPoint]) {
        let maxWidth = proposal.width ?? .infinity
        var positions: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth && x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            positions.append(CGPoint(x: x, y: y))
            rowHeight = max(rowHeight, size.height)
            x += size.width + spacing
        }

        return (CGSize(width: maxWidth, height: y + rowHeight), positions)
    }
}

