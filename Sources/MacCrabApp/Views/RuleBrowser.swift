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
                Text("Tactics")
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
                        Text("All Rules")
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
                    Text("Rules")
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
                        Label("Create Rule", systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    TextField("Search rules...", text: $searchText)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 250)
                        .accessibilityLabel("Search detection rules")
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
                        Text("No rules matching current filters")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    List(displayedRules) { rule in
                        RuleRow(rule: rule)
                    }
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

