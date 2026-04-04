// ResponseActionsView.swift
// MacCrabApp
//
// UI for viewing and configuring response actions.
// Shows configured actions per rule and allows editing.

import SwiftUI
import AppKit

/// Manages response action configuration via the UI.
/// Reads/writes ~/Library/Application Support/MacCrab/actions.json
struct ResponseActionsView: View {
    @State private var config: ActionConfig = ActionConfig()
    @State private var newRuleId: String = ""
    @State private var saveStatus: String?
    @State private var showAddSheet = false

    private var configPath: String {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("MacCrab").path
        return dir + "/actions.json"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Response Actions")
                    .font(.title2).fontWeight(.bold)
                Spacer()
                Button { showAddSheet = true } label: {
                    Label("Add Rule Action", systemImage: "plus")
                }.buttonStyle(.borderedProminent).controlSize(.small)
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Explanation
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Response actions execute automatically when detection rules fire.")
                                .font(.callout)
                            Text("Configure what happens when specific rules trigger — kill processes, quarantine files, send notifications, or run custom scripts.")
                                .font(.caption).foregroundColor(.secondary)
                        }.padding(4)
                    }

                    // Default actions
                    GroupBox("Default Actions (all rules)") {
                        VStack(alignment: .leading, spacing: 8) {
                            if config.defaults.isEmpty {
                                Text("No default actions configured").font(.caption).foregroundColor(.secondary)
                            }
                            ForEach(config.defaults.indices, id: \.self) { i in
                                ActionRow(action: $config.defaults[i], onDelete: {
                                    config.defaults.remove(at: i)
                                    save()
                                })
                            }
                            Button {
                                config.defaults.append(ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil))
                                save()
                            } label: {
                                Label("Add Default Action", systemImage: "plus.circle")
                            }.font(.caption)
                        }.padding(8)
                    }

                    // Per-rule actions
                    GroupBox("Per-Rule Actions") {
                        VStack(alignment: .leading, spacing: 12) {
                            if config.rules.isEmpty {
                                VStack(spacing: 8) {
                                    Image(systemName: "bolt.slash").font(.title2).foregroundColor(.secondary.opacity(0.5))
                                    Text("No per-rule actions configured").font(.caption).foregroundColor(.secondary)
                                    Text("Click 'Add Rule Action' to configure responses for specific rules.")
                                        .font(.caption2).foregroundColor(.secondary)
                                }.frame(maxWidth: .infinity).padding()
                            }

                            ForEach(Array(config.rules.keys.sorted()), id: \.self) { ruleId in
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack {
                                        Text(ruleId)
                                            .font(.system(.caption, design: .monospaced))
                                            .fontWeight(.medium)
                                        Spacer()
                                        Button {
                                            config.rules.removeValue(forKey: ruleId)
                                            save()
                                        } label: {
                                            Image(systemName: "trash").foregroundColor(.red).font(.caption)
                                        }.buttonStyle(.borderless)
                                    }

                                    ForEach((config.rules[ruleId] ?? []).indices, id: \.self) { i in
                                        ActionRow(action: Binding(
                                            get: { config.rules[ruleId]?[i] ?? ActionEntry(action: "log", minimumSeverity: "high", scriptPath: nil) },
                                            set: { config.rules[ruleId]?[i] = $0; save() }
                                        ), onDelete: {
                                            config.rules[ruleId]?.remove(at: i)
                                            if config.rules[ruleId]?.isEmpty == true { config.rules.removeValue(forKey: ruleId) }
                                            save()
                                        })
                                    }

                                    Button {
                                        if config.rules[ruleId] == nil { config.rules[ruleId] = [] }
                                        config.rules[ruleId]?.append(ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil))
                                        save()
                                    } label: {
                                        Label("Add Action", systemImage: "plus.circle")
                                    }.font(.caption)

                                    Divider()
                                }
                            }
                        }.padding(8)
                    }

                    // Suppression patterns
                    GroupBox("Active Suppressions") {
                        Text("Alerts matching these patterns are hidden from the dashboard.")
                            .font(.caption).foregroundColor(.secondary)
                        // This is managed via AppState.suppressionPatterns
                        Text("Manage via 'Suppress All Like This' button in alert details.")
                            .font(.caption2).foregroundColor(.secondary)
                    }

                    if let status = saveStatus {
                        Text(status).font(.caption).foregroundColor(.green)
                    }
                }
                .padding()
            }
        }
        .onAppear { load() }
        .sheet(isPresented: $showAddSheet) {
            AddRuleActionSheet(onAdd: { ruleId, action in
                if config.rules[ruleId] == nil { config.rules[ruleId] = [] }
                config.rules[ruleId]?.append(action)
                save()
            })
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let decoded = try? JSONDecoder().decode(ActionConfig.self, from: data) else { return }
        config = decoded
    }

    private func save() {
        let dir = (configPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(config) {
            try? data.write(to: URL(fileURLWithPath: configPath))
            saveStatus = "Saved. Restart daemon to apply."
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { saveStatus = nil }
        }
    }
}

// MARK: - Data Models

private struct ActionConfig: Codable {
    var defaults: [ActionEntry] = []
    var rules: [String: [ActionEntry]] = [:]
}

private struct ActionEntry: Codable {
    var action: String // "log", "notify", "kill", "quarantine", "script"
    var minimumSeverity: String // "low", "medium", "high", "critical"
    var scriptPath: String?
}

// MARK: - Action Row

private struct ActionRow: View {
    @Binding var action: ActionEntry
    let onDelete: () -> Void

    let actions = ["log", "notify", "kill", "quarantine", "script"]
    let severities = ["informational", "low", "medium", "high", "critical"]

    var actionIcon: String {
        switch action.action {
        case "kill": return "xmark.circle.fill"
        case "quarantine": return "archivebox.fill"
        case "script": return "terminal.fill"
        case "notify": return "bell.fill"
        default: return "doc.text"
        }
    }

    var actionColor: Color {
        switch action.action {
        case "kill": return .red
        case "quarantine": return .orange
        case "script": return .blue
        case "notify": return .green
        default: return .secondary
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: actionIcon)
                .foregroundColor(actionColor)
                .frame(width: 20)

            Picker("Action", selection: $action.action) {
                ForEach(actions, id: \.self) { Text($0.capitalized).tag($0) }
            }
            .labelsHidden()
            .frame(width: 110)
            .controlSize(.small)

            Text("when severity ≥")
                .font(.caption).foregroundColor(.secondary)

            Picker("Severity", selection: $action.minimumSeverity) {
                ForEach(severities, id: \.self) { Text($0.capitalized).tag($0) }
            }
            .labelsHidden()
            .frame(width: 110)
            .controlSize(.small)

            if action.action == "script" {
                TextField("Script path", text: Binding(
                    get: { action.scriptPath ?? "" },
                    set: { action.scriptPath = $0.isEmpty ? nil : $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .font(.caption)
                .frame(width: 150)
            }

            Spacer()

            Button { onDelete() } label: {
                Image(systemName: "minus.circle").foregroundColor(.red)
            }.buttonStyle(.borderless)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Add Rule Action Sheet

private struct AddRuleActionSheet: View {
    let onAdd: (String, ActionEntry) -> Void
    @Environment(\.dismiss) var dismiss
    @State private var ruleId: String = ""
    @State private var action = ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil)

    var body: some View {
        VStack(spacing: 16) {
            Text("Add Response Action for Rule").font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                Text("Rule ID (paste from rule detail panel)").font(.caption).foregroundColor(.secondary)
                TextField("e.g., d1a2b3c4-2001-4000-a000-000000002001", text: $ruleId)
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.large)
            }

            HStack {
                Picker("Action", selection: $action.action) {
                    Text("Notify").tag("notify")
                    Text("Kill Process").tag("kill")
                    Text("Quarantine File").tag("quarantine")
                    Text("Run Script").tag("script")
                    Text("Log Only").tag("log")
                }.controlSize(.large)

                Picker("Min Severity", selection: $action.minimumSeverity) {
                    Text("Low").tag("low")
                    Text("Medium").tag("medium")
                    Text("High").tag("high")
                    Text("Critical").tag("critical")
                }.controlSize(.large)
            }

            if action.action == "script" {
                TextField("Script path", text: Binding(
                    get: { action.scriptPath ?? "" },
                    set: { action.scriptPath = $0.isEmpty ? nil : $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .controlSize(.large)
            }

            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Add Action") {
                    guard !ruleId.isEmpty else { return }
                    onAdd(ruleId, action)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(ruleId.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 500)
    }
}
