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

    /// Read path: prefer the system-installed `actions.json` (most recent
    /// daemon wins), fall back to user-home if system is missing.
    private var readConfigPath: String {
        let fm = FileManager.default
        let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            .map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemConfig = "/Library/Application Support/MacCrab/actions.json"
        let userConfig = userDir + "/actions.json"
        if fm.isReadableFile(atPath: systemConfig) { return systemConfig }
        return userConfig
    }

    /// Write path: ALWAYS user-home. Pre-v1.6.19.1 the view tried to write
    /// to the system path which silently failed (try? swallowed the EPERM)
    /// and the "Saved" banner lied. Daemon now overlays user-home on top
    /// of system via `ResponseEngine.loadConfig`'s multi-user walk +
    /// SIGHUP reload, so user writes activate without a restart.
    private var writeConfigPath: String {
        let fm = FileManager.default
        let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            .map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        return userDir + "/actions.json"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(String(localized: "responseActions.title", defaultValue: "Response Actions"))
                    .font(.title2).fontWeight(.bold)
                Spacer()
                Button {
                    config = ActionConfig()  // Resets to built-in defaults
                    save()
                } label: {
                    Label(String(localized: "responseActions.resetDefaults", defaultValue: "Reset to Defaults"), systemImage: "arrow.counterclockwise")
                }
                .controlSize(.small)
                .accessibilityLabel("Reset all response actions to defaults")
                Button { showAddSheet = true } label: {
                    Label(String(localized: "responseActions.addRuleAction", defaultValue: "Add Rule Action"), systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .accessibilityLabel("Add a new response action rule")
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Explanation
                    GroupBox {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(String(localized: "responseActions.explanation", defaultValue: "Response actions execute automatically when detection rules fire."))
                                .font(.callout)
                            Text(String(localized: "responseActions.explanationDetail", defaultValue: "Configure what happens when specific rules trigger \u{2014} kill processes, quarantine files, send notifications, or run custom scripts."))
                                .font(.caption).foregroundColor(.secondary)
                        }.padding(4)
                    }

                    // Default actions
                    GroupBox(String(localized: "responseActions.defaultActions", defaultValue: "Default Actions (all rules)")) {
                        VStack(alignment: .leading, spacing: 8) {
                            if config.defaults.isEmpty {
                                Text(String(localized: "responseActions.noDefaults", defaultValue: "No default actions configured")).font(.caption).foregroundColor(.secondary)
                            }
                            ForEach(config.defaults.indices, id: \.self) { i in
                                ActionRow(action: $config.defaults[i], onDelete: {
                                    config.defaults.remove(at: i)
                                    save()
                                })
                            }
                            Button {
                                config.defaults.append(ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil, requireConfirmation: nil))
                                save()
                            } label: {
                                Label(String(localized: "responseActions.addDefault", defaultValue: "Add Default Action"), systemImage: "plus.circle")
                            }.font(.caption)
                        }.padding(8)
                    }

                    // Per-rule actions
                    GroupBox(String(localized: "responseActions.perRule", defaultValue: "Per-Rule Actions")) {
                        VStack(alignment: .leading, spacing: 12) {
                            if config.rules.isEmpty {
                                VStack(spacing: 8) {
                                    Image(systemName: "bolt.slash").font(.title2).foregroundColor(.secondary.opacity(0.5))
                                        .accessibilityHidden(true)
                                    Text(String(localized: "responseActions.noPerRule", defaultValue: "No per-rule actions configured")).font(.caption).foregroundColor(.secondary)
                                    Text(String(localized: "responseActions.noPerRuleHint", defaultValue: "Click 'Add Rule Action' to configure responses for specific rules."))
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
                                        }
                                        .buttonStyle(.borderless)
                                        .accessibilityLabel("Delete this action")
                                    }

                                    ForEach((config.rules[ruleId] ?? []).indices, id: \.self) { i in
                                        ActionRow(action: Binding(
                                            get: { config.rules[ruleId]?[i] ?? ActionEntry(action: "log", minimumSeverity: "high", scriptPath: nil, requireConfirmation: nil) },
                                            set: { config.rules[ruleId]?[i] = $0; save() }
                                        ), onDelete: {
                                            config.rules[ruleId]?.remove(at: i)
                                            if config.rules[ruleId]?.isEmpty == true { config.rules.removeValue(forKey: ruleId) }
                                            save()
                                        })
                                    }

                                    Button {
                                        if config.rules[ruleId] == nil { config.rules[ruleId] = [] }
                                        config.rules[ruleId]?.append(ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil, requireConfirmation: nil))
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
                    GroupBox(String(localized: "responseActions.activeSuppressions", defaultValue: "Active Suppressions")) {
                        Text(String(localized: "responseActions.suppressionsDesc", defaultValue: "Alerts matching these patterns are hidden from the dashboard."))
                            .font(.caption).foregroundColor(.secondary)
                        // This is managed via AppState.suppressionPatterns
                        Text(String(localized: "responseActions.suppressionsHint", defaultValue: "Manage via 'Suppress All Like This' button in alert details."))
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
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: readConfigPath)),
              let decoded = try? JSONDecoder().decode(ActionConfig.self, from: data) else {
            // No config file — use built-in defaults (already set via default values)
            return
        }
        config = decoded
    }

    private func save() {
        let path = writeConfigPath
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        guard let data = try? JSONEncoder().encode(config) else {
            saveStatus = "Save failed: could not encode config"
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { saveStatus = nil }
            return
        }
        do {
            // Atomic write so the daemon's loader never sees a partial file.
            let tmp = path + ".tmp"
            try data.write(to: URL(fileURLWithPath: tmp))
            _ = try? FileManager.default.removeItem(atPath: path)
            try FileManager.default.moveItem(atPath: tmp, toPath: path)
        } catch {
            saveStatus = "Save failed: \(error.localizedDescription)"
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { saveStatus = nil }
            return
        }
        // Ask the engine to re-read the response-action config. v1.21.4 (audit):
        // the old bare `pkill -HUP com.maccrab.agent` here was EPERM cross-uid
        // (uid-501 app → root sysext), so on a release build the SIGHUP never
        // fired and ResponseEngine.loadConfig never ran — yet the banner still
        // claimed "Daemon reloaded" whenever pkill *exited 0* (which it does
        // even when it matches nothing). Route through the proven inbox path
        // like the webhook / notification config writers, and base the banner
        // on the inbox-drop success (dev `maccrabd` still honors SIGHUP via the
        // same helper), so the message tells the truth on release.
        let reloaded = V2DaemonControl.reloadDetectionRules()
        saveStatus = reloaded
            ? "Saved. Daemon reloading."
            : "Saved. Daemon will reload on next start."
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { saveStatus = nil }
    }
}

// MARK: - Data Models

private struct ActionConfig: Codable {
    var defaults: [ActionEntry] = ActionConfig.builtInDefaults
    var rules: [String: [ActionEntry]] = ActionConfig.builtInRuleActions

    static let builtInDefaults: [ActionEntry] = [
        ActionEntry(action: "notify", minimumSeverity: "critical", scriptPath: nil),
        ActionEntry(action: "log", minimumSeverity: "low", scriptPath: nil),
    ]

    static let builtInRuleActions: [String: [ActionEntry]] = [
        // AI Guard — critical credential access gets escalated notification
        "maccrab.ai-guard.credential-access": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "high", scriptPath: nil),
        ],
        // Event tap keylogger — kill the process
        "maccrab.deep.event-tap-keylogger": [
            ActionEntry(action: "kill", minimumSeverity: "critical", scriptPath: nil),
            ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil),
        ],
        // Prompt injection — escalated notification
        "maccrab.ai-guard.prompt-injection": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "high", scriptPath: nil),
        ],
        // Cross-process attack chain — escalated notification
        "maccrab.correlator.cross-process": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "high", scriptPath: nil),
        ],
        // MCP suspicious server — escalated notification
        "maccrab.ai-guard.mcp-mcp_server_suspicious": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "high", scriptPath: nil),
        ],
        // AI boundary violation — notify
        "maccrab.ai-guard.boundary-violation": [
            ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil),
        ],
        // Behavioral score threshold — escalated notification
        "maccrab.behavior.composite": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "high", scriptPath: nil),
        ],
        // Threat intel DNS match — escalated notification + block
        "maccrab.dns.threat-intel-match": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "critical", scriptPath: nil),
        ],
        // Self-defense tamper — escalated notification
        "maccrab.self-defense.binary_modified": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "critical", scriptPath: nil),
        ],
        "maccrab.self-defense.rules_modified": [
            ActionEntry(action: "escalateNotification", minimumSeverity: "critical", scriptPath: nil),
        ],
    ]
}

private struct ActionEntry: Codable {
    var action: String // "log", "notify", "kill", "quarantine", "script", "escalateNotification", "blockNetwork"
    var minimumSeverity: String // "low", "medium", "high", "critical"
    var scriptPath: String?
    /// When true, ResponseEngine logs the action as pending and skips
    /// auto-execution. v1.6.19.1 wired the flag through; pre-fix it was
    /// decoded but ignored. Default `false` to preserve historical
    /// behaviour for existing actions; new destructive actions added
    /// from the editor default to `true` (set in `ActionRow` defaults
    /// for kill / quarantine / blockNetwork — see DEFAULT_REQUIRE_CONFIRM).
    var requireConfirmation: Bool? = nil
}

/// Action types that default to `requireConfirmation = true` when
/// added from the editor. The flag stays editable; this just makes the
/// safer default the one you opt out of, not the one you opt in to.
private let DEFAULT_REQUIRE_CONFIRM: Set<String> = ["kill", "quarantine", "blockNetwork"]

// MARK: - Action Row

private struct ActionRow: View {
    @Binding var action: ActionEntry
    let onDelete: () -> Void


    var actionIcon: String {
        switch action.action {
        case "kill": return "xmark.circle.fill"
        case "quarantine": return "archivebox.fill"
        case "script": return "terminal.fill"
        case "notify": return "bell.fill"
        case "escalateNotification": return "bell.badge.fill"
        case "blockNetwork": return "network.slash"
        default: return "doc.text"
        }
    }

    var actionColor: Color {
        switch action.action {
        case "kill": return .red
        case "quarantine": return .orange
        case "script": return .blue
        case "notify": return .green
        case "escalateNotification": return .purple
        case "blockNetwork": return .red
        default: return .secondary
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: actionIcon)
                .foregroundColor(actionColor)
                .frame(width: 20)
                .accessibilityHidden(true)

            Picker("Action", selection: $action.action) {
                Text(String(localized: "responseAction.logOnly", defaultValue: "Log Only")).tag("log")
                Text(String(localized: "responseAction.notify", defaultValue: "Notify")).tag("notify")
                Text(String(localized: "responseAction.escalate", defaultValue: "Escalate Notification")).tag("escalateNotification")
                Text(String(localized: "responseAction.killProcess", defaultValue: "Kill Process")).tag("kill")
                Text(String(localized: "responseAction.quarantine", defaultValue: "Quarantine File")).tag("quarantine")
                Text(String(localized: "responseAction.blockNetwork", defaultValue: "Block Network")).tag("blockNetwork")
                Text(String(localized: "responseAction.runScript", defaultValue: "Run Script")).tag("script")
            }
            .labelsHidden()
            .frame(width: 200)
            .controlSize(.small)

            Text(String(localized: "responseActions.whenSeverity", defaultValue: "when severity \u{2265}"))
                .font(.caption).foregroundColor(.secondary)

            Picker("Severity", selection: $action.minimumSeverity) {
                Text(String(localized: "severity.informational", defaultValue: "Informational")).tag("informational")
                Text(String(localized: "severity.low", defaultValue: "Low")).tag("low")
                Text(String(localized: "severity.medium", defaultValue: "Medium")).tag("medium")
                Text(String(localized: "severity.high", defaultValue: "High")).tag("high")
                Text(String(localized: "severity.critical", defaultValue: "Critical")).tag("critical")
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

            // requireConfirmation toggle. Surfaced for every action type
            // so the operator can flip the gate even on benign actions.
            // Defaults to true for kill / quarantine / blockNetwork via
            // DEFAULT_REQUIRE_CONFIRM at row creation.
            Toggle(isOn: Binding(
                get: { action.requireConfirmation ?? false },
                set: { action.requireConfirmation = $0 ? true : nil }
            )) {
                Text(String(localized: "responseAction.requireConfirm", defaultValue: "Confirm before"))
                    .font(.caption)
            }
            .toggleStyle(.checkbox)
            .help("When checked, MacCrab logs this action as pending instead of auto-executing. Useful as a safety gate on kill / quarantine / blockNetwork.")

            Spacer()

            Button { onDelete() } label: {
                Image(systemName: "minus.circle").foregroundColor(.red)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Delete this action")
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Add Rule Action Sheet

private struct AddRuleActionSheet: View {
    let onAdd: (String, ActionEntry) -> Void
    @Environment(\.dismiss) var dismiss
    @State private var ruleId: String = ""
    @State private var action = ActionEntry(action: "notify", minimumSeverity: "high", scriptPath: nil, requireConfirmation: nil)

    var body: some View {
        VStack(spacing: 16) {
            Text(String(localized: "addRuleAction.title", defaultValue: "Add Response Action for Rule")).font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                Text(String(localized: "addRuleAction.ruleIdHint", defaultValue: "Rule ID (paste from rule detail panel)")).font(.caption).foregroundColor(.secondary)
                TextField("e.g., d1a2b3c4-2001-4000-a000-000000002001", text: $ruleId)
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.large)
            }

            HStack {
                Picker("Action", selection: $action.action) {
                    Text(String(localized: "responseAction.logOnly", defaultValue: "Log Only")).tag("log")
                    Text(String(localized: "responseAction.notify", defaultValue: "Notify")).tag("notify")
                    Text(String(localized: "responseAction.escalate", defaultValue: "Escalate Notification")).tag("escalateNotification")
                    Text(String(localized: "responseAction.killProcess", defaultValue: "Kill Process")).tag("kill")
                    Text(String(localized: "responseAction.quarantine", defaultValue: "Quarantine File")).tag("quarantine")
                    Text(String(localized: "responseAction.blockNetwork", defaultValue: "Block Network")).tag("blockNetwork")
                    Text(String(localized: "responseAction.runScript", defaultValue: "Run Script")).tag("script")
                }.controlSize(.large)

                Picker("Min Severity", selection: $action.minimumSeverity) {
                    Text(String(localized: "severity.informational", defaultValue: "Informational")).tag("informational")
                    Text(String(localized: "severity.low", defaultValue: "Low")).tag("low")
                    Text(String(localized: "severity.medium", defaultValue: "Medium")).tag("medium")
                    Text(String(localized: "severity.high", defaultValue: "High")).tag("high")
                    Text(String(localized: "severity.critical", defaultValue: "Critical")).tag("critical")
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

            // Show + edit requireConfirmation. Defaults to true when the
            // selected action is destructive (kill / quarantine / blockNetwork).
            // The destructive picks display a red warning icon to remind
            // operators what they're enabling.
            HStack(spacing: 6) {
                if DEFAULT_REQUIRE_CONFIRM.contains(action.action) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                        .accessibilityLabel("Destructive action")
                }
                Toggle(isOn: Binding(
                    get: {
                        // If user hasn't set the flag explicitly, infer
                        // based on whether the action is destructive.
                        action.requireConfirmation ?? DEFAULT_REQUIRE_CONFIRM.contains(action.action)
                    },
                    set: { action.requireConfirmation = $0 ? true : nil }
                )) {
                    Text(String(localized: "addRuleAction.requireConfirm", defaultValue: "Require operator confirmation before executing"))
                        .font(.caption)
                }
                .toggleStyle(.checkbox)
            }
            .padding(.top, 4)

            HStack {
                Button(String(localized: "addRuleAction.cancel", defaultValue: "Cancel")) { dismiss() }
                Spacer()
                Button(String(localized: "addRuleAction.add", defaultValue: "Add Action")) {
                    guard !ruleId.isEmpty else { return }
                    // If the user opened the destructive action picker but
                    // didn't toggle anything, persist the inferred default
                    // explicitly so subsequent edits don't surprise them.
                    var pendingAction = action
                    if pendingAction.requireConfirmation == nil
                       && DEFAULT_REQUIRE_CONFIRM.contains(pendingAction.action) {
                        pendingAction.requireConfirmation = true
                    }
                    onAdd(ruleId, pendingAction)
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
