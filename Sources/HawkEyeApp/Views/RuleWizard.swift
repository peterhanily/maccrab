// RuleWizard.swift
// HawkEyeApp
//
// Interactive rule creation wizard. Walk through steps to build a
// detection rule, preview the YAML, and save it to disk.

import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: - Rule Wizard

struct RuleWizard: View {
    @Environment(\.dismiss) private var dismiss
    @State private var step: WizardStep = .metadata
    @State private var rule = RuleDraft()
    @State private var savedPath: String? = nil

    enum WizardStep: Int, CaseIterable {
        case metadata = 0
        case detection = 1
        case filters = 2
        case options = 3
        case preview = 4

        var title: String {
            switch self {
            case .metadata:  return "Rule Info"
            case .detection: return "Detection"
            case .filters:   return "Filters"
            case .options:    return "Options"
            case .preview:    return "Preview & Save"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Step indicator
            HStack(spacing: 0) {
                ForEach(WizardStep.allCases, id: \.rawValue) { s in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(s.rawValue <= step.rawValue ? Color.accentColor : Color.secondary.opacity(0.3))
                            .frame(width: 24, height: 24)
                            .overlay(
                                Text("\(s.rawValue + 1)")
                                    .font(.caption2).fontWeight(.bold)
                                    .foregroundColor(.white)
                            )
                        if s != WizardStep.allCases.last {
                            Rectangle()
                                .fill(s.rawValue < step.rawValue ? Color.accentColor : Color.secondary.opacity(0.2))
                                .frame(height: 2)
                        }
                    }
                }
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 12)

            Text(step.title)
                .font(.title3).fontWeight(.semibold)
                .padding(.bottom, 8)

            Divider()

            // Step content
            ScrollView {
                Group {
                    switch step {
                    case .metadata:  MetadataStep(rule: $rule)
                    case .detection: DetectionStep(rule: $rule)
                    case .filters:   FiltersStep(rule: $rule)
                    case .options:   OptionsStep(rule: $rule)
                    case .preview:   PreviewStep(rule: $rule, savedPath: $savedPath)
                    }
                }
                .padding(24)
            }

            Divider()

            // Navigation buttons
            HStack {
                if step != .metadata {
                    Button("Back") {
                        withAnimation { step = WizardStep(rawValue: step.rawValue - 1) ?? .metadata }
                    }
                }
                Spacer()
                if step == .preview {
                    if savedPath != nil {
                        Button("Done") { dismiss() }
                            .keyboardShortcut(.return)
                    } else {
                        Button("Save Rule") { saveRule() }
                            .keyboardShortcut(.return)
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    Button("Next") {
                        withAnimation { step = WizardStep(rawValue: step.rawValue + 1) ?? .preview }
                    }
                    .keyboardShortcut(.return)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdvance)
                }
            }
            .padding(16)
        }
        .frame(width: 700, height: 600)
    }

    private var canAdvance: Bool {
        switch step {
        case .metadata:
            return !rule.title.isEmpty
        case .detection:
            return !rule.conditions.isEmpty && rule.conditions.allSatisfy { !$0.field.isEmpty && !$0.value.isEmpty }
        default:
            return true
        }
    }

    private func saveRule() {
        let yaml = rule.toYAML()

        let panel = NSSavePanel()
        panel.title = "Save Detection Rule"
        panel.nameFieldStringValue = rule.filename
        panel.allowedContentTypes = [.yaml]
        panel.canCreateDirectories = true

        // Default to Rules directory
        let rulesDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Rules")
            .appendingPathComponent(rule.tacticDir)
        if FileManager.default.fileExists(atPath: rulesDir.path) {
            panel.directoryURL = rulesDir
        }

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try yaml.write(to: url, atomically: true, encoding: .utf8)
                savedPath = url.path
            } catch {
                savedPath = nil
            }
        }
    }
}

// MARK: - Rule Draft Model

struct RuleConditionEntry: Identifiable {
    let id = UUID()
    var field: String = ""
    var modifier: String = "contains"
    var value: String = ""
}

struct RuleFilterEntry: Identifiable {
    let id = UUID()
    var field: String = "SignerType"
    var modifier: String = "equals"
    var values: [String] = ["apple", "devId"]
}

struct RuleDraft {
    var title: String = ""
    var description: String = ""
    var author: String = NSFullUserName()
    var category: String = "process_creation"
    var severity: String = "high"
    var tactic: String = "attack.execution"
    var techniqueId: String = ""

    var conditions: [RuleConditionEntry] = [RuleConditionEntry()]
    var filters: [RuleFilterEntry] = []
    var falsepositives: String = ""

    var filename: String {
        let slug = title.lowercased()
            .replacingOccurrences(of: " ", with: "_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" }
        return (slug.isEmpty ? "new_rule" : slug) + ".yml"
    }

    var tacticDir: String {
        let tac = tactic.replacingOccurrences(of: "attack.", with: "")
        return tac.isEmpty ? "other" : tac
    }

    func toYAML() -> String {
        let id = UUID().uuidString.lowercased()
        let date = {
            let f = DateFormatter(); f.dateFormat = "yyyy/MM/dd"
            return f.string(from: Date())
        }()

        var tags = [tactic]
        if !techniqueId.isEmpty {
            let tid = techniqueId.lowercased()
            tags.append(tid.hasPrefix("attack.") ? tid : "attack.\(tid)")
        }

        var yaml = """
        title: \(title)
        id: \(id)
        status: experimental
        description: >
            \(description.isEmpty ? "Custom detection rule." : description)
        author: \(author)
        date: \(date)
        references:
            - https://attack.mitre.org/techniques/\(techniqueId.uppercased().replacingOccurrences(of: "ATTACK.", with: ""))/
        tags:
        \(tags.map { "    - \($0)" }.joined(separator: "\n"))
        logsource:
            category: \(category)
            product: macos
        detection:
            selection:

        """

        // Build selection block
        for cond in conditions where !cond.field.isEmpty && !cond.value.isEmpty {
            let fieldKey: String
            if cond.modifier == "equals" {
                fieldKey = "        \(cond.field):"
            } else {
                fieldKey = "        \(cond.field)|\(cond.modifier):"
            }
            let values = cond.value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if values.count == 1 {
                yaml += "\(fieldKey) '\(values[0])'\n"
            } else {
                yaml += "\(fieldKey)\n"
                for v in values {
                    yaml += "            - '\(v)'\n"
                }
            }
        }

        // Build filter blocks
        if filters.isEmpty {
            yaml += "    condition: selection\n"
        } else {
            for (i, filter) in filters.enumerated() {
                let name = "filter_\(i)"
                let fieldKey: String
                if filter.modifier == "equals" {
                    fieldKey = "        \(filter.field):"
                } else {
                    fieldKey = "        \(filter.field)|\(filter.modifier):"
                }
                yaml += "    \(name):\n"
                if filter.values.count == 1 {
                    yaml += "\(fieldKey) '\(filter.values[0])'\n"
                } else {
                    yaml += "\(fieldKey)\n"
                    for v in filter.values {
                        yaml += "            - '\(v)'\n"
                    }
                }
            }
            let filterNames = filters.indices.map { "not filter_\($0)" }.joined(separator: " and ")
            yaml += "    condition: selection and \(filterNames)\n"
        }

        yaml += """
        falsepositives:
            - \(falsepositives.isEmpty ? "Unknown" : falsepositives)
        level: \(severity)

        """

        return yaml
    }
}

// MARK: - Step 1: Metadata

private struct MetadataStep: View {
    @Binding var rule: RuleDraft

    let categories = [
        ("process_creation", "Process Creation"),
        ("file_event", "File Event"),
        ("network_connection", "Network Connection"),
        ("tcc_event", "TCC Permission"),
    ]

    let tactics = [
        "attack.initial_access", "attack.execution", "attack.persistence",
        "attack.privilege_escalation", "attack.defense_evasion",
        "attack.credential_access", "attack.discovery", "attack.lateral_movement",
        "attack.collection", "attack.command_and_control", "attack.exfiltration",
    ]

    let severities = ["informational", "low", "medium", "high", "critical"]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Basic Information") {
                VStack(alignment: .leading, spacing: 12) {
                    LabeledField("Rule Title") {
                        TextField("e.g., Suspicious Python Script Downloads Payload", text: $rule.title)
                            .textFieldStyle(.roundedBorder)
                    }
                    LabeledField("Description") {
                        TextEditor(text: $rule.description)
                            .frame(height: 60)
                            .border(Color.secondary.opacity(0.2))
                    }
                    LabeledField("Author") {
                        TextField("Your name", text: $rule.author)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                .padding(8)
            }

            GroupBox("Classification") {
                VStack(alignment: .leading, spacing: 12) {
                    LabeledField("Event Category") {
                        Picker("", selection: $rule.category) {
                            ForEach(categories, id: \.0) { cat in
                                Text(cat.1).tag(cat.0)
                            }
                        }.labelsHidden()
                    }
                    HStack(spacing: 16) {
                        LabeledField("Severity") {
                            Picker("", selection: $rule.severity) {
                                ForEach(severities, id: \.self) { Text($0.capitalized).tag($0) }
                            }.labelsHidden()
                        }
                        LabeledField("MITRE Tactic") {
                            Picker("", selection: $rule.tactic) {
                                ForEach(tactics, id: \.self) { t in
                                    Text(t.replacingOccurrences(of: "attack.", with: "").replacingOccurrences(of: "_", with: " ").capitalized).tag(t)
                                }
                            }.labelsHidden()
                        }
                        LabeledField("Technique ID") {
                            TextField("e.g., T1059.004", text: $rule.techniqueId)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 120)
                        }
                    }
                }
                .padding(8)
            }
        }
    }
}

// MARK: - Step 2: Detection Conditions

private struct DetectionStep: View {
    @Binding var rule: RuleDraft

    var fieldSuggestions: [String] {
        switch rule.category {
        case "process_creation":
            return ["Image", "CommandLine", "ParentImage", "User"]
        case "file_event":
            return ["TargetFilename", "SourceFilename"]
        case "network_connection":
            return ["DestinationIp", "DestinationPort", "DestinationIsPrivate"]
        case "tcc_event":
            return ["TCCService", "TCCClient", "TCCAllowed"]
        default:
            return ["Image", "CommandLine"]
        }
    }

    let modifiers = ["equals", "contains", "startswith", "endswith", "regex"]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Define what the rule should match. Each condition is AND-ed together.")
                .font(.callout).foregroundColor(.secondary)

            ForEach($rule.conditions) { $cond in
                HStack(spacing: 10) {
                    Picker("Field", selection: $cond.field) {
                        Text("Select field...").tag("")
                        ForEach(fieldSuggestions, id: \.self) { Text($0).tag($0) }
                    }
                    .frame(width: 200)
                    .controlSize(.large)

                    Picker("Modifier", selection: $cond.modifier) {
                        ForEach(modifiers, id: \.self) { Text($0).tag($0) }
                    }
                    .frame(width: 140)
                    .controlSize(.large)

                    TextField("Value (comma-separate multiple)", text: $cond.value)
                        .textFieldStyle(.roundedBorder)
                        .controlSize(.large)

                    Button {
                        rule.conditions.removeAll { $0.id == cond.id }
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundColor(.red)
                    }
                    .buttonStyle(.borderless)
                    .disabled(rule.conditions.count <= 1)
                }
            }

            Button {
                rule.conditions.append(RuleConditionEntry())
            } label: {
                Label("Add Condition", systemImage: "plus.circle")
            }

            if rule.category == "process_creation" {
                GroupBox {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Example").font(.caption).fontWeight(.semibold)
                        Text("Field: Image | Modifier: endswith | Value: /curl, /wget")
                            .font(.caption).foregroundColor(.secondary)
                        Text("Field: CommandLine | Modifier: contains | Value: --insecure")
                            .font(.caption).foregroundColor(.secondary)
                    }
                    .padding(4)
                }
            }
        }
    }
}

// MARK: - Step 3: Filters

private struct FiltersStep: View {
    @Binding var rule: RuleDraft

    let commonFilters: [(String, String, [String])] = [
        ("SignerType", "equals", ["apple", "appStore", "devId"]),
        ("SignerType", "equals", ["apple"]),
        ("ParentImage", "endswith", ["/Terminal", "/iTerm2", "/login"]),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Filters exclude known-good activity (NOT conditions). Optional.")
                .font(.callout).foregroundColor(.secondary)

            ForEach($rule.filters) { $filter in
                HStack(spacing: 10) {
                    TextField("Field", text: $filter.field)
                        .textFieldStyle(.roundedBorder)
                        .controlSize(.large)
                        .frame(width: 180)
                    TextField("Values (comma-separated)", text: Binding(
                        get: { filter.values.joined(separator: ", ") },
                        set: { filter.values = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .controlSize(.large)

                    Button {
                        rule.filters.removeAll { $0.id == filter.id }
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundColor(.red)
                    }
                    .buttonStyle(.borderless)
                }
            }

            HStack(spacing: 12) {
                Button {
                    rule.filters.append(RuleFilterEntry())
                } label: {
                    Label("Add Custom Filter", systemImage: "plus.circle")
                }

                Divider().frame(height: 20)

                Text("Quick add:").font(.caption).foregroundColor(.secondary)

                Button("Exclude Apple-signed") {
                    rule.filters.append(RuleFilterEntry(field: "SignerType", values: ["apple", "appStore", "devId"]))
                }
                .font(.caption)

                Button("Exclude Terminal parents") {
                    rule.filters.append(RuleFilterEntry(field: "ParentImage", modifier: "endswith", values: ["/Terminal", "/iTerm2", "/login", "/sshd"]))
                }
                .font(.caption)
            }
        }
    }
}

// MARK: - Step 4: Options

private struct OptionsStep: View {
    @Binding var rule: RuleDraft

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("False Positives") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Describe known legitimate scenarios that might trigger this rule:")
                        .font(.callout).foregroundColor(.secondary)
                    TextEditor(text: $rule.falsepositives)
                        .frame(height: 80)
                        .border(Color.secondary.opacity(0.2))
                }
                .padding(8)
            }

            GroupBox("Summary") {
                VStack(alignment: .leading, spacing: 8) {
                    SummaryRow(label: "Title", value: rule.title)
                    SummaryRow(label: "Category", value: rule.category)
                    SummaryRow(label: "Severity", value: rule.severity)
                    SummaryRow(label: "Conditions", value: "\(rule.conditions.count) detection conditions")
                    SummaryRow(label: "Filters", value: rule.filters.isEmpty ? "None" : "\(rule.filters.count) exclusion filters")
                    SummaryRow(label: "File", value: rule.filename)
                }
                .padding(8)
            }
        }
    }
}

private struct SummaryRow: View {
    let label: String
    let value: String
    var body: some View {
        HStack {
            Text(label).font(.caption).foregroundColor(.secondary).frame(width: 80, alignment: .trailing)
            Text(value).font(.body)
        }
    }
}

// MARK: - Step 5: Preview & Save

private struct PreviewStep: View {
    @Binding var rule: RuleDraft
    @Binding var savedPath: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let path = savedPath {
                HStack {
                    Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.title2)
                    VStack(alignment: .leading) {
                        Text("Rule saved!").font(.headline)
                        Text(path).font(.caption).foregroundColor(.secondary)
                    }
                }
                .padding()
                .background(Color.green.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))

                Text("Next: run **make compile-rules && make restart** to load the new rule.")
                    .font(.callout)
            }

            Text("Generated YAML:")
                .font(.caption).foregroundColor(.secondary)

            ScrollView {
                Text(rule.toYAML())
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            HStack {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(rule.toYAML(), forType: .string)
                } label: {
                    Label("Copy YAML", systemImage: "doc.on.doc")
                }
            }
        }
    }
}

// MARK: - Helpers

private struct LabeledField<Content: View>: View {
    let label: String
    @ViewBuilder let content: () -> Content

    init(_ label: String, @ViewBuilder content: @escaping () -> Content) {
        self.label = label
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption).fontWeight(.medium).foregroundColor(.secondary)
            content()
                .controlSize(.large)
        }
    }
}
