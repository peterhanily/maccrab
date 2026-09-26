import SwiftUI
import AppKit
import MacCrabForensics

struct InspectionFinding: Identifiable {
    let id: Int64
    let title: String, explanation: String, action: String, path: String, trigger: String, code: String, lineLabel: String
    let line: Int, trace: [String], attention: Bool
    var gap: Bool { code == "coverage-gap" || code == "selection-required" }
    static let plugins = ["repo_tripwire.finding": "com.maccrab.forensics.repo-tripwire",
                          "script_trace.finding": "com.maccrab.forensics.script-trace"]
    static func accepts(contentType: String, artifacts: [CommittedArtifact]) -> Bool {
        guard let plugin = plugins[contentType], !artifacts.isEmpty else { return false }
        return artifacts.allSatisfy { $0.record.contentType == contentType && $0.record.pluginID == plugin }
    }
    init?(_ artifact: CommittedArtifact) {
        guard Self.accepts(contentType: artifact.record.contentType, artifacts: [artifact]),
              artifact.record.schemaVersion == 1 else { return nil }
        let data = artifact.record.data
        func text(_ key: String, limit: Int = 4096) -> String? {
            guard case .string(let value) = data[key], value.utf8.count <= limit else { return nil }
            return value
        }
        guard let title = text("title", limit: 200), let explanation = text("explanation"),
              let action = text("action"), let path = text("path", limit: 2048),
              let trigger = text("trigger", limit: 300), let code = text("code", limit: 100),
              case .integer(let line) = data["line"], line > 0, line <= 131_072,
              case .bool(let attention) = data["attention"],
              case .array(let rawTrace) = data["trace"], rawTrace.count <= 3 else { return nil }
        let trace = rawTrace.compactMap { value -> String? in
            if case .string(let text) = value, text.utf8.count <= 200 { return text }; return nil
        }
        guard trace.count == rawTrace.count else { return nil }
        self.id = artifact.id; self.title = title; self.explanation = explanation; self.action = action
        self.path = path; self.trigger = trigger; self.code = code; self.line = Int(line)
        self.trace = trace; self.attention = attention; self.lineLabel = text("lineLabel", limit: 80) ?? "Text line"
    }
    var handoff: String {
        ([title, trigger, path.isEmpty ? "" : path + " · " + lineLabel + " \(line)"]
         + trace + [explanation, "Review: " + action, "Static inspection; execution and compromise are not established."])
            .filter { !$0.isEmpty }.joined(separator: "\n")
    }
}

/// Findings stay inside the existing scan detail surface. No additional workspace.
struct InspectionFindingsView: View {
    let artifacts: [CommittedArtifact]
    @State private var showAll = false
    @State private var query = ""
    private var findings: [InspectionFinding] { artifacts.prefix(2500).compactMap(InspectionFinding.init) }
    private var title: String { artifacts.first?.record.pluginID.hasSuffix("repo-tripwire") == true ? "Repo Tripwire" : "Script Trace" }
    private var attentionCount: Int { findings.filter(\.attention).count }
    private var gaps: Int { findings.filter(\.gap).count + max(0, artifacts.count - findings.count) }
    private var visible: [InspectionFinding] {
        findings.filter { (showAll || $0.attention || attentionCount == 0) &&
            (query.isEmpty || [$0.title, $0.path, $0.trigger, $0.code].joined(separator: " ").localizedCaseInsensitiveContains(query)) }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).font(.title2.weight(.semibold))
                    Text("\(attentionCount) \(attentionCount == 1 ? "review reason" : "review reasons") · \(gaps) \(gaps == 1 ? "coverage gap" : "coverage gaps")")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Text(String(localized: "rave.inspection.staticBadge", defaultValue: "STATIC INSPECTION")).font(.system(size: 10, weight: .semibold))
                    .padding(7).background(.secondary.opacity(0.1)).cornerRadius(5)
            }
            Text(String(localized: "rave.inspection.limitations", defaultValue: "Commands were not run. These findings explain what to review; they do not establish execution or compromise."))
                .font(.callout).foregroundStyle(.secondary)
            if gaps > 0 {
                HStack {
                    Label(String(localized: "rave.inspection.uninspected", defaultValue: "Some behavior remains uninspected."), systemImage: "exclamationmark.circle")
                        .font(.callout).foregroundStyle(.orange)
                    Spacer()
                    Button(String(localized: "rave.inspection.showCoverage", defaultValue: "Show coverage")) { showAll = true; query = "coverage-gap" }.buttonStyle(.link)
                }
            }
            HStack {
                TextField("Filter by file, trigger or behavior", text: $query).textFieldStyle(.roundedBorder)
                Toggle("All findings", isOn: $showAll).toggleStyle(.checkbox)
            }
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    if visible.isEmpty { Text(String(localized: "rave.inspection.noMatches", defaultValue: "No findings match this filter.")).foregroundStyle(.secondary).padding(.vertical, 16) }
                    ForEach(visible) { finding in card(finding) }
                    if artifacts.count > findings.count {
                        Text(String(localized: "rave.inspection.hiddenRows", defaultValue: "Rows not displayed: \(artifacts.count - findings.count). Review their raw artifacts and coverage before drawing conclusions."))
                            .font(.caption).foregroundStyle(.orange)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }.padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    private func card(_ finding: InspectionFinding) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top) {
                Image(systemName: finding.gap ? "circle.dashed" : finding.attention ? "arrow.triangle.branch" : "doc.text")
                    .foregroundStyle(finding.attention ? Color.orange : Color.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(finding.title).font(.headline)
                    Text(finding.trigger).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(finding.handoff, forType: .string)
                } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.plain).help(String(localized: "rave.inspection.copyNote", defaultValue: "Copy redacted review note"))
            }
            if !finding.path.isEmpty {
                Text(finding.path + " · " + finding.lineLabel + " \(finding.line)")
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            }
            if !finding.trace.isEmpty {
                Text(finding.trace.joined(separator: "  →  "))
                    .font(.caption.weight(.medium)).foregroundStyle(.orange)
            }
            Text(finding.explanation).font(.callout).fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("What to check") { Text(finding.action).font(.callout).padding(.top, 4) }
                .font(.caption)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.18)))
        .cornerRadius(8)
    }
}
