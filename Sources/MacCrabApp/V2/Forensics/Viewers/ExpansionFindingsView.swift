import SwiftUI
import AppKit
import MacCrabForensics

struct ExpansionFinding: Identifiable {
    static let slugs = ["remote-hands", "skill-check", "localhost-lens", "dependency-autopsy", "decoy", "exit-check", "side-door", "identity-aftershock", "build-witness", "last-good"]
    static let identities: [String: String] = Dictionary(uniqueKeysWithValues: slugs.flatMap { slug in
        ["finding", "summary"].map { (slug.replacingOccurrences(of: "-", with: "_") + "." + $0, "com.maccrab.forensics." + slug) }
    })
    static func accepts(contentType: String, artifacts: [CommittedArtifact]) -> Bool {
        guard let id = identities[contentType], !artifacts.isEmpty else { return false }
        return artifacts.allSatisfy { $0.record.pluginID == id && $0.record.contentType == contentType && $0.record.pluginVersion == "0.1.0" && $0.record.schemaVersion == 1 }
    }
    let id: Int64
    let title: String, detail: String, path: String, code: String, statement: String, evidence: String
    init?(_ artifact: CommittedArtifact) {
        guard Self.accepts(contentType: artifact.record.contentType, artifacts: [artifact]) else { return nil }
        func text(_ key: String, max: Int = 8192) -> String? {
            guard case .string(let value) = artifact.record.data[key], value.utf8.count <= max else { return nil }; return value
        }
        let isSummary = artifact.record.contentType.hasSuffix(".summary")
        let recordSummary = artifact.record.summary.flatMap { $0.utf8.count <= 500 ? $0 : nil }
        guard let title = text("title", max: 500) ?? (isSummary ? recordSummary : nil),
              let detail = text("detail") ?? (isSummary ? text("limitation") : nil) else { return nil }
        self.id = artifact.id; self.title = title; self.detail = detail; path = text("path", max: 4096) ?? ""
        code = text("code", max: 200) ?? "summary"; statement = text("statementType", max: 100) ?? artifact.record.confidence.rawValue
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let supporting = artifact.record.data["evidence"] ?? (isSummary ? .object(artifact.record.data.filter { !["title", "detail", "limitation"].contains($0.key) }) : nil)
        if case .object(let fields) = supporting, fields.isEmpty {
            evidence = ""
        } else if let value = supporting, let bytes = try? encoder.encode(value), bytes.count <= 65_536 {
            evidence = String(decoding: bytes, as: UTF8.self)
        } else { evidence = supporting == nil ? "" : "Supporting fields exceed this view's limit. Inspect the original artifact before relying on this result." }
    }
    var note: String { [title, statement, path, detail, evidence].filter { !$0.isEmpty }.joined(separator: "\n\n") }
}

/// The ten plugins share the existing encrypted case view and export controls.
struct ExpansionFindingsView: View {
    let artifacts: [CommittedArtifact]
    @State private var query = ""
    private var findings: [ExpansionFinding] { artifacts.prefix(2500).compactMap(ExpansionFinding.init) }
    private var title: String {
        (artifacts.first?.record.pluginID.components(separatedBy: ".").last ?? "Rave")
            .split(separator: "-").map { $0.capitalized }.joined(separator: " ")
    }
    private var visible: [ExpansionFinding] { findings.filter { query.isEmpty || [$0.title,$0.path,$0.code,$0.detail].joined(separator: " ").localizedCaseInsensitiveContains(query) } }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).font(.title2.weight(.semibold))
                    Text(String(localized: "rave.expansion.categoryCount", defaultValue: "Results in this evidence category: \(findings.count)")).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Text(String(localized: "rave.expansion.selectedEvidence", defaultValue: "SELECTED EVIDENCE")).font(.system(size: 10, weight: .semibold)).padding(7).background(.secondary.opacity(0.1)).cornerRadius(5)
            }
            Text(String(localized: "rave.expansion.coverageNote", defaultValue: "Each result states what its source can establish. Review collection coverage and unavailable sources alongside these findings."))
                .font(.callout).foregroundStyle(.secondary)
            TextField("Filter by source or finding", text: $query).textFieldStyle(.roundedBorder)
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(visible) { finding in
                        VStack(alignment: .leading, spacing: 9) {
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(finding.title).font(.headline)
                                    Text(finding.statement.capitalized + " · " + finding.code).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(finding.note, forType: .string) }
                                    label: { Image(systemName: "doc.on.doc") }.buttonStyle(.plain).help(String(localized: "rave.expansion.copyNote", defaultValue: "Copy review note"))
                            }
                            if !finding.path.isEmpty { Text(finding.path).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                            Text(finding.detail).font(.callout).fixedSize(horizontal: false, vertical: true)
                            if !finding.evidence.isEmpty && finding.evidence != "{}" {
                                DisclosureGroup("Supporting observations") { Text(finding.evidence).font(.system(.caption, design: .monospaced)).textSelection(.enabled).padding(.top, 4) }.font(.caption)
                            }
                        }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(nsColor: .controlBackgroundColor))
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.18))).cornerRadius(8)
                    }
                    if visible.isEmpty { Text(String(localized: "rave.expansion.noMatches", defaultValue: "No displayable results match this filter. Check the original artifacts and collection coverage.")).foregroundStyle(.secondary).padding(.vertical, 16) }
                    if artifacts.count > findings.count { Text(String(localized: "rave.expansion.hiddenRows", defaultValue: "Rows not displayed: \(artifacts.count-findings.count). Use Export → JSON to inspect them; they were not assessed by this view.")).font(.caption).foregroundStyle(.orange) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }.padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
