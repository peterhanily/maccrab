import SwiftUI
import AppKit
import MacCrabForensics

struct SecretTrailFinding: Identifiable {
    struct Location: Identifiable {
        let id: Int
        let path: String
        let kind: String
        let line: Int64
        let escaped: Bool
        var label: String { "\(path):\(line)" }
    }
    let id: Int64
    let family: String
    let reviewFirst: Bool
    let reason: String
    let files: Int64
    let occurrences: Int64
    let partial: Bool
    let locations: [Location]
    let omitted: Int64
    let steps: [String]
    var handoff: String {
        ([family + " candidate", reason, partial ? "Coverage incomplete; counts are lower bounds." : "Candidate validity not checked."]
         + locations.map { "\($0.kind): \($0.label)\($0.escaped ? " (JSON-escaped)" : "")" }
         + (omitted > 0 ? ["\(omitted) additional occurrences: see scan export."] : [])).joined(separator: "\n")
    }
    init?(_ artifact: CommittedArtifact) {
        let record = artifact.record, data = record.data
        guard record.pluginID == SecretTrailScope.pluginID, record.contentType == "secret_trail.credential" else { return nil }
        func string(_ key: String, _ fallback: String = "") -> String {
            guard case .string(let value) = data[key] else { return fallback }; return String(value.prefix(1024))
        }
        func integer(_ key: String) -> Int64 {
            guard case .integer(let value) = data[key] else { return 0 }; return max(0, value)
        }
        id = artifact.id; family = string("family", "Credential")
        reviewFirst = string("reviewPriority") == "review-first"
        reason = string("priorityReason", "Review these candidate locations. Credential validity has not been checked.")
        files = integer("fileCount"); occurrences = integer("occurrenceCount")
        partial = data["countsAreLowerBounds"] == .bool(true)
        var parsed: [Location] = []
        if case .array(let rows) = data["locations"] {
            for (index, row) in rows.prefix(24).enumerated() {
                guard case .object(let object) = row,
                      case .string(let path) = object["relativePath"],
                      case .string(let kind) = object["sourceKind"],
                      case .integer(let line) = object["line"], line > 0 else { continue }
                parsed.append(.init(id: index, path: String(path.prefix(1024)), kind: String(kind.prefix(64)),
                                    line: line, escaped: object["representation"] == .string("json-escaped")))
            }
        }
        locations = parsed
        // Also covers older candidates without embedded locations and malformed
        // previews, so this viewer never implies that omitted evidence is absent.
        omitted = max(integer("locationsOmitted"), occurrences - Int64(parsed.count))
        if case .array(let values) = data["reviewSteps"] {
            steps = values.prefix(6).compactMap { if case .string(let text) = $0 { return String(text.prefix(1024)) }; return nil }
        } else { steps = [] }
    }
}

struct SecretTrailFindingsView: View {
    let artifacts: [CommittedArtifact]
    @State private var search = ""
    @State private var copied: Int64?
    private var findings: [SecretTrailFinding] {
        artifacts.compactMap(SecretTrailFinding.init).sorted {
            if $0.reviewFirst != $1.reviewFirst { return $0.reviewFirst }
            if $0.files != $1.files { return $0.files > $1.files }
            return $0.id < $1.id
        }
    }
    private var visible: [SecretTrailFinding] {
        findings.filter { search.isEmpty || $0.family.localizedCaseInsensitiveContains(search)
            || $0.locations.contains { $0.path.localizedCaseInsensitiveContains(search) || $0.kind.localizedCaseInsensitiveContains(search) } }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("Credential copies").font(.title2.bold())
                Spacer()
                Text("\(findings.filter(\.reviewFirst).count) to review first").font(.subheadline).foregroundStyle(.secondary)
            }
            Text("Matching candidates in your selected files. Locations are redacted; validity and transmission have not been established.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("Filter by credential family, file or source type", text: $search)
                .textFieldStyle(.roundedBorder)
            if visible.isEmpty { Text("No groups match this filter.").foregroundStyle(.secondary).padding() }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(Array(visible.prefix(128))) { finding in card(finding) }
                    if visible.count > 128 {
                        Text("Showing 128 of \(visible.count) groups. Export the scan for the remaining records.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }.padding(12)
    }
    private func card(_ finding: SecretTrailFinding) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(finding.family).font(.headline)
                    Text("\(finding.files) files · \(finding.occurrences) occurrences")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if finding.reviewFirst {
                    Label("Review first", systemImage: "flag.fill")
                        .font(.caption.weight(.semibold)).foregroundStyle(.orange)
                }
            }
            Text(finding.reason).font(.callout)
            if finding.partial {
                Label("Coverage incomplete — these counts are lower bounds.", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
            }
            ForEach(Array(finding.locations.prefix(4))) { location in locationRow(location) }
            if finding.locations.count > 4 {
                DisclosureGroup("Show \(finding.locations.count - 4) more locations") {
                    ForEach(Array(finding.locations.dropFirst(4))) { location in locationRow(location) }
                }.font(.caption)
            }
            if finding.omitted > 0 {
                Text("\(finding.omitted) additional occurrences are available under Occurrences or in the scan export.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !finding.steps.isEmpty {
                DisclosureGroup("Review and cleanup guidance") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(finding.steps.enumerated()), id: \.offset) { index, step in
                            Text("\(index + 1). \(step)").font(.caption)
                        }
                    }.padding(.top, 6)
                }.font(.caption)
            }
            Button(copied == finding.id ? "Copied redacted locations" : "Copy redacted locations") {
                NSPasteboard.general.clearContents()
                if NSPasteboard.general.setString(finding.handoff, forType: .string) { copied = finding.id }
            }.buttonStyle(.bordered).controlSize(.small)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.1)))
    }
    private func locationRow(_ location: SecretTrailFinding.Location) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(location.label).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Text(location.kind + (location.escaped ? " · JSON-escaped copy" : ""))
                .font(.caption2).foregroundStyle(.secondary)
        }.padding(.vertical, 2)
    }
}
