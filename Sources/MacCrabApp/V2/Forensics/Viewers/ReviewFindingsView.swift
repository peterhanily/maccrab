import Foundation
import SwiftUI
import AppKit
import Darwin
import MacCrabForensics

struct NativeReview {
    let document: RaveReviewDocument
    var snapshot: RaveSnapshot { document.snapshot }
    var previous: RaveSnapshot? { document.previous }
    var mode: String { document.mode }
    static let identities = ["trust_delta.review": "com.maccrab.forensics.trust-delta",
                             "first_hour.review": "com.maccrab.forensics.first-hour",
                             ReviewCaseWorkflow.contentType: ReviewCaseWorkflow.pluginID]
    init(document: RaveReviewDocument) throws {
        try RaveReviewDocumentIO.validate(document); self.document = document
    }
    init(_ artifact: CommittedArtifact) throws {
        let record = artifact.record
        guard Self.identities[record.contentType] == record.pluginID,
              record.schemaVersion == 1, [.content, .credentialAdjacent].contains(record.privacyClass) else { throw RaveReviewError.invalid }
        if record.contentType == ReviewCaseWorkflow.contentType {
            guard record.pluginVersion == "1.0.0" else { throw RaveReviewError.unsupported }
            self.document = try RaveReviewDocumentIO.decode(JSONEncoder().encode(record.data), imported: false)
            guard !document.requiresCredentialPrivacy || record.privacyClass == .credentialAdjacent else { throw RaveReviewError.invalid }
            return
        }
        guard ["0.1.0", "0.2.0"].contains(record.pluginVersion) else { throw RaveReviewError.unsupported }
        if let raw = record.data["document"] {
            self.document = try RaveReviewDocumentIO.decode(JSONEncoder().encode(raw), imported: false)
        } else {
            guard record.pluginVersion == "0.1.0", case .string(let mode) = record.data["mode"],
                  let raw = record.data["snapshot"] else { throw RaveReviewError.invalid }
            self.document = .init(mode: mode, snapshot: try RaveReviewEngine.decode(JSONEncoder().encode(raw)),
                previous: try record.data["previous"].map { try RaveReviewEngine.decode(JSONEncoder().encode($0)) })
            try RaveReviewDocumentIO.validate(document)
        }
        if record.pluginVersion == "0.2.0", document.requiresCredentialPrivacy, record.privacyClass != .credentialAdjacent { throw RaveReviewError.invalid }
        if record.contentType == "trust_delta.review" {
            guard document.mode == "compare", document.snapshot.domain == "app" else { throw RaveReviewError.invalid }
        }
    }
    var findings: [RaveFinding] { get throws { try document.findings } }
}

enum ReviewFileIO {
    static func directory(_ url: URL) throws -> Int32 {
        guard url.isFileURL, url.path.hasPrefix("/") else { throw RaveReviewError.invalid }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw RaveReviewError.invalid }
        var path = url.path
        if path == "/tmp" || path.hasPrefix("/tmp/") { path = "/private" + path }
        if path == "/var" || path.hasPrefix("/var/") { path = "/private" + path }
        for part in path.split(separator: "/") {
            guard part != ".", part != ".." else { close(fd); throw RaveReviewError.invalid }
            let next = openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(fd)
            guard next >= 0 else { throw RaveReviewError.invalid }; fd = next
        }
        return fd
    }
    static func read(_ url: URL) throws -> Data {
        let dir = try directory(url.deletingLastPathComponent()); defer { close(dir) }
        let fd = openat(dir, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw RaveReviewError.invalid }; defer { close(fd) }
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_size <= RaveReviewEngine.maxBytes else { throw RaveReviewError.oversized }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while result.count <= RaveReviewEngine.maxBytes {
            let count = Darwin.read(fd, &buffer, min(buffer.count, RaveReviewEngine.maxBytes + 1 - result.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RaveReviewError.invalid }
            if count == 0 { break }
            result.append(contentsOf: buffer.prefix(count))
        }
        guard fstat(fd, &after) == 0, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              result.count <= RaveReviewEngine.maxBytes else { throw RaveReviewError.invalid }
        return result
    }
    static func write(_ bytes: Data, to url: URL) throws {
        guard bytes.count <= RaveReviewEngine.maxBytes else { throw RaveReviewError.oversized }
        let dir = try directory(url.deletingLastPathComponent())
        guard dir >= 0 else { throw RaveReviewError.invalid }; defer { close(dir) }
        let temporary = ".rave-review-" + UUID().uuidString
        let fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RaveReviewError.invalid }
        defer { close(fd); unlinkat(dir, temporary, 0) }
        try bytes.withUnsafeBytes { raw in
            var count = 0
            while count < raw.count {
                let n = Darwin.write(fd, raw.baseAddress!.advanced(by: count), raw.count - count)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw RaveReviewError.invalid }; count += n
            }
        }
        var existing = stat()
        if fstatat(dir, url.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG else { throw RaveReviewError.invalid }
        } else if errno != ENOENT { throw RaveReviewError.invalid }
        guard fsync(fd) == 0, renameat(dir, temporary, dir, url.lastPathComponent) == 0 else { throw RaveReviewError.invalid }
    }
}

struct ReviewFindingsView: View {
    let artifacts: [CommittedArtifact]
    var caseHandle: CaseHandle? = nil
    var onSaved: (() async -> Void)? = nil
    @State private var review: NativeReview?
    @State private var findings: [RaveFinding] = []
    @State private var selectedID: Int64?
    @State private var status = ""
    @State private var failure: String?
    @State private var busy = false
    @State private var includeRoutine = false
    @State private var showDecision = false
    @State private var reviewer = ""
    @State private var disposition = "inconclusive"
    @State private var note = ""
    private var title: String { review?.snapshot.domain == "app" ? "Trust Delta" : "First Hour" }
    private var attentionCount: Int { findings.filter(\.attention).count }
    private var visible: [RaveFinding] {
        findings.filter { includeRoutine || attentionCount == 0 || $0.attention }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).font(.title2.weight(.semibold))
                    Text(status).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                if artifacts.count > 1 {
                    Picker("Saved review", selection: $selectedID) {
                        ForEach(artifacts.sorted { $0.id > $1.id }, id: \.id) { item in
                            Text(item.record.capturedAt.formatted(date: .abbreviated, time: .shortened) + " · #\(item.id)").tag(Optional(item.id))
                        }
                    }.labelsHidden().frame(maxWidth: 230)
                }
            }
            if review != nil {
                HStack {
                    Menu("Save & share") {
                        Button(String(localized: "rave.review.saveCase", defaultValue: "Save in encrypted case"), action: saveInCase).disabled(caseHandle == nil)
                        Button(String(localized: "rave.review.export", defaultValue: "Export review…"), action: exportReview)
                        Button(String(localized: "rave.review.copyBrief", defaultValue: "Copy investigation brief"), action: copyBrief)
                        Divider()
                        Button(String(localized: "rave.review.open", defaultValue: "Open saved review…"), action: openReview)
                    }
                    Button(String(localized: "rave.review.verify", defaultValue: "Verify…"), action: verify)
                    Button(String(localized: "rave.review.recheck", defaultValue: "Recheck"), action: recheck).disabled(review?.snapshot.domain == "app")
                        .help(String(localized: "rave.review.recheckHelp", defaultValue: "Apply current supported rules to these retained facts."))
                    Button(String(localized: "rave.review.recordDecision", defaultValue: "Record decision…")) { showDecision = true }
                    Spacer()
                    if busy { ProgressView().controlSize(.small) }
                }.disabled(busy)
            }
            if let failure { Text(failure).font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            if let review {
                Text(review.snapshot.domain == "app" ?
                    "Compare assessed executable bytes and signing declarations. Runtime behavior and software safety remain unassessed." :
                    "Review retained observations, verify a follow-up, or recheck with updated rules. These actions do not collect new evidence.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 20) {
                    metric("Needs review", attentionCount)
                    metric("Retained facts", review.snapshot.facts.count)
                    metric("Coverage gaps", review.snapshot.gaps.count + (review.previous?.gaps.count ?? 0))
                    Spacer()
                    if findings.contains(where: { !$0.attention }) && attentionCount > 0 {
                        Toggle("Include routine items", isOn: $includeRoutine).toggleStyle(.checkbox).font(.caption)
                    }
                }
                DisclosureGroup("Scope, coverage and provenance") {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(review.snapshot.provenance == "unverified-import" ? "Imported observations · provenance not authenticated" : "Local static observations · signatures not validated")
                        Text(String(localized: "rave.review.rulesPrefix", defaultValue: "Rules \(review.snapshot.ruleVersion) · ") + review.snapshot.scope.joined(separator: ", "))
                        ForEach(review.snapshot.gaps, id: \.self) { Text(String(localized: "rave.review.currentPrefix", defaultValue: "Current: ") + $0) }
                        ForEach(review.previous?.gaps ?? [], id: \.self) { Text(String(localized: "rave.review.earlierPrefix", defaultValue: "Earlier: ") + $0) }
                        if let digest = try? RaveReviewDocumentIO.digest(review.document) { Text(String(localized: "rave.review.digestPrefix", defaultValue: "Review SHA-256: ") + digest).textSelection(.enabled) }
                    }.font(.caption).foregroundStyle(.secondary).padding(.top, 5)
                }.font(.caption)
                if !review.document.decisions.isEmpty {
                    DisclosureGroup("\(review.document.decisions.count) recorded operator decisions") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(String(localized: "rave.review.unsignedNotes", defaultValue: "Unsigned notes tied to these retained facts. Reviewer names are self-reported.")).foregroundStyle(.secondary)
                            ForEach(review.document.decisions, id: \.id) { decision in
                                Text("\(decision.reviewer) · \(decision.disposition) · \(decision.recordedAt)").bold()
                                if !decision.note.isEmpty { Text(decision.note).textSelection(.enabled) }
                            }
                        }.font(.caption).padding(.top, 5)
                    }.font(.caption)
                }
            }
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    if findings.isEmpty, review != nil {
                        Text(String(localized: "rave.review.noNewFindings", defaultValue: "No new findings under these rules. Review coverage before drawing a conclusion.")).foregroundStyle(.secondary)
                    }
                    ForEach(visible, id: \.id) { finding in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Image(systemName: finding.attention ? "arrow.triangle.branch" : "circle.dashed")
                                    .foregroundStyle(finding.attention ? Color.orange : Color.secondary)
                                Text(finding.title).font(.headline)
                                Spacer()
                                Button { copy([finding.title, finding.explanation, finding.action, finding.references.joined(separator: "\n")].joined(separator: "\n\n")) }
                                    label: { Image(systemName: "doc.on.doc") }.buttonStyle(.plain).help(String(localized: "rave.review.copyFinding", defaultValue: "Copy finding"))
                            }
                            Text(finding.explanation).font(.callout).textSelection(.enabled)
                            DisclosureGroup("Evidence and next check") {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(finding.action).font(.callout)
                                    ForEach(Array(finding.references.enumerated()), id: \.offset) { _, reference in
                                        Text(reference).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                    }
                                }.padding(.top, 6)
                            }.font(.caption)
                        }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(nsColor: .controlBackgroundColor))
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.18))).cornerRadius(8)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }.padding(20).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .task(id: selectedID ?? artifacts.map(\.id).max()) {
                do {
                    guard let artifact = artifacts.first(where: { $0.id == selectedID }) ?? artifacts.max(by: { $0.id < $1.id }) else { throw RaveReviewError.invalid }
                    try display(NativeReview(artifact).document)
                    if selectedID == nil { selectedID = artifact.id }
                } catch { failure = "This result could not be validated. Inspect its raw record; no review conclusion is available." }
            }
            .sheet(isPresented: $showDecision) { decisionSheet }
    }
    private func metric(_ label: String, _ value: Int) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(String(value)).font(.title3.weight(.semibold))
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }
    private var decisionSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(String(localized: "rave.review.decisionTitle", defaultValue: "Record your review decision")).font(.headline)
            Text(String(localized: "rave.review.decisionScope", defaultValue: "The note is tied to this review's scope, facts, comparison and rule version. It does not approve future code or establish containment."))
                .font(.callout).foregroundStyle(.secondary)
            TextField("Reviewer name", text: $reviewer)
            Picker("Decision", selection: $disposition) {
                Text(String(localized: "rave.review.expected", defaultValue: "Expected within reviewed scope")).tag("expected")
                Text(String(localized: "rave.review.investigate", defaultValue: "Investigate further")).tag("investigate")
                Text(String(localized: "rave.review.inconclusive", defaultValue: "Inconclusive")).tag("inconclusive")
            }
            TextField("Reason or next action", text: $note)
            if let failure { Text(failure).foregroundStyle(.orange).font(.caption) }
            HStack {
                Spacer()
                Button(String(localized: "common.cancel", defaultValue: "Cancel")) { showDecision = false }.keyboardShortcut(.cancelAction)
                Button(caseHandle == nil ? "Add to review" : "Record in case", action: recordDecision)
                    .disabled(busy || reviewer.trimmingCharacters(in: .whitespaces).isEmpty).keyboardShortcut(.defaultAction)
            }
        }.padding(24).frame(width: 480)
    }
    @MainActor private func display(_ document: RaveReviewDocument) throws {
        let value = try NativeReview(document: document)
        findings = try value.findings; review = value; failure = nil
        let count = findings.filter(\.attention).count
        status = (count == 1 ? "1 item needs review" : "\(count) items need review") + " · " + document.mode
    }
    @MainActor private func copy(_ text: String) {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
    }
    @MainActor private func copyBrief() {
        guard let review else { return }
        do { copy(try RaveReviewDocumentIO.brief(review.document)); status = "Investigation brief copied, including scope and gaps." }
        catch { failure = "The brief could not be prepared." }
    }
    @MainActor private func exportReview() {
        guard let review else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "rave-review.json"
        panel.message = "Export both sides, coverage and operator notes. This file is outside case encryption and can contain sensitive paths. Choose a protected location."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try ReviewFileIO.write(RaveReviewDocumentIO.encode(review.document), to: url); status = "Review exported with private file permissions." }
        catch { failure = "The review could not be exported. Choose a regular file in a directory without symbolic links." }
    }
    @MainActor private func openReview() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false; panel.resolvesAliases = false
        panel.message = "Open a complete saved Rave review, including its comparison and operator notes."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task {
            do {
                let document = try await Task.detached { try RaveReviewDocumentIO.decode(ReviewFileIO.read(url)) }.value
                try display(document)
            } catch { failure = "The review is unsupported, changed, oversized or invalid. It was not opened." }
            busy = false
        }
    }
    @MainActor private func saveInCase() {
        guard let review, let caseHandle else { return }; busy = true
        Task {
            do { try await ReviewCaseWorkflow.save(review.document, handle: caseHandle); await onSaved?(); status = "Review saved in this encrypted case."; failure = nil }
            catch { failure = "The case could not save this review. The current result remains available." }
            busy = false
        }
    }
    @MainActor private func recordDecision() {
        guard var document = review?.document else { return }; busy = true
        Task {
            do {
                document.decisions.append(try .init(document: document, reviewer: reviewer, disposition: disposition, note: note))
                if let caseHandle { try await ReviewCaseWorkflow.save(document, handle: caseHandle); await onSaved?() }
                try display(document); showDecision = false; note = ""
                status = caseHandle == nil ? "Decision added. Export the review to retain it." : "Decision recorded in this encrypted case."
            } catch { failure = "The decision could not be recorded. Use a reviewer name up to 120 bytes and a single-line note up to 2,000 bytes." }
            busy = false
        }
    }
    @MainActor private func verify() {
        guard let review else { return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false; panel.resolvesAliases = false
        panel.message = "Choose an earlier report or review to compare with this result's retained observations. Matching source scope is required."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true; failure = nil
        Task {
            do {
                let earlier = try await Task.detached { try RaveReviewImport.decode(ReviewFileIO.read(url)) }.value
                try display(.init(mode: "verify", snapshot: review.snapshot, previous: earlier))
            } catch { failure = "These observations cannot be compared. Check their selected source scope, format and size." }
            busy = false
        }
    }
    @MainActor private func recheck() {
        guard let review else { return }
        do {
            let checked = try RaveReviewEngine.recheck(review.snapshot)
            try display(.init(mode: "recheck", snapshot: checked.snapshot, previous: review.snapshot))
            status = "\(checked.added.count) new findings · rules \(review.snapshot.ruleVersion) → \(checked.snapshot.ruleVersion)"
        } catch { failure = "These retained facts could not be rechecked." }
    }
}
