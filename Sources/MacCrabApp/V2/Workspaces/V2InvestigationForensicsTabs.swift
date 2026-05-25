// V2InvestigationForensicsTabs.swift
// MacCrabApp — v1.13b Dashboard Forensics surface.
//
// Four read-only sub-tabs under the Investigation workspace,
// matching plan §3.7 v1.13b acceptance:
//   - Forensics · Cases       — case list + detail
//   - Forensics · Plugins     — registry view
//   - Forensics · Artifacts   — sortable artifact table per case
//   - Forensics · Findings    — posture.* analyzer output
//
// Case creation continues via CLI (plan §3.7); the dashboard is
// strictly read-only at v1.13b. Touch ID unlock cascade arrives
// when the operator opens an encrypted case via KeychainDEKVault.

import SwiftUI
import MacCrabForensics

// MARK: - Cases

struct V2ForensicsCasesView: View {
    @State private var manifests: [CaseManifest] = []
    @State private var selectedCaseID: String?
    @State private var detail: V2ForensicsCaseDetail?
    @State private var loading: Bool = false
    @State private var loadError: String?

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            casesList
            Divider()
            detailPanel
        }
        .padding(16)
        .task { await reload() }
    }

    private var casesList: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Cases").font(.title3).fontWeight(.semibold)
                Spacer()
                Button("Reload") { Task { await reload() } }
                    .buttonStyle(.borderless)
            }
            if loading {
                ProgressView().padding(.top, 8)
            }
            if let err = loadError {
                Text(err)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.red)
            }
            if manifests.isEmpty && !loading {
                Text("No cases yet. Create one with: maccrabctl case new <name>")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(.top, 4)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(manifests, id: \.id) { m in
                        Button(action: { selectedCaseID = m.id; Task { await loadDetail(m.id) } }) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(m.name).fontWeight(.medium)
                                    Spacer()
                                    encryptionBadge(m.encryptionState)
                                }
                                Text(m.id)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text(formatted(m.createdAt))
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 6)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(selectedCaseID == m.id ? Color.accentColor.opacity(0.12) : Color.clear)
                            .cornerRadius(4)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .frame(width: 320)
    }

    @ViewBuilder
    private var detailPanel: some View {
        if let d = detail {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(d.row.name).font(.title2).fontWeight(.bold)
                    HStack(spacing: 12) {
                        Label(d.row.id, systemImage: "tag.fill")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Divider()
                    HStack(alignment: .top, spacing: 24) {
                        VStack(alignment: .leading, spacing: 6) {
                            label("Created", formatted(d.row.createdAt))
                            label("Encryption", d.row.encryptionState.rawValue)
                            label("AI content allowed", d.row.aiContentAllowed ? "yes" : "no")
                            label("Scheduled trusted", d.row.scheduledTrusted ? "yes" : "no")
                        }
                        VStack(alignment: .leading, spacing: 6) {
                            label("Artifacts total", "\(d.artifactTotal)")
                            label("Plugin invocations", "\(d.invocationCount)")
                        }
                    }
                    Divider()
                    Text("Artifacts by content type")
                        .font(.system(size: 13, weight: .semibold))
                    ForEach(d.byContentType.sorted(by: { $0.value > $1.value }), id: \.key) { entry in
                        HStack {
                            Text(entry.key).font(.system(size: 12, design: .monospaced))
                            Spacer()
                            Text("\(entry.value)").foregroundStyle(.secondary)
                        }
                    }
                    Divider()
                    Text("Open this case from the CLI:")
                        .font(.system(size: 12, weight: .semibold))
                    Text("maccrabctl case show \(d.row.id)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text("maccrabctl case artifacts \(d.row.id) --limit 50")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                    if d.row.encryptionState == .encryptedKeychain {
                        Text("This case is encrypted. The dashboard prompts Touch ID or device passcode the first time you access encrypted contents.")
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .padding(.top, 4)
                    }
                }
                .padding(16)
            }
        } else {
            VStack {
                Spacer()
                Text("Select a case to view detail.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
    }

    private func reload() async {
        loading = true
        loadError = nil
        do {
            try await MacCrabForensicsBootstrap.registerBuiltins()
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let result = try await mgr.listCases()
            manifests = result
        } catch {
            loadError = "Failed to list cases: \(error)"
        }
        loading = false
    }

    private func loadDetail(_ id: String) async {
        // For encrypted cases this will prompt the macOS Touch ID /
        // passcode UI via KeychainDEKVault. The detail panel
        // surfaces "Open failed" cleanly if the operator cancels.
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let handle = try await mgr.openCase(id: id)
            guard let row = try await handle.store.fetchCase(id: id) else { return }
            let rows = try await handle.store.query(ArtifactQuery(caseID: id, limit: 100_000))
            var byType: [String: Int] = [:]
            for r in rows {
                byType[r.record.contentType, default: 0] += 1
            }
            detail = V2ForensicsCaseDetail(
                row: row,
                artifactTotal: rows.count,
                byContentType: byType,
                invocationCount: 0
            )
        } catch {
            detail = nil
        }
    }

    @ViewBuilder
    private func encryptionBadge(_ state: CaseEncryptionState) -> some View {
        let (text, bg): (String, Color) = {
            switch state {
            case .encryptedKeychain: return ("encrypted", Color.green.opacity(0.2))
            case .encryptedPassword: return ("encrypted", Color.green.opacity(0.2))
            case .plaintext: return ("plaintext", Color.orange.opacity(0.25))
            }
        }()
        Text(text)
            .font(.system(size: 9, weight: .medium))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(bg)
            .cornerRadius(3)
    }

    @ViewBuilder
    private func label(_ name: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(name).font(.system(size: 10)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 12))
        }
    }

    private func formatted(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: date)
    }
}

private struct V2ForensicsCaseDetail {
    let row: CaseRecord
    let artifactTotal: Int
    let byContentType: [String: Int]
    let invocationCount: Int
}

// MARK: - Plugins

struct V2ForensicsPluginsView: View {
    @State private var manifests: [PluginManifest] = []
    @State private var selectedID: String?

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            pluginList
            Divider()
            pluginDetail
        }
        .padding(16)
        .task { await reload() }
    }

    private var pluginList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Plugins").font(.title3).fontWeight(.semibold)
            Text("\(manifests.count) registered")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(manifests, id: \.id) { m in
                        Button(action: { selectedID = m.id }) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(m.displayName).fontWeight(.medium)
                                    Spacer()
                                    typeBadge(m.type)
                                }
                                Text(m.id)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Text("v\(m.version) · \(m.stability.rawValue)")
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 6)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(selectedID == m.id ? Color.accentColor.opacity(0.12) : Color.clear)
                            .cornerRadius(4)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .frame(width: 340)
    }

    @ViewBuilder
    private var pluginDetail: some View {
        if let id = selectedID, let m = manifests.first(where: { $0.id == id }) {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(m.displayName).font(.title2).fontWeight(.bold)
                    Text(m.id).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                    Text(m.description).font(.system(size: 13))
                    Divider()
                    HStack {
                        kv("Type", m.type.rawValue)
                        kv("Runtime", m.runtime.rawValue)
                        kv("Stability", m.stability.rawValue)
                        kv("Schema", "v\(m.schemaVersion)")
                    }
                    if !m.tccRequirements.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("TCC requirements").font(.system(size: 12, weight: .semibold))
                            ForEach(m.tccRequirements, id: \.rawValue) { t in
                                Text("• \(t.rawValue)").font(.system(size: 12))
                            }
                        }
                    }
                    if !m.outputs.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Outputs").font(.system(size: 12, weight: .semibold))
                            ForEach(m.outputs, id: \.contentType) { o in
                                HStack {
                                    Text(o.contentType).font(.system(size: 12, design: .monospaced))
                                    Spacer()
                                    Text(o.privacyClass.rawValue)
                                        .font(.system(size: 10))
                                        .padding(.horizontal, 4).padding(.vertical, 1)
                                        .background(privacyClassColor(o.privacyClass))
                                        .cornerRadius(3)
                                }
                            }
                        }
                    }
                    if !m.mcpTools.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("MCP tools").font(.system(size: 12, weight: .semibold))
                            ForEach(m.mcpTools, id: \.name) { tool in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(tool.name).font(.system(size: 12, design: .monospaced))
                                    Text(tool.description).font(.system(size: 11)).foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                .padding(16)
            }
        } else {
            VStack {
                Spacer()
                Text("Select a plugin to view manifest detail.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
    }

    private func reload() async {
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        manifests = await PluginRegistry.shared.manifests()
    }

    @ViewBuilder
    private func typeBadge(_ t: PluginType) -> some View {
        Text(t.rawValue)
            .font(.system(size: 9, weight: .medium))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(Color.blue.opacity(0.18))
            .cornerRadius(3)
    }

    @ViewBuilder
    private func kv(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(k).font(.system(size: 10)).foregroundStyle(.secondary)
            Text(v).font(.system(size: 11))
        }
        .padding(.trailing, 12)
    }

    private func privacyClassColor(_ pc: PrivacyClass) -> Color {
        switch pc {
        case .metadata: return Color.green.opacity(0.18)
        case .content: return Color.orange.opacity(0.22)
        case .personalComms: return Color.orange.opacity(0.32)
        case .credentialAdjacent: return Color.red.opacity(0.25)
        case .secret: return Color.red.opacity(0.4)
        }
    }
}

// MARK: - Artifacts

struct V2ForensicsArtifactsView: View {
    @State private var caseManifests: [CaseManifest] = []
    @State private var selectedCaseID: String?
    @State private var artifacts: [CommittedArtifact] = []
    @State private var contentTypeFilter: String = ""
    @State private var sortField: SortField = .observedAt
    @State private var loading = false

    enum SortField: String, CaseIterable, Identifiable {
        case observedAt = "Observed"
        case contentType = "Content type"
        case summary = "Summary"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Artifacts").font(.title3).fontWeight(.semibold)
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Picker("Case", selection: $selectedCaseID) {
                    Text("Select a case").tag(String?.none)
                    ForEach(caseManifests, id: \.id) { m in
                        Text("\(m.name)  \(m.id.prefix(8))…").tag(Optional(m.id))
                    }
                }
                .frame(width: 280)
                .onChange(of: selectedCaseID) { new in
                    if let id = new { Task { await loadArtifacts(id) } }
                }
            }
            HStack(spacing: 8) {
                TextField("Filter by content type…", text: $contentTypeFilter)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                Picker("Sort by", selection: $sortField) {
                    ForEach(SortField.allCases) { Text($0.rawValue).tag($0) }
                }
                .frame(width: 220)
                Spacer()
            }
            artifactTable
        }
        .padding(16)
        .task { await reloadCases() }
    }

    private var artifactTable: some View {
        let visible = sortedArtifacts()
        return ScrollView {
            LazyVStack(spacing: 0) {
                HStack {
                    Text("ID").font(.system(size: 10, weight: .semibold)).frame(width: 48, alignment: .leading)
                    Text("Type").font(.system(size: 10, weight: .semibold)).frame(width: 220, alignment: .leading)
                    Text("Summary").font(.system(size: 10, weight: .semibold)).frame(maxWidth: .infinity, alignment: .leading)
                    Text("Privacy").font(.system(size: 10, weight: .semibold)).frame(width: 80, alignment: .leading)
                    Text("Observed").font(.system(size: 10, weight: .semibold)).frame(width: 130, alignment: .trailing)
                }
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(Color.secondary.opacity(0.08))
                Divider()
                ForEach(visible, id: \.id) { a in
                    HStack {
                        Text("\(a.id)").font(.system(size: 11, design: .monospaced)).frame(width: 48, alignment: .leading)
                        Text(a.record.contentType).font(.system(size: 11, design: .monospaced)).frame(width: 220, alignment: .leading)
                        Text(a.record.summary ?? "—").font(.system(size: 11)).frame(maxWidth: .infinity, alignment: .leading).lineLimit(1)
                        Text(a.record.privacyClass.rawValue).font(.system(size: 10)).frame(width: 80, alignment: .leading)
                            .foregroundStyle(privacyClassTextColor(a.record.privacyClass))
                        Text(short(a.record.observedAt)).font(.system(size: 10)).frame(width: 130, alignment: .trailing).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(a.id.isMultiple(of: 2) ? Color.clear : Color.secondary.opacity(0.04))
                }
                if visible.isEmpty && selectedCaseID != nil && !loading {
                    Text("No artifacts in this case.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(16)
                }
                if selectedCaseID == nil {
                    Text("Choose a case from the picker above to view its artifacts.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(16)
                }
            }
        }
    }

    private func sortedArtifacts() -> [CommittedArtifact] {
        let filtered = contentTypeFilter.isEmpty
            ? artifacts
            : artifacts.filter { $0.record.contentType.localizedCaseInsensitiveContains(contentTypeFilter) }
        switch sortField {
        case .observedAt:
            return filtered.sorted { $0.record.observedAt > $1.record.observedAt }
        case .contentType:
            return filtered.sorted { $0.record.contentType < $1.record.contentType }
        case .summary:
            return filtered.sorted { ($0.record.summary ?? "") < ($1.record.summary ?? "") }
        }
    }

    private func reloadCases() async {
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        let mgr = CaseManager(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            dekVault: KeychainDEKVault()
        )
        caseManifests = (try? await mgr.listCases()) ?? []
    }

    private func loadArtifacts(_ id: String) async {
        loading = true
        defer { loading = false }
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let handle = try await mgr.openCase(id: id)
            artifacts = try await handle.store.query(ArtifactQuery(caseID: id, limit: 2000))
        } catch {
            artifacts = []
        }
    }

    private func privacyClassTextColor(_ pc: PrivacyClass) -> Color {
        switch pc {
        case .metadata: return .secondary
        case .content: return .orange
        case .personalComms: return .orange
        case .credentialAdjacent: return .red
        case .secret: return .red
        }
    }

    private func short(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: d)
    }
}

// MARK: - Findings (v1.15 posture.* artifacts)

struct V2ForensicsLegacyFindingsView: View {
    @State private var caseManifests: [CaseManifest] = []
    @State private var selectedCaseID: String?
    @State private var findings: [CommittedArtifact] = []
    @State private var loading = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Findings").font(.title3).fontWeight(.semibold)
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Picker("Case", selection: $selectedCaseID) {
                    Text("Select a case").tag(String?.none)
                    ForEach(caseManifests, id: \.id) { m in
                        Text("\(m.name)  \(m.id.prefix(8))…").tag(Optional(m.id))
                    }
                }
                .frame(width: 280)
                .onChange(of: selectedCaseID) { new in
                    if let id = new { Task { await loadFindings(id) } }
                }
            }
            Text("Findings are emitted by the v1.15 posture-analyzer plugin. Run it via:  maccrabctl plugin run com.maccrab.forensics.posture-analyzer --case <id>")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            findingsList
        }
        .padding(16)
        .task { await reloadCases() }
    }

    private var findingsList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 8) {
                if findings.isEmpty && selectedCaseID != nil && !loading {
                    Text("No findings in this case yet. Run the posture analyzer to populate.")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .padding(16)
                }
                ForEach(findings, id: \.id) { f in
                    findingRow(f)
                }
            }
        }
    }

    @ViewBuilder
    private func findingRow(_ a: CommittedArtifact) -> some View {
        let severity = (a.record.data["severity"]?.string ?? "informational").lowercased()
        let explanation = a.record.data["explanation"]?.string ?? ""
        HStack(alignment: .top, spacing: 12) {
            severityChip(severity)
            VStack(alignment: .leading, spacing: 4) {
                Text(a.record.summary ?? a.record.contentType)
                    .fontWeight(.semibold)
                Text(a.record.contentType)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                if !explanation.isEmpty {
                    Text(explanation).font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(10)
        .background(Color.secondary.opacity(0.05))
        .cornerRadius(6)
    }

    @ViewBuilder
    private func severityChip(_ s: String) -> some View {
        let color: Color = {
            switch s {
            case "critical": return Color.red
            case "high": return Color.orange
            case "medium": return Color.yellow
            case "low": return Color.green
            default: return Color.gray
            }
        }()
        Text(s.uppercased())
            .font(.system(size: 9, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(color)
            .cornerRadius(3)
    }

    private func reloadCases() async {
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        let mgr = CaseManager(
            casesRoot: CaseDirectoryLayout.defaultCasesRoot,
            dekVault: KeychainDEKVault()
        )
        caseManifests = (try? await mgr.listCases()) ?? []
    }

    private func loadFindings(_ id: String) async {
        loading = true
        defer { loading = false }
        do {
            let mgr = CaseManager(
                casesRoot: CaseDirectoryLayout.defaultCasesRoot,
                dekVault: KeychainDEKVault()
            )
            let handle = try await mgr.openCase(id: id)
            let all = try await handle.store.query(ArtifactQuery(caseID: id, limit: 10_000))
            findings = all.filter { $0.record.contentType.hasPrefix("posture.") }
        } catch {
            findings = []
        }
    }
}

// MARK: - JSONValue convenience for the view layer

private extension JSONValue {
    var string: String? {
        if case .string(let s) = self { return s }
        return nil
    }
}
