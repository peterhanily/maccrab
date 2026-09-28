import SwiftUI
import AppKit

/// Inline in the existing plugin inspector. Nothing is scanned by this editor.
struct SecretTrailSourcePicker: View {
    @Binding var ready: Bool
    var profile: SecretTrailScope.Profile = .secretTrail
    @State private var sources: [SecretTrailScope.Source] = []
    @State private var saved: [SecretTrailScope.Source] = []
    @State private var error: String?
    @State private var selectedKind = SecretTrailScope.Kind.project
    @State private var didSave = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(profile.selectionHelp)
                .font(.caption).foregroundStyle(.secondary)
            ForEach($sources) { $source in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .top) {
                        Text(source.path).font(.system(.caption, design: .monospaced))
                            .lineLimit(3).textSelection(.enabled)
                        Spacer()
                        Button {
                            let selectedPath = source.path
                            sources.removeAll { $0.path == selectedPath }
                            changed()
                        } label: {
                            Image(systemName: "minus.circle")
                        }.buttonStyle(.plain).accessibilityLabel(String(localized: "rave.sources.remove", defaultValue: "Remove selected source"))
                    }
                    Picker("Source type", selection: $source.kind) {
                        ForEach(profile.kinds) { kind in Text(kind.title).tag(kind) }
                    }.labelsHidden().onChange(of: source.kind) { _ in changed() }
                }
                Divider()
            }
            HStack {
                Picker("Add as", selection: $selectedKind) {
                    ForEach(profile.kinds) { kind in Text(kind.title).tag(kind) }
                }.labelsHidden()
                Button(profile == .repoTripwire ? "Choose projects…" : profile == .scriptTrace ? "Choose scripts…" : "Choose files or folders…", action: choose).disabled(sources.count >= 32)
            }
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Text(didSave ? "Selection saved. Ready to scan." : ready ? "\(sources.count) selected · encrypted results" : "Save your selection to enable Run.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button(String(localized: "rave.sources.save", defaultValue: "Save selection")) { save() }.disabled(sources.isEmpty || sources == saved)
            }
        }
        .task {
            selectedKind = profile.kinds[0]
            do { sources = try SecretTrailScope.load(profile: profile); saved = sources; ready = !sources.isEmpty }
            catch { self.error = "The previous selection could not be loaded. Choose and save the sources for this scan."; ready = false }
        }
    }
    private func changed() { didSave = false; ready = !sources.isEmpty && sources == saved }
    @MainActor private func choose() {
        let panel = NSOpenPanel()
        panel.title = "Choose " + profile.title + " sources"
        panel.message = profile.selectionHelp + " Choose sources inside your home."
        panel.canChooseFiles = profile.allowsFiles; panel.canChooseDirectories = profile.allowsDirectories
        panel.allowsMultipleSelection = true; panel.showsHiddenFiles = true
        panel.resolvesAliases = false
        panel.treatsFilePackagesAsDirectories = profile == .trustDelta
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
        guard panel.runModal() == .OK else { return }
        do {
            let home = FileManager.default.homeDirectoryForCurrentUser
            let additions = try panel.urls.map { SecretTrailScope.Source(path: try SecretTrailScope.relativeSelection($0, home: home, profile: profile), kind: selectedKind) }
            var updated = sources
            for source in additions where !updated.contains(where: { $0.path == source.path }) { updated.append(source) }
            try SecretTrailScope.validate(updated, profile: profile, complete: false)
            sources = updated; error = nil; changed()
            if profile == .trustDelta && updated.contains(where: { $0.kind == .previousApp }) && !updated.contains(where: { $0.kind == .currentApp }) { selectedKind = .currentApp }
            if profile == .firstHour && selectedKind == .baseline { selectedKind = .current }
        } catch { self.error = (error as? SecretTrailScope.Failure)?.errorDescription ?? "That selection could not be added." }
    }
    private func save() {
        do { try SecretTrailScope.save(sources, profile: profile); saved = sources; ready = true; didSave = true; error = nil }
        catch { self.error = (error as? SecretTrailScope.Failure)?.errorDescription ?? "The selection could not be saved."; ready = false }
    }
}
