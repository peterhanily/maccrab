// BrowserExtensionsView.swift
// MacCrabApp
//
// Shows all installed browser extensions with risk scoring. Tapping a row
// opens a detail sheet with manifest contents, permission explanations,
// on-disk metadata, and quick actions (reveal in Finder, open extension
// page in the browser). Scans Chrome, Firefox, Brave, Edge, and Arc
// directly — no daemon required.

import SwiftUI
import MacCrabCore
import AppKit

struct BrowserExtensionsView: View {
    @ObservedObject var appState: AppState
    @State private var extensions: [ExtensionRow] = []
    @State private var isScanning = false
    @State private var lastScanned: Date?
    @State private var showSuspiciousOnly = false
    @State private var selected: ExtensionRow?

    var filtered: [ExtensionRow] {
        showSuspiciousOnly ? extensions.filter { $0.isSuspicious } : extensions
    }

    var suspiciousCount: Int { extensions.filter { $0.isSuspicious }.count }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                Text(String(localized: "extensions.description",
                    defaultValue: "Extensions requesting dangerous permission combinations (webRequest, nativeMessaging, cookies, <all_urls>) may intercept traffic, steal credentials, or run native code. Tap an extension for full details."))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                if isScanning {
                    HStack { Spacer(); ProgressView(); Spacer() }.padding(40)
                } else if filtered.isEmpty && !extensions.isEmpty {
                    emptyState(
                        system: "checkmark.shield",
                        color: .green.opacity(0.7),
                        title: String(localized: "extensions.noSuspicious",
                            defaultValue: "No suspicious extensions found"),
                        subtitle: nil
                    )
                } else if extensions.isEmpty {
                    emptyState(
                        system: "puzzlepiece.extension",
                        color: .secondary.opacity(0.5),
                        title: String(localized: "extensions.none",
                            defaultValue: "No browser extensions found"),
                        subtitle: String(localized: "extensions.noneDetail",
                            defaultValue: "Tap Scan to check Chrome, Firefox, Brave, Edge, and Arc")
                    )
                } else {
                    let grouped = Dictionary(grouping: filtered) { $0.browser }
                    ForEach(grouped.keys.sorted(), id: \.self) { browser in
                        if let rows = grouped[browser] {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Image(systemName: "globe")
                                        .font(.caption).foregroundColor(.secondary)
                                        .accessibilityHidden(true)
                                    Text(browser.capitalized).font(.headline)
                                    Text("(\(rows.count))")
                                        .font(.caption).foregroundColor(.secondary)
                                }
                                .padding(.horizontal)

                                VStack(spacing: 6) {
                                    ForEach(rows.sorted { lhs, rhs in
                                        if lhs.isSuspicious != rhs.isSuspicious { return lhs.isSuspicious }
                                        return lhs.riskScore > rhs.riskScore
                                    }) { row in
                                        Button {
                                            selected = row
                                        } label: {
                                            ExtensionRowView(row: row)
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                                .padding(.horizontal)
                            }
                        }
                    }
                }
                Spacer(minLength: 24)
            }
        }
        .navigationTitle("Browser Extensions")
        .sheet(item: $selected) { row in
            ExtensionDetailSheet(row: row) { selected = nil }
        }
        .task { await scan() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(String(localized: "extensions.title", defaultValue: "Browser Extensions"))
                    .font(.title2).fontWeight(.bold)
                if let scanned = lastScanned {
                    Text(String(localized: "extensions.lastScanned",
                        defaultValue: "Last scanned \(scanned.formatted(.relative(presentation: .named)))"))
                        .font(.caption).foregroundColor(.secondary)
                }
            }
            Spacer()
            if suspiciousCount > 0 {
                Label("\(suspiciousCount) suspicious",
                    systemImage: "exclamationmark.shield.fill")
                    .font(.subheadline).foregroundColor(.red)
            }
            Toggle(String(localized: "extensions.suspiciousOnly",
                defaultValue: "Suspicious only"), isOn: $showSuspiciousOnly)
                .toggleStyle(.switch).font(.caption)
            Button {
                Task { await scan() }
            } label: {
                Label(isScanning
                    ? String(localized: "extensions.scanning", defaultValue: "Scanning…")
                    : String(localized: "extensions.scanNow", defaultValue: "Scan"),
                    systemImage: "arrow.clockwise")
            }
            .disabled(isScanning)
        }
        .padding(.horizontal).padding(.top)
    }

    private func emptyState(system: String, color: Color, title: String, subtitle: String?) -> some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: system)
                .font(.system(size: 48)).foregroundColor(color)
                .accessibilityHidden(true)
            Text(title).font(.headline).foregroundColor(.secondary)
            if let subtitle {
                Text(subtitle).font(.subheadline).foregroundColor(.secondary)
            }
            Spacer()
        }.frame(maxWidth: .infinity).padding(40)
    }

    private func scan() async {
        isScanning = true
        extensions = await BrowserExtensionScanner.scan()
        lastScanned = Date()
        isScanning = false
    }
}

// MARK: - Row View

private struct ExtensionRowView: View {
    let row: ExtensionRow

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .top) {
                    if row.isSuspicious {
                        Image(systemName: "exclamationmark.shield.fill")
                            .foregroundColor(.red)
                            .accessibilityLabel("Suspicious")
                    } else {
                        Image(systemName: "puzzlepiece.extension")
                            .foregroundColor(.secondary)
                            .accessibilityHidden(true)
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.name).font(.headline)
                        HStack(spacing: 6) {
                            if let version = row.version {
                                Text("v\(version)").font(.caption2).foregroundColor(.secondary)
                            }
                            Text(row.extensionId)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    Spacer()
                    Text(row.riskLabel)
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(row.riskColor.opacity(0.15))
                        .foregroundColor(row.riskColor)
                        .clipShape(Capsule())
                    Image(systemName: "chevron.right")
                        .font(.caption2).foregroundColor(.secondary)
                }

                if !row.permissions.isEmpty {
                    Text(row.permissions.prefix(6).joined(separator: " · "))
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(2)
                }

                if let reason = row.suspicionReason {
                    Text(reason)
                        .font(.caption)
                        .foregroundColor(.red)
                        .lineLimit(2)
                }
            }
            .padding(4)
            .contentShape(Rectangle())
        }
    }
}

// MARK: - Detail Sheet

private struct ExtensionDetailSheet: View {
    let row: ExtensionRow
    let dismiss: () -> Void
    @State private var showFullManifest = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                titleSection
                Divider()
                riskSection
                if let desc = row.descriptionText, !desc.isEmpty {
                    sectionHeader("Description")
                    Text(desc).font(.body).textSelection(.enabled)
                }
                identitySection
                permissionsSection
                if !row.hostPermissions.isEmpty {
                    hostsSection
                }
                if !row.contentScripts.isEmpty {
                    contentScriptsSection
                }
                codeSection
                onDiskSection
                actionsSection
            }
            .padding(24)
            .frame(minWidth: 540, idealWidth: 620)
        }
        .frame(minHeight: 520, idealHeight: 700)
    }

    // MARK: Sections

    private var titleSection: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: row.isSuspicious
                ? "exclamationmark.shield.fill"
                : "puzzlepiece.extension.fill")
                .font(.system(size: 40))
                .foregroundColor(row.isSuspicious ? .red : .blue)
            VStack(alignment: .leading, spacing: 4) {
                Text(row.name).font(.title2).fontWeight(.bold)
                HStack(spacing: 8) {
                    Text(row.browser.capitalized)
                        .font(.caption).foregroundColor(.secondary)
                    if let version = row.version {
                        Text("·").font(.caption).foregroundColor(.secondary)
                        Text("v\(version)").font(.caption).foregroundColor(.secondary)
                    }
                    if let mv = row.manifestVersion {
                        Text("·").font(.caption).foregroundColor(.secondary)
                        Text("Manifest v\(mv)").font(.caption).foregroundColor(.secondary)
                    }
                }
                Text(row.extensionId)
                    .font(.caption2).foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            Button("Close", action: dismiss).keyboardShortcut(.cancelAction)
        }
    }

    private var riskSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Text(row.riskLabel)
                    .font(.callout).fontWeight(.semibold)
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(row.riskColor.opacity(0.18))
                    .foregroundColor(row.riskColor)
                    .clipShape(Capsule())
                Text("Risk score: \(row.riskScore)/100")
                    .font(.callout).foregroundColor(.secondary)
                Spacer()
            }
            if !row.riskReasons.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(row.riskReasons, id: \.self) { reason in
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.caption).foregroundColor(.orange)
                            Text(reason).font(.caption)
                        }
                    }
                }
                .padding(8)
                .background(Color.orange.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    private var identitySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Identity")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                detailRow("Author", row.author)
                detailRow("Homepage", row.homepageUrl, isLink: true)
                detailRow("Update URL", row.updateUrl, isLink: true,
                    annotation: row.hasNonStoreUpdateUrl
                        ? ("sideloaded — not served from the official store", .orange) : nil)
            }
        }
    }

    private var permissionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Permissions (\(row.apiPermissions.count))")
            if row.apiPermissions.isEmpty {
                Text("No API permissions declared.").font(.caption).foregroundColor(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(row.apiPermissions, id: \.self) { perm in
                        PermissionLine(permission: perm)
                    }
                }
            }
        }
    }

    private var hostsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Host permissions (\(row.hostPermissions.count))")
            Text("Pages the extension can read and modify. `<all_urls>`, `http://*/*`, and `https://*/*` grant access to every page the user visits.")
                .font(.caption).foregroundColor(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                ForEach(row.hostPermissions, id: \.self) { host in
                    HStack(spacing: 6) {
                        Image(systemName: PermissionDictionary.isBroadHost(host)
                            ? "exclamationmark.triangle.fill" : "globe")
                            .font(.caption)
                            .foregroundColor(PermissionDictionary.isBroadHost(host) ? .orange : .secondary)
                        Text(host).font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var contentScriptsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Content scripts (\(row.contentScripts.count))")
            Text("JavaScript the extension injects into matching pages at load time.")
                .font(.caption).foregroundColor(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(row.contentScripts.enumerated()), id: \.offset) { _, cs in
                    VStack(alignment: .leading, spacing: 2) {
                        if !cs.matches.isEmpty {
                            Text("Matches: " + cs.matches.joined(separator: ", "))
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        if !cs.scripts.isEmpty {
                            Text("Scripts: " + cs.scripts.joined(separator: ", "))
                                .font(.caption).foregroundColor(.secondary)
                        }
                    }
                    .padding(6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                }
            }
        }
    }

    private var codeSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Background code")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                detailRow("Service worker", row.serviceWorker,
                    annotation: row.serviceWorker != nil
                        ? ("always-running background page", .secondary) : nil)
                detailRow("Background scripts",
                    row.backgroundScripts.isEmpty ? nil : row.backgroundScripts.joined(separator: ", "))
            }
        }
    }

    private var onDiskSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("On disk")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                detailRow("Installed", row.installDate?.formatted(date: .abbreviated, time: .shortened))
                detailRow("Size", row.sizeBytes.map(formatBytes))
                detailRow("Path", row.extensionPath)
            }
        }
    }

    private var actionsSection: some View {
        HStack(spacing: 8) {
            Button {
                if let path = row.extensionPath {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                }
            } label: {
                Label("Reveal in Finder", systemImage: "folder")
            }
            .disabled(row.extensionPath == nil)

            if let url = browserExtensionsURL(for: row.browser) {
                Button {
                    NSWorkspace.shared.open(url)
                } label: {
                    Label("Manage in \(row.browser.capitalized)", systemImage: "gear")
                }
            }

            if let homepage = row.homepageUrl, let url = URL(string: homepage) {
                Button {
                    NSWorkspace.shared.open(url)
                } label: {
                    Label("Homepage", systemImage: "safari")
                }
            }
            Spacer()
        }
        .padding(.top, 4)
    }

    // MARK: - Helpers

    private func sectionHeader(_ text: String) -> some View {
        Text(text).font(.headline)
    }

    @ViewBuilder
    private func detailRow(
        _ label: String,
        _ value: String?,
        isLink: Bool = false,
        annotation: (String, Color)? = nil
    ) -> some View {
        if let value, !value.isEmpty {
            GridRow {
                Text(label).font(.caption).foregroundColor(.secondary).gridColumnAlignment(.trailing)
                VStack(alignment: .leading, spacing: 2) {
                    if isLink, let url = URL(string: value) {
                        Link(value, destination: url)
                            .font(.system(.caption, design: .monospaced))
                    } else {
                        Text(value)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    if let (note, color) = annotation {
                        Text(note).font(.caption2).foregroundColor(color)
                    }
                }
            }
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        let fmt = ByteCountFormatter()
        fmt.allowedUnits = [.useKB, .useMB]
        fmt.countStyle = .file
        return fmt.string(fromByteCount: bytes)
    }

    private func browserExtensionsURL(for browser: String) -> URL? {
        switch browser {
        case "chrome": return URL(string: "chrome://extensions/?id=\(row.extensionId)")
        case "brave":  return URL(string: "brave://extensions/?id=\(row.extensionId)")
        case "edge":   return URL(string: "edge://extensions/?id=\(row.extensionId)")
        case "arc":    return URL(string: "chrome://extensions/?id=\(row.extensionId)")
        case "firefox": return URL(string: "about:addons")
        default: return nil
        }
    }
}

// MARK: - Permission Line

private struct PermissionLine: View {
    let permission: String

    var body: some View {
        let info = PermissionDictionary.info(for: permission)
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: info.dangerous ? "exclamationmark.triangle.fill" : "circle.fill")
                .font(.caption2)
                .foregroundColor(info.dangerous ? .orange : .secondary.opacity(0.6))
                .frame(width: 12)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(permission).font(.system(.caption, design: .monospaced))
                    Text(info.category).font(.caption2).foregroundColor(.secondary)
                }
                Text(info.description).font(.caption2).foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Permission Dictionary

private enum PermissionDictionary {
    struct Info {
        let category: String
        let description: String
        let dangerous: Bool
    }

    static func info(for permission: String) -> Info {
        if let known = table[permission] { return known }
        if permission.hasPrefix("http://") || permission.hasPrefix("https://") || permission.hasPrefix("*://") {
            return Info(category: "host", description: "Pages the extension can read and modify.",
                        dangerous: isBroadHost(permission))
        }
        return Info(category: "other", description: "Undocumented or optional permission.", dangerous: false)
    }

    static func isBroadHost(_ host: String) -> Bool {
        host == "<all_urls>"
            || host == "http://*/*" || host == "https://*/*"
            || host == "*://*/*"
            || host.contains("://*/*")
    }

    private static let table: [String: Info] = [
        "webRequest": Info(category: "network",
            description: "Observe outgoing requests. Combined with webRequestBlocking or a host permission, can read or alter every HTTPS body — effectively a user-space MITM.",
            dangerous: true),
        "webRequestBlocking": Info(category: "network",
            description: "Block or rewrite requests before they reach the network stack.",
            dangerous: true),
        "proxy": Info(category: "network",
            description: "Redirect all browser traffic through an arbitrary proxy server.",
            dangerous: true),
        "cookies": Info(category: "data",
            description: "Read and write cookies for hosts the extension has access to — includes auth session tokens.",
            dangerous: true),
        "history": Info(category: "data",
            description: "Read the full browsing history.",
            dangerous: true),
        "bookmarks": Info(category: "data",
            description: "Read and modify bookmarks.",
            dangerous: false),
        "downloads": Info(category: "data",
            description: "Download files to the user's disk (write access within the downloads dir).",
            dangerous: true),
        "tabs": Info(category: "data",
            description: "Read tab titles, URLs, and favicons across every window.",
            dangerous: true),
        "clipboardRead": Info(category: "data",
            description: "Read the system clipboard at any time.",
            dangerous: true),
        "clipboardWrite": Info(category: "data",
            description: "Overwrite the system clipboard.",
            dangerous: true),
        "geolocation": Info(category: "device",
            description: "Request the device's geolocation.",
            dangerous: false),
        "notifications": Info(category: "device",
            description: "Show system notifications.",
            dangerous: false),
        "nativeMessaging": Info(category: "execution",
            description: "Launch and exchange JSON with a native host binary on the user's machine — full arbitrary code execution path.",
            dangerous: true),
        "debugger": Info(category: "execution",
            description: "Attach the Chrome DevTools debugger to any tab — read DOM, JS state, and capture credentials as they are typed.",
            dangerous: true),
        "management": Info(category: "execution",
            description: "Install, enable, disable, and uninstall other extensions.",
            dangerous: true),
        "declarativeNetRequest": Info(category: "network",
            description: "Block or redirect requests via declarative rules.",
            dangerous: false),
        "scripting": Info(category: "execution",
            description: "Inject arbitrary JavaScript into pages at runtime.",
            dangerous: true),
        "activeTab": Info(category: "data",
            description: "Access the current tab when the user clicks the extension.",
            dangerous: false),
        "storage": Info(category: "data",
            description: "Read/write extension-owned persistent storage.",
            dangerous: false),
        "idle": Info(category: "device",
            description: "Detect when the machine is idle.",
            dangerous: false),
        "alarms": Info(category: "meta",
            description: "Schedule recurring background tasks.",
            dangerous: false),
        "contextMenus": Info(category: "meta",
            description: "Add items to the right-click menu.",
            dangerous: false),
        "identity": Info(category: "data",
            description: "Obtain OAuth tokens for Google accounts.",
            dangerous: true),
        "privacy": Info(category: "meta",
            description: "Read and modify browser privacy settings (Do Not Track, referrers, safe browsing).",
            dangerous: true),
        "<all_urls>": Info(category: "host",
            description: "Read and modify every page the user visits on any origin.",
            dangerous: true),
        "http://*/*": Info(category: "host",
            description: "Access every HTTP page on every domain.",
            dangerous: true),
        "https://*/*": Info(category: "host",
            description: "Access every HTTPS page on every domain.",
            dangerous: true),
    ]
}

// MARK: - Data Model

struct ExtensionRow: Identifiable {
    let id: String
    let browser: String
    let extensionId: String
    let name: String
    let version: String?
    let manifestVersion: Int?
    let descriptionText: String?
    let author: String?
    let homepageUrl: String?
    let updateUrl: String?
    let apiPermissions: [String]
    let hostPermissions: [String]
    let contentScripts: [ContentScriptInfo]
    let serviceWorker: String?
    let backgroundScripts: [String]
    let installDate: Date?
    let sizeBytes: Int64?
    let extensionPath: String?
    let riskScore: Int
    let riskReasons: [String]

    var permissions: [String] { apiPermissions + hostPermissions }

    var isSuspicious: Bool { riskScore >= 40 }

    var hasNonStoreUpdateUrl: Bool {
        guard let url = updateUrl else { return false }
        // Chrome Web Store canonical update URL; anything else is sideloaded.
        return !url.contains("clients2.google.com/service/update2/crx")
    }

    var riskLabel: String {
        switch riskScore {
        case ..<20: return "Low risk"
        case ..<40: return "Caution"
        case ..<70: return "Suspicious"
        default: return "High risk"
        }
    }

    var riskColor: Color {
        switch riskScore {
        case ..<20: return .green
        case ..<40: return .yellow
        case ..<70: return .orange
        default: return .red
        }
    }

    var suspicionReason: String? {
        riskReasons.first
    }

    struct ContentScriptInfo: Sendable {
        let matches: [String]
        let scripts: [String]
    }
}

// MARK: - Scanner

enum BrowserExtensionScanner {
    static func scan() async -> [ExtensionRow] {
        let home = NSHomeDirectory()
        let fm = FileManager.default
        var results: [ExtensionRow] = []

        let chromiumBrowsers: [(name: String, path: String)] = [
            ("chrome",  home + "/Library/Application Support/Google/Chrome"),
            ("brave",   home + "/Library/Application Support/BraveSoftware/Brave-Browser"),
            ("edge",    home + "/Library/Application Support/Microsoft Edge"),
            ("arc",     home + "/Library/Application Support/Arc/User Data"),
        ]

        for (browser, baseDir) in chromiumBrowsers {
            for profile in ["Default", "Profile 1", "Profile 2", "Profile 3", "Guest Profile"] {
                let extDir = baseDir + "/\(profile)/Extensions"
                guard fm.fileExists(atPath: extDir),
                      let extIds = try? fm.contentsOfDirectory(atPath: extDir) else { continue }

                for extId in extIds {
                    let extPath = extDir + "/" + extId
                    guard let versions = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
                    // Pick the newest version directory (lexicographic sort is fine for
                    // Chrome Web Store layout "1.2.3_0") so the details we display match
                    // the installed extension, not a stale unpacked copy.
                    let latest = versions.sorted().last
                    guard let version = latest else { continue }
                    let versionPath = extPath + "/" + version
                    let manifestPath = versionPath + "/manifest.json"
                    guard let row = parseChromiumManifest(
                        at: manifestPath, versionDir: versionPath,
                        browser: browser, extId: extId, extPath: extPath
                    ) else { continue }
                    // Deduplicate: same extId may appear in multiple profiles
                    if !results.contains(where: { $0.extensionId == extId && $0.browser == browser }) {
                        results.append(row)
                    }
                }
            }
        }

        // Firefox: extensions appear as .xpi files or directory names. Chrome-
        // style manifest introspection would require unzipping the xpi first,
        // which is out of scope — we surface the id and mark low-risk.
        let ffProfilesPath = home + "/Library/Application Support/Firefox/Profiles"
        if let profiles = try? fm.contentsOfDirectory(atPath: ffProfilesPath) {
            for profile in profiles {
                let extPath = ffProfilesPath + "/" + profile + "/extensions"
                guard let files = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
                for file in files {
                    let extId = file.replacingOccurrences(of: ".xpi", with: "")
                    let fullPath = extPath + "/" + file
                    if !results.contains(where: { $0.extensionId == extId && $0.browser == "firefox" }) {
                        results.append(ExtensionRow(
                            id: "\(extId)-firefox",
                            browser: "firefox",
                            extensionId: extId,
                            name: extId,
                            version: nil, manifestVersion: nil,
                            descriptionText: nil, author: nil,
                            homepageUrl: nil, updateUrl: nil,
                            apiPermissions: [], hostPermissions: [],
                            contentScripts: [],
                            serviceWorker: nil, backgroundScripts: [],
                            installDate: mtime(of: fullPath),
                            sizeBytes: sizeOfItem(at: fullPath),
                            extensionPath: fullPath,
                            riskScore: 0, riskReasons: []
                        ))
                    }
                }
            }
        }

        return results
    }

    private static func parseChromiumManifest(
        at path: String, versionDir: String,
        browser: String, extId: String, extPath: String
    ) -> ExtensionRow? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        let rawName = manifest["name"] as? String ?? extId
        // Chrome Web Store uses __MSG_*__ tokens that resolve from _locales/. We
        // skip the full locale lookup but strip the token so the UI doesn't
        // show "__MSG_extName__" as the display name.
        let name = rawName.hasPrefix("__MSG_")
            ? resolveMessage(token: rawName, versionDir: versionDir) ?? extId
            : rawName

        let version = manifest["version"] as? String
        let manifestVersion = manifest["manifest_version"] as? Int
        let descriptionText: String? = {
            guard let desc = manifest["description"] as? String else { return nil }
            if desc.hasPrefix("__MSG_") {
                return resolveMessage(token: desc, versionDir: versionDir)
            }
            return desc
        }()
        let author = manifest["author"] as? String
            ?? ((manifest["author"] as? [String: Any])?["email"] as? String)
        let homepageUrl = manifest["homepage_url"] as? String
        let updateUrl = manifest["update_url"] as? String

        // API-style permissions (non-URL strings).
        let rawPerms = (manifest["permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
        let optionalPerms = (manifest["optional_permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
        let apiPerms = (rawPerms + optionalPerms).filter {
            !isHostPattern($0)
        }

        // Host permissions: combined list from `host_permissions` (MV3) +
        // any URL-shaped entries in `permissions` (MV2) + content_scripts matches.
        var hostPerms = (manifest["host_permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
        hostPerms += rawPerms.filter(isHostPattern)

        // Content scripts.
        var scripts: [ExtensionRow.ContentScriptInfo] = []
        if let arr = manifest["content_scripts"] as? [[String: Any]] {
            for cs in arr {
                let matches = (cs["matches"] as? [Any])?.compactMap { $0 as? String } ?? []
                let files = (cs["js"] as? [Any])?.compactMap { $0 as? String } ?? []
                scripts.append(.init(matches: matches, scripts: files))
                hostPerms += matches
            }
        }
        // Dedupe hosts.
        hostPerms = Array(NSOrderedSet(array: hostPerms)) as? [String] ?? hostPerms

        // Background.
        var serviceWorker: String?
        var bgScripts: [String] = []
        if let bg = manifest["background"] as? [String: Any] {
            serviceWorker = bg["service_worker"] as? String
            if let arr = bg["scripts"] as? [Any] {
                bgScripts = arr.compactMap { $0 as? String }
            }
        }

        let installDate = mtime(of: versionDir)
        let sizeBytes = sizeOfItem(at: versionDir)

        let (score, reasons) = computeRisk(
            apiPerms: apiPerms,
            hostPerms: hostPerms,
            updateUrl: updateUrl,
            hasNativeMessaging: apiPerms.contains("nativeMessaging"),
            contentScripts: scripts
        )

        return ExtensionRow(
            id: "\(extId)-\(browser)",
            browser: browser,
            extensionId: extId,
            name: name,
            version: version,
            manifestVersion: manifestVersion,
            descriptionText: descriptionText,
            author: author,
            homepageUrl: homepageUrl,
            updateUrl: updateUrl,
            apiPermissions: apiPerms,
            hostPermissions: hostPerms,
            contentScripts: scripts,
            serviceWorker: serviceWorker,
            backgroundScripts: bgScripts,
            installDate: installDate,
            sizeBytes: sizeBytes,
            extensionPath: versionDir,
            riskScore: score,
            riskReasons: reasons
        )
    }

    private static func isHostPattern(_ s: String) -> Bool {
        s == "<all_urls>"
            || s.hasPrefix("http://")
            || s.hasPrefix("https://")
            || s.hasPrefix("*://")
            || s.hasPrefix("file://")
    }

    /// Compute a 0-100 risk score with per-factor reasons. Thresholds map to
    /// `riskLabel` in ExtensionRow: <20 low, <40 caution, <70 suspicious, ≥70 high.
    private static func computeRisk(
        apiPerms: [String],
        hostPerms: [String],
        updateUrl: String?,
        hasNativeMessaging: Bool,
        contentScripts: [ExtensionRow.ContentScriptInfo]
    ) -> (Int, [String]) {
        var score = 0
        var reasons: [String] = []

        // Very dangerous capabilities (each).
        if hasNativeMessaging {
            score += 35
            reasons.append("Declares nativeMessaging — can launch native binaries.")
        }
        if apiPerms.contains("debugger") {
            score += 35
            reasons.append("Declares debugger — can attach devtools to any tab.")
        }
        if apiPerms.contains("proxy") {
            score += 25
            reasons.append("Declares proxy — can redirect all browser traffic.")
        }
        if apiPerms.contains("management") {
            score += 20
            reasons.append("Declares management — can install/disable other extensions.")
        }
        if apiPerms.contains("webRequest") && apiPerms.contains("webRequestBlocking") {
            score += 25
            reasons.append("Declares webRequestBlocking — can modify requests in-flight.")
        } else if apiPerms.contains("webRequest") {
            score += 15
            reasons.append("Declares webRequest — can observe outgoing requests.")
        }

        // Broad host access.
        let broadHost = hostPerms.contains(where: { PermissionDictionary.isBroadHost($0) })
        if broadHost {
            score += 20
            reasons.append("Requests access to every site (`<all_urls>` or equivalent).")
        }

        // Credential / data-access surface.
        if apiPerms.contains("cookies") { score += 10; reasons.append("Reads cookies (includes session tokens).") }
        if apiPerms.contains("history") { score += 8; reasons.append("Reads full browsing history.") }
        if apiPerms.contains("tabs") { score += 5 }
        if apiPerms.contains("clipboardRead") { score += 10; reasons.append("Can read the system clipboard.") }
        if apiPerms.contains("identity") { score += 10; reasons.append("Can mint OAuth tokens for Google accounts.") }

        // Sideloaded update URL.
        if let updateUrl, !updateUrl.contains("clients2.google.com/service/update2/crx") {
            score += 15
            reasons.append("Update URL is not the Chrome Web Store — sideloaded.")
        }

        // Content scripts with broad matches.
        if contentScripts.contains(where: { cs in
            cs.matches.contains(where: PermissionDictionary.isBroadHost)
        }) {
            score += 5
        }

        return (min(score, 100), reasons)
    }

    // MARK: filesystem helpers

    private static func mtime(of path: String) -> Date? {
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        return attrs?[.modificationDate] as? Date
    }

    private static func sizeOfItem(at path: String) -> Int64? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { return nil }
        if !isDir.boolValue {
            let attrs = try? FileManager.default.attributesOfItem(atPath: path)
            return (attrs?[.size] as? NSNumber)?.int64Value
        }
        var total: Int64 = 0
        guard let enumerator = FileManager.default.enumerator(atPath: path) else { return nil }
        for case let sub as String in enumerator {
            let full = path + "/" + sub
            if let s = try? FileManager.default.attributesOfItem(atPath: full)[.size] as? NSNumber {
                total += s.int64Value
            }
        }
        return total
    }

    /// Resolve a `__MSG_key__` locale token against `_locales/en/messages.json`.
    /// Falls back to `_locales/<any>/messages.json` if `en` isn't present.
    private static func resolveMessage(token: String, versionDir: String) -> String? {
        let key = token
            .replacingOccurrences(of: "__MSG_", with: "")
            .replacingOccurrences(of: "__", with: "")
        let localesDir = versionDir + "/_locales"
        let candidates = ["en", "en_US"] + ((try? FileManager.default.contentsOfDirectory(atPath: localesDir)) ?? [])
        for locale in candidates {
            let path = localesDir + "/" + locale + "/messages.json"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            // Chrome stores keys case-insensitively; look up both.
            let lookup = dict[key] as? [String: Any]
                ?? dict.first(where: { $0.key.caseInsensitiveCompare(key) == .orderedSame })?.value as? [String: Any]
            if let message = lookup?["message"] as? String, !message.isEmpty {
                return message
            }
        }
        return nil
    }
}
