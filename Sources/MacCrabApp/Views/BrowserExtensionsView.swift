// BrowserExtensionsView.swift
// MacCrabApp
//
// Shows all installed browser extensions with risk scoring.
// Scans Chrome, Firefox, Brave, Edge, and Arc extension directories directly —
// no daemon required. Dangerous permission combinations are flagged immediately.

import SwiftUI
import MacCrabCore

struct BrowserExtensionsView: View {
    @ObservedObject var appState: AppState
    @State private var extensions: [ExtensionRow] = []
    @State private var isScanning = false
    @State private var lastScanned: Date?
    @State private var showSuspiciousOnly = false

    var filtered: [ExtensionRow] {
        showSuspiciousOnly ? extensions.filter { $0.isSuspicious } : extensions
    }

    var suspiciousCount: Int { extensions.filter { $0.isSuspicious }.count }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
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
                            .font(.subheadline)
                            .foregroundColor(.red)
                    }
                    Toggle(String(localized: "extensions.suspiciousOnly",
                        defaultValue: "Suspicious only"), isOn: $showSuspiciousOnly)
                        .toggleStyle(.switch)
                        .font(.caption)
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
                .padding(.horizontal)
                .padding(.top)

                Text(String(localized: "extensions.description",
                    defaultValue: "Extensions requesting dangerous permission combinations (webRequest, nativeMessaging, cookies, <all_urls>) may intercept traffic, steal credentials, or run native code."))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                if isScanning {
                    HStack { Spacer(); ProgressView(); Spacer() }.padding(40)
                } else if filtered.isEmpty && !extensions.isEmpty {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 48)).foregroundColor(.green.opacity(0.7))
                            .accessibilityHidden(true)
                        Text(String(localized: "extensions.noSuspicious",
                            defaultValue: "No suspicious extensions found"))
                            .font(.headline).foregroundColor(.secondary)
                        Spacer()
                    }.frame(maxWidth: .infinity).padding(40)
                } else if extensions.isEmpty {
                    VStack(spacing: 12) {
                        Spacer()
                        Image(systemName: "puzzlepiece.extension")
                            .font(.system(size: 48)).foregroundColor(.secondary.opacity(0.5))
                            .accessibilityHidden(true)
                        Text(String(localized: "extensions.none",
                            defaultValue: "No browser extensions found"))
                            .font(.headline).foregroundColor(.secondary)
                        Text(String(localized: "extensions.noneDetail",
                            defaultValue: "Tap Scan to check Chrome, Firefox, Brave, Edge, and Arc"))
                            .font(.subheadline).foregroundColor(.secondary)
                        Spacer()
                    }.frame(maxWidth: .infinity).padding(40)
                } else {
                    // Group by browser
                    let grouped = Dictionary(grouping: filtered) { $0.browser }
                    ForEach(grouped.keys.sorted(), id: \.self) { browser in
                        if let rows = grouped[browser] {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Image(systemName: "globe")
                                        .font(.caption).foregroundColor(.secondary)
                                        .accessibilityHidden(true)
                                    Text(browser.capitalized)
                                        .font(.headline)
                                    Text("(\(rows.count))")
                                        .font(.caption).foregroundColor(.secondary)
                                }
                                .padding(.horizontal)

                                VStack(spacing: 6) {
                                    ForEach(rows) { row in
                                        ExtensionRowView(row: row)
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
        .task { await scan() }
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
                        Text(row.name)
                            .font(.headline)
                        Text(row.extensionId)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    Text(row.riskLabel)
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(row.riskColor.opacity(0.15))
                        .foregroundColor(row.riskColor)
                        .clipShape(Capsule())
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
        }
    }
}

// MARK: - Data Model

struct ExtensionRow: Identifiable {
    let id: String          // extensionId
    let browser: String
    let extensionId: String
    let name: String
    let permissions: [String]
    let isSuspicious: Bool
    let suspicionReason: String?

    var riskLabel: String { isSuspicious ? "Suspicious" : "OK" }
    var riskColor: Color { isSuspicious ? .red : .green }
}

// MARK: - Scanner

enum BrowserExtensionScanner {
    private static let dangerousPermissions: Set<String> = [
        "webRequest", "webRequestBlocking",
        "cookies",
        "clipboardRead", "clipboardWrite",
        "nativeMessaging",
        "debugger",
        "management",
        "proxy",
        "<all_urls>",
        "http://*/*", "https://*/*",
        "tabs",
        "history",
        "downloads",
    ]

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
            // Scan Default profile + numbered profiles
            for profile in ["Default", "Profile 1", "Profile 2", "Guest Profile"] {
                let extDir = baseDir + "/\(profile)/Extensions"
                guard fm.fileExists(atPath: extDir),
                      let extIds = try? fm.contentsOfDirectory(atPath: extDir) else { continue }

                for extId in extIds {
                    let extPath = extDir + "/" + extId
                    guard let versions = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
                    for version in versions {
                        let manifestPath = extPath + "/" + version + "/manifest.json"
                        if let row = parseChromiumManifest(
                            at: manifestPath, browser: browser, extId: extId, extPath: extPath
                        ) {
                            // Deduplicate: same extId may appear in multiple profiles
                            if !results.contains(where: { $0.extensionId == extId && $0.browser == browser }) {
                                results.append(row)
                            }
                        }
                    }
                }
            }
        }

        // Firefox: extensions appear as .xpi files or directory names
        let ffProfilesPath = home + "/Library/Application Support/Firefox/Profiles"
        if let profiles = try? fm.contentsOfDirectory(atPath: ffProfilesPath) {
            for profile in profiles {
                let extPath = ffProfilesPath + "/" + profile + "/extensions"
                guard let files = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
                for file in files {
                    let extId = file.replacingOccurrences(of: ".xpi", with: "")
                    if !results.contains(where: { $0.extensionId == extId && $0.browser == "firefox" }) {
                        results.append(ExtensionRow(
                            id: "\(extId)-firefox",
                            browser: "firefox",
                            extensionId: extId,
                            name: extId,
                            permissions: [],
                            isSuspicious: false,
                            suspicionReason: nil
                        ))
                    }
                }
            }
        }

        return results.sorted { $0.isSuspicious && !$1.isSuspicious }
    }

    private static func parseChromiumManifest(
        at path: String, browser: String, extId: String, extPath: String
    ) -> ExtensionRow? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        let name = manifest["name"] as? String ?? extId

        // Collect all permission arrays (permissions, optional_permissions, host_permissions)
        var perms: [String] = []
        for key in ["permissions", "optional_permissions", "host_permissions"] {
            if let arr = manifest[key] as? [Any] {
                perms += arr.compactMap { $0 as? String }
            }
        }

        let dangerous = perms.filter { dangerousPermissions.contains($0) }
        let isSuspicious = dangerous.count >= 3
            || perms.contains("<all_urls>")
            || perms.contains("nativeMessaging")

        return ExtensionRow(
            id: "\(extId)-\(browser)",
            browser: browser,
            extensionId: extId,
            name: name,
            permissions: perms,
            isSuspicious: isSuspicious,
            suspicionReason: isSuspicious
                ? "Dangerous permissions: \(dangerous.prefix(4).joined(separator: ", "))"
                : nil
        )
    }
}
