// ExtensionsCommand.swift
// maccrabctl
//
// Scans browser extension directories and prints a table of installed
// extensions with risk indicators.  Covers Chrome, Firefox, Brave, Edge, Arc.

import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func listExtensions(suspiciousOnly: Bool) {
        let home = NSHomeDirectory()
        let fm = FileManager.default
        var rows: [ExtCLIRow] = []

        // ── Chromium-family browsers ─────────────────────────────────────
        let chromiumBrowsers: [(name: String, base: String)] = [
            ("Chrome",  home + "/Library/Application Support/Google/Chrome"),
            ("Brave",   home + "/Library/Application Support/BraveSoftware/Brave-Browser"),
            ("Edge",    home + "/Library/Application Support/Microsoft Edge"),
            ("Arc",     home + "/Library/Application Support/Arc/User Data"),
        ]

        for (browser, baseDir) in chromiumBrowsers {
            for profile in ["Default", "Profile 1", "Profile 2"] {
                let extDir = baseDir + "/\(profile)/Extensions"
                guard let extIds = try? fm.contentsOfDirectory(atPath: extDir) else { continue }
                for extId in extIds {
                    let extPath = extDir + "/" + extId
                    guard let versions = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
                    for version in versions {
                        let manifestPath = extPath + "/" + version + "/manifest.json"
                        if let row = parseManifest(at: manifestPath, browser: browser, extId: extId) {
                            if !rows.contains(where: { $0.extId == extId && $0.browser == browser }) {
                                rows.append(row)
                            }
                        }
                    }
                }
            }
        }

        // ── Firefox ──────────────────────────────────────────────────────
        let ffProfiles = home + "/Library/Application Support/Firefox/Profiles"
        if let profiles = try? fm.contentsOfDirectory(atPath: ffProfiles) {
            for profile in profiles {
                let extPath = ffProfiles + "/" + profile + "/extensions"
                guard let files = try? fm.contentsOfDirectory(atPath: extPath) else { continue }
                for file in files {
                    let extId = file.replacingOccurrences(of: ".xpi", with: "")
                    if !rows.contains(where: { $0.extId == extId && $0.browser == "Firefox" }) {
                        rows.append(ExtCLIRow(
                            browser: "Firefox", extId: extId, name: extId,
                            permissions: [], isSuspicious: false, reason: nil
                        ))
                    }
                }
            }
        }

        guard !rows.isEmpty else {
            print("No browser extensions found.")
            return
        }

        let visible = suspiciousOnly ? rows.filter { $0.isSuspicious } : rows

        if visible.isEmpty {
            print("No suspicious extensions found across \(rows.count) total extension(s).")
            return
        }

        print("MacCrab Browser Extension Scan")
        print("══════════════════════════════════════════")

        // Group by browser
        let grouped = Dictionary(grouping: visible) { $0.browser }
        for browser in grouped.keys.sorted() {
            let exts = grouped[browser]!
            let suspicious = exts.filter { $0.isSuspicious }.count
            print("\n\(browser)  (\(exts.count) ext\(exts.count == 1 ? "" : "s")" + (suspicious > 0 ? ", \(suspicious) suspicious" : "") + ")")
            print(String(repeating: "─", count: 60))

            for ext in exts.sorted(by: { $0.isSuspicious && !$1.isSuspicious || $0.name < $1.name }) {
                let flag = ext.isSuspicious ? "⚠️ " : "   "
                print("\(flag)\(ext.name)")
                print("     ID: \(ext.extId)")
                if !ext.permissions.isEmpty {
                    print("     Permissions: \(ext.permissions.prefix(6).joined(separator: ", "))")
                }
                if let reason = ext.reason {
                    print("     Risk: \(reason)")
                }
            }
        }

        let suspCount = rows.filter { $0.isSuspicious }.count
        print("\n══════════════════════════════════════════")
        print("Total: \(rows.count) extension(s)", terminator: "")
        if suspCount > 0 { print("  |  ⚠️  \(suspCount) suspicious", terminator: "") }
        print()
    }

    // MARK: - Manifest Parsing

    private static let dangerousPermissions: Set<String> = [
        "webRequest", "webRequestBlocking",
        "cookies", "clipboardRead", "clipboardWrite",
        "nativeMessaging", "debugger", "management", "proxy",
        "<all_urls>", "http://*/*", "https://*/*",
        "tabs", "history", "downloads",
    ]

    private static func parseManifest(
        at path: String, browser: String, extId: String
    ) -> ExtCLIRow? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        let name = manifest["name"] as? String ?? extId
        var perms: [String] = []
        for key in ["permissions", "optional_permissions", "host_permissions"] {
            if let arr = manifest[key] as? [Any] { perms += arr.compactMap { $0 as? String } }
        }

        let dangerous = perms.filter { dangerousPermissions.contains($0) }
        let isSuspicious = dangerous.count >= 3
            || perms.contains("<all_urls>")
            || perms.contains("nativeMessaging")

        return ExtCLIRow(
            browser: browser, extId: extId, name: name, permissions: perms,
            isSuspicious: isSuspicious,
            reason: isSuspicious ? "Dangerous permissions: \(dangerous.prefix(4).joined(separator: ", "))" : nil
        )
    }
}

private struct ExtCLIRow {
    let browser: String
    let extId: String
    let name: String
    let permissions: [String]
    let isSuspicious: Bool
    let reason: String?
}
