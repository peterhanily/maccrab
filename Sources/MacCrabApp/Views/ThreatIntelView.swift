// ThreatIntelView.swift
// MacCrabApp
//
// Threat Intelligence dashboard — view loaded IOCs, configure feeds,
// import custom intel from CSV/JSON/STIX, manage API keys.

import SwiftUI
import UniformTypeIdentifiers
import MacCrabCore

struct ThreatIntelView: View {
    @ObservedObject var appState: AppState
    @State private var selectedSection: IntelSection = .overview
    @State private var importText: String = ""
    @State private var importType: ImportType = .domains
    @State private var showImportSheet = false
    @State private var showFileImporter = false
    @State private var importStatus: String?

    // API key storage — @State backed by Keychain (SecretsStore). Previously
    // these were @AppStorage, which wrote API keys to the world-readable
    // `com.maccrab.app.plist`. Now the plist holds no secrets; the Keychain
    // is authoritative. `loadAPIKeys()` populates on view appear;
    // `keychainBinding(for:state:)` below persists every SecureField edit.
    @State private var virusTotalKey = ""
    @State private var abuseIPDBKey  = ""
    @State private var otxKey        = ""
    @State private var shodanKey     = ""
    @State private var urlscanKey    = ""
    @State private var greynoiseKey  = ""
    @State private var hibpKey       = ""
    private let secrets = SecretsStore()

    enum IntelSection: String, CaseIterable {
        case overview = "Overview"
        case feeds = "Feeds"
        case browse = "Browse IOCs"
        case importData = "Import"
        case apiKeys = "API Keys"
    }

    enum ImportType: String, CaseIterable {
        case domains = "Domains"
        case ips = "IPs"
        case hashes = "Hashes (SHA-256)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Text(String(localized: "threatIntel.title", defaultValue: "Threat Intelligence"))
                    .font(.title2).fontWeight(.bold)
                Spacer()
                Picker("", selection: $selectedSection) {
                    ForEach(IntelSection.allCases, id: \.self) { section in
                        Text(section.rawValue).tag(section)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 420)
                .accessibilityLabel(String(localized: "threatIntel.sectionPicker", defaultValue: "Threat intel section"))
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch selectedSection {
                    case .overview:
                        overviewSection
                    case .feeds:
                        feedsSection
                    case .browse:
                        browseSection
                    case .importData:
                        importSection
                    case .apiKeys:
                        apiKeysSection
                    }
                }
                .padding()
            }
        }
        .onAppear { loadAPIKeys() }
    }

    // MARK: - Keychain plumbing

    /// Populate every API-key @State field from the Keychain. Called once
    /// on view appear — without this, the SecureFields render empty and
    /// the user thinks no key is stored.
    private func loadAPIKeys() {
        virusTotalKey = keychainOrEmpty(.virusTotalKey)
        abuseIPDBKey  = keychainOrEmpty(.abuseIPDBKey)
        otxKey        = keychainOrEmpty(.alienVaultKey)
        shodanKey     = keychainOrEmpty(.shodanKey)
        urlscanKey    = keychainOrEmpty(.urlScanKey)
        greynoiseKey  = keychainOrEmpty(.greyNoiseKey)
        hibpKey       = keychainOrEmpty(.haveIBeenPwnedKey)
    }

    /// Read a secret from the Keychain, flattening `String??` (try?
    /// wraps the already-optional return of `get`) down to the empty
    /// string when either layer is nil.
    private func keychainOrEmpty(_ key: SecretKey) -> String {
        (try? secrets.get(key)).flatMap { $0 } ?? ""
    }

    /// A Binding<String> whose setter both updates the @State mirror and
    /// writes to the Keychain. Every SecureField hooked through this
    /// persists on every keystroke (which is what the user expects from
    /// @AppStorage — same UX, different storage).
    private func keychainBinding(for key: SecretKey, state: Binding<String>) -> Binding<String> {
        Binding(
            get: { state.wrappedValue },
            set: { newValue in
                state.wrappedValue = newValue
                try? secrets.set(key, value: newValue)
            }
        )
    }

    // MARK: - Overview

    private var overviewSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Stats boxes
            HStack(spacing: 16) {
                IntelMetricBox(label: "Malicious Hashes", value: "\(appState.threatIntelStats.hashes)", icon: "number", color: .red)
                IntelMetricBox(label: "Malicious IPs", value: "\(appState.threatIntelStats.ips)", icon: "network", color: .orange)
                IntelMetricBox(label: "Malicious Domains", value: "\(appState.threatIntelStats.domains)", icon: "globe", color: .blue)
                IntelMetricBox(label: "Malicious URLs", value: "\(appState.threatIntelStats.urls)", icon: "link", color: .purple)
            }

            // Last update
            GroupBox("Status") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Circle().fill(.green).frame(width: 8, height: 8)
                        Text(String(localized: "threatintel.feedsActive", defaultValue: "Threat intel feeds active"))
                            .font(.callout)
                        Spacer()
                        if let lastUpdate = appState.threatIntelStats.lastUpdate {
                            Text("Last update: \(lastUpdate, style: .relative) ago")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    Text(String(localized: "threatintel.refreshNote", defaultValue: "IOCs are refreshed every 4 hours from abuse.ch feeds. Custom IOCs persist across restarts."))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }.padding(4)
            }

            // Coverage summary
            GroupBox("Detection Coverage") {
                VStack(alignment: .leading, spacing: 6) {
                    CoverageRow(label: "Binary hash matching", detail: "CDHash from eslogger matched against MalwareBazaar hashes", active: appState.threatIntelStats.hashes > 0)
                    CoverageRow(label: "IP reputation", detail: "Network connections checked against Feodo Tracker C2 IPs", active: appState.threatIntelStats.ips > 0)
                    CoverageRow(label: "Domain reputation", detail: "DNS queries checked against URLhaus malicious domains", active: appState.threatIntelStats.domains > 0)
                    CoverageRow(label: "Package freshness", detail: "npm/PyPI/Brew/Cargo install-time age checking via registry APIs", active: true)
                    CoverageRow(label: "Notarization status", detail: "Binary notarization verified via spctl on execution", active: true)
                }.padding(4)
            }
        }
    }

    // MARK: - Feeds

    private var feedsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "threatintel.activeFeedsSection", defaultValue: "Active Feeds"))
                .font(.headline)

            FeedCard(name: "abuse.ch Feodo Tracker", url: "https://feodotracker.abuse.ch", type: "C2 IP addresses", status: "Active", color: .green)
            FeedCard(name: "abuse.ch URLhaus", url: "https://urlhaus.abuse.ch", type: "Malicious URLs & domains", status: "Active", color: .green)
            FeedCard(name: "abuse.ch MalwareBazaar", url: "https://bazaar.abuse.ch", type: "Malware SHA-256 hashes", status: "Active", color: .green)

            Divider()

            Text(String(localized: "threatintel.availableFeedsSection", defaultValue: "Available Feeds (requires API key)"))
                .font(.headline)
                .padding(.top, 8)

            FeedCard(name: "VirusTotal", url: "https://virustotal.com", type: "Multi-engine file/URL/domain scanning", status: virusTotalKey.isEmpty ? "Not configured" : "Configured", color: virusTotalKey.isEmpty ? .secondary : .green)
            FeedCard(name: "AbuseIPDB", url: "https://abuseipdb.com", type: "IP reputation and abuse reports", status: abuseIPDBKey.isEmpty ? "Not configured" : "Configured", color: abuseIPDBKey.isEmpty ? .secondary : .green)
            FeedCard(name: "AlienVault OTX", url: "https://otx.alienvault.com", type: "Open threat exchange pulses", status: otxKey.isEmpty ? "Not configured" : "Configured", color: otxKey.isEmpty ? .secondary : .green)
            FeedCard(name: "Shodan", url: "https://shodan.io", type: "Internet-wide host intelligence", status: shodanKey.isEmpty ? "Not configured" : "Configured", color: shodanKey.isEmpty ? .secondary : .green)
            FeedCard(name: "URLScan.io", url: "https://urlscan.io", type: "URL scanning and screenshots", status: urlscanKey.isEmpty ? "Not configured" : "Configured", color: urlscanKey.isEmpty ? .secondary : .green)
            FeedCard(name: "GreyNoise", url: "https://greynoise.io", type: "IP noise/threat classification", status: greynoiseKey.isEmpty ? "Not configured" : "Configured", color: greynoiseKey.isEmpty ? .secondary : .green)
            FeedCard(name: "Have I Been Pwned", url: "https://haveibeenpwned.com", type: "Credential breach detection", status: hibpKey.isEmpty ? "Not configured" : "Configured", color: hibpKey.isEmpty ? .secondary : .green)

            Divider()

            Text(String(localized: "threatintel.freeFeedsSection", defaultValue: "Free Feeds (no API key needed)"))
                .font(.headline)
                .padding(.top, 8)

            FeedCard(name: "PhishTank", url: "https://phishtank.org", type: "Phishing URL database", status: "Available", color: .green)

            Divider()

            Text(String(localized: "threatintel.customFeedSection", defaultValue: "Custom Feed Support"))
                .font(.headline)
                .padding(.top, 8)

            Text(String(localized: "threatintel.importNote", defaultValue: "Import IOCs from CSV, JSON, or STIX 2.1 bundles via the Import tab. Custom IOCs are merged with feed data and persist across detection engine restarts."))
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }

    // MARK: - Browse IOCs

    private var browseSection: some View {
        IOCBrowserSection(appState: appState)
    }

    // MARK: - Import

    private var importSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "threatIntel.importTitle", defaultValue: "Import Custom IOCs"))
                .font(.headline)

            Text(String(localized: "threatIntel.importDesc", defaultValue: "Add your own indicators of compromise from text lists, CSV files, JSON arrays, or STIX 2.1 bundles."))
                .font(.caption)
                .foregroundColor(.secondary)

            // Format selector
            Picker(String(localized: "threatIntel.iocType", defaultValue: "IOC Type"), selection: $importType) {
                ForEach(ImportType.allCases, id: \.self) { type in
                    Text(type.rawValue).tag(type)
                }
            }
            .pickerStyle(.segmented)
            .accessibilityLabel(String(localized: "threatIntel.iocType", defaultValue: "IOC Type"))

            // Text input
            GroupBox(String(localized: "threatIntel.pasteIOCs", defaultValue: "Paste IOCs (one per line)")) {
                TextEditor(text: $importText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 120)
                    .accessibilityLabel(String(localized: "threatIntel.iocTextEditor", defaultValue: "IOC text input"))
            }

            HStack {
                Button(String(localized: "threatIntel.importFromText", defaultValue: "Import from Text")) {
                    importFromText()
                }
                .buttonStyle(.borderedProminent)
                .disabled(importText.isEmpty)
                .accessibilityLabel(String(localized: "threatIntel.importFromText", defaultValue: "Import from Text"))
                .accessibilityHint(String(localized: "threatIntel.importFromTextHint", defaultValue: "Imports pasted IOCs into the threat intelligence database"))

                Button(String(localized: "threatIntel.importFromFile", defaultValue: "Import from File...")) {
                    showFileImporter = true
                }
                .accessibilityLabel(String(localized: "threatIntel.importFromFile", defaultValue: "Import from File"))
                .accessibilityHint(String(localized: "threatIntel.importFromFileHint", defaultValue: "Opens file picker to import threat intelligence"))

                Spacer()

                if let status = importStatus {
                    Text(status)
                        .font(.caption)
                        .foregroundColor(.green)
                }
            }

            Divider()

            // Supported formats
            GroupBox("Supported Formats") {
                VStack(alignment: .leading, spacing: 6) {
                    FormatRow(format: "Plain text", ext: ".txt", description: "One IOC per line")
                    FormatRow(format: "CSV", ext: ".csv", description: "Column containing IOCs (auto-detected)")
                    FormatRow(format: "JSON array", ext: ".json", description: "[\"ioc1\", \"ioc2\", ...]")
                    FormatRow(format: "STIX 2.1 Bundle", ext: ".json", description: "STIX bundle with indicator objects")
                    FormatRow(format: "MISP Event", ext: ".json", description: "MISP event export with attributes")
                }.padding(4)
            }
        }
        .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.plainText, .json, .commaSeparatedText], allowsMultipleSelection: false) { result in
            if case .success(let urls) = result, let url = urls.first {
                importFromFile(url)
            }
        }
    }

    // MARK: - API Keys

    private var apiKeysSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "threatIntel.apiKeys", defaultValue: "API Keys"))
                .font(.headline)

            Text(String(localized: "threatIntel.apiKeysDesc", defaultValue: "Configure API keys to enable additional threat intelligence feeds. Keys are stored in the macOS Keychain, encrypted at rest under your login password."))
                .font(.caption)
                .foregroundColor(.secondary)

            GroupBox("VirusTotal") {
                apiKeyRow(
                    description: String(localized: "threatintel.vtDesc", defaultValue: "Multi-engine file, URL, and domain scanning"),
                    binding: keychainBinding(for: .virusTotalKey, state: $virusTotalKey),
                    provider: "VirusTotal",
                    signupURL: "https://www.virustotal.com/gui/join-us",
                    linkKind: .free
                )
            }

            GroupBox("AbuseIPDB") {
                apiKeyRow(
                    description: String(localized: "threatintel.abuseDesc", defaultValue: "IP address reputation and abuse reports"),
                    binding: keychainBinding(for: .abuseIPDBKey, state: $abuseIPDBKey),
                    provider: "AbuseIPDB",
                    signupURL: "https://www.abuseipdb.com/register",
                    linkKind: .free
                )
            }

            GroupBox("AlienVault OTX") {
                apiKeyRow(
                    description: String(localized: "threatintel.otxDesc", defaultValue: "Open Threat Exchange community intelligence"),
                    binding: keychainBinding(for: .alienVaultKey, state: $otxKey),
                    provider: "AlienVault OTX",
                    signupURL: "https://otx.alienvault.com/api",
                    linkKind: .free
                )
            }

            GroupBox("Shodan") {
                apiKeyRow(
                    description: String(localized: "threatintel.shodanDesc", defaultValue: "Internet-wide host and service intelligence"),
                    binding: keychainBinding(for: .shodanKey, state: $shodanKey),
                    provider: "Shodan",
                    signupURL: "https://account.shodan.io/register",
                    linkKind: .free
                )
            }

            GroupBox("URLScan.io") {
                apiKeyRow(
                    description: String(localized: "threatintel.urlscanDesc", defaultValue: "URL scanning, screenshots, and threat verdicts"),
                    binding: keychainBinding(for: .urlScanKey, state: $urlscanKey),
                    provider: "URLScan.io",
                    signupURL: "https://urlscan.io/user/signup",
                    linkKind: .free
                )
            }

            GroupBox("GreyNoise") {
                apiKeyRow(
                    description: String(localized: "threatintel.grenoiseDesc", defaultValue: "IP noise and threat classification \u{2014} identify scanners vs targeted attacks"),
                    binding: keychainBinding(for: .greyNoiseKey, state: $greynoiseKey),
                    provider: "GreyNoise",
                    signupURL: "https://viz.greynoise.io/signup",
                    linkKind: .free
                )
            }

            GroupBox("Have I Been Pwned") {
                apiKeyRow(
                    description: String(localized: "threatintel.hibpDesc", defaultValue: "Credential breach detection \u{2014} check if accounts appear in known breaches"),
                    binding: keychainBinding(for: .haveIBeenPwnedKey, state: $hibpKey),
                    provider: "Have I Been Pwned",
                    signupURL: "https://haveibeenpwned.com/API/Key",
                    linkKind: .paid
                )
            }
        }
    }

    // Localized factory so every provider box uses the same strings and
    // translators only need to supply one copy of "API Key" / "Get a free
    // API key →". Product names (VirusTotal, Shodan …) stay in English.
    private enum APIKeyLinkKind { case free, paid }

    @ViewBuilder
    private func apiKeyRow(
        description: String,
        binding: Binding<String>,
        provider: String,
        signupURL: String,
        linkKind: APIKeyLinkKind
    ) -> some View {
        let placeholder = String(localized: "threatintel.apiKey.placeholder", defaultValue: "API Key")
        let accessibility = String(
            localized: "threatintel.apiKey.accessibility",
            defaultValue: "\(provider) API Key"
        )
        let linkText: String = {
            switch linkKind {
            case .free: return String(localized: "threatintel.apiKey.getFree", defaultValue: "Get a free API key \u{2192}")
            case .paid: return String(localized: "threatintel.apiKey.getPaid", defaultValue: "Get an API key \u{2192}")
            }
        }()

        VStack(alignment: .leading, spacing: 4) {
            Text(description).font(.caption).foregroundColor(.secondary)
            SecureField(placeholder, text: binding)
                .textFieldStyle(.roundedBorder)
                .font(.system(.caption, design: .monospaced))
                .accessibilityLabel(accessibility)
            Link(linkText, destination: URL(string: signupURL)!)
                .font(.caption2)
        }
        .padding(4)
    }

    // MARK: - Import Logic

    private func importFromText() {
        let lines = importText.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        guard !lines.isEmpty else { return }

        // Write to a temp file for the daemon to pick up
        let importDir = NSHomeDirectory() + "/Library/Application Support/MacCrab"
        try? FileManager.default.createDirectory(atPath: importDir, withIntermediateDirectories: true)

        let filename: String
        switch importType {
        case .domains: filename = "custom_domains.txt"
        case .ips: filename = "custom_ips.txt"
        case .hashes: filename = "custom_hashes.txt"
        }

        let path = importDir + "/" + filename
        // Append to existing
        var existing = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
        existing += lines.joined(separator: "\n") + "\n"
        try? existing.write(toFile: path, atomically: true, encoding: .utf8)

        importStatus = "Imported \(lines.count) \(importType.rawValue.lowercased()). Restart daemon to apply."
        importText = ""

        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { importStatus = nil }
    }

    private func importFromFile(_ url: URL) {
        guard url.startAccessingSecurityScopedResource() else { return }
        defer { url.stopAccessingSecurityScopedResource() }

        guard let content = try? String(contentsOf: url, encoding: .utf8) else { return }

        // Try to detect format
        if content.trimmingCharacters(in: .whitespaces).hasPrefix("[") || content.trimmingCharacters(in: .whitespaces).hasPrefix("{") {
            // JSON — try to parse as array of strings or STIX bundle
            if let data = content.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) {
                if let array = json as? [String] {
                    importText = array.joined(separator: "\n")
                } else if let dict = json as? [String: Any],
                          let objects = dict["objects"] as? [[String: Any]] {
                    // STIX bundle — extract indicator patterns
                    var iocs: [String] = []
                    for obj in objects {
                        if let pattern = obj["pattern"] as? String {
                            // Extract value from STIX pattern like [domain-name:value = 'evil.com']
                            if let valueRange = pattern.range(of: "'") {
                                let afterQuote = pattern[valueRange.upperBound...]
                                if let endRange = afterQuote.range(of: "'") {
                                    iocs.append(String(afterQuote[afterQuote.startIndex..<endRange.lowerBound]))
                                }
                            }
                        }
                    }
                    importText = iocs.joined(separator: "\n")
                }
            }
        } else {
            // Plain text or CSV — use as-is
            importText = content
        }

        importStatus = "File loaded — review and click Import"
    }
}

// MARK: - Supporting Views

private struct IntelMetricBox: View {
    let label: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        GroupBox {
            VStack(spacing: 4) {
                Image(systemName: icon).font(.title3).foregroundColor(color)
                    .accessibilityHidden(true)
                Text(value).font(.system(.title2, design: .rounded, weight: .bold))
                Text(label).font(.caption2).foregroundColor(.secondary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 2)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(value)")
    }
}

private struct FeedCard: View {
    let name: String
    let url: String
    let type: String
    let status: String
    let color: Color

    var body: some View {
        HStack(spacing: 12) {
            Circle().fill(color).frame(width: 8, height: 8)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.callout).fontWeight(.medium)
                Text(type).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Text(status).font(.caption).foregroundColor(color)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(name), \(status)")
    }
}

private struct CoverageRow: View {
    let label: String
    let detail: String
    let active: Bool

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: active ? "checkmark.circle.fill" : "circle")
                .foregroundColor(active ? .green : .secondary)
                .font(.caption)
                .accessibilityLabel(active ? "Active" : "Inactive")
            VStack(alignment: .leading, spacing: 1) {
                Text(label).font(.caption).fontWeight(.medium)
                Text(detail).font(.caption2).foregroundColor(.secondary)
            }
        }
    }
}

private struct FormatRow: View {
    let format: String
    let ext: String
    let description: String

    var body: some View {
        HStack(spacing: 8) {
            Text(ext)
                .font(.system(.caption2, design: .monospaced))
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Color.secondary.opacity(0.15))
                .clipShape(Capsule())
            Text(format).font(.caption).fontWeight(.medium)
            Text("— \(description)").font(.caption).foregroundColor(.secondary)
        }
    }
}

// MARK: - IOC Browser
//
// Replaces the v1.6.14 Browse IOCs stub (counts + CLI hints) with a
// real searchable browser. Users can:
//   - Pick a category (Hashes / IPs / Domains / URLs)
//   - Search by substring (case-insensitive)
//   - See the source attribution for the selected category
//   - See a "Recent Matches" panel listing alerts the IOC list has
//     actually caught — answers the analyst question "what's being
//     considered a match?" that wasn't surfaced before v1.6.16

enum IOCCategory: String, CaseIterable, Identifiable {
    case hashes = "Hashes"
    case ips = "IPs"
    case domains = "Domains"
    case urls = "URLs"
    var id: String { rawValue }
}

private struct IOCBrowserSection: View {
    @ObservedObject var appState: AppState
    @State private var category: IOCCategory = .hashes
    @State private var query: String = ""
    @State private var refreshing: Bool = false

    private var allRecords: [ThreatIntelFeed.IOCRecord] {
        let set = appState.threatIntelIOCs
        switch category {
        case .hashes:  return set?.hashes ?? []
        case .ips:     return set?.ips ?? []
        case .domains: return set?.domains ?? []
        case .urls:    return set?.urls ?? []
        }
    }

    /// Filtered + sorted records. Sort is newest-first by
    /// `lastSeenInFeed` so the highest-signal entries (just
    /// observed in the wild) appear at the top.
    private var filtered: [ThreatIntelFeed.IOCRecord] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let base = allRecords.sorted { $0.lastSeenInFeed > $1.lastSeenInFeed }
        guard !q.isEmpty else { return base }
        return base.filter {
            $0.value.lowercased().contains(q)
                || ($0.malwareFamily?.lowercased().contains(q) ?? false)
                || $0.tags.contains(where: { $0.lowercased().contains(q) })
                || $0.source.lowercased().contains(q)
                || ($0.fileType?.lowercased().contains(q) ?? false)
        }
    }

    /// Renders the first N results to keep SwiftUI snappy on 100K+
    /// records. Search narrows the cap; users can pivot to `maccrabctl`
    /// for deeper analysis.
    private static let renderCap = 250

    private var sourceCaption: String {
        switch category {
        case .hashes:  return "SHA-256 of binaries seen in malware samples. Source: abuse.ch MalwareBazaar + custom imports."
        case .ips:     return "Active command-and-control IP addresses. Source: abuse.ch Feodo Tracker + custom imports."
        case .domains: return "Hosts serving malware (URL parent domains). Source: abuse.ch URLhaus + custom imports."
        case .urls:    return "Full URLs hosting malware payloads. Source: abuse.ch URLhaus + custom imports."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            headerRow

            // Per-feed health row — visible signal when an upstream
            // feed is failing (502, network blocked, etc.) instead of
            // the analyst guessing why counts haven't moved.
            FeedHealthRow(iocs: appState.threatIntelIOCs)

            if appState.threatIntelIOCs == nil {
                noCacheBanner
            }

            // Category picker + search.
            HStack(spacing: 12) {
                Picker("Category", selection: $category) {
                    ForEach(IOCCategory.allCases) { cat in
                        Text("\(cat.rawValue) (\(countFor(cat).formatted()))").tag(cat)
                    }
                }
                .pickerStyle(.segmented)
                .accessibilityLabel("IOC category")

                TextField("Search value, family, tag, source…", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)
                    .accessibilityLabel("Search IOCs")
            }

            HStack {
                Text(sourceCaption)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Text(visibilityCaption)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            // Rich rows per record.
            GroupBox {
                if filtered.isEmpty {
                    Text(query.isEmpty
                         ? "No IOCs loaded in this category."
                         : "Nothing in this category matches “\(query)”.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(filtered.prefix(Self.renderCap), id: \.value) { record in
                                IOCRecordRow(record: record, category: category)
                                Divider().opacity(0.4)
                            }
                        }
                    }
                    .frame(maxHeight: 360)
                }
            }

            recentMatchesSection
        }
    }

    private var headerRow: some View {
        HStack {
            Text("Browse IOCs")
                .font(.headline)
            Spacer()
            if let last = appState.threatIntelStats.lastUpdate {
                Text("Last sync: \(last.formatted(.relative(presentation: .named)))")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                Text("Never synced")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Button {
                refreshing = true
                Task {
                    await appState.refreshThreatIntelNow()
                    refreshing = false
                }
            } label: {
                Label(refreshing ? "Refreshing…" : "Refresh Now", systemImage: "arrow.clockwise")
            }
            .disabled(refreshing)
            .help("Trigger a one-shot feed refresh on the daemon. Without this, feeds refresh every 4 hours.")
        }
    }

    private var noCacheBanner: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Label("No threat intel cache yet", systemImage: "clock.arrow.circlepath")
                    .font(.subheadline)
                Text("The daemon refreshes feeds every 4 hours. Click Refresh Now or wait for the first sync.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(4)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var visibilityCaption: String {
        let total = allRecords.count
        let shown = min(filtered.count, Self.renderCap)
        if filtered.count > Self.renderCap {
            return "Showing \(shown.formatted()) of \(total.formatted()) (use search to narrow)"
        }
        return "Showing \(shown.formatted()) of \(total.formatted())"
    }

    private func countFor(_ cat: IOCCategory) -> Int {
        let set = appState.threatIntelIOCs
        switch cat {
        case .hashes:  return set?.hashes.count ?? 0
        case .ips:     return set?.ips.count ?? 0
        case .domains: return set?.domains.count ?? 0
        case .urls:    return set?.urls.count ?? 0
        }
    }

    @ViewBuilder
    private var recentMatchesSection: some View {
        let matches = appState.threatIntelMatches
        GroupBox("Recent Matches") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Events where threat-intel rules fired. Click an alert in the Alerts tab for full triage context.")
                    .font(.caption)
                    .foregroundColor(.secondary)

                if matches.isEmpty {
                    HStack {
                        Image(systemName: "checkmark.shield")
                            .foregroundColor(.green.opacity(0.7))
                            .accessibilityHidden(true)
                        Text("No threat-intel matches in the current alert window. Either the IOC list isn't catching anything, or you're seeing a clean machine.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                } else {
                    ForEach(matches.prefix(20)) { match in
                        ThreatIntelMatchRow(alert: match)
                    }
                    if matches.count > 20 {
                        Text("Showing 20 of \(matches.count). Open the Alerts tab and filter by `maccrab.threat-intel` to see the rest.")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .padding(4)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Feed health row

private struct FeedHealthRow: View {
    let iocs: ThreatIntelFeed.IOCSet?

    private let feedNames = ["MalwareBazaar", "Feodo", "URLhaus"]

    var body: some View {
        HStack(spacing: 14) {
            ForEach(feedNames, id: \.self) { feed in
                FeedHealthBadge(
                    feed: feed,
                    lastUpdate: iocs?.perFeedLastUpdate[feed],
                    error: iocs?.perFeedLastError[feed]
                )
            }
            Spacer()
        }
    }
}

private struct FeedHealthBadge: View {
    let feed: String
    let lastUpdate: Date?
    let error: ThreatIntelFeed.FeedError?

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
                .accessibilityHidden(true)
            Text(feed)
                .font(.caption2)
                .fontWeight(.medium)
            Text(detail)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
        .help(tooltip)
    }

    private var color: Color {
        guard let lastUpdate else { return .secondary }
        // Healthy = updated within 1.5× the daemon's 4 h cadence.
        if let error, error.at > lastUpdate { return .red }
        if Date().timeIntervalSince(lastUpdate) < 6 * 3600 { return .green }
        return .orange
    }

    private var detail: String {
        if let error, lastUpdate.map({ error.at > $0 }) ?? true {
            return "failing"
        }
        guard let lastUpdate else { return "never" }
        return lastUpdate.formatted(.relative(presentation: .numeric))
    }

    private var tooltip: String {
        if let error {
            return "Last error: \(error.reason) at \(error.at.formatted())"
        }
        if let lastUpdate {
            return "Last successful sync: \(lastUpdate.formatted())"
        }
        return "No sync recorded yet — daemon may not be running, or the first refresh hasn't completed."
    }
}

// MARK: - Rich IOC row

private struct IOCRecordRow: View {
    let record: ThreatIntelFeed.IOCRecord
    let category: IOCCategory

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundColor(iconColor)
                .frame(width: 14)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(displayValue)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 8)
                    SourceChip(source: record.source)
                }
                contextRow
            }
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 5)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var icon: String {
        switch category {
        case .hashes:  return "number.circle.fill"
        case .ips:     return "network"
        case .domains: return "globe.americas.fill"
        case .urls:    return "link.circle.fill"
        }
    }

    private var iconColor: Color {
        switch category {
        case .hashes:  return .red
        case .ips:     return .orange
        case .domains: return .blue
        case .urls:    return .purple
        }
    }

    /// Hashes are 64 hex chars — show first/last 12 with an ellipsis
    /// so they fit a row without truncating to "7e2f1c…" useless.
    private var displayValue: String {
        if category == .hashes, record.value.count == 64 {
            let prefix = record.value.prefix(12)
            let suffix = record.value.suffix(12)
            return "\(prefix)…\(suffix)"
        }
        return record.value
    }

    @ViewBuilder
    private var contextRow: some View {
        HStack(spacing: 6) {
            if let family = record.malwareFamily, !family.isEmpty {
                ContextPill(text: family, color: .red)
            }
            if let fileType = record.fileType, !fileType.isEmpty {
                ContextPill(text: fileType, color: .gray)
            }
            ForEach(record.tags.prefix(3), id: \.self) { tag in
                ContextPill(text: tag, color: .secondary)
            }
            if record.tags.count > 3 {
                Text("+\(record.tags.count - 3)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            Spacer(minLength: 8)
            if let firstSeen = record.firstSeen {
                Text("first seen \(firstSeen.formatted(date: .abbreviated, time: .omitted))")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }
}

private struct SourceChip: View {
    let source: String

    private var color: Color {
        switch source {
        case "MalwareBazaar": return .red
        case "Feodo":         return .orange
        case "URLhaus":       return .blue
        case "Custom":        return .green
        default:              return .secondary
        }
    }

    var body: some View {
        Text(source)
            .font(.caption2)
            .fontWeight(.medium)
            .foregroundColor(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(color.opacity(0.12))
            .clipShape(Capsule())
    }
}

private struct ContextPill: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2)
            .foregroundColor(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(color.opacity(0.1))
            .clipShape(Capsule())
    }
}

private struct ThreatIntelMatchRow: View {
    let alert: AlertViewModel

    private var kind: (label: String, icon: String, color: Color) {
        if alert.ruleId.contains("hash-match") {
            return ("hash", "number", .red)
        }
        if alert.ruleId.contains("threat-intel-match") {
            return ("domain/ip", "globe.americas.fill", .orange)
        }
        return ("ioc", "shield.fill", .secondary)
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: kind.icon)
                .font(.caption2)
                .foregroundColor(kind.color)
                .frame(width: 14)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(alert.ruleTitle)
                        .font(.caption)
                        .fontWeight(.medium)
                    Text(kind.label)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 4).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.1))
                        .clipShape(Capsule())
                    Spacer()
                    Text(alert.dateTimeString)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                if !alert.processName.isEmpty {
                    Text("\(alert.processName) — \(alert.description)")
                        .font(.caption2)
                        .foregroundColor(.primary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            }
        }
        .padding(.vertical, 3)
    }
}
