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

            Text(String(localized: "threatintel.importNote", defaultValue: "Import IOCs from CSV, JSON, or STIX 2.1 bundles via the Import tab. Custom IOCs are merged with feed data and persist across daemon restarts."))
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }

    // MARK: - Browse IOCs

    private var browseSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(String(localized: "threatintel.queryNote", defaultValue: "Loaded IOC data is stored in the daemon's memory and threat intel cache. Use maccrabctl to query specific IOCs:"))
                .font(.caption)
                .foregroundColor(.secondary)

            GroupBox("Quick Stats") {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(String(localized: "threatintel.hashesLabel", defaultValue: "SHA-256 Hashes:")).font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.hashes)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                    HStack {
                        Text(String(localized: "threatintel.ipsLabel", defaultValue: "IP Addresses:")).font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.ips)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                    HStack {
                        Text(String(localized: "threatintel.domainsLabel", defaultValue: "Domains:")).font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.domains)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                    HStack {
                        Text(String(localized: "threatintel.urlsLabel", defaultValue: "URLs:")).font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.urls)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                }.padding(4)
            }

            GroupBox("CLI Access") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("maccrabctl hunt \"show threat intel matches\"")
                        .font(.system(.caption, design: .monospaced))
                    Text("maccrabctl hunt \"find network connections to malicious IPs\"")
                        .font(.system(.caption, design: .monospaced))
                    Text("maccrabctl hunt \"show DNS queries to malicious domains\"")
                        .font(.system(.caption, design: .monospaced))
                }.padding(4)
            }
        }
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
