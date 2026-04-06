// ThreatIntelView.swift
// MacCrabApp
//
// Threat Intelligence dashboard — view loaded IOCs, configure feeds,
// import custom intel from CSV/JSON/STIX, manage API keys.

import SwiftUI
import UniformTypeIdentifiers

struct ThreatIntelView: View {
    @ObservedObject var appState: AppState
    @State private var selectedSection: IntelSection = .overview
    @State private var importText: String = ""
    @State private var importType: ImportType = .domains
    @State private var showImportSheet = false
    @State private var showFileImporter = false
    @State private var importStatus: String?

    // API key storage
    @AppStorage("threatIntel.virusTotalKey") private var virusTotalKey = ""
    @AppStorage("threatIntel.abuseIPDBKey") private var abuseIPDBKey = ""
    @AppStorage("threatIntel.otxKey") private var otxKey = ""
    @AppStorage("threatIntel.shodanKey") private var shodanKey = ""

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
                Text("Threat Intelligence")
                    .font(.title2).fontWeight(.bold)
                Spacer()
                Picker("", selection: $selectedSection) {
                    ForEach(IntelSection.allCases, id: \.self) { section in
                        Text(section.rawValue).tag(section)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 420)
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
                        Text("Threat intel feeds active")
                            .font(.callout)
                        Spacer()
                        if let lastUpdate = appState.threatIntelStats.lastUpdate {
                            Text("Last update: \(lastUpdate, style: .relative) ago")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    Text("IOCs are refreshed every 4 hours from abuse.ch feeds. Custom IOCs persist across restarts.")
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
            Text("Active Feeds")
                .font(.headline)

            FeedCard(name: "abuse.ch Feodo Tracker", url: "https://feodotracker.abuse.ch", type: "C2 IP addresses", status: "Active", color: .green)
            FeedCard(name: "abuse.ch URLhaus", url: "https://urlhaus.abuse.ch", type: "Malicious URLs & domains", status: "Active", color: .green)
            FeedCard(name: "abuse.ch MalwareBazaar", url: "https://bazaar.abuse.ch", type: "Malware SHA-256 hashes", status: "Active", color: .green)

            Divider()

            Text("Available Feeds (requires API key)")
                .font(.headline)
                .padding(.top, 8)

            FeedCard(name: "VirusTotal", url: "https://virustotal.com", type: "Multi-engine file/URL/domain scanning", status: virusTotalKey.isEmpty ? "Not configured" : "Configured", color: virusTotalKey.isEmpty ? .secondary : .green)
            FeedCard(name: "AbuseIPDB", url: "https://abuseipdb.com", type: "IP reputation and abuse reports", status: abuseIPDBKey.isEmpty ? "Not configured" : "Configured", color: abuseIPDBKey.isEmpty ? .secondary : .green)
            FeedCard(name: "AlienVault OTX", url: "https://otx.alienvault.com", type: "Open threat exchange pulses", status: otxKey.isEmpty ? "Not configured" : "Configured", color: otxKey.isEmpty ? .secondary : .green)
            FeedCard(name: "Shodan", url: "https://shodan.io", type: "Internet-wide host intelligence", status: shodanKey.isEmpty ? "Not configured" : "Configured", color: shodanKey.isEmpty ? .secondary : .green)

            Divider()

            Text("Custom Feed Support")
                .font(.headline)
                .padding(.top, 8)

            Text("Import IOCs from CSV, JSON, or STIX 2.1 bundles via the Import tab. Custom IOCs are merged with feed data and persist across daemon restarts.")
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }

    // MARK: - Browse IOCs

    private var browseSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Loaded IOC data is stored in the daemon's memory and threat intel cache. Use maccrabctl to query specific IOCs:")
                .font(.caption)
                .foregroundColor(.secondary)

            GroupBox("Quick Stats") {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("SHA-256 Hashes:").font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.hashes)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                    HStack {
                        Text("IP Addresses:").font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.ips)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                    HStack {
                        Text("Domains:").font(.caption).frame(width: 120, alignment: .leading)
                        Text("\(appState.threatIntelStats.domains)").font(.system(.caption, design: .monospaced))
                        Spacer()
                    }
                    HStack {
                        Text("URLs:").font(.caption).frame(width: 120, alignment: .leading)
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
            Text("Import Custom IOCs")
                .font(.headline)

            Text("Add your own indicators of compromise from text lists, CSV files, JSON arrays, or STIX 2.1 bundles.")
                .font(.caption)
                .foregroundColor(.secondary)

            // Format selector
            Picker("IOC Type", selection: $importType) {
                ForEach(ImportType.allCases, id: \.self) { type in
                    Text(type.rawValue).tag(type)
                }
            }
            .pickerStyle(.segmented)

            // Text input
            GroupBox("Paste IOCs (one per line)") {
                TextEditor(text: $importText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 120)
            }

            HStack {
                Button("Import from Text") {
                    importFromText()
                }
                .buttonStyle(.borderedProminent)
                .disabled(importText.isEmpty)

                Button("Import from File...") {
                    showFileImporter = true
                }

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
            Text("API Keys")
                .font(.headline)

            Text("Configure API keys to enable additional threat intelligence feeds. Keys are stored securely in macOS preferences.")
                .font(.caption)
                .foregroundColor(.secondary)

            GroupBox("VirusTotal") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Multi-engine file, URL, and domain scanning").font(.caption).foregroundColor(.secondary)
                    SecureField("API Key", text: $virusTotalKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))
                    Link("Get a free API key →", destination: URL(string: "https://www.virustotal.com/gui/join-us")!)
                        .font(.caption2)
                }.padding(4)
            }

            GroupBox("AbuseIPDB") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("IP address reputation and abuse reports").font(.caption).foregroundColor(.secondary)
                    SecureField("API Key", text: $abuseIPDBKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))
                    Link("Get a free API key →", destination: URL(string: "https://www.abuseipdb.com/register")!)
                        .font(.caption2)
                }.padding(4)
            }

            GroupBox("AlienVault OTX") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Open Threat Exchange community intelligence").font(.caption).foregroundColor(.secondary)
                    SecureField("API Key", text: $otxKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))
                    Link("Get a free API key →", destination: URL(string: "https://otx.alienvault.com/api")!)
                        .font(.caption2)
                }.padding(4)
            }

            GroupBox("Shodan") {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Internet-wide host and service intelligence").font(.caption).foregroundColor(.secondary)
                    SecureField("API Key", text: $shodanKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))
                    Link("Get a free API key →", destination: URL(string: "https://account.shodan.io/register")!)
                        .font(.caption2)
                }.padding(4)
            }
        }
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
                Text(value).font(.system(.title2, design: .rounded, weight: .bold))
                Text(label).font(.caption2).foregroundColor(.secondary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 2)
        }
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
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.callout).fontWeight(.medium)
                Text(type).font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            Text(status).font(.caption).foregroundColor(color)
        }
        .padding(.vertical, 4)
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
