// ESHealthView.swift
// MacCrabApp
//
// Endpoint Security and daemon health dashboard.
// Shows collection status, database health, event throughput, and
// whether all key subsystems are active.

import SwiftUI
import MacCrabCore

struct ESHealthView: View {
    @ObservedObject var appState: AppState
    @State private var dbSize: UInt64 = 0
    @State private var walSize: UInt64 = 0
    @State private var eventCount: Int = 0
    @State private var esloggerAvailable = false
    @State private var lastRefresh: Date?

    private let dataDir: String = {
        let fm = FileManager.default
        let systemDB = "/Library/Application Support/MacCrab/events.db"
        let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        if fm.isReadableFile(atPath: systemDB) { return "/Library/Application Support/MacCrab" }
        return userDir
    }()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {

                HStack {
                    Text(String(localized: "esHealth.title", defaultValue: "Endpoint Security Health"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                    Button {
                        Task { await refresh() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .accessibilityLabel("Refresh")
                    .keyboardShortcut("r", modifiers: .command)
                }
                .padding(.horizontal)
                .padding(.top)

                // Status grid
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    HealthCard(
                        title: "Daemon",
                        value: appState.isConnected ? "Running" : "Offline",
                        icon: "antenna.radiowaves.left.and.right",
                        color: appState.isConnected ? .green : .red,
                        detail: appState.isConnected ? "Events being collected" : "Start with: sudo maccrabd"
                    )

                    HealthCard(
                        title: "Event Rate",
                        value: "\(appState.eventsPerSecond) ev/s",
                        icon: "bolt.fill",
                        color: appState.eventsPerSecond > 0 ? .green : .secondary,
                        detail: "\(eventCount) total events stored"
                    )

                    HealthCard(
                        title: "Database",
                        value: ByteCountFormatter.string(fromByteCount: Int64(dbSize), countStyle: .file),
                        icon: "cylinder.fill",
                        color: dbSize > 0 ? .blue : .secondary,
                        detail: walSize > 0
                            ? "WAL active — daemon writing (\(ByteCountFormatter.string(fromByteCount: Int64(walSize), countStyle: .file)))"
                            : "WAL not present"
                    )

                    HealthCard(
                        title: "Rules",
                        value: "\(appState.rulesLoaded)",
                        icon: "shield.checkered",
                        color: appState.rulesLoaded > 0 ? .green : .orange,
                        detail: appState.rulesLoaded > 0
                            ? "Detection rules loaded"
                            : "Run: make compile-rules"
                    )

                    HealthCard(
                        title: "eslogger",
                        value: esloggerAvailable ? "Available" : "Not found",
                        icon: "waveform.path.ecg",
                        color: esloggerAvailable ? .green : .orange,
                        detail: esloggerAvailable
                            ? "Zero-entitlement ES events enabled"
                            : "Install Xcode Command Line Tools for eslogger support"
                    )

                    HealthCard(
                        title: "AI Backend",
                        value: appState.llmStatus.isConfigured
                            ? appState.llmStatus.provider.capitalized
                            : "Not configured",
                        icon: "brain.head.profile",
                        color: appState.llmStatus.isConfigured ? .green : .secondary,
                        detail: appState.llmStatus.isConfigured
                            ? "Threat hunting and summaries enabled"
                            : "Configure in Settings > AI Backend"
                    )

                    HealthCard(
                        title: "Fleet",
                        value: appState.fleetStatus.isConfigured ? "Connected" : "Standalone",
                        icon: "network",
                        color: appState.fleetStatus.isConfigured ? .green : .secondary,
                        detail: appState.fleetStatus.isConfigured
                            ? appState.fleetStatus.fleetURL
                            : "Set MACCRAB_FLEET_URL to enroll"
                    )

                    HealthCard(
                        title: "Data Directory",
                        value: dataDir.contains("/Library/Application Support/MacCrab")
                            ? (dataDir.hasPrefix("/Library") ? "System" : "User")
                            : "Custom",
                        icon: "folder.fill",
                        color: .blue,
                        detail: dataDir
                    )
                }
                .padding(.horizontal)

                // Collector checklist
                VStack(alignment: .leading, spacing: 10) {
                    Text(String(localized: "esHealth.collectors", defaultValue: "Active Collectors"))
                        .font(.headline)
                        .padding(.horizontal)

                    let collectors: [(name: String, icon: String, note: String)] = [
                        ("Endpoint Security", "shield.fill", "Kernel events (requires root + entitlement or eslogger)"),
                        ("Unified Log", "doc.text.fill", "12 subsystems: TCC, AMFI, SandboxD, OpenDirectory, more"),
                        ("Clipboard Monitor", "doc.on.clipboard", "Sensitive data + injection detection (3s poll)"),
                        ("Browser Extension Monitor", "puzzlepiece.extension", "Chrome, Firefox, Brave, Edge, Arc (60s poll)"),
                        ("Ultrasonic Monitor", "waveform", "DolphinAttack, NUIT, SurfingAttack (30s poll, mic required)"),
                        ("USB Monitor", "cable.connector", "Device connect/disconnect (10s poll)"),
                        ("Rootkit Detector", "eye.slash", "Hidden process cross-reference (120s poll)"),
                        ("Network + DNS", "network", "Connection tracking, DoH detection, TLS fingerprinting"),
                        ("MCP Monitor", "brain", "AI tool MCP server config drift detection"),
                        ("Git Security Monitor", "arrow.triangle.branch", "Credential theft and hook injection detection"),
                    ]

                    VStack(spacing: 4) {
                        ForEach(collectors, id: \.name) { collector in
                            HStack(spacing: 10) {
                                Image(systemName: appState.isConnected ? "checkmark.circle.fill" : "circle.dashed")
                                    .foregroundColor(appState.isConnected ? .green : .secondary)
                                    .frame(width: 16)
                                    .accessibilityLabel(appState.isConnected ? "Active" : "Inactive")
                                Image(systemName: collector.icon)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .frame(width: 16)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(collector.name).font(.subheadline)
                                    Text(collector.note)
                                        .font(.caption).foregroundColor(.secondary)
                                }
                                Spacer()
                            }
                            .padding(.horizontal, 20)
                            .padding(.vertical, 4)
                        }
                    }
                }

                if let refreshed = lastRefresh {
                    Text(String(localized: "esHealth.refreshed",
                        defaultValue: "Refreshed \(refreshed.formatted(.relative(presentation: .named)))"))
                        .font(.caption2).foregroundColor(.secondary)
                        .padding(.horizontal)
                }

                Spacer(minLength: 24)
            }
        }
        .navigationTitle("ES Health")
        .task { await refresh() }
    }

    private func refresh() async {
        let fm = FileManager.default
        let dbPath = dataDir + "/events.db"
        let walPath = dbPath + "-wal"

        dbSize = (try? fm.attributesOfItem(atPath: dbPath))?[.size] as? UInt64 ?? 0
        walSize = (try? fm.attributesOfItem(atPath: walPath))?[.size] as? UInt64 ?? 0
        esloggerAvailable = fm.fileExists(atPath: "/usr/bin/eslogger")

        // Count events via SQLite (lightweight row count)
        if dbSize > 0 {
            do {
                let store = try EventStore(directory: dataDir)
                eventCount = try await store.count()
            } catch {
                eventCount = 0
            }
        }

        await appState.refresh()
        lastRefresh = Date()
    }
}

// MARK: - Health Card

private struct HealthCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    let detail: String

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: icon)
                        .foregroundColor(color)
                        .accessibilityHidden(true)
                    Text(title)
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                Text(value)
                    .font(.headline)
                    .foregroundColor(color)
                Text(detail)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
            .padding(4)
        }
    }
}
