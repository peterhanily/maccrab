// PackageFreshnessView.swift
// MacCrabApp
//
// Supply-chain attack dashboard. Lets the user manually query a package
// registry for freshness/risk before running it, and shows supply-chain
// alerts that the daemon has already detected.

import SwiftUI
import MacCrabCore

struct PackageFreshnessView: View {
    @ObservedObject var appState: AppState

    @State private var packageName: String = ""
    @State private var selectedRegistry: PackageFreshnessChecker.Registry = .npm
    @State private var isChecking = false
    @State private var result: PackageFreshnessChecker.PackageInfo?
    @State private var error: String?

    private var supplyChainAlerts: [AlertViewModel] {
        appState.dashboardAlerts.filter {
            $0.ruleTitle.lowercased().contains("supply") ||
            $0.ruleTitle.lowercased().contains("package") ||
            $0.ruleTitle.lowercased().contains("fresh") ||
            $0.ruleTitle.lowercased().contains("install") ||
            $0.mitreTechniques.lowercased().contains("t1195") ||
            $0.mitreTechniques.lowercased().contains("t1072")
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {

                // Header
                HStack {
                    Text(String(localized: "packageFreshness.title",
                        defaultValue: "Package Freshness"))
                        .font(.title2).fontWeight(.bold)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.top)

                Text(String(localized: "packageFreshness.description",
                    defaultValue: "Supply-chain attacks (slopsquatting, dependency confusion) target newly published packages. Packages published in the last 7 days are flagged as fresh and should be verified before use."))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)

                // Manual check form
                GroupBox(label: Label(
                    String(localized: "packageFreshness.checkTitle", defaultValue: "Check a Package"),
                    systemImage: "magnifyingglass"
                )) {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            TextField(
                                String(localized: "packageFreshness.namePlaceholder",
                                    defaultValue: "Package name (e.g. lodash, requests, serde)"),
                                text: $packageName
                            )
                            .textFieldStyle(.roundedBorder)
                            .onSubmit { Task { await check() } }

                            Picker("", selection: $selectedRegistry) {
                                Text("npm").tag(PackageFreshnessChecker.Registry.npm)
                                Text("PyPI").tag(PackageFreshnessChecker.Registry.pypi)
                                Text("Homebrew").tag(PackageFreshnessChecker.Registry.homebrew)
                                Text("Cask").tag(PackageFreshnessChecker.Registry.homebrewCask)
                                Text("Cargo").tag(PackageFreshnessChecker.Registry.cargo)
                            }
                            .pickerStyle(.menu)
                            .frame(width: 100)

                            Button {
                                Task { await check() }
                            } label: {
                                if isChecking {
                                    ProgressView().scaleEffect(0.7)
                                } else {
                                    Text(String(localized: "packageFreshness.check",
                                        defaultValue: "Check"))
                                }
                            }
                            .disabled(packageName.trimmingCharacters(in: .whitespaces).isEmpty || isChecking)
                        }

                        if let error {
                            Text(error).font(.caption).foregroundColor(.red)
                        }

                        if let result {
                            PackageResultView(info: result)
                        }
                    }
                    .padding(4)
                }
                .padding(.horizontal)

                // Daemon supply-chain alerts
                if !supplyChainAlerts.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(String(localized: "packageFreshness.daemonAlerts",
                            defaultValue: "Supply-Chain Alerts"))
                            .font(.headline)
                            .padding(.horizontal)

                        VStack(spacing: 6) {
                            ForEach(supplyChainAlerts.prefix(20)) { alert in
                                SupplyChainAlertRow(alert: alert)
                            }
                        }
                        .padding(.horizontal)
                    }
                }

                Spacer(minLength: 24)
            }
        }
        .navigationTitle("Package Freshness")
    }

    private func check() async {
        let name = packageName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        isChecking = true
        error = nil
        result = nil
        let checker = PackageFreshnessChecker()
        result = await checker.checkPackage(name: name, registry: selectedRegistry)
        isChecking = false
    }
}

// MARK: - Result View

private struct PackageResultView: View {
    let info: PackageFreshnessChecker.PackageInfo

    private var riskColor: Color {
        switch info.riskLevel {
        case .safe:     return .green
        case .low:      return .blue
        case .medium:   return .yellow
        case .high:     return .orange
        case .critical: return .red
        }
    }

    private var riskIcon: String {
        switch info.riskLevel {
        case .safe:     return "checkmark.shield.fill"
        case .low:      return "checkmark.circle.fill"
        case .medium:   return "exclamationmark.circle.fill"
        case .high:     return "exclamationmark.triangle.fill"
        case .critical: return "exclamationmark.shield.fill"
        }
    }

    private var riskLabel: String {
        switch info.riskLevel {
        case .safe:     return "Risk: Safe"
        case .low:      return "Risk: Low"
        case .medium:   return "Risk: Medium"
        case .high:     return "Risk: High"
        case .critical: return "Risk: Critical"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: riskIcon)
                .font(.title2)
                .foregroundColor(riskColor)
                .accessibilityLabel(riskLabel)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("\(info.name)")
                        .font(.headline)
                    Text("(\(info.registry.rawValue))")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(info.riskLevel.rawValue.uppercased())
                        .font(.caption).fontWeight(.semibold)
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(riskColor.opacity(0.15))
                        .foregroundColor(riskColor)
                        .clipShape(Capsule())
                }

                Text(info.description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                HStack(spacing: 16) {
                    if let age = info.ageInDays {
                        if age < 1 {
                            Label(String(format: "%.1f hours old", age * 24),
                                systemImage: "clock.fill")
                                .font(.caption)
                                .foregroundColor(age < 0.25 ? .red : .orange)
                        } else {
                            Label(String(format: "%.0f days old", age),
                                systemImage: "clock")
                                .font(.caption)
                                .foregroundColor(info.isFresh ? .orange : .secondary)
                        }
                    }
                    if let downloads = info.downloadCount {
                        Label("\(downloads) downloads",
                            systemImage: "arrow.down.circle")
                            .font(.caption)
                            .foregroundColor(info.isLowPopularity ? .orange : .secondary)
                    }
                }
            }
        }
        .padding(8)
        .background(riskColor.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Alert Row

private struct SupplyChainAlertRow: View {
    let alert: AlertViewModel

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(alert.severityColor)
                .frame(width: 8, height: 8)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                Text(alert.ruleTitle)
                    .font(.subheadline)
                    .lineLimit(1)
                Text("\(alert.processName) · \(alert.timeString)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(Color(NSColor.alternatingContentBackgroundColors[1]))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}
