// PackageFreshnessView.swift
// MacCrabApp
//
// Supply-chain attack dashboard. Lets the user manually query a package
// registry for freshness/risk before running it, and shows supply-chain
// alerts that the daemon has already detected. Tapping a package row
// opens a detail sheet with the full registry metadata: homepage,
// repository, maintainers, license, version, and per-factor risk
// breakdown — mirroring the browser-extension drill-in.

import SwiftUI
import MacCrabCore
import AppKit

struct PackageFreshnessView: View {
    @ObservedObject var appState: AppState

    @State private var packageName: String = ""
    @State private var selectedRegistry: PackageFreshnessChecker.Registry = .npm
    @State private var isChecking = false
    @State private var result: PackageFreshnessChecker.PackageInfo?
    @State private var error: String?

    // Bulk scan state
    @State private var isScanning = false
    @State private var scanResults: [PackageFreshnessChecker.PackageInfo] = []
    @State private var scanProgress: String = ""

    // Drill-in detail sheet. Wrap in an Identifiable struct so SwiftUI's
    // `.sheet(item:)` can present it without requiring retroactive
    // conformance on the core-library type.
    struct PackageSelection: Identifiable {
        let info: PackageFreshnessChecker.PackageInfo
        var id: String { "\(info.registry.rawValue):\(info.name)" }
    }
    @State private var selectedPackage: PackageSelection?

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
                            Button {
                                selectedPackage = PackageSelection(info: result)
                            } label: {
                                PackageResultView(info: result)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(4)
                }
                .padding(.horizontal)

                // Scan installed packages
                GroupBox(label: Label(
                    String(localized: "packageFreshness.scanTitle", defaultValue: "Scan Installed Packages"),
                    systemImage: "arrow.triangle.2.circlepath"
                )) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(String(localized: "packageFreshness.scanDescription",
                            defaultValue: "Discover all packages from npm (global), pip (user), and Homebrew, then check each against its registry for freshness and risk."))
                            .font(.caption)
                            .foregroundColor(.secondary)

                        HStack {
                            Button {
                                Task { await scanAll() }
                            } label: {
                                if isScanning {
                                    HStack(spacing: 6) {
                                        ProgressView().scaleEffect(0.7)
                                        Text(scanProgress)
                                            .font(.caption)
                                    }
                                } else {
                                    Label(String(localized: "packageFreshness.scanButton",
                                        defaultValue: "Scan All Packages"),
                                        systemImage: "magnifyingglass.circle.fill")
                                }
                            }
                            .disabled(isScanning)
                            .controlSize(.large)

                            Spacer()

                            if !scanResults.isEmpty {
                                let risky = scanResults.filter { $0.riskLevel >= .medium }.count
                                Text("\(scanResults.count) packages scanned\(risky > 0 ? " — \(risky) flagged" : "")")
                                    .font(.caption)
                                    .foregroundColor(risky > 0 ? .orange : .secondary)
                            }
                        }

                        if !scanResults.isEmpty {
                            Divider()

                            // Show risky packages first, then safe ones collapsed
                            let risky = scanResults.filter { $0.riskLevel >= .medium }
                            let safe = scanResults.filter { $0.riskLevel < .medium }

                            if !risky.isEmpty {
                                Text("Flagged Packages (\(risky.count))")
                                    .font(.subheadline).fontWeight(.semibold)
                                    .foregroundColor(.orange)
                                ForEach(risky, id: \.name) { pkg in
                                    Button {
                                        selectedPackage = PackageSelection(info: pkg)
                                    } label: {
                                        PackageResultView(info: pkg)
                                    }
                                    .buttonStyle(.plain)
                                    Divider()
                                }
                            }

                            if !safe.isEmpty {
                                DisclosureGroup(
                                    "\(safe.count) packages OK"
                                ) {
                                    ForEach(safe, id: \.name) { pkg in
                                        Button {
                                            selectedPackage = PackageSelection(info: pkg)
                                        } label: {
                                            HStack(spacing: 8) {
                                                Image(systemName: "checkmark.circle.fill")
                                                    .foregroundColor(.green)
                                                    .font(.caption)
                                                Text(pkg.name)
                                                    .font(.caption)
                                                Text("(\(pkg.registry.rawValue))")
                                                    .font(.caption2)
                                                    .foregroundColor(.secondary)
                                                Spacer()
                                                if let age = pkg.ageInDays {
                                                    Text("\(Int(age))d old")
                                                        .font(.caption2)
                                                        .foregroundColor(.secondary)
                                                }
                                                Image(systemName: "chevron.right")
                                                    .font(.caption2)
                                                    .foregroundColor(.secondary)
                                            }
                                            .contentShape(Rectangle())
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                                .font(.subheadline)
                            }
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
        .sheet(item: $selectedPackage) { sel in
            PackageDetailSheet(info: sel.info) { selectedPackage = nil }
        }
    }

    private func scanAll() async {
        isScanning = true
        scanProgress = "Discovering installed packages..."
        scanResults = []
        let checker = PackageFreshnessChecker()
        scanProgress = "Checking freshness against registries..."
        let results = await checker.scanInstalledPackages()
        scanResults = results
        isScanning = false
        scanProgress = ""
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
                    Image(systemName: "chevron.right")
                        .font(.caption2)
                        .foregroundColor(.secondary)
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

// MARK: - Detail Sheet

private struct PackageDetailSheet: View {
    let info: PackageFreshnessChecker.PackageInfo
    let dismiss: () -> Void

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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Divider()
                riskSection
                if let summary = info.summary, !summary.isEmpty {
                    sectionHeader("Summary")
                    Text(summary).font(.body).textSelection(.enabled)
                }
                metadataSection
                if !info.maintainers.isEmpty {
                    maintainersSection
                }
                installSection
                actionsSection
            }
            .padding(24)
            .frame(minWidth: 540, idealWidth: 620)
        }
        .frame(minHeight: 460, idealHeight: 620)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: riskIcon)
                .font(.system(size: 40))
                .foregroundColor(riskColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(info.name).font(.title2).fontWeight(.bold)
                HStack(spacing: 8) {
                    Text(info.registry.rawValue.uppercased())
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.15))
                        .clipShape(Capsule())
                    if let version = info.latestVersion {
                        Text("v\(version)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    if let license = info.license, !license.isEmpty {
                        Text("·").foregroundColor(.secondary).font(.caption)
                        Text(license).font(.caption).foregroundColor(.secondary)
                    }
                }
            }
            Spacer()
            Button("Close", action: dismiss).keyboardShortcut(.cancelAction)
        }
    }

    private var riskSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Text(info.riskLevel.rawValue.uppercased())
                    .font(.callout).fontWeight(.semibold)
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(riskColor.opacity(0.18))
                    .foregroundColor(riskColor)
                    .clipShape(Capsule())
                if let age = info.ageInDays {
                    if age < 1 {
                        Label(String(format: "%.1f hours old", age * 24),
                              systemImage: "clock.fill")
                            .font(.callout)
                            .foregroundColor(age < 0.25 ? .red : .orange)
                    } else {
                        Label(String(format: "%.0f days old", age),
                              systemImage: "clock")
                            .font(.callout)
                            .foregroundColor(info.isFresh ? .orange : .secondary)
                    }
                }
                if let downloads = info.downloadCount {
                    Label("\(downloads.formatted()) installs",
                          systemImage: "arrow.down.circle")
                        .font(.callout)
                        .foregroundColor(info.isLowPopularity ? .orange : .secondary)
                }
                Spacer()
            }
            if !info.riskReasons.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(info.riskReasons, id: \.self) { reason in
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

    private var metadataSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Metadata")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                detailRow("Registry", info.registry.rawValue)
                detailRow("Latest version", info.latestVersion)
                detailRow("License", info.license)
                detailRow("Homepage", info.homepage, isLink: true)
                detailRow("Repository", info.repository, isLink: true)
                detailRow("Registry page", info.registryURL, isLink: true)
                detailRow("First published", info.publishedDate?
                    .formatted(date: .abbreviated, time: .shortened))
                if let downloads = info.downloadCount {
                    detailRow("Weekly installs", "\(downloads.formatted())")
                }
            }
        }
    }

    private var maintainersSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Maintainers (\(info.maintainers.count))")
            VStack(alignment: .leading, spacing: 3) {
                ForEach(info.maintainers, id: \.self) { m in
                    HStack(spacing: 6) {
                        Image(systemName: "person.crop.circle")
                            .font(.caption).foregroundColor(.secondary)
                        Text(m).font(.caption).textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var installSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Install command")
            HStack {
                Text(installCommand)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(installCommand, forType: .string)
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
            }
        }
    }

    private var actionsSection: some View {
        HStack(spacing: 8) {
            if let homepage = info.homepage, let url = URL(string: homepage) {
                Button { NSWorkspace.shared.open(url) } label: {
                    Label("Homepage", systemImage: "safari")
                }
            }
            if let repo = info.repository, let url = URL(string: repo) {
                Button { NSWorkspace.shared.open(url) } label: {
                    Label("Repository", systemImage: "chevron.left.forwardslash.chevron.right")
                }
            }
            if let reg = info.registryURL, let url = URL(string: reg) {
                Button { NSWorkspace.shared.open(url) } label: {
                    Label("Registry page", systemImage: "shippingbox")
                }
            }
            Spacer()
        }
        .padding(.top, 4)
    }

    // MARK: Helpers

    private var installCommand: String {
        switch info.registry {
        case .npm:          return "npm install \(info.name)"
        case .pypi:         return "pip install \(info.name)"
        case .homebrew:     return "brew install \(info.name)"
        case .homebrewCask: return "brew install --cask \(info.name)"
        case .cargo:        return "cargo add \(info.name)"
        }
    }

    private func sectionHeader(_ text: String) -> some View {
        Text(text).font(.headline)
    }

    @ViewBuilder
    private func detailRow(
        _ label: String, _ value: String?,
        isLink: Bool = false
    ) -> some View {
        if let value, !value.isEmpty {
            GridRow {
                Text(label).font(.caption).foregroundColor(.secondary)
                    .gridColumnAlignment(.trailing)
                if isLink, let url = URL(string: value) {
                    Link(value, destination: url)
                        .font(.system(.caption, design: .monospaced))
                } else {
                    Text(value)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }
}
