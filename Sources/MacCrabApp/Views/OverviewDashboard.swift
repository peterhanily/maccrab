// OverviewDashboard.swift
// MacCrabApp
//
// The overview homepage — the first thing users see.
// Shows call-to-action banners, stats, severity distribution,
// recent alerts, and system health at a glance.

import SwiftUI

struct OverviewDashboard: View {
    @ObservedObject var appState: AppState
    @ObservedObject var sysextManager: SystemExtensionManager
    @Binding var selectedSection: MainView.SidebarSection?
    @AppStorage("prevention.dnsSinkhole") private var dnsSinkholeEnabled = false
    @AppStorage("prevention.networkBlocker") private var networkBlockerEnabled = false
    @AppStorage("prevention.persistenceGuard") private var persistenceGuardEnabled = false

    // Muted colors for a professional look
    private let criticalColor = Color(red: 0.75, green: 0.22, blue: 0.22)
    private let highColor = Color(red: 0.80, green: 0.52, blue: 0.20)
    private let allClearColor = Color(red: 0.25, green: 0.60, blue: 0.35)

    private var preventionActive: Bool {
        dnsSinkholeEnabled || networkBlockerEnabled || persistenceGuardEnabled
    }

    var body: some View {
        ScrollView {
            // While the system extension isn't activated, the sysext
            // panel is the ONLY useful thing on this page — it's how
            // the user starts protection. Show it unconditionally at
            // the top so we never hide the activation control behind
            // a "connecting to daemon" spinner that can never resolve
            // (the daemon is the sysext; activating it *is* the
            // connection). Once the sysext is active, fall through to
            // the normal "connecting" spinner (brief, while the
            // dashboard reads its first rows from the DB) and then
            // the full overview.
            if sysextManager.state != .activated {
                VStack(alignment: .leading, spacing: 20) {
                    SystemExtensionPanel(manager: sysextManager)
                    if !appState.isConnected {
                        Text(String(
                            localized: "overview.enableAbove",
                            defaultValue: "Enable protection above to start the detection engine."
                        ))
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 4)
                    }
                }
                .padding()
            } else if !appState.isConnected && appState.rulesLoaded == 0 {
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text(String(localized: "overview.connecting", defaultValue: "Connecting to the detection engine\u{2026}"))
                        .font(.headline)
                        .foregroundColor(.secondary)
                    Text(String(
                        localized: "overview.populating",
                        defaultValue: "The extension is active \u{2014} populating the dashboard."
                    ))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(40)
            } else {
                VStack(alignment: .leading, spacing: 20) {
                    // === FDA Warning Banner ===
                    // Surfaced prominently because the silent failure mode
                    // ("protection enabled but half the events are dropped")
                    // is the single biggest ease-of-use risk in the product.
                    // Tells the user WHICH principal is missing FDA — app,
                    // sysext, or both — so they don't go hunting.
                    if !appState.fullDiskAccessGranted {
                        FullDiskAccessWarningBanner(
                            appNeedsFDA: !appState.appHasFDA,
                            sysextNeedsFDA: !appState.sysextHasFDA
                        )
                        .padding(.horizontal)
                    }

                    // v1.4.3 fail-loud: zero-rules-loaded banner. Silent
                    // detection-is-disabled is the worst protection-failure
                    // mode — the app looks fine but is evaluating zero
                    // rules. Show a red banner in Overview whenever we've
                    // gotten connected but rulesLoaded is still zero.
                    if appState.isConnected && appState.rulesLoaded == 0 {
                        DetectionHealthBanner(
                            severity: .critical,
                            title: String(localized: "health.zeroRules.title", defaultValue: "No detection rules loaded"),
                            message: String(localized: "health.zeroRules.body", defaultValue: "The detection engine is running but has zero rules to evaluate. You are not being protected. Try reinstalling MacCrab via `brew reinstall --cask maccrab`, or check the detection engine's rule directory at /Library/Application Support/MacCrab/compiled_rules/."),
                            icon: "exclamationmark.octagon.fill"
                        )
                        .padding(.horizontal)
                    }

                    // v1.4.3 fail-loud: rule tamper. SHA-256 mismatch
                    // between bundled manifest.json and installed
                    // compiled_rules/. Either someone modified
                    // /Library/Application Support/MacCrab/compiled_rules/
                    // after sync (bundled_tampered=false,
                    // installed_tampered=true) — we auto-resynced to
                    // the bundled copy — OR the shipped .app bundle
                    // itself is tampered, in which case we refused
                    // to propagate.
                    if let tamper = appState.ruleTamper {
                        DetectionHealthBanner(
                            severity: .critical,
                            title: tamper.bundledTampered
                                ? String(localized: "health.ruleTamper.bundledTitle", defaultValue: "Bundled detection rules have been tampered with")
                                : String(localized: "health.ruleTamper.installedTitle", defaultValue: "Detection rules on disk were modified"),
                            message: tamper.bundledTampered
                                ? String(
                                    localized: "health.ruleTamper.bundledBody",
                                    defaultValue: "\(tamper.mismatchedFileCount) rule file(s) inside MacCrab.app do not match the signed manifest. This should not happen on a legitimately installed copy. Re-download MacCrab from maccrab.com or reinstall via `brew reinstall --cask maccrab`."
                                )
                                : String(
                                    localized: "health.ruleTamper.installedBody",
                                    defaultValue: "\(tamper.mismatchedFileCount) rule file(s) in /Library/Application Support/MacCrab/compiled_rules/ differ from the expected SHA-256. MacCrab re-synced from the bundled copy; if this keeps happening, something on this machine is modifying the rules directory."
                                ),
                            icon: "shield.slash.fill"
                        )
                        .padding(.horizontal)
                    }

                    // v1.4.3 fail-loud: heartbeat stale → detection
                    // engine is either crashed, hung, or silently
                    // replaced. Shows banner as soon as the last
                    // written_at timestamp is older than 120s (4× the
                    // 30s write cadence — tolerates one missed tick).
                    if let hb = appState.heartbeat, hb.isStale {
                        let ageSeconds = Int(Date().timeIntervalSince(hb.writtenAt))
                        let ageText: String = {
                            if hb.writtenAt == .distantPast {
                                return String(localized: "health.heartbeat.never", defaultValue: "never")
                            }
                            if ageSeconds < 3600 { return "\(ageSeconds / 60)m ago" }
                            return "\(ageSeconds / 3600)h ago"
                        }()
                        DetectionHealthBanner(
                            severity: .critical,
                            title: String(
                                localized: "health.heartbeat.title",
                                defaultValue: "Detection engine appears silent"
                            ),
                            message: String(
                                localized: "health.heartbeat.body",
                                defaultValue: "The detection engine's last heartbeat was \(ageText). It may have crashed, hung, or been disabled. Try relaunching MacCrab; if it persists, run `systemextensionsctl list` to check the extension state, then `pkill -HUP com.maccrab.agent` to force a reload."
                            ),
                            icon: "heart.slash.fill"
                        )
                        .padding(.horizontal)
                    }

                    // v1.4.3 fail-loud: accumulated storage failures.
                    // When inserts are failing (disk full / DB locked /
                    // permissions) alerts and events silently never land
                    // in the DB. Show a warning banner with the most
                    // recent error text so the user can act without
                    // digging through `sudo log show`.
                    if let snap = appState.storageErrors,
                       appState.hasConcerningStorageError(snap) {
                        DetectionHealthBanner(
                            severity: .critical,
                            title: String(
                                localized: "health.storage.title",
                                defaultValue: "Detection data is not being saved"
                            ),
                            message: String(
                                localized: "health.storage.body",
                                defaultValue: "\(snap.alertInsertErrors) alert and \(snap.eventInsertErrors) event writes have failed. Last error: \(snap.lastErrorMessage). Check available disk space, DB permissions under /Library/Application Support/MacCrab/, and that no third-party backup tool is holding the DB open."
                            ),
                            icon: "internaldrive.fill"
                        )
                        .padding(.horizontal)
                    }

                    // === Call to Action Banner (clickable → navigates to Alerts) ===
                    Button { selectedSection = .alerts } label: {
                        HStack(spacing: 12) {
                            Image(systemName: criticalCount > 0 ? "exclamationmark.triangle.fill" : highCount > 0 ? "exclamationmark.circle.fill" : "checkmark.shield.fill")
                                .font(.title)
                                .foregroundColor(.white)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 4) {
                                if criticalCount > 0 {
                                    // Apple's ^[...](inflect: true) markdown only renders
                                    // correctly when backed by a matching .xcstrings or
                                    // .stringsdict entry with grammatical-agreement rules.
                                    // Without one, String(localized:defaultValue:) renders
                                    // the markdown literally. Until we ship that entry,
                                    // fall back to plain English pluralisation — the
                                    // localization keys still exist so a translator can
                                    // override per-locale.
                                    let noun = criticalCount == 1 ? "critical alert" : "critical alerts"
                                    let verb = criticalCount == 1 ? "needs" : "need"
                                    Text(String(
                                        localized: "overview.critical.count",
                                        defaultValue: "\(criticalCount) \(noun) \(verb) investigation"
                                    ))
                                    .font(.system(.body, weight: .semibold))
                                    .foregroundColor(.white)
                                    Text(String(localized: "overview.reviewAlerts", defaultValue: "Click to review in Alerts"))
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                } else if highCount > 0 {
                                    let noun = highCount == 1 ? "high-severity alert" : "high-severity alerts"
                                    Text(String(
                                        localized: "overview.high.count",
                                        defaultValue: "\(highCount) \(noun) to review"
                                    ))
                                    .font(.system(.body, weight: .semibold))
                                    .foregroundColor(.white)
                                    Text(String(localized: "overview.reviewAlerts", defaultValue: "Click to review in Alerts"))
                                        .font(.subheadline)
                                        .foregroundColor(.white.opacity(0.8))
                                } else {
                                    Text(String(localized: "overview.allClear", defaultValue: "All clear \u{2014} no critical alerts"))
                                        .font(.system(.body, weight: .semibold))
                                        .foregroundColor(.white)
                                    Text(String(
                                        localized: "overview.eventsRate",
                                        defaultValue: "\(appState.eventsPerSecond) events/sec monitored"
                                    ))
                                    .font(.subheadline)
                                    .foregroundColor(.white.opacity(0.8))
                                }
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundColor(.white.opacity(0.6))
                                .flipsForRightToLeftLayoutDirection(true)
                                .accessibilityHidden(true)
                        }
                        .padding()
                        .background(criticalCount > 0 ? criticalColor : highCount > 0 ? highColor : allClearColor)
                        .cornerRadius(12)
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal)

                    // === Stats Row ===
                    HStack(spacing: 16) {
                        StatCard(title: "Alerts", value: "\(appState.totalAlerts)", icon: "exclamationmark.triangle", color: .orange)
                        StatCard(title: "Rules", value: "\(appState.rulesLoaded)", icon: "shield.checkered", color: .blue)
                        StatCard(title: "Events/sec", value: "\(appState.eventsPerSecond)", icon: "waveform.path.ecg", color: .green)
                        StatCard(title: "Connected", value: appState.isConnected ? "Yes" : "No", icon: appState.isConnected ? "checkmark.circle" : "xmark.circle", color: appState.isConnected ? .green : .red)
                        StatCard(title: "Security", value: appState.securityGrade.isEmpty ? "\u{2014}" : appState.securityGrade, icon: "shield.checkered", color: appState.securityGrade.isEmpty ? .secondary : appState.securityScore >= 80 ? .green : appState.securityScore >= 60 ? .orange : .red)
                    }
                    .padding(.horizontal)

                    // === Prevention Status ===
                    Button { selectedSection = .prevention } label: {
                        HStack(spacing: 10) {
                            Image(systemName: preventionActive ? "shield.checkered" : "shield")
                                .font(.title3)
                                .foregroundColor(preventionActive ? .green : .secondary)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(preventionActive ? "Prevention Active" : "Prevention Off")
                                    .font(.subheadline)
                                    .fontWeight(.medium)
                                    .foregroundColor(.primary)
                                Text(preventionActive ? "DNS sinkhole, network blocker, and more enabled" : "Enable prevention in the Prevention tab")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .flipsForRightToLeftLayoutDirection(true)
                                .accessibilityHidden(true)
                        }
                        .padding(10)
                        .background(Color.secondary.opacity(0.06))
                        .cornerRadius(8)
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal)

                    // === Severity Breakdown ===
                    GroupBox("Alert Severity") {
                        HStack(spacing: 20) {
                            SeverityCount(label: "Critical", count: criticalCount, color: criticalColor)
                            SeverityCount(label: "High", count: highCount, color: highColor)
                            SeverityCount(label: "Medium", count: mediumCount, color: .yellow)
                            SeverityCount(label: "Low", count: lowCount, color: .blue)
                        }
                        .padding(8)
                    }
                    .padding(.horizontal)

                    HStack(alignment: .top, spacing: 16) {
                        // === Recent Alerts ===
                        GroupBox("Recent Alerts") {
                            if appState.recentAlerts.isEmpty {
                                Text(String(localized: "overview.noRecentAlerts", defaultValue: "No recent alerts"))
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                                    .frame(maxWidth: .infinity)
                                    .padding()
                            } else {
                                VStack(alignment: .leading, spacing: 8) {
                                    ForEach(appState.recentAlerts.prefix(5), id: \.id) { alert in
                                        Button { selectedSection = .alerts } label: {
                                            HStack(spacing: 8) {
                                                Circle()
                                                    .fill(alert.severityColor)
                                                    .frame(width: 8, height: 8)
                                                Text(alert.ruleTitle)
                                                    .font(.subheadline)
                                                    .lineLimit(1)
                                                Spacer()
                                                Text(alert.timeAgoString)
                                                    .font(.caption)
                                                    .foregroundColor(.secondary)
                                                Image(systemName: "chevron.right")
                                                    .font(.caption2)
                                                    .foregroundColor(.secondary)
                                                    .flipsForRightToLeftLayoutDirection(true)
                                                    .accessibilityHidden(true)
                                            }
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                                .padding(4)
                            }
                        }

                        // === System Health ===
                        GroupBox("System Health") {
                            VStack(alignment: .leading, spacing: 6) {
                                HealthRow(label: "Detection Engine", status: appState.isConnected, detail: appState.isConnected ? "Active" : "Not connected")
                                HealthRow(label: "Rules", status: appState.rulesLoaded > 0, detail: "\(appState.rulesLoaded) loaded")
                                HealthRow(label: "Events", status: appState.eventsPerSecond > 0, detail: "\(appState.eventsPerSecond)/sec")
                            }
                            .padding(4)
                        }
                    }
                    .padding(.horizontal)

                    Spacer()
                }
                .padding(.top)
            }
        }
        .navigationTitle("Overview")
    }

    // Computed properties — must check BOTH .suppressed flag AND pattern suppression
    private func isEffectivelySuppressed(_ alert: AlertViewModel) -> Bool {
        alert.suppressed || appState.isPatternSuppressed(alert)
    }

    private var criticalCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .critical && !isEffectivelySuppressed($0) }.count
    }
    private var highCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .high && !isEffectivelySuppressed($0) }.count
    }
    private var mediumCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .medium && !isEffectivelySuppressed($0) }.count
    }
    private var lowCount: Int {
        appState.dashboardAlerts.filter { $0.severity == .low && !isEffectivelySuppressed($0) }.count
    }
}

// MARK: - Supporting Views

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        GroupBox {
            VStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                    .accessibilityHidden(true)
                Text(value)
                    .font(.system(.title, design: .rounded, weight: .bold))
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }
}

struct SeverityCount: View {
    let label: String
    let count: Int
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 10, height: 10)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("\(count)")
                    .font(.system(.title3, design: .rounded, weight: .bold))
                Text(label)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(count) \(label)")
    }
}

// MARK: - Full Disk Access Warning Banner

/// Prominent banner shown on the Overview when FDA is missing from either
/// MacCrab principal (the app itself, or the sysext, or both). Without FDA,
/// TCC monitoring is blind and ES file events for protected paths silently
/// drop. This is the product's worst silent-failure mode ("enabled but
/// half-dark") — surfacing it loudly is intentional.
///
/// v1.4.3 fail-loud banner shared by several protection-health states:
/// zero rules loaded, stale detection-engine heartbeat, accumulated
/// storage-write failures. Each condition builds one of these with a
/// clear title + actionable body + appropriate severity color. Kept
/// generic so the Overview doesn't end up with six lookalike bespoke
/// banners when new health signals land.
enum DetectionHealthBannerSeverity {
    case critical   // user is actively unprotected — red treatment
    case warning    // protection degraded but partly working — amber

    var tint: Color {
        switch self {
        case .critical: return .red
        case .warning:  return .orange
        }
    }
}

struct DetectionHealthBanner: View {
    let severity: DetectionHealthBannerSeverity
    let title: String
    let message: String     // renamed from `body` to avoid clobbering SwiftUI's View.body
    let icon: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(severity.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(.headline, weight: .semibold))
                    .foregroundColor(.primary)
                Text(message)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(14)
        .background(severity.tint.opacity(0.1))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(severity.tint.opacity(0.4), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// macOS treats `com.maccrab.app` and `com.maccrab.agent` as separate TCC
/// principals. Each must be granted FDA independently. The banner tells the
/// user which one is missing so they don't dig through System Settings.
struct FullDiskAccessWarningBanner: View {
    let appNeedsFDA: Bool
    let sysextNeedsFDA: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.slash.fill")
                .font(.title2)
                .foregroundColor(.white)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(String(
                    localized: "overview.fda.title",
                    defaultValue: "Full Disk Access is not granted"
                ))
                .font(.system(.body, weight: .semibold))
                .foregroundColor(.white)

                Text(bodyText)
                    .font(.subheadline)
                    .foregroundColor(.white.opacity(0.9))
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 6) {
                Button {
                    openFullDiskAccessPane()
                } label: {
                    Text(String(
                        localized: "overview.fda.openSettings",
                        defaultValue: "Open Settings"
                    ))
                    .fontWeight(.semibold)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.white)
                    .foregroundColor(Color(red: 0.75, green: 0.22, blue: 0.22))
                    .clipShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityHint(Text("Opens System Settings → Privacy & Security → Full Disk Access"))

                Button {
                    // Reveal MacCrab.app in Finder so users can drag
                    // directly into the FDA settings pane. Less ceremony
                    // than clicking + and navigating to /Applications/.
                    NSWorkspace.shared.selectFile(
                        "/Applications/MacCrab.app",
                        inFileViewerRootedAtPath: "/Applications"
                    )
                } label: {
                    Text(String(
                        localized: "overview.fda.revealInFinder",
                        defaultValue: "Reveal MacCrab in Finder"
                    ))
                    .font(.caption)
                    .foregroundColor(.white)
                    .underline()
                }
                .buttonStyle(.plain)
                .accessibilityHint(Text("Opens Finder with MacCrab.app selected so you can drag it into the FDA settings pane"))
            }
        }
        .padding()
        .background(Color(red: 0.75, green: 0.22, blue: 0.22))
        .cornerRadius(12)
        .accessibilityElement(children: .combine)
    }

    /// Per-scenario copy. macOS treats the two principals separately — name
    /// both when both are missing so the user knows they need two toggles.
    private var bodyText: String {
        switch (appNeedsFDA, sysextNeedsFDA) {
        case (true, true):
            return String(
                localized: "overview.fda.body.both",
                defaultValue: "Grant Full Disk Access to BOTH \u{201C}MacCrab\u{201D} and \u{201C}MacCrab Endpoint Security Extension\u{201D} in System Settings. Detection coverage is incomplete until both principals have access."
            )
        case (true, false):
            return String(
                localized: "overview.fda.body.appOnly",
                defaultValue: "Grant Full Disk Access to \u{201C}MacCrab\u{201D} in System Settings. The dashboard can\u{2019}t read TCC state until this is approved."
            )
        case (false, true):
            return String(
                localized: "overview.fda.body.sysextOnly",
                defaultValue: "Grant Full Disk Access to \u{201C}MacCrab Endpoint Security Extension\u{201D} in System Settings. The detection engine is blind to protected paths until this is approved."
            )
        case (false, false):
            // Shouldn't reach here — the banner is only rendered when at least
            // one is missing — but keep a sensible default.
            return String(
                localized: "overview.fda.body",
                defaultValue: "MacCrab needs Full Disk Access to monitor TCC permissions and protected file paths."
            )
        }
    }

    private func openFullDiskAccessPane() {
        // Apple has moved this URL scheme between macOS releases; walk the
        // known variants in order and return on the first success.
        let urls = [
            "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
            "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles",
        ]
        for raw in urls {
            if let url = URL(string: raw), NSWorkspace.shared.open(url) {
                return
            }
        }
        // Last-ditch fallback: open the pane chooser.
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security") {
            _ = NSWorkspace.shared.open(url)
        }
    }
}

// Kept for backward compatibility but no longer used in Overview
struct SeverityBar: View {
    let label: String
    let count: Int
    let color: Color
    let total: Int

    var body: some View {
        let fraction = CGFloat(count) / CGFloat(total)
        if count > 0 {
            Rectangle()
                .fill(color)
                .frame(maxWidth: .infinity)
                .scaleEffect(x: max(fraction, 0.05), y: 1, anchor: .leading)
                .overlay(
                    Text("\(count)")
                        .font(.system(.caption2, weight: .bold))
                        .foregroundColor(.white)
                )
        }
    }
}

struct HealthRow: View {
    let label: String
    let status: Bool
    let detail: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: status ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(status ? .green : .red)
                .font(.subheadline)
                .accessibilityLabel(status ? "OK" : "Failed")
            Text(label)
                .font(.subheadline)
                .fontWeight(.medium)
            Spacer()
            Text(detail)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
    }
}
