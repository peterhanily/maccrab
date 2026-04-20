// PowerAnomalyDetector.swift
// MacCrabCore
//
// Detects power and thermal anomalies indicating crypto mining or C2 beacons.
// Monitors power assertions (processes preventing sleep) and thermal pressure
// via sysctl, and flags unusual activity.

import Foundation
import Darwin
import os.log

/// Detects power and thermal anomalies indicating crypto mining or C2 beacons.
/// Monitors power assertions (processes preventing sleep) and thermal pressure.
public actor PowerAnomalyDetector {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "power-anomaly")

    public struct PowerAnomaly: Sendable {
        public let type: AnomalyType
        public let processName: String
        public let pid: Int32
        public let detail: String
        public let severity: Severity
    }

    public enum AnomalyType: String, Sendable {
        case preventingSleep = "preventing_sleep"
        case highThermal = "high_thermal"
        case sustainedCPU = "sustained_cpu"
    }

    /// Processes that legitimately hold power assertions. This is a
    /// steady-state allowlist, not a threat heuristic — holding a sleep
    /// assertion is completely normal for media playback, remote access,
    /// screen sharing, and user-invoked tools like `caffeinate`.
    private static let knownLegitimate: Set<String> = [
        // System / Apple daemons
        "backupd", "mds", "mds_stores", "mdworker", "mdworker_shared",
        "powerd", "coreaudiod", "bluetoothd", "bluetoothuserd",
        "WindowServer", "loginwindow", "SystemUIServer",
        "screensharingd", "ScreenSharingAgent", "AirPlayXPCHelper",
        "wifid", "rapportd", "sharingd", "mediaremoted",
        "runningboardd", "assertiond", "ContextStoreAgent",
        "soagent", "locationd", "cloudd", "bird",
        "caffeinate", "dtrace",
        // iCloud + Contacts sync — AddressBookSourceSync holds a sleep
        // assertion whenever it's syncing your address book with iCloud.
        // Completely normal, fires several times a day per account.
        "AddressBookSourceSync", "AddressBookManager",
        "CalendarAgent", "ContactsAgent", "AccountSync",
        "RemindersSync", "NotesMigratorService",
        // Apple diagnostics / health telemetry — holds assertions during
        // log collection runs.
        "ReportCrash", "Crash Reporter", "diagnosticd",
        "com.apple.PerformanceAnalysisCoreSkylight",
        // Safari / WebKit extension tasks that routinely hold power
        // assertions during background fetches.
        "com.apple.WebKit.WebContent", "com.apple.WebKit.Networking",
        // User-facing media / meeting / chat (media-playback assertions)
        "Music", "TV", "Podcasts", "Spotify",
        "QuickTime Player", "IINA", "VLC",
        "zoom.us", "FaceTime", "Slack", "Teams", "Microsoft Teams",
        "Discord", "WebEx", "GoToMeeting", "BlueJeans",
        "Google Chrome", "Safari", "firefox", "Microsoft Edge", "Arc",
        // Dev tools commonly left running under a sleep assertion
        "Docker Desktop", "com.docker.hyperkit", "OrbStack",
        "Xcode", "Simulator", "com.apple.dt.Xcode",
    ]

    /// Thermal level threshold above which we flag an anomaly.
    private let thermalWarningThreshold: Int32 = 70
    private let thermalCriticalThreshold: Int32 = 90

    /// Process names we've already emitted a preventingSleep alert for in
    /// this daemon lifetime. Re-emitting once per 5-minute poll created
    /// most of the power-anomaly noise.
    private var alertedSleepProcesses: Set<String> = []

    public init() {}

    /// Check for power anomalies. Returns any detected issues.
    public func scan() -> [PowerAnomaly] {
        var anomalies: [PowerAnomaly] = []

        // Check power assertions (processes preventing sleep)
        let assertions = getPowerAssertions()
        for assertion in assertions {
            if Self.knownLegitimate.contains(assertion.processName) { continue }
            if alertedSleepProcesses.contains(assertion.processName) { continue }
            alertedSleepProcesses.insert(assertion.processName)
            anomalies.append(PowerAnomaly(
                type: .preventingSleep,
                processName: assertion.processName,
                pid: assertion.pid,
                detail: "Process preventing sleep: \(assertion.assertionType). Duration: \(assertion.detail)",
                severity: .medium
            ))
        }

        // Check thermal pressure
        let thermalLevel = getCPUThermalLevel()
        if thermalLevel > thermalWarningThreshold {
            let severity: Severity = thermalLevel > thermalCriticalThreshold ? .high : .medium
            anomalies.append(PowerAnomaly(
                type: .highThermal,
                processName: "system",
                pid: 0,
                detail: "CPU thermal level: \(thermalLevel)% — possible crypto mining or sustained compute attack",
                severity: severity
            ))
        }

        return anomalies
    }

    // MARK: - Private Helpers

    private struct PowerAssertion: Sendable {
        let processName: String
        let pid: Int32
        let assertionType: String
        let detail: String
    }

    private nonisolated func getCPUThermalLevel() -> Int32 {
        var thermalLevel: Int32 = 0
        var size = MemoryLayout<Int32>.size
        if sysctlbyname("machdep.xcpm.cpu_thermal_level", &thermalLevel, &size, nil, 0) == 0 {
            return thermalLevel
        }
        return 0
    }

    private nonisolated func getPowerAssertions() -> [PowerAssertion] {
        // Use pmset -g assertions and parse output
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/pmset")
        proc.arguments = ["-g", "assertions"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            return []
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        var assertions: [PowerAssertion] = []

        // Parse lines like:
        //   pid 1234(processName): [0x00000012345] 00:05:00 PreventUserIdleSystemSleep named: "..."
        for line in output.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.contains("pid ") && trimmed.contains("(") else { continue }

            // Extract PID and process name
            guard let pidRange = trimmed.range(of: "pid "),
                  let parenStart = trimmed.firstIndex(of: "("),
                  let parenEnd = trimmed.firstIndex(of: ")"),
                  parenStart > pidRange.upperBound else { continue }

            let pidStr = trimmed[pidRange.upperBound..<parenStart]
            let name = String(trimmed[trimmed.index(after: parenStart)..<parenEnd])
            let pid = Int32(pidStr) ?? 0

            // Extract assertion type
            let assertionType: String
            if trimmed.contains("PreventUserIdleSystemSleep") {
                assertionType = "PreventUserIdleSystemSleep"
            } else if trimmed.contains("PreventSystemSleep") {
                assertionType = "PreventSystemSleep"
            } else if trimmed.contains("PreventUserIdleDisplaySleep") {
                assertionType = "PreventUserIdleDisplaySleep"
            } else {
                assertionType = "Unknown"
            }

            assertions.append(PowerAssertion(
                processName: name, pid: pid,
                assertionType: assertionType,
                detail: String(trimmed.prefix(200))
            ))
        }

        return assertions
    }
}
