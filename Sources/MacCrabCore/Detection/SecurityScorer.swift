import Foundation
import Darwin
import os.log

/// Calculates a real-time security score (0-100) for the system.
/// Higher is better. Factors in system config, runtime behavior, and hygiene.
public actor SecurityScorer {
    public init() {}
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "security-score")

    public struct ScoreResult: Sendable {
        public let totalScore: Int  // 0-100
        public let grade: String    // A+, A, B+, B, C, D, F
        public let factors: [Factor]
        public let recommendations: [String]
    }

    public struct Factor: Sendable {
        public let name: String
        public let category: String  // "system", "runtime", "hygiene"
        public let score: Int        // Points earned
        public let maxScore: Int     // Points possible
        public let status: String    // "pass", "warn", "fail"
        public let detail: String
    }

    /// Calculate the current security score.
    ///
    /// - Parameter recentCriticalHigh: count of critical/high alerts in the last 24h.
    ///   When `nil` (the default), the scorer reads it from the on-disk AlertStore
    ///   itself — mirroring how the other runtime factors self-probe — so callers that
    ///   don't have a count handy (CLI `status`/`security`, MCP, dashboard) still get a
    ///   real "Active Alerts" factor instead of the old placeholder. Callers that already
    ///   loaded alerts can inject the count to skip the extra DB read.
    public func calculate(recentCriticalHigh: Int? = nil) async -> ScoreResult {
        var factors: [Factor] = []
        var recommendations: [String] = []

        // === System Configuration (40 points max) ===

        // SIP enabled? (8 points)
        let sipEnabled = checkSIP()
        factors.append(Factor(name: "System Integrity Protection", category: "system", score: sipEnabled ? 8 : 0, maxScore: 8, status: sipEnabled ? "pass" : "fail", detail: sipEnabled ? "SIP is enabled" : "SIP is disabled — critical vulnerability"))
        if !sipEnabled { recommendations.append("Enable SIP: boot to Recovery Mode → csrutil enable") }

        // FileVault? (8 points)
        let fvEnabled = checkFileVault()
        factors.append(Factor(name: "FileVault Disk Encryption", category: "system", score: fvEnabled ? 8 : 0, maxScore: 8, status: fvEnabled ? "pass" : "fail", detail: fvEnabled ? "Disk is encrypted" : "Disk is NOT encrypted"))
        if !fvEnabled { recommendations.append("Enable FileVault: System Settings → Privacy & Security → FileVault") }

        // Firewall? (6 points)
        let fwEnabled = checkFirewall()
        factors.append(Factor(name: "macOS Firewall", category: "system", score: fwEnabled ? 6 : 0, maxScore: 6, status: fwEnabled ? "pass" : "fail", detail: fwEnabled ? "Firewall is enabled" : "Firewall is disabled"))
        if !fwEnabled { recommendations.append("Enable Firewall: System Settings → Network → Firewall") }

        // Gatekeeper? (6 points)
        let gkEnabled = checkGatekeeper()
        factors.append(Factor(name: "Gatekeeper", category: "system", score: gkEnabled ? 6 : 0, maxScore: 6, status: gkEnabled ? "pass" : "fail", detail: gkEnabled ? "App assessment enabled" : "Gatekeeper is disabled"))
        if !gkEnabled { recommendations.append("Enable Gatekeeper: sudo spctl --master-enable") }

        // Auto-updates? (4 points)
        let updatesEnabled = checkAutoUpdates()
        factors.append(Factor(name: "Automatic Updates", category: "system", score: updatesEnabled ? 4 : 0, maxScore: 4, status: updatesEnabled ? "pass" : "warn", detail: updatesEnabled ? "Auto-updates enabled" : "Auto-updates may be disabled"))

        // Screen lock? (4 points)
        let screenLock = checkScreenLock()
        factors.append(Factor(name: "Screen Lock", category: "system", score: screenLock ? 4 : 0, maxScore: 4, status: screenLock ? "pass" : "warn", detail: screenLock ? "Screen lock configured" : "No screen lock timeout detected"))
        if !screenLock { recommendations.append("Set screen lock: System Settings → Lock Screen → Require password after 5 minutes") }

        // Remote login disabled? (4 points)
        let sshDisabled = !checkSSHEnabled()
        factors.append(Factor(name: "Remote Login (SSH)", category: "system", score: sshDisabled ? 4 : 2, maxScore: 4, status: sshDisabled ? "pass" : "warn", detail: sshDisabled ? "SSH is disabled" : "SSH is enabled — ensure this is intentional"))

        // === Runtime Security (25 points max) ===

        // v1.21.4 (deep-audit corr-campaign-anomaly): the "Unsigned Processes"
        // factor was removed. Its `countUnsignedProcesses()` was a hardcoded
        // `return 0`, so the factor ALWAYS awarded a full 10/10 and reported
        // "0 unsigned process(es)" regardless of reality — inflating every
        // machine's score by a check that never ran. Rather than ship a
        // dishonest full-marks factor (or a heavyweight per-PID codesign probe
        // on the score hot path), the factor is dropped; the total is computed
        // from the remaining factors' maxScores so the percentage stays honest.

        // Processes from /tmp? (8 points)
        let tmpCount = countTmpProcesses()
        let tmpScore = tmpCount == 0 ? 8 : 0
        factors.append(Factor(name: "Processes from /tmp", category: "runtime", score: tmpScore, maxScore: 8, status: tmpCount == 0 ? "pass" : "fail", detail: tmpCount == 0 ? "No processes from temp directories" : "\(tmpCount) process(es) running from /tmp"))
        if tmpCount > 0 { recommendations.append("CRITICAL: \(tmpCount) processes running from /tmp — investigate immediately") }

        // Active alerts? (10 points) — real factor: scale points down as recent
        // critical/high alerts climb. 0 → 10/10; ~1 point lost per 2 alerts; floors at
        // 0 once the count reaches the low dozens. Injected count wins; otherwise read
        // from the AlertStore. A nil count (no readable store) is reported honestly as
        // "unknown" rather than a fake full mark.
        let criticalHighCount: Int?
        if let injected = recentCriticalHigh {
            criticalHighCount = injected
        } else {
            criticalHighCount = await recentCriticalHighFromStore()
        }
        if let count = criticalHighCount {
            let alertScore = max(0, 10 - (count + 1) / 2)
            let alertStatus: String = count == 0 ? "pass" : (alertScore == 0 ? "fail" : "warn")
            let plural = count == 1 ? "" : "s"
            let detail = count == 0
                ? "No critical/high alerts in the last 24h"
                : "\(count) critical/high alert\(plural) in the last 24h"
            factors.append(Factor(name: "Active Alerts", category: "runtime", score: alertScore, maxScore: 10, status: alertStatus, detail: detail))
            if count >= 10 { recommendations.append("Triage \(count) recent critical/high alerts — run: maccrabctl alerts") }
        } else {
            // Store unreadable (e.g. daemon not yet writing, or no permission): don't
            // award a placeholder full mark. Give partial credit and say so.
            factors.append(Factor(name: "Active Alerts", category: "runtime", score: 5, maxScore: 10, status: "warn", detail: "Alert history unavailable — could not read alert store"))
        }

        // ES/eslogger active? (7 points)
        let esActive = isProcessRunning("eslogger") || isProcessRunning("maccrabd") || isProcessRunning("com.maccrab.agent")
        factors.append(Factor(name: "MacCrab Daemon", category: "runtime", score: esActive ? 7 : 0, maxScore: 7, status: esActive ? "pass" : "fail", detail: esActive ? "Detection engine active" : "MacCrab detection engine not running"))
        if !esActive { recommendations.append("Enable Protection in MacCrab.app (release) or start the dev daemon") }

        // === Hygiene (25 points max) ===

        // XProtect definitions current? (8 points)
        let xprotectCurrent = checkXProtectCurrent()
        factors.append(Factor(name: "XProtect Definitions", category: "hygiene", score: xprotectCurrent ? 8 : 2, maxScore: 8, status: xprotectCurrent ? "pass" : "warn", detail: xprotectCurrent ? "XProtect definitions up to date" : "XProtect may need updating"))

        // No auth plugins? (5 points)
        let noAuthPlugins = !FileManager.default.fileExists(atPath: "/Library/Security/SecurityAgentPlugins") || (try? FileManager.default.contentsOfDirectory(atPath: "/Library/Security/SecurityAgentPlugins"))?.isEmpty ?? true
        factors.append(Factor(name: "Authorization Plugins", category: "hygiene", score: noAuthPlugins ? 5 : 0, maxScore: 5, status: noAuthPlugins ? "pass" : "warn", detail: noAuthPlugins ? "No third-party auth plugins" : "Third-party auth plugins detected"))

        // SSH keys have passphrase? (6 points — approximate check)
        let sshKeysSecure = checkSSHKeySecurity()
        factors.append(Factor(name: "SSH Key Security", category: "hygiene", score: sshKeysSecure ? 6 : 3, maxScore: 6, status: sshKeysSecure ? "pass" : "warn", detail: sshKeysSecure ? "SSH keys appear secure" : "SSH keys found — ensure they have passphrases"))

        // .env files in home? (6 points)
        let noEnvFiles = !FileManager.default.fileExists(atPath: NSHomeDirectory() + "/.env")
        factors.append(Factor(name: "Credential Files", category: "hygiene", score: noEnvFiles ? 6 : 2, maxScore: 6, status: noEnvFiles ? "pass" : "warn", detail: noEnvFiles ? "No .env files in home directory" : ".env file found in home directory"))

        // Calculate total
        let totalMax = factors.reduce(0) { $0 + $1.maxScore }
        let totalEarned = factors.reduce(0) { $0 + $1.score }
        let percentage = totalMax > 0 ? totalEarned * 100 / totalMax : 0

        let grade: String
        switch percentage {
        case 95...100: grade = "A+"
        case 90..<95: grade = "A"
        case 85..<90: grade = "A-"
        case 80..<85: grade = "B+"
        case 75..<80: grade = "B"
        case 70..<75: grade = "B-"
        case 60..<70: grade = "C"
        case 50..<60: grade = "D"
        default: grade = "F"
        }

        return ScoreResult(totalScore: percentage, grade: grade, factors: factors, recommendations: recommendations)
    }

    /// Count critical+high alerts from the last 24h by reading the on-disk AlertStore
    /// read-only. Resolves the data dir the same way the CLI does (prefer the root
    /// `/Library/Application Support/MacCrab` when its `alerts.db` exists, else the
    /// per-user dir). Returns nil when no store is readable so the caller can report
    /// "unknown" rather than a placeholder full mark.
    private func recentCriticalHighFromStore() async -> Int? {
        let fm = FileManager.default
        let userDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first.map { $0.appendingPathComponent("MacCrab").path }
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"

        // Prefer whichever dir actually has a readable alerts.db (system first — that's
        // where the root daemon writes on release builds).
        let candidates = [systemDir, userDir].filter {
            fm.isReadableFile(atPath: $0 + "/alerts.db")
        }
        guard let dir = candidates.first else { return nil }

        // forceReadOnly: do NOT create dirs or chmod a daemon-owned file just to count.
        guard let store = try? AlertStore(directory: dir, forceReadOnly: true) else { return nil }
        let since = Date().addingTimeInterval(-24 * 3600)
        // severity: .high returns high AND critical (Severity is ordered high+). Bound
        // the fetch — the curve floors well before this, so we only need to distinguish
        // 0 / a few / dozens.
        guard let recent = try? await store.alerts(since: since, severity: .high, suppressed: false, limit: 500) else {
            return nil
        }
        return recent.count
    }

    // MARK: - Checks

    /// Run a short-lived system probe with a HARD deadline. Reads stdout on a
    /// background queue (a full pipe can't deadlock the caller) and SIGKILLs the
    /// process if it overruns `timeout` — so a wedged probe (e.g. fdesetup /
    /// spctl under MDM, Recovery, or disk pressure) can never hang the score,
    /// and therefore can never hang `maccrabctl status`, the CLI's reliability
    /// anchor. Returns captured stdout, or "" on timeout/launch-failure. Callers
    /// treat "" as the conservative default (a protection is assumed OFF/unknown
    /// rather than blocking) — under-reporting posture beats hanging.
    private nonisolated func runProbe(_ path: String, _ args: [String],
                                      captureStderr: Bool = false,
                                      timeout: TimeInterval = 2.0) -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = captureStderr ? pipe : FileHandle.nullDevice
        do { try proc.run() } catch { return "" }

        let q = DispatchQueue(label: "maccrab.probe")
        var captured = ""
        var done = false
        let sem = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let s = String(data: data, encoding: .utf8) ?? ""
            q.sync { captured = s; done = true }
            sem.signal()
        }
        if sem.wait(timeout: .now() + timeout) == .timedOut {
            if proc.isRunning { kill(proc.processIdentifier, SIGKILL) }
            _ = sem.wait(timeout: .now() + 1.0)  // reader unblocks on post-kill EOF
        }
        proc.waitUntilExit()
        return q.sync { done ? captured : "" }
    }

    private nonisolated func checkSIP() -> Bool {
        runProbe("/usr/bin/csrutil", ["status"]).contains("enabled")
    }

    private nonisolated func checkFileVault() -> Bool {
        runProbe("/usr/bin/fdesetup", ["status"]).contains("On")
    }

    private nonisolated func checkFirewall() -> Bool {
        runProbe("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]).contains("enabled")
    }

    private nonisolated func checkGatekeeper() -> Bool {
        let output = runProbe("/usr/sbin/spctl", ["--status"], captureStderr: true)
        return output.contains("enabled") || output.contains("assessments enabled")
    }

    private nonisolated func checkAutoUpdates() -> Bool {
        runProbe("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
            .trimmingCharacters(in: .whitespacesAndNewlines) == "1"
    }

    private nonisolated func checkScreenLock() -> Bool {
        // `askForPassword` is frequently ABSENT on modern macOS (the setting
        // moved; `defaults read` then errors → empty output). Absent ≠ disabled,
        // so don't false-warn: only a present "0" is a genuine fail.
        let raw = runProbe("/usr/bin/defaults", ["read", "com.apple.screensaver", "askForPassword"])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.isEmpty { return true }   // key unreadable/absent → treat as unknown, don't penalize
        return raw == "1"
    }

    private nonisolated func checkSSHEnabled() -> Bool {
        isProcessRunning("sshd")
    }

    private nonisolated func checkXProtectCurrent() -> Bool {
        // XProtect is Apple-managed (silent background updates via XProtect
        // Remediator / config-data), so a present bundle with a readable Version
        // IS current. The old mtime + 30-day cliff false-warned on any Mac that
        // simply hadn't received a (infrequent) update in a month.
        let meta = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
        if let dict = NSDictionary(contentsOfFile: meta),
           let v = dict["Version"], !"\(v)".isEmpty {
            return true
        }
        // Fallback: the bundle/app exists at all → managed by Apple.
        let fm = FileManager.default
        return fm.fileExists(atPath: "/Library/Apple/System/Library/CoreServices/XProtect.bundle")
            || fm.fileExists(atPath: "/Library/Apple/System/Library/CoreServices/XProtect.app")
    }

    private nonisolated func checkSSHKeySecurity() -> Bool {
        let sshDir = NSHomeDirectory() + "/.ssh"
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: sshDir) else { return true }
        let privateKeys = files.filter { $0.hasPrefix("id_") && !$0.hasSuffix(".pub") }
        return privateKeys.isEmpty  // Simplified: true if no private keys (or would need to check passphrase)
    }

    private nonisolated func countTmpProcesses() -> Int {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return 0 }
        var pids = [Int32](repeating: 0, count: Int(count) + 50)
        let actual = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.size))
        guard actual > 0 else { return 0 }

        var tmpCount = 0
        for pid in pids.prefix(Int(actual)) where pid > 0 {
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
            if result > 0 {
                let path = String(cString: buffer)
                if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/var/tmp/") {
                    tmpCount += 1
                }
            }
        }
        return tmpCount
    }

    private nonisolated func isProcessRunning(_ name: String) -> Bool {
        // pgrep -x prints matching PIDs to stdout (empty = no match). Run it
        // through runProbe so it's bounded (a wedged pgrep can't stall the
        // score) and never touches `terminationStatus` — the v1.9 SIGABRT
        // (NSException "task hasn't finished running" when pgrep failed to
        // launch; crash 2026-05-06-013543) is structurally avoided.
        !runProbe("/usr/bin/pgrep", ["-x", name])
            .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
