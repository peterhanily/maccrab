// ViewModels.swift
// MacCrabApp
//
// View models for displaying data in the SwiftUI interface.
// These decouple the UI from the MacCrabCore domain types and provide
// formatted strings, colors, and mock data for development.

import SwiftUI
import MacCrabCore

// MARK: - Severity (local mirror for the UI layer)

/// Mirrors `MacCrabCore.Severity` so the app target can be built independently
/// of the core library during UI development. At integration time, replace
/// usages with the canonical type or add a mapping extension.
enum Severity: String, CaseIterable, Hashable, Comparable {
    case informational
    case low
    case medium
    case high
    case critical

    private var ordinal: Int {
        switch self {
        case .informational: return 0
        case .low:           return 1
        case .medium:        return 2
        case .high:          return 3
        case .critical:      return 4
        }
    }

    static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.ordinal < rhs.ordinal
    }

    var color: Color {
        switch self {
        case .informational: return .secondary
        case .low:           return .blue
        case .medium:        return Color(red: 0.67, green: 0.37, blue: 0.0)  // Dark amber — WCAG AA compliant (~4.8:1 on white)
        case .high:          return .orange
        case .critical:      return .red
        }
    }

    var label: String {
        rawValue.capitalized
    }

    /// Distinct SF Symbol per severity level for accessibility.
    /// Ensures severity is distinguishable without relying on color alone
    /// (supports accessibilityDifferentiateWithoutColor).
    var sfSymbol: String {
        switch self {
        case .informational: return "info.circle.fill"
        case .low:           return "minus.circle.fill"
        case .medium:        return "exclamationmark.triangle.fill"
        case .high:          return "exclamationmark.circle.fill"
        case .critical:      return "xmark.octagon.fill"
        }
    }
}

// MARK: - EventCategory (local mirror)

/// Mirrors `MacCrabCore.EventCategory` for the UI layer.
enum EventCategory: String, CaseIterable, Hashable {
    case process
    case file
    case network
    case authentication
    case tcc
    case registry
}

// MARK: - AlertViewModel

/// Presentation model for a single detection alert.
struct AlertViewModel: Identifiable, Hashable {
    let id: String
    let timestamp: Date
    let ruleId: String
    let ruleTitle: String
    let severity: Severity
    let processName: String
    let processPath: String
    let description: String
    let mitreTechniques: String
    var suppressed: Bool
    /// Phase 4 agentic investigation output. Nil until an LLM has
    /// triaged this alert. Default nil so existing memberwise init
    /// callers (mocks, previews, tests) don't need to pass it.
    var llmInvestigation: MacCrabCore.LLMInvestigation? = nil

    var timeString: String {
        Self.timeFormatter.string(from: timestamp)
    }

    var severityColor: Color {
        severity.color
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .medium    // Respects user's 12/24h preference
        f.dateStyle = .none
        return f
    }()

    private static let datePart: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "ddMMMyyyy"
        return f
    }()

    var dateTimeString: String {
        "\(Self.datePart.string(from: timestamp).uppercased()) \(Self.timeFormatter.string(from: timestamp))"
    }
}

// MARK: - EventViewModel

/// Presentation model for a single security event.
struct EventViewModel: Identifiable {
    let id: UUID
    let timestamp: Date
    let action: String
    let category: EventCategory
    let processName: String
    let pid: Int32
    let detail: String
    let signerType: String

    var timeString: String {
        Self.timeFormatter.string(from: timestamp)
    }

    var dateTimeString: String {
        "\(Self.datePart.string(from: timestamp).uppercased()) \(Self.timeFormatter.string(from: timestamp))"
    }

    var actionColor: Color {
        switch action {
        case "exec", "fork":
            return .green
        case "exit":
            return .secondary
        case "create", "write":
            return .blue
        case "delete", "unlink":
            return .red
        case "rename":
            return .orange
        case "connect":
            return .purple
        case "tcc_grant":
            return .green
        case "tcc_revoke":
            return .red
        default:
            return .primary
        }
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .medium
        f.dateStyle = .none
        return f
    }()

    private static let datePart: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "ddMMMyyyy"
        return f
    }()
}

// MARK: - RuleViewModel

/// Presentation model for a compiled detection rule.
struct RuleViewModel: Identifiable, Hashable {
    let id: String
    let title: String
    let level: String
    let tags: [String]
    let description: String
    var enabled: Bool

    /// Extracts the first MITRE ATT&CK tactic name from tags.
    /// Tags follow the convention `attack.<tactic_name>`.
    var tacticName: String {
        for tag in tags {
            let lower = tag.lowercased()
            if lower.hasPrefix("attack.") && !lower.hasPrefix("attack.t") {
                let tactic = String(lower.dropFirst("attack.".count))
                return tactic.replacingOccurrences(of: "_", with: " ").capitalized
            }
        }
        return "Other"
    }

    /// All MITRE technique IDs from tags.
    var techniqueIds: [String] {
        tags.filter { $0.lowercased().hasPrefix("attack.t") }
            .map { String($0.dropFirst("attack.".count)).uppercased() }
    }
}

// MARK: - TCCEventViewModel

/// Presentation model for a TCC permission event.
struct TCCEventViewModel: Identifiable {
    let id: String
    let timestamp: Date
    let serviceName: String
    let clientName: String
    let clientPath: String
    let allowed: Bool
    let authReason: String

    var timeString: String {
        "\(Self.datePart.string(from: timestamp).uppercased()) \(Self.clockPart.string(from: timestamp))"
    }

    /// Friendly display name for the TCC service identifier.
    var friendlyServiceName: String {
        let mapping: [String: String] = [
            "kTCCServiceAccessibility": "Accessibility",
            "kTCCServiceScreenCapture": "Screen Recording",
            "kTCCServiceMicrophone": "Microphone",
            "kTCCServiceCamera": "Camera",
            "kTCCServicePhotos": "Photos",
            "kTCCServiceAddressBook": "Contacts",
            "kTCCServiceCalendar": "Calendar",
            "kTCCServiceReminders": "Reminders",
            "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
            "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
            "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
            "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
            "kTCCServiceAppleEvents": "Automation",
            "kTCCServiceListenEvent": "Input Monitoring",
            "kTCCServiceMediaLibrary": "Media Library",
            "kTCCServiceSpeechRecognition": "Speech Recognition",
            "kTCCServiceLocation": "Location",
        ]
        return mapping[serviceName] ?? serviceName
    }

    private static let datePart: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "ddMMMyyyy"
        return f
    }()
    private static let clockPart: DateFormatter = {
        let f = DateFormatter()
        f.timeStyle = .medium
        f.dateStyle = .none
        return f
    }()
}

// MARK: - TacticGroup

/// Groups rules by MITRE ATT&CK tactic for the sidebar.
struct TacticGroup: Identifiable, Hashable {
    let id: String
    let name: String
    var ruleCount: Int

    static func == (lhs: TacticGroup, rhs: TacticGroup) -> Bool {
        lhs.id == rhs.id
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

// MARK: - Mock Data

/// Mock data for SwiftUI previews and development builds.
enum MockData {

    static let alerts: [AlertViewModel] = [
        AlertViewModel(
            id: "alert-001",
            timestamp: Date().addingTimeInterval(-120),
            ruleId: "maccrab.shell_from_web_server",
            ruleTitle: "Suspicious Shell Spawned from Web Server",
            severity: .critical,
            processName: "bash",
            processPath: "/bin/bash",
            description: "A shell process was spawned by httpd, which may indicate a web shell or command injection exploit.",
            mitreTechniques: "T1059.004",
            suppressed: false
        ),
        AlertViewModel(
            id: "alert-002",
            timestamp: Date().addingTimeInterval(-300),
            ruleId: "maccrab.launch_agent_persistence",
            ruleTitle: "Launch Agent Persistence Installed",
            severity: .high,
            processName: "python3",
            processPath: "/usr/bin/python3",
            description: "A new Launch Agent plist was written to ~/Library/LaunchAgents, establishing persistence.",
            mitreTechniques: "T1543.001",
            suppressed: false
        ),
        AlertViewModel(
            id: "alert-003",
            timestamp: Date().addingTimeInterval(-600),
            ruleId: "maccrab.tcc_db_access",
            ruleTitle: "TCC Database Direct Access",
            severity: .high,
            processName: "sqlite3",
            processPath: "/usr/bin/sqlite3",
            description: "Direct read access to the TCC.db file was detected, possibly to enumerate granted permissions.",
            mitreTechniques: "T1005",
            suppressed: false
        ),
        AlertViewModel(
            id: "alert-004",
            timestamp: Date().addingTimeInterval(-900),
            ruleId: "maccrab.outbound_c2",
            ruleTitle: "Outbound Connection to Known C2",
            severity: .critical,
            processName: "curl",
            processPath: "/usr/bin/curl",
            description: "An outbound network connection was made to a known command-and-control IP address.",
            mitreTechniques: "T1071.001",
            suppressed: false
        ),
        AlertViewModel(
            id: "alert-005",
            timestamp: Date().addingTimeInterval(-1800),
            ruleId: "maccrab.unsigned_binary_exec",
            ruleTitle: "Unsigned Binary Execution",
            severity: .medium,
            processName: "payload",
            processPath: "/tmp/payload",
            description: "An unsigned binary was executed from a temporary directory.",
            mitreTechniques: "T1204.002",
            suppressed: false
        ),
        AlertViewModel(
            id: "alert-006",
            timestamp: Date().addingTimeInterval(-2400),
            ruleId: "maccrab.keychain_dump",
            ruleTitle: "Keychain Dump Attempt",
            severity: .high,
            processName: "security",
            processPath: "/usr/bin/security",
            description: "The security command-line tool was used to dump keychain items.",
            mitreTechniques: "T1555.001",
            suppressed: true
        ),
        AlertViewModel(
            id: "alert-007",
            timestamp: Date().addingTimeInterval(-3600),
            ruleId: "maccrab.cron_modified",
            ruleTitle: "Cron Job Modified",
            severity: .medium,
            processName: "crontab",
            processPath: "/usr/bin/crontab",
            description: "A cron job entry was modified, which could indicate persistence setup.",
            mitreTechniques: "T1053.003",
            suppressed: false
        ),
        AlertViewModel(
            id: "alert-008",
            timestamp: Date().addingTimeInterval(-7200),
            ruleId: "maccrab.suspicious_dns",
            ruleTitle: "Suspicious DNS Query",
            severity: .low,
            processName: "nslookup",
            processPath: "/usr/bin/nslookup",
            description: "A DNS query was made to a recently registered domain with high entropy.",
            mitreTechniques: "T1071.004",
            suppressed: false
        ),
    ]

    static let events: [EventViewModel] = [
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-10),
            action: "exec",
            category: .process,
            processName: "bash",
            pid: 1234,
            detail: "/bin/bash -c 'whoami'",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-15),
            action: "write",
            category: .file,
            processName: "python3",
            pid: 5678,
            detail: "/Users/admin/Library/LaunchAgents/com.evil.plist",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-20),
            action: "connect",
            category: .network,
            processName: "curl",
            pid: 9101,
            detail: "45.33.32.156:443 (TCP outbound)",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-25),
            action: "exec",
            category: .process,
            processName: "osascript",
            pid: 1122,
            detail: "/usr/bin/osascript -e 'display dialog \"Enter password\"'",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-30),
            action: "create",
            category: .file,
            processName: "Safari",
            pid: 3344,
            detail: "/Users/admin/Downloads/installer.dmg",
            signerType: "appStore"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-35),
            action: "fork",
            category: .process,
            processName: "httpd",
            pid: 5566,
            detail: "fork -> pid 5567",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-40),
            action: "tcc_grant",
            category: .tcc,
            processName: "Terminal",
            pid: 7788,
            detail: "kTCCServiceSystemPolicyAllFiles -> Terminal.app",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-45),
            action: "delete",
            category: .file,
            processName: "rm",
            pid: 9900,
            detail: "/var/log/system.log",
            signerType: "apple"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-50),
            action: "connect",
            category: .network,
            processName: "nscurl",
            pid: 2233,
            detail: "192.168.1.100:8080 (TCP outbound)",
            signerType: "unsigned"
        ),
        EventViewModel(
            id: UUID(),
            timestamp: Date().addingTimeInterval(-55),
            action: "exit",
            category: .process,
            processName: "payload",
            pid: 4455,
            detail: "exit code 0",
            signerType: "unsigned"
        ),
    ]

    static let rules: [RuleViewModel] = [
        RuleViewModel(
            id: "rule-001",
            title: "Suspicious Shell Spawned from Web Server",
            level: "critical",
            tags: ["attack.initial_access", "attack.t1190", "attack.execution", "attack.t1059.004"],
            description: "Detects shell processes spawned by web server processes such as httpd or nginx.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-002",
            title: "Launch Agent Persistence",
            level: "high",
            tags: ["attack.persistence", "attack.t1543.001"],
            description: "Detects creation of plist files in LaunchAgents directories.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-003",
            title: "TCC Database Direct Access",
            level: "high",
            tags: ["attack.discovery", "attack.t1005"],
            description: "Detects processes directly reading the TCC.db file.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-004",
            title: "Unsigned Binary Execution from /tmp",
            level: "medium",
            tags: ["attack.execution", "attack.t1204.002"],
            description: "Detects execution of unsigned binaries from temporary directories.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-005",
            title: "Keychain Credential Dump",
            level: "high",
            tags: ["attack.credential_access", "attack.t1555.001"],
            description: "Detects use of the security tool to export or dump keychain items.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-006",
            title: "Cron Persistence",
            level: "medium",
            tags: ["attack.persistence", "attack.t1053.003"],
            description: "Detects modifications to crontab entries.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-007",
            title: "SSH Lateral Movement",
            level: "medium",
            tags: ["attack.lateral_movement", "attack.t1021.004"],
            description: "Detects SSH connections initiated from suspicious parent processes.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-008",
            title: "Kext Loading",
            level: "high",
            tags: ["attack.privilege_escalation", "attack.t1547.006"],
            description: "Detects loading of kernel extensions which could indicate rootkit installation.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-009",
            title: "DNS Tunneling Suspicion",
            level: "low",
            tags: ["attack.command_and_control", "attack.t1071.004"],
            description: "Detects high-entropy DNS queries that may indicate DNS tunneling.",
            enabled: false
        ),
        RuleViewModel(
            id: "rule-010",
            title: "Screen Capture via screencapture",
            level: "medium",
            tags: ["attack.collection", "attack.t1113"],
            description: "Detects use of the screencapture command-line tool.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-011",
            title: "Defense Evasion via Gatekeeper Bypass",
            level: "high",
            tags: ["attack.defense_evasion", "attack.t1553.001"],
            description: "Detects removal of quarantine attributes to bypass Gatekeeper.",
            enabled: true
        ),
        RuleViewModel(
            id: "rule-012",
            title: "Suspicious Outbound Connection",
            level: "medium",
            tags: ["attack.command_and_control", "attack.t1071.001"],
            description: "Detects outbound connections to unusual ports from non-browser processes.",
            enabled: true
        ),
    ]

    static let tccEvents: [TCCEventViewModel] = [
        TCCEventViewModel(
            id: "tcc-001",
            timestamp: Date().addingTimeInterval(-60),
            serviceName: "kTCCServiceSystemPolicyAllFiles",
            clientName: "com.apple.Terminal",
            clientPath: "/System/Applications/Utilities/Terminal.app",
            allowed: true,
            authReason: "user_consent"
        ),
        TCCEventViewModel(
            id: "tcc-002",
            timestamp: Date().addingTimeInterval(-180),
            serviceName: "kTCCServiceScreenCapture",
            clientName: "com.example.malware",
            clientPath: "/tmp/malware.app",
            allowed: false,
            authReason: "system_policy"
        ),
        TCCEventViewModel(
            id: "tcc-003",
            timestamp: Date().addingTimeInterval(-360),
            serviceName: "kTCCServiceAccessibility",
            clientName: "com.logi.optionsplus",
            clientPath: "/Applications/Logi Options+.app",
            allowed: true,
            authReason: "user_consent"
        ),
        TCCEventViewModel(
            id: "tcc-004",
            timestamp: Date().addingTimeInterval(-600),
            serviceName: "kTCCServiceMicrophone",
            clientName: "us.zoom.xos",
            clientPath: "/Applications/zoom.us.app",
            allowed: true,
            authReason: "user_consent"
        ),
        TCCEventViewModel(
            id: "tcc-005",
            timestamp: Date().addingTimeInterval(-900),
            serviceName: "kTCCServiceCamera",
            clientName: "us.zoom.xos",
            clientPath: "/Applications/zoom.us.app",
            allowed: true,
            authReason: "user_consent"
        ),
        TCCEventViewModel(
            id: "tcc-006",
            timestamp: Date().addingTimeInterval(-1200),
            serviceName: "kTCCServiceAppleEvents",
            clientName: "com.suspicious.agent",
            clientPath: "/Users/admin/.local/agent",
            allowed: false,
            authReason: "system_policy"
        ),
        TCCEventViewModel(
            id: "tcc-007",
            timestamp: Date().addingTimeInterval(-2400),
            serviceName: "kTCCServiceAddressBook",
            clientName: "com.apple.mail",
            clientPath: "/System/Applications/Mail.app",
            allowed: true,
            authReason: "user_consent"
        ),
    ]
}
