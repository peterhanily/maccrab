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
        // Route through the severity.* keys (was hardcoded rawValue.capitalized,
        // so badges rendered English in every locale). Dynamic key → the runtime
        // bundle lookup API; falls back to the capitalized rawValue if a locale
        // lacks the key.
        Bundle.main.localizedString(forKey: "severity.\(rawValue)", value: rawValue.capitalized, table: nil)
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
    /// ID of the Event that triggered this alert. The detail view
    /// uses it to fetch the full event record (command line, parent,
    /// signer, file path, network destination, ancestor chain) so
    /// the user sees what actually fired, not just the rule title.
    /// Empty for alerts generated outside the rule engine (USB,
    /// clipboard, tamper) where no backing Event exists. Defaults
    /// empty so mock/preview constructors don't need updating.
    var eventId: String = ""
    /// Phase 4 agentic investigation output. Nil until an LLM has
    /// triaged this alert. Default nil so existing memberwise init
    /// callers (mocks, previews, tests) don't need to pass it.
    var llmInvestigation: MacCrabCore.LLMInvestigation? = nil
    /// (v1.17.2) JSON array of the triggering event(s) snapshotted onto the
    /// alert at creation (AlertStore schema v6), so the originating event is
    /// visible even after events.db prunes it. Nil for alerts with no backing
    /// Event. Default nil so mock/preview constructors don't need updating.
    var triggeringEventsJson: String? = nil

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
    // v1.12.6 Wave 9H: surface Wave-2 schema additions in the event
    // detail panel. Pre-9H these were populated in events.db but the
    // dashboard's EventViewModel didn't carry them, so the detail
    // pane never rendered user/ai_tool/parent/arch/notarization. Each
    // field defaults to "" so the 12+ existing mock-construction
    // sites in this file stay valid without an audit pass.
    var executablePath: String = ""
    var userName: String = ""
    var workingDirectory: String = ""
    var architecture: String = ""
    var isNotarized: Bool? = nil
    var aiTool: String = ""
    var parentName: String = ""
    var parentExecutable: String = ""
    var processSHA256: String = ""

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
