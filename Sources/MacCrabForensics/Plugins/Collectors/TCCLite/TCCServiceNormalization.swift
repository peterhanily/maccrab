// TCCServiceNormalization — maps every `kTCCService*` raw constant
// found in TCC.db's `access` table to a stable canonical short
// name. The dashboard, MCP tools, and risk-scoring table all
// consume the canonical name; the raw constant is preserved on
// the emitted artifact as `service_raw` for round-trip fidelity.
//
// Plan reference: §4.1 — "service — normalized short canonical
// name (microphone, camera, screen_recording, automation, fda,
// accessibility, input_monitoring, apple_events, etc.)"
//
// The mapping table is the source of truth for the audit:
// canonical-name strings here must match what the manifest
// outputs declare and what the dashboard renders. A future Pass
// would scan the manifest's declared content-type variants and
// confirm every emitted `service` value is enumerated.

import Foundation

/// Canonical short names for TCC services. The set is deliberately
/// small and operator-friendly — same vocabulary the dashboard
/// uses, no `kTCCService*` prefix.
public enum TCCServiceCanonical: String, Codable, Sendable, CaseIterable {
    // High-value services tracked by the risk-scoring table.
    case fullDiskAccess = "fda"
    case accessibility = "accessibility"
    case automation = "automation"            // kTCCServiceAppleEvents grants generally
    case appleEvents = "apple_events"         // alias of automation in some macOS versions
    case screenRecording = "screen_recording"
    case inputMonitoring = "input_monitoring"
    case microphone = "microphone"
    case camera = "camera"

    // Privacy surfaces that don't carry inherent risk weight on
    // their own but the operator still wants to see catalogued.
    case contacts = "contacts"
    case photos = "photos"
    case calendars = "calendars"
    case reminders = "reminders"
    case desktopFolder = "desktop_folder"
    case documentsFolder = "documents_folder"
    case downloadsFolder = "downloads_folder"
    case removableVolumes = "removable_volumes"
    case networkVolumes = "network_volumes"
    case bluetoothAlways = "bluetooth"
    case mediaLibrary = "media_library"
    case speechRecognition = "speech_recognition"
    case userTracking = "user_tracking"
    case willow = "homekit"
    case focusStatus = "focus_status"
    case motion = "motion"
    case fitness = "fitness"
    case prototype3Rights = "prototype3"
    case prototype4Rights = "prototype4"
    case post = "system_post"
    case fileProviderDomain = "file_provider_domain"
    case fileProviderPresence = "file_provider_presence"
    case allFiles = "all_files"               // historical alias of FDA
    case shareKit = "sharekit"
    case accessibilityForBranding = "accessibility_branding"
    case other = "other"
}

public enum TCCServiceNormalization {

    /// Map a raw `kTCCService*` constant (or any variant we've
    /// observed in real TCC.db files) to its canonical short name.
    ///
    /// Falls back to `.other` for unknown constants — the artifact
    /// still gets emitted with `service = "other"` and the raw
    /// constant preserved in `service_raw`, so a future plugin
    /// version can introduce the canonical name without rewriting
    /// historical cases.
    public static func canonical(for raw: String) -> TCCServiceCanonical {
        switch raw {
        case "kTCCServiceSystemPolicyAllFiles": return .fullDiskAccess
        case "kTCCServiceAllFiles":             return .allFiles
        case "kTCCServiceAccessibility":        return .accessibility
        case "kTCCServiceAppleEvents":          return .automation
        case "kTCCServicePostEvent":            return .automation
        case "kTCCServiceScreenCapture":        return .screenRecording
        case "kTCCServiceListenEvent":          return .inputMonitoring
        case "kTCCServiceMicrophone":           return .microphone
        case "kTCCServiceCamera":               return .camera
        case "kTCCServiceAddressBook":          return .contacts
        case "kTCCServicePhotos":               return .photos
        case "kTCCServicePhotosAdd":            return .photos
        case "kTCCServiceCalendar":             return .calendars
        case "kTCCServiceReminders":            return .reminders
        case "kTCCServiceSystemPolicyDesktopFolder":   return .desktopFolder
        case "kTCCServiceSystemPolicyDocumentsFolder": return .documentsFolder
        case "kTCCServiceSystemPolicyDownloadsFolder": return .downloadsFolder
        case "kTCCServiceSystemPolicyRemovableVolumes": return .removableVolumes
        case "kTCCServiceSystemPolicyNetworkVolumes":   return .networkVolumes
        case "kTCCServiceBluetoothAlways":      return .bluetoothAlways
        case "kTCCServiceMediaLibrary":         return .mediaLibrary
        case "kTCCServiceSpeechRecognition":    return .speechRecognition
        case "kTCCServiceUserTracking":         return .userTracking
        case "kTCCServiceWillow":               return .willow
        case "kTCCServiceFocusStatus":          return .focusStatus
        case "kTCCServiceMotion":               return .motion
        case "kTCCServiceFitness":              return .fitness
        case "kTCCServicePrototype3Rights":     return .prototype3Rights
        case "kTCCServicePrototype4Rights":     return .prototype4Rights
        case "kTCCServiceFileProviderDomain":   return .fileProviderDomain
        case "kTCCServiceFileProviderPresence": return .fileProviderPresence
        case "kTCCServiceShareKit":             return .shareKit
        default:                                return .other
        }
    }

    /// Reverse direction: convenient for tests + the dashboard's
    /// "I have a canonical name, what raw constant does it most
    /// often correspond to?" affordance. For multi-source services
    /// (e.g. `.automation` can come from either AppleEvents or
    /// PostEvent), returns the primary mapping per Apple's
    /// historical default.
    public static func primaryRawConstant(for canonical: TCCServiceCanonical) -> String? {
        switch canonical {
        case .fullDiskAccess: return "kTCCServiceSystemPolicyAllFiles"
        case .accessibility: return "kTCCServiceAccessibility"
        case .automation, .appleEvents: return "kTCCServiceAppleEvents"
        case .screenRecording: return "kTCCServiceScreenCapture"
        case .inputMonitoring: return "kTCCServiceListenEvent"
        case .microphone: return "kTCCServiceMicrophone"
        case .camera: return "kTCCServiceCamera"
        case .contacts: return "kTCCServiceAddressBook"
        case .photos: return "kTCCServicePhotos"
        case .calendars: return "kTCCServiceCalendar"
        case .reminders: return "kTCCServiceReminders"
        case .desktopFolder: return "kTCCServiceSystemPolicyDesktopFolder"
        case .documentsFolder: return "kTCCServiceSystemPolicyDocumentsFolder"
        case .downloadsFolder: return "kTCCServiceSystemPolicyDownloadsFolder"
        case .removableVolumes: return "kTCCServiceSystemPolicyRemovableVolumes"
        case .networkVolumes: return "kTCCServiceSystemPolicyNetworkVolumes"
        case .bluetoothAlways: return "kTCCServiceBluetoothAlways"
        case .mediaLibrary: return "kTCCServiceMediaLibrary"
        case .speechRecognition: return "kTCCServiceSpeechRecognition"
        case .userTracking: return "kTCCServiceUserTracking"
        case .willow: return "kTCCServiceWillow"
        case .focusStatus: return "kTCCServiceFocusStatus"
        case .motion: return "kTCCServiceMotion"
        case .fitness: return "kTCCServiceFitness"
        case .prototype3Rights: return "kTCCServicePrototype3Rights"
        case .prototype4Rights: return "kTCCServicePrototype4Rights"
        case .fileProviderDomain: return "kTCCServiceFileProviderDomain"
        case .fileProviderPresence: return "kTCCServiceFileProviderPresence"
        case .shareKit: return "kTCCServiceShareKit"
        case .allFiles: return "kTCCServiceAllFiles"
        case .post: return "kTCCServicePostEvent"
        case .accessibilityForBranding: return nil
        case .other: return nil
        }
    }
}

/// Auth-value decoding for TCC.db's `access.auth_value` column.
/// Apple's values:
///   0 — denied
///   1 — unknown / pending
///   2 — allowed
///   3 — limited (e.g. Photos with "Selected Photos" choice)
public enum TCCAuthValue: Int, Codable, Sendable {
    case denied = 0
    case unknown = 1
    case allowed = 2
    case limited = 3

    public static func decode(_ raw: Int) -> TCCAuthValue {
        TCCAuthValue(rawValue: raw) ?? .unknown
    }

    /// Operator-facing string for dashboard / JSON output.
    public var token: String {
        switch self {
        case .denied: return "denied"
        case .unknown: return "unknown"
        case .allowed: return "allowed"
        case .limited: return "limited"
        }
    }
}

/// Auth-reason decoding for TCC.db's `access.auth_reason` column.
/// Apple's values shift between macOS releases; the lookup
/// tolerates that — known values map; unknown values become
/// `.unknown`.
public enum TCCAuthReason: Int, Codable, Sendable {
    case unknown = 0
    case error = 1
    case userConsent = 2
    case userSet = 3
    case systemSet = 4
    case serviceForUser = 5
    case mdmSet = 6
    case allowlist = 7
    case denylist = 8
    case servicePolicy = 9
    case inherited = 10

    public static func decode(_ raw: Int) -> TCCAuthReason {
        TCCAuthReason(rawValue: raw) ?? .unknown
    }

    /// Operator-facing string.
    public var token: String {
        switch self {
        case .unknown: return "unknown"
        case .error: return "error"
        case .userConsent: return "user_consent"
        case .userSet: return "user_set"
        case .systemSet: return "system_set"
        case .serviceForUser: return "service_for_user"
        case .mdmSet: return "mdm_set"
        case .allowlist: return "allowlist"
        case .denylist: return "denylist"
        case .servicePolicy: return "service_policy"
        case .inherited: return "inherited"
        }
    }

    public var isMDMGranted: Bool { self == .mdmSet }
    public var isUserGranted: Bool { self == .userSet || self == .userConsent }
}
