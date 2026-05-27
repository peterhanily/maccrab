// FindingHeuristics.swift
//
// rc.8 — presentation-layer severity for committed artifacts.
// Built-in scanners (hosts-collector, launch-agents-collector,
// etc.) emit raw rows; the operator needs a "this looks
// normal" vs "this needs a look" distinction without waiting
// for the posture analyzer (v1.18 scope).
//
// Heuristics ONLY. Never decisive. Real severity comes from
// analyzer plugins; this is the bridge until those exist.

import Foundation
import MacCrabForensics

public enum FindingSeverity: String, Codable, Sendable, Comparable {
    case routine      // inventory entry — looks normal
    case notable      // worth a glance — recent change, unusual location
    case attention    // worth investigating now — unsigned, suspicious path
    case critical     // real signal — known indicator, active malware match

    public static func < (lhs: FindingSeverity, rhs: FindingSeverity) -> Bool {
        let order: [FindingSeverity] = [.routine, .notable, .attention, .critical]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }

    public var displayName: String {
        switch self {
        case .routine:   return "Inventoried"
        case .notable:   return "Notable"
        case .attention: return "Needs review"
        case .critical:  return "Critical"
        }
    }

    public var sfSymbol: String {
        switch self {
        case .routine:   return "circle.fill"
        case .notable:   return "info.circle.fill"
        case .attention: return "exclamationmark.triangle.fill"
        case .critical:  return "exclamationmark.octagon.fill"
        }
    }
}

/// Severity tally for a scan's artifact list. Sendable so it
/// can ride along inside KitRunner.State across the actor hop.
public struct SeverityTally: Sendable, Equatable {
    public let routine: Int
    public let notable: Int
    public let attention: Int
    public let critical: Int

    public init(routine: Int, notable: Int, attention: Int, critical: Int) {
        self.routine = routine
        self.notable = notable
        self.attention = attention
        self.critical = critical
    }

    public static let zero = SeverityTally(routine: 0, notable: 0, attention: 0, critical: 0)

    public var total: Int { routine + notable + attention + critical }

    /// Operator-readable one-liner. Critical/attention lead.
    public var bannerSummary: String {
        if total == 0 { return "Nothing collected." }
        var parts: [String] = []
        if critical > 0 { parts.append("\(critical) critical") }
        if attention > 0 { parts.append("\(attention) needs review") }
        if notable > 0 { parts.append("\(notable) notable") }
        if routine > 0 { parts.append("\(routine) inventoried") }
        return parts.joined(separator: ", ")
    }
}

public enum FindingHeuristics {

    /// Classify a single artifact for presentation.
    public static func severity(for a: CommittedArtifact) -> FindingSeverity {
        let ct = a.record.contentType.lowercased()
        let summary = (a.record.summary ?? "").lowercased()
        let data = a.record.data

        // Posture analyzer findings are real findings, not
        // heuristics. Promote to attention by default.
        if ct.hasPrefix("posture.") || ct.contains("anomaly") {
            return .attention
        }

        // Launchd persistence: surfaces unsigned binaries +
        // suspicious paths.
        if ct.hasPrefix("launchd.") || ct.contains("launch_agent") || ct.contains("launchagent") {
            if case .bool(let unsigned) = data["unsigned"] ?? .null, unsigned == true {
                return .attention
            }
            if case .string(let path) = data["binary_path"] ?? data["program_path"] ?? .null {
                if isSuspiciousLaunchPath(path) {
                    return .attention
                }
            }
            return .routine
        }

        // /etc/hosts entries — sometimes legit (corp proxy) but
        // always worth a look when they're non-loopback.
        if ct.contains("hosts") {
            if case .string(let ip) = data["ip"] ?? .null,
               ip != "127.0.0.1" && ip != "::1" && ip != "0.0.0.0" && !ip.isEmpty {
                return .notable
            }
            return .routine
        }

        // TCC: grants of sensitive services are notable. Grants
        // to Terminal.app / unsigned apps to FDA = attention.
        if ct.hasPrefix("tcc.") {
            let service = stringValue(data["service"]).lowercased()
            let client  = stringValue(data["client"]).lowercased()
            let signed  = boolValue(data["client_signed"]) ?? true
            if !signed, sensitiveServices.contains(service) {
                return .attention
            }
            if client.hasSuffix("/terminal.app") && sensitiveServices.contains(service) {
                return .attention
            }
            if sensitiveServices.contains(service) {
                return .notable
            }
            return .routine
        }

        // Quarantine: notable always; attention when origin URL
        // suggests a credential-theft or supply-chain pattern.
        if ct.hasPrefix("quarantine.") {
            let origin = stringValue(data["origin_url"]).lowercased()
            if origin.contains("npmjs") || origin.contains("pypi") || origin.contains(".onion") {
                return .attention
            }
            return .notable
        }

        // Safari history / downloads / extensions.
        if ct.hasPrefix("safari.") {
            if ct == "safari.history_visit" {
                let url = stringValue(data["url"]).lowercased()
                if looksLikePunycode(url) {
                    return .notable
                }
                return .routine
            }
            if ct == "safari.download" {
                let url = stringValue(data["origin_url"]).lowercased()
                if url.hasSuffix(".dmg") || url.hasSuffix(".pkg") || url.contains("install") {
                    return .notable
                }
                return .routine
            }
            if ct == "safari.extension" {
                if case .bool(let signed) = data["signed"] ?? .null, signed == false {
                    return .attention
                }
                return .routine
            }
            return .routine
        }

        // iMessage — url_mention is the high-signal entry
        // (phish links shared via SMS forwarding), everything
        // else is routine.
        if ct.hasPrefix("imessage.") {
            if ct == "imessage.url_mention" {
                return .attention
            }
            return .routine
        }

        // Mail metadata — notable on attachments from unfamiliar
        // senders, otherwise routine.
        if ct.hasPrefix("mail.") {
            if case .bool(let hasAttachment) = data["has_attachment"] ?? .null,
               hasAttachment == true {
                return .notable
            }
            return .routine
        }

        // FaceTime + KnowledgeC + Biome — activity inventory,
        // routine unless explicitly tagged.
        if ct.hasPrefix("facetime.") || ct.hasPrefix("knowledgec.") || ct.hasPrefix("biome.") {
            return .routine
        }

        // Static analysis: codesigning + Mach-O. Unsigned is
        // attention. Suspicious load commands also attention.
        if ct.hasPrefix("codesigning.") || ct.hasPrefix("macho.") {
            if case .bool(let signed) = data["signed"] ?? .null, signed == false {
                return .attention
            }
            if case .bool(let hardened) = data["hardened_runtime"] ?? .null, hardened == false {
                return .notable
            }
            return .routine
        }

        // Installer payloads.
        if ct.hasPrefix("dmg.") || ct.hasPrefix("pkg.") {
            if case .bool(let signed) = data["signed"] ?? .null, signed == false {
                return .attention
            }
            return .notable
        }

        // AppleScript activity is content-class — every entry
        // is notable (recent automation invoked another app).
        if ct.hasPrefix("applescript.") {
            return .notable
        }

        // Default fallback for non-classified content types.
        if summary.contains("unsigned") || summary.contains("unfamiliar") {
            return .attention
        }
        return .routine
    }

    // MARK: - Value helpers

    private static func stringValue(_ v: JSONValue?) -> String {
        if case .string(let s) = v ?? .null { return s }
        return ""
    }

    private static func boolValue(_ v: JSONValue?) -> Bool? {
        if case .bool(let b) = v ?? .null { return b }
        return nil
    }

    private static func looksLikePunycode(_ url: String) -> Bool {
        url.contains("xn--")
    }

    /// Tally severities in a scan's artifact list.
    public static func tally(_ artifacts: [CommittedArtifact]) -> SeverityTally {
        var r = 0, n = 0, a = 0, c = 0
        for art in artifacts {
            switch severity(for: art) {
            case .routine:   r += 1
            case .notable:   n += 1
            case .attention: a += 1
            case .critical:  c += 1
            }
        }
        return SeverityTally(routine: r, notable: n, attention: a, critical: c)
    }

    /// Operator-readable summary like "Inventoried 3, 1 needs review".
    public static func bannerSummary(_ artifacts: [CommittedArtifact]) -> String {
        tally(artifacts).bannerSummary
    }

    // MARK: - Internals

    private static let sensitiveServices: Set<String> = [
        "screen-recording", "screencapture", "screencapture-all",
        "input-monitoring", "accessibility", "full-disk-access",
        "camera", "microphone", "speech-recognition",
        "addressbook", "calendars", "photos", "reminders",
        "location",
    ]

    private static func isSuspiciousLaunchPath(_ path: String) -> Bool {
        let lower = path.lowercased()
        if lower.hasPrefix("/tmp/") { return true }
        if lower.hasPrefix("/private/tmp/") { return true }
        if lower.contains("/library/caches/") { return true }
        if lower.contains("/downloads/") { return true }
        // Hidden subdirs of $HOME (.foo/bar) — unusual for legit agents
        let home = NSHomeDirectory().lowercased()
        if lower.hasPrefix(home + "/.") { return true }
        return false
    }

    private static func isPrivateIP(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") { return true }
        if ip.hasPrefix("192.168.") { return true }
        // 172.16.0.0 / 12
        let parts = ip.split(separator: ".")
        if parts.count == 4, parts[0] == "172",
           let oct = Int(parts[1]), oct >= 16 && oct <= 31 {
            return true
        }
        return false
    }
}
