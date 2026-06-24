// ATTACKRef.swift
// MacCrabCore
//
// Humanize MITRE ATT&CK technique codes for the dashboard (FIQ-7). Alerts
// carry bare codes like "attack.t1059.004"; this turns them into
// "T1059.004 — Command and Scripting Interpreter" + a link to the canonical
// attack.mitre.org page.
//
// Design (mirrors D3FENDRef): the URL is MECHANICAL and correct for ANY code
// (sub-technique → /T1059/004/). Names are a curated map keyed by PARENT
// technique — covering the ~98 techniques MacCrab's rules reference — so a
// sub-technique displays its parent's name and links to the exact sub page.
// Unknown codes fall back to the bare code. We deliberately do NOT bundle the
// full ~600-technique ATT&CK set.
//
// Reference: https://attack.mitre.org/

import Foundation

public enum ATTACKRef {

    /// Parent-technique names (MITRE ATT&CK Enterprise) for every parent
    /// referenced by the shipped rules. A test asserts this stays in sync.
    public static let parentNames: [String: String] = [
        "T1003": "OS Credential Dumping",
        "T1005": "Data from Local System",
        "T1011": "Exfiltration Over Other Network Medium",
        "T1014": "Rootkit",
        "T1016": "System Network Configuration Discovery",
        "T1021": "Remote Services",
        "T1027": "Obfuscated Files or Information",
        "T1029": "Scheduled Transfer",
        "T1033": "System Owner/User Discovery",
        "T1036": "Masquerading",
        "T1037": "Boot or Logon Initialization Scripts",
        "T1040": "Network Sniffing",
        "T1041": "Exfiltration Over C2 Channel",
        "T1046": "Network Service Discovery",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1049": "System Network Connections Discovery",
        "T1053": "Scheduled Task/Job",
        "T1055": "Process Injection",
        "T1056": "Input Capture",
        "T1057": "Process Discovery",
        "T1059": "Command and Scripting Interpreter",
        "T1068": "Exploitation for Privilege Escalation",
        "T1069": "Permission Groups Discovery",
        "T1070": "Indicator Removal",
        "T1071": "Application Layer Protocol",
        "T1078": "Valid Accounts",
        "T1082": "System Information Discovery",
        "T1083": "File and Directory Discovery",
        "T1087": "Account Discovery",
        "T1090": "Proxy",
        "T1091": "Replication Through Removable Media",
        "T1095": "Non-Application Layer Protocol",
        "T1098": "Account Manipulation",
        "T1102": "Web Service",
        "T1105": "Ingress Tool Transfer",
        "T1110": "Brute Force",
        "T1113": "Screen Capture",
        "T1114": "Email Collection",
        "T1115": "Clipboard Data",
        "T1123": "Audio Capture",
        "T1125": "Video Capture",
        "T1135": "Network Share Discovery",
        "T1140": "Deobfuscate/Decode Files or Information",
        "T1176": "Browser Extensions",
        "T1185": "Browser Session Hijacking",
        "T1189": "Drive-by Compromise",
        "T1190": "Exploit Public-Facing Application",
        "T1195": "Supply Chain Compromise",
        "T1200": "Hardware Additions",
        "T1201": "Password Policy Discovery",
        "T1204": "User Execution",
        "T1217": "Browser Information Discovery",
        "T1219": "Remote Access Software",
        "T1480": "Execution Guardrails",
        "T1485": "Data Destruction",
        "T1486": "Data Encrypted for Impact",
        "T1489": "Service Stop",
        "T1490": "Inhibit System Recovery",
        "T1496": "Resource Hijacking",
        "T1497": "Virtualization/Sandbox Evasion",
        "T1498": "Network Denial of Service",
        "T1505": "Server Software Component",
        "T1518": "Software Discovery",
        "T1528": "Steal Application Access Token",
        "T1529": "System Shutdown/Reboot",
        "T1539": "Steal Web Session Cookie",
        "T1542": "Pre-OS Boot",
        "T1543": "Create or Modify System Process",
        "T1546": "Event Triggered Execution",
        "T1547": "Boot or Logon Autostart Execution",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1552": "Unsecured Credentials",
        "T1553": "Subvert Trust Controls",
        "T1554": "Compromise Host Software Binary",
        "T1555": "Credentials from Password Stores",
        "T1556": "Modify Authentication Process",
        "T1557": "Adversary-in-the-Middle",
        "T1559": "Inter-Process Communication",
        "T1560": "Archive Collected Data",
        "T1562": "Impair Defenses",
        "T1563": "Remote Service Session Hijacking",
        "T1564": "Hide Artifacts",
        "T1565": "Data Manipulation",
        "T1566": "Phishing",
        "T1567": "Exfiltration Over Web Service",
        "T1568": "Dynamic Resolution",
        "T1569": "System Services",
        "T1570": "Lateral Tool Transfer",
        "T1571": "Non-Standard Port",
        "T1572": "Protocol Tunneling",
        "T1574": "Hijack Execution Flow",
        "T1580": "Cloud Infrastructure Discovery",
        "T1609": "Container Administration Command",
        "T1610": "Deploy Container",
        "T1611": "Escape to Host",
        "T1614": "System Location Discovery",
        "T1620": "Reflective Code Loading",
        "T1622": "Debugger Evasion",
    ]

    /// Normalize a tag/code to canonical form: "attack.t1059.004" → "T1059.004",
    /// "T1059" → "T1059". Returns nil when it isn't a technique code.
    public static func normalize(_ raw: String) -> String? {
        var s = raw.lowercased().trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("attack.") { s = String(s.dropFirst("attack.".count)) }
        guard s.hasPrefix("t") else { return nil }
        let body = s.dropFirst()
        let parts = body.split(separator: ".", omittingEmptySubsequences: false)
        guard let first = parts.first, !first.isEmpty, first.allSatisfy(\.isNumber) else { return nil }
        if parts.count == 1 { return "T\(first)" }
        guard parts.count == 2, !parts[1].isEmpty, parts[1].allSatisfy(\.isNumber) else { return nil }
        return "T\(first).\(parts[1])"
    }

    /// Parent technique of a normalized code ("T1059.004" → "T1059").
    public static func parent(_ normalizedCode: String) -> String {
        String(normalizedCode.split(separator: ".").first ?? Substring(normalizedCode))
    }

    /// Human technique name for a code (the parent-technique name), or nil.
    public static func name(forCode raw: String) -> String? {
        guard let code = normalize(raw) else { return nil }
        return parentNames[parent(code)]
    }

    /// Canonical attack.mitre.org URL for a code (mechanical — correct for any
    /// well-formed code, even one not in `parentNames`). nil if unparseable.
    public static func url(forCode raw: String) -> String? {
        guard let code = normalize(raw) else { return nil }
        let parts = code.dropFirst().split(separator: ".")   // drop the leading "T"
        if parts.count == 2 {
            return "https://attack.mitre.org/techniques/T\(parts[0])/\(parts[1])/"
        }
        return "https://attack.mitre.org/techniques/\(code)/"
    }

    /// "T1059.004 — Command and Scripting Interpreter", or the bare normalized
    /// code when the technique isn't in the map, or the raw input if unparseable.
    public static func display(forCode raw: String) -> String {
        guard let code = normalize(raw) else { return raw }
        if let n = parentNames[parent(code)] { return "\(code) — \(n)" }
        return code
    }
}
