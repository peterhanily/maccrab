// RuleTranslations.swift
// MacCrabApp
//
// Translates rule titles and descriptions for display.
// Sigma rules stay in English (community standard) — this layer
// provides localized display text at the UI level.

import Foundation

/// Provides localized display text for detection rule categories and common terms.
/// Individual rules use their English titles with category/severity translated.
enum RuleTranslations {

    /// Translate a MITRE ATT&CK tactic name for display.
    static func translateTactic(_ tactic: String) -> String {
        switch tactic.lowercased().replacingOccurrences(of: "attack.", with: "") {
        case "initial_access":
            return String(localized: "mitre.initial_access", defaultValue: "Initial Access")
        case "execution":
            return String(localized: "mitre.execution", defaultValue: "Execution")
        case "persistence":
            return String(localized: "mitre.persistence", defaultValue: "Persistence")
        case "privilege_escalation":
            return String(localized: "mitre.privilege_escalation", defaultValue: "Privilege Escalation")
        case "defense_evasion":
            return String(localized: "mitre.defense_evasion", defaultValue: "Defense Evasion")
        case "credential_access":
            return String(localized: "mitre.credential_access", defaultValue: "Credential Access")
        case "discovery":
            return String(localized: "mitre.discovery", defaultValue: "Discovery")
        case "lateral_movement":
            return String(localized: "mitre.lateral_movement", defaultValue: "Lateral Movement")
        case "collection":
            return String(localized: "mitre.collection", defaultValue: "Collection")
        case "command_and_control":
            return String(localized: "mitre.command_and_control", defaultValue: "Command & Control")
        case "exfiltration":
            return String(localized: "mitre.exfiltration", defaultValue: "Exfiltration")
        default:
            return tactic
        }
    }

    /// Translate a rule category directory name for display.
    static func translateCategory(_ category: String) -> String {
        switch category.lowercased() {
        case "execution": return String(localized: "category.execution", defaultValue: "Execution")
        case "persistence": return String(localized: "category.persistence", defaultValue: "Persistence")
        case "defense_evasion": return String(localized: "category.defense_evasion", defaultValue: "Defense Evasion")
        case "credential_access": return String(localized: "category.credential_access", defaultValue: "Credential Access")
        case "command_and_control": return String(localized: "category.command_and_control", defaultValue: "Command & Control")
        case "discovery": return String(localized: "category.discovery", defaultValue: "Discovery")
        case "collection": return String(localized: "category.collection", defaultValue: "Collection")
        case "privilege_escalation": return String(localized: "category.privilege_escalation", defaultValue: "Privilege Escalation")
        case "exfiltration": return String(localized: "category.exfiltration", defaultValue: "Exfiltration")
        case "initial_access": return String(localized: "category.initial_access", defaultValue: "Initial Access")
        case "lateral_movement": return String(localized: "category.lateral_movement", defaultValue: "Lateral Movement")
        case "tcc": return String(localized: "category.tcc", defaultValue: "TCC Permissions")
        case "ai_safety": return String(localized: "category.ai_safety", defaultValue: "AI Safety")
        case "supply_chain": return String(localized: "category.supply_chain", defaultValue: "Supply Chain")
        case "sequences": return String(localized: "category.sequences", defaultValue: "Attack Sequences")
        default: return category
        }
    }

    /// Translate a severity level for display.
    static func translateSeverity(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return String(localized: "severity.critical", defaultValue: "Critical")
        case "high": return String(localized: "severity.high", defaultValue: "High")
        case "medium": return String(localized: "severity.medium", defaultValue: "Medium")
        case "low": return String(localized: "severity.low", defaultValue: "Low")
        case "informational": return String(localized: "severity.informational", defaultValue: "Informational")
        default: return severity
        }
    }

    /// Translate common alert action descriptions.
    static func translateAction(_ action: String) -> String {
        switch action.lowercased() {
        case "exec": return String(localized: "action.exec", defaultValue: "Process Executed")
        case "fork": return String(localized: "action.fork", defaultValue: "Process Forked")
        case "exit": return String(localized: "action.exit", defaultValue: "Process Exited")
        case "create": return String(localized: "action.create", defaultValue: "File Created")
        case "write": return String(localized: "action.write", defaultValue: "File Written")
        case "rename": return String(localized: "action.rename", defaultValue: "File Renamed")
        case "unlink": return String(localized: "action.unlink", defaultValue: "File Deleted")
        case "connect": return String(localized: "action.connect", defaultValue: "Network Connection")
        case "close_modified": return String(localized: "action.close_modified", defaultValue: "File Modified")
        case "kextload": return String(localized: "action.kextload", defaultValue: "Kernel Extension Loaded")
        case "mmap_wx": return String(localized: "action.mmap_wx", defaultValue: "Writable+Executable Memory")
        case "setowner": return String(localized: "action.setowner", defaultValue: "Ownership Changed")
        case "setmode": return String(localized: "action.setmode", defaultValue: "Permissions Changed")
        default:
            if action.hasPrefix("signal(") {
                return String(localized: "action.signal", defaultValue: "Signal Sent")
            }
            return action
        }
    }
}
