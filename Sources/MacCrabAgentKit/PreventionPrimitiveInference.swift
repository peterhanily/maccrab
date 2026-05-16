// PreventionPrimitiveInference.swift
// MacCrabAgentKit
//
// v1.12.0 — maps an enriched `Event` to the prevention-primitive label
// `CounterfactualReasoner` knows how to match. Used by EventLoop when
// a high-severity sequence rule fires so the single-step counterfactual
// has a meaningful primitive to lookup ("outbound TCP" / "LaunchAgent
// write" / etc.) rather than just the rule's name.

import Foundation
import MacCrabCore

/// Map an Event to the primitive string `CounterfactualReasoner.capability`
/// inspects (substring-matched there). Falls back to a generic process
/// label so the reasoner can still return a "no shipped capability"
/// narrative.
func inferPreventionPrimitive(from event: Event) -> String {
    switch event.eventCategory {
    case .network:
        let host = event.network?.destinationHostname?.lowercased() ?? ""
        if !host.isEmpty {
            return "outbound TCP to \(host)"
        }
        return "outbound TCP"
    case .file:
        let path = event.file?.path.lowercased() ?? ""
        if path.contains("/library/launchagents/") || path.contains("/library/launchdaemons/") {
            return "LaunchAgent write"
        }
        if path.hasSuffix(".plist") {
            return "plist write"
        }
        return "file write"
    case .process:
        let cmd = event.process.commandLine.lowercased()
        if cmd.contains("npm install") || cmd.contains("pnpm install") || cmd.contains("yarn add") {
            return "npm install"
        }
        if cmd.contains("pip install") || cmd.contains("pip3 install") || cmd.contains("uv pip install") {
            return "pip install"
        }
        if cmd.contains("brew install") {
            return "fresh package install"
        }
        return "process exec"
    default:
        return "uncategorized event"
    }
}

/// v1.12.0 — extract MITRE tactic values from a sequence/rule match's
/// `tags` array so `NextTechniquePredictor.predictNext` can forecast
/// the most-likely next tactic. Tags follow the SigmaHQ
/// `attack.<tactic>` convention; map them to the predictor's enum
/// values.
func inferTacticsFromMatch(_ match: RuleMatch) -> [NextTechniquePredictor.Tactic] {
    var out: [NextTechniquePredictor.Tactic] = []
    for tag in match.tags {
        let lower = tag.lowercased()
        if lower.contains("reconnaissance")           { out.append(.reconnaissance) }
        else if lower.contains("resource_development")     { out.append(.resourceDevelopment) }
        else if lower.contains("initial_access")           { out.append(.initialAccess) }
        else if lower.contains("execution")                { out.append(.execution) }
        else if lower.contains("persistence")              { out.append(.persistence) }
        else if lower.contains("privilege_escalation")     { out.append(.privilegeEscalation) }
        else if lower.contains("defense_evasion")          { out.append(.defenseEvasion) }
        else if lower.contains("credential_access")        { out.append(.credentialAccess) }
        else if lower.contains("discovery")                { out.append(.discovery) }
        else if lower.contains("lateral_movement")         { out.append(.lateralMovement) }
        else if lower.contains("collection")               { out.append(.collection) }
        else if lower.contains("command_and_control")     { out.append(.commandAndControl) }
        else if lower.contains("exfiltration")             { out.append(.exfiltration) }
        else if lower.contains("impact")                   { out.append(.impact) }
    }
    return out
}
