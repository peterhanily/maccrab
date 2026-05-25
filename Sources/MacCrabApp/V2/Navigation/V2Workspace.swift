// V2Workspace.swift
// MacCrabApp — Dashboard v2
//
// The 7-workspace IA per spec §13. Sidebar is fixed; tabs live
// inside workspaces. New capabilities land as tabs / panels /
// command-palette destinations, not new sidebar entries.

import SwiftUI

public enum V2Workspace: String, CaseIterable, Identifiable, Hashable, Codable, Sendable {
    case overview
    case alerts
    case events
    case investigation
    case forensics
    case detection
    case prevention
    case intelligence
    case system
    case docs

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview:      return String(localized: "workspace.overview.title",      defaultValue: "Overview")
        case .alerts:        return String(localized: "workspace.alerts.title",        defaultValue: "Alerts")
        case .events:        return String(localized: "workspace.events.title",        defaultValue: "Events")
        case .investigation: return String(localized: "workspace.investigation.title", defaultValue: "Investigation")
        case .forensics:     return String(localized: "workspace.forensics.title",     defaultValue: "Forensics")
        case .detection:     return String(localized: "workspace.detection.title",     defaultValue: "Detection")
        case .prevention:    return String(localized: "workspace.prevention.title",    defaultValue: "Prevention")
        case .intelligence:  return String(localized: "workspace.intelligence.title",  defaultValue: "Intelligence")
        case .system:        return String(localized: "workspace.system.title",        defaultValue: "System")
        case .docs:          return String(localized: "workspace.docs.title",          defaultValue: "Docs")
        }
    }

    public var systemImage: String {
        switch self {
        case .overview:      return "gauge.with.dots.needle.50percent"
        case .alerts:        return "bell.fill"
        case .events:        return "list.bullet.rectangle"
        case .investigation: return "magnifyingglass"
        case .forensics:     return "doc.text.magnifyingglass"
        case .detection:     return "shield.lefthalf.filled"
        case .prevention:    return "bolt.shield.fill"
        case .intelligence:  return "globe.americas.fill"
        case .system:        return "gearshape.fill"
        case .docs:          return "book.closed.fill"
        }
    }

    public var subtitle: String {
        switch self {
        case .overview:      return "At-a-glance system posture and shortcuts"
        case .alerts:        return "Triage and route findings"
        case .events:        return "Live event stream — filter, search, and drill in"
        case .investigation: return "Trace graph and AI analysis (Forensics moved to its own workspace)"
        case .forensics:     return "Scan this Mac, browse plugins, export evidence"
        case .detection:     return "Rules, AI Guard, browser, and MCP"
        case .prevention:    return "DNS sinkhole, network blocker, persistence guard, response actions"
        case .intelligence:  return "IOC context, feeds, packages, and integrations"
        case .system:        return "Platform health, permissions, trust, and settings"
        case .docs:          return "Embedded reference and onboarding"
        }
    }

    /// ⌘1-⌘7 indices.
    public var keyboardIndex: Int {
        (V2Workspace.allCases.firstIndex(of: self) ?? 0) + 1
    }

    public var tabs: [V2WorkspaceTab] {
        switch self {
        case .overview:      return []
        case .alerts:        return [.alertsOpen, .alertsCampaigns, .alertsHistory, .alertsSuppressions]
        case .events:        return []
        case .investigation: return [.investigationTraceGraph, .investigationAgentTraces,
                                     .investigationAIAnalysis,
                                     .investigationForensicsCases,
                                     .investigationForensicsPlugins,
                                     .investigationForensicsArtifacts,
                                     .investigationForensicsFindings]
        case .forensics:     return [.forensicsScans,
                                     .forensicsFindings]
        case .detection:     return [.detectionRules, .detectionAIGuard, .detectionBrowser,
                                     .detectionMCP]
        case .prevention:    return []
        case .intelligence:  return [.intelligenceThreatIntel, .intelligencePackageFreshness,
                                     .intelligenceIntegrations]
        case .system:        return [.systemHealth, .systemPermissions, .systemSettings]
        case .docs:          return [.docsBrowser]
        }
    }

    public var defaultTab: V2WorkspaceTab? { tabs.first }
}

// MARK: - V2WorkspaceTab

public enum V2WorkspaceTab: String, CaseIterable, Identifiable, Hashable, Codable, Sendable {
    // Alerts
    case alertsOpen
    case alertsCampaigns
    case alertsHistory
    case alertsSuppressions

    // Investigation
    case investigationTraceGraph
    case investigationAgentTraces
    case investigationAIAnalysis

    // Investigation → Forensics (v1.13b — Mac Context Plugin Platform).
    // v1.17: legacy tabs — show "Moved to Forensics →" redirect
    // banner. New work lives under the .forensics workspace tabs.
    case investigationForensicsCases
    case investigationForensicsPlugins
    case investigationForensicsArtifacts
    case investigationForensicsFindings

    // v1.17 rc.4 — customer-shaped Forensics workspace per
    // docs/forensics-rebuild-2026-05-25.md. Two tabs:
    //   forensicsScans     kit-driven scan flow (was: Cases + Plugins + Evidence)
    //   forensicsFindings  actionable findings feed across all scans
    case forensicsScans
    case forensicsFindings

    // Detection
    case detectionRules
    case detectionAIGuard
    case detectionBrowser
    case detectionMCP

    // Intelligence
    case intelligenceThreatIntel
    case intelligencePackageFreshness
    case intelligenceIntegrations

    // System
    case systemHealth
    case systemPermissions
    case systemSettings

    // Docs
    case docsBrowser

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .alertsOpen:                     return String(localized: "workspaceTab.alerts.open",                  defaultValue: "Open")
        case .alertsCampaigns:                return String(localized: "workspaceTab.alerts.campaigns",             defaultValue: "Campaigns")
        case .alertsHistory:                  return String(localized: "workspaceTab.alerts.history",               defaultValue: "History")
        case .alertsSuppressions:             return String(localized: "workspaceTab.alerts.suppressions",          defaultValue: "Suppressions")
        case .investigationTraceGraph:        return String(localized: "workspaceTab.investigation.traceGraph",     defaultValue: "TraceGraph")
        case .investigationAgentTraces:       return String(localized: "workspaceTab.investigation.agentTraces",    defaultValue: "Agent Traces")
        case .investigationAIAnalysis:        return String(localized: "workspaceTab.investigation.aiAnalysis",     defaultValue: "AI Analysis")
        case .investigationForensicsCases:    return String(localized: "workspaceTab.investigation.forensicsCases", defaultValue: "Forensics · Cases")
        case .investigationForensicsPlugins:  return String(localized: "workspaceTab.investigation.forensicsPlugins", defaultValue: "Forensics · Plugins")
        case .forensicsScans:                 return String(localized: "workspaceTab.forensics.scans",    defaultValue: "Scans")
        case .forensicsFindings:              return String(localized: "workspaceTab.forensics.findings", defaultValue: "Findings")
        case .investigationForensicsArtifacts: return String(localized: "workspaceTab.investigation.forensicsArtifacts", defaultValue: "Forensics · Artifacts")
        case .investigationForensicsFindings: return String(localized: "workspaceTab.investigation.forensicsFindings", defaultValue: "Forensics · Findings")
        case .detectionRules:                 return String(localized: "workspaceTab.detection.rules",              defaultValue: "Rules")
        case .detectionAIGuard:               return String(localized: "workspaceTab.detection.aiGuard",            defaultValue: "AI Guard")
        case .detectionBrowser:               return String(localized: "workspaceTab.detection.browser",            defaultValue: "Browser")
        case .detectionMCP:                   return String(localized: "workspaceTab.detection.mcp",                defaultValue: "MCP")
        case .intelligenceThreatIntel:        return String(localized: "workspaceTab.intelligence.threatIntel",     defaultValue: "Threat Intel")
        case .intelligencePackageFreshness:   return String(localized: "workspaceTab.intelligence.packageFreshness", defaultValue: "Package Freshness")
        case .intelligenceIntegrations:       return String(localized: "workspaceTab.intelligence.integrations",    defaultValue: "Integrations")
        case .systemHealth:                   return String(localized: "workspaceTab.system.health",                defaultValue: "Health")
        case .systemPermissions:              return String(localized: "workspaceTab.system.permissions",           defaultValue: "Permissions")
        case .systemSettings:                 return String(localized: "workspaceTab.system.settings",              defaultValue: "Settings")
        case .docsBrowser:                    return String(localized: "workspaceTab.docs.browser",                 defaultValue: "Docs")
        }
    }

    public var workspace: V2Workspace {
        switch self {
        case .alertsOpen, .alertsCampaigns, .alertsHistory, .alertsSuppressions:
            return .alerts
        case .investigationTraceGraph, .investigationAgentTraces,
             .investigationAIAnalysis,
             .investigationForensicsCases, .investigationForensicsPlugins,
             .investigationForensicsArtifacts, .investigationForensicsFindings:
            return .investigation
        case .forensicsScans, .forensicsFindings:
            return .forensics
        case .detectionRules, .detectionAIGuard, .detectionBrowser,
             .detectionMCP:
            return .detection
        case .intelligenceThreatIntel, .intelligencePackageFreshness, .intelligenceIntegrations:
            return .intelligence
        case .systemHealth, .systemPermissions, .systemSettings:
            return .system
        case .docsBrowser:
            return .docs
        }
    }
}

// MARK: - V2NavigationDestination

/// A deep-link target — workspace + optional tab + optional entity
/// + optional pre-applied filters. Spec §3.5 + §3.6.
public struct V2NavigationDestination: Sendable, Equatable {
    public let workspace: V2Workspace
    public let tab: V2WorkspaceTab?
    public let entityId: String?
    public let filters: [String: String]

    public init(
        workspace: V2Workspace,
        tab: V2WorkspaceTab? = nil,
        entityId: String? = nil,
        filters: [String: String] = [:]
    ) {
        self.workspace = workspace
        self.tab = tab
        self.entityId = entityId
        self.filters = filters
    }
}
