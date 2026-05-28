// V2ForensicsWorkspace.swift
// MacCrabApp — v1.17 customer-shaped Forensics workspace per
// docs/forensics-ia-redesign-plan.md §3.
//
// Three tabs collapse the legacy five (Cases / Plugins / Tier B
// / Artifacts / Findings) into job-shaped surfaces:
//
//   Scans      — run / schedule / review a scan on this Mac
//   Plugins    — what scanners are available; install more
//   Evidence   — pull artifacts out for export / sharing
//
// The legacy `Investigation` workspace keeps its forensics tabs
// for v1.17, showing a "Moved to Forensics →" banner. v1.18
// removes those tabs entirely.

import SwiftUI

struct V2ForensicsWorkspace: View {
    @ObservedObject var state: V2DashboardState
    @ObservedObject var appState: AppState
    @State private var settingsOpen = false

    var body: some View {
        VStack(spacing: 0) {
            tabBar
            Divider()
            content
        }
        .sheet(isPresented: $settingsOpen) {
            V2ForensicsSettingsSheet(isPresented: $settingsOpen)
        }
    }

    private var tabBar: some View {
        HStack(spacing: 0) {
            ForEach(V2Workspace.forensics.tabs, id: \.self) { tab in
                Button {
                    state.selectedTabs[.forensics] = tab
                } label: {
                    Text(tab.title)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(currentTab == tab ? .primary : .secondary)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(
                            Rectangle()
                                .fill(Color.accentColor.opacity(currentTab == tab ? 0.12 : 0))
                        )
                        .overlay(
                            Rectangle()
                                .fill(currentTab == tab ? Color.accentColor : Color.clear)
                                .frame(height: 2)
                                .padding(.top, 28),
                            alignment: .bottom
                        )
                }
                .buttonStyle(.plain)
            }
            Spacer()
            Button {
                settingsOpen = true
            } label: {
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 10)
            }
            .buttonStyle(.plain)
            .help("Forensics settings")
        }
        .padding(.horizontal, 8)
    }

    private var currentTab: V2WorkspaceTab {
        state.selectedTabs[.forensics] ?? .forensicsScans
    }

    @ViewBuilder
    private var content: some View {
        switch currentTab {
        case .forensicsScans:
            V2ForensicsScansView(onShowAllScans: {
                state.selectedTabs[.forensics] = .forensicsPastScans
            })
        case .forensicsPastScans:
            V2ForensicsPastScansView()
        case .forensicsFindings:
            V2ForensicsFindingsView()
        case .forensicsCatalog:
            V2RaveCatalogBrowserView()
        default:
            V2ForensicsScansView(onShowAllScans: {
                state.selectedTabs[.forensics] = .forensicsPastScans
            })
        }
    }
}
