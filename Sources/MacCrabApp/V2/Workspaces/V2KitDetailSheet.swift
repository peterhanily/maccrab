// V2KitDetailSheet.swift
//
// rc.11 — "How it works" sheet for a forensic kit. Opens when
// the operator taps the info button on a kit card. Explains:
//   - What this kit is for (kit.description)
//   - Whether it's encrypted (with explanation)
//   - For each scanner: purpose, data sources, TCC requirements,
//     content types emitted, privacy class
//
// Source data: ScannerCatalog.swift + Kit.swift + ScannerDisplay.

import SwiftUI

struct V2KitDetailSheet: View {
    let kit: Kit
    @Binding var isPresented: Bool
    /// Called when the operator taps Run from inside the sheet.
    let onRun: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    kitOverview
                    if kit.encrypted {
                        encryptedNotice
                    }
                    scannerList
                }
                .padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 720, height: 600)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: kit.category.sfSymbol)
                .scaledSystem(22)
                .foregroundStyle(.tint)
                .padding(8)
                .background(Color.accentColor.opacity(0.12))
                .cornerRadius(8)
                .accessibilityHidden(true) // decorative — title text follows
            VStack(alignment: .leading, spacing: 2) {
                Text(kit.name).font(.title3).fontWeight(.semibold)
                HStack(spacing: 6) {
                    Text(kit.category.displayName)
                        .scaledSystem(11)
                        .foregroundStyle(.secondary)
                    if kit.encrypted {
                        Label("Encrypted", systemImage: "lock.fill")
                            .labelStyle(.titleAndIcon)
                            .scaledSystem(10, weight: .medium)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.purple.opacity(0.15))
                            .foregroundStyle(.purple)
                            .cornerRadius(3)
                    }
                }
            }
            Spacer()
            Button("Close") { isPresented = false }
                .keyboardShortcut(.cancelAction)
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    // MARK: - Overview

    private var kitOverview: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("What this kit does")
                .scaledSystem(10, weight: .semibold)
                .foregroundStyle(.tertiary)
                .textCase(.uppercase)
            Text(kit.description)
                .scaledSystem(13)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var encryptedNotice: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.fill")
                .foregroundStyle(.purple)
            VStack(alignment: .leading, spacing: 4) {
                Text("Encrypted scan")
                    .scaledSystem(12, weight: .semibold)
                Text("Some scanners in this kit extract personal data (messages, mail, call history). MacCrab stores those rows encrypted on disk and asks for your Keychain password once to unlock the encryption key. The plaintext data never leaves your Mac.")
                    .scaledSystem(11)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.purple.opacity(0.08))
        .cornerRadius(8)
    }

    // MARK: - Scanner list

    private var scannerList: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Scanners in this kit (\(kit.plugins.count))")
                .scaledSystem(10, weight: .semibold)
                .foregroundStyle(.tertiary)
                .textCase(.uppercase)
            ForEach(kit.plugins, id: \.pluginID) { ref in
                scannerCard(ref)
            }
        }
    }

    private func scannerCard(_ ref: Kit.PluginRef) -> some View {
        let fact = ScannerCatalog.fact(forPluginID: ref.pluginID)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(ScannerDisplay.name(forPluginID: ref.pluginID))
                    .scaledSystem(13, weight: .semibold)
                if !ref.required {
                    Text("Optional")
                        .scaledSystem(9, weight: .medium)
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15))
                        .foregroundStyle(.secondary)
                        .cornerRadius(3)
                }
                Spacer()
                Text(ref.pluginID)
                    .scaledSystem(9, design: .monospaced)
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
            }
            if let fact {
                Text(fact.purpose)
                    .scaledSystem(12)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                detailRow("Reads", fact.dataSources)
                if !fact.tccRequirements.isEmpty {
                    detailRow("Needs", fact.tccRequirements)
                }
                detailRow("Emits", fact.emits.map { ScannerDisplay.name(forContentType: $0) })
                HStack(spacing: 4) {
                    Image(systemName: fact.privacyClass == .metadata ? "checkmark.shield" : "lock.fill")
                        .scaledSystem(9)
                        .foregroundStyle(fact.privacyClass == .metadata ? .green : .purple)
                    Text(fact.privacyClass.label)
                        .scaledSystem(10)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 2)
            } else {
                Text("\(ref.role)")
                    .scaledSystem(12)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Detailed reference not yet documented — see the plugin manifest.")
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
                    .italic()
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }

    private func detailRow(_ label: String, _ values: [String]) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(.tertiary)
                .frame(width: 50, alignment: .trailing)
            VStack(alignment: .leading, spacing: 1) {
                ForEach(values, id: \.self) { v in
                    Text(v)
                        .scaledSystem(11)
                        .foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Text("\(kit.plugins.count) scanner\(kit.plugins.count == 1 ? "" : "s") · v\(kit.version) · \(kit.maintainer)")
                .scaledSystem(11)
                .foregroundStyle(.tertiary)
            Spacer()
            Button("Run this kit") {
                isPresented = false
                onRun()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
    }
}
