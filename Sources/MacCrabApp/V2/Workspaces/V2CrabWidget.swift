// V2CrabWidget.swift
// "Crabby" — a Tamagotchi-style virtual pet on the Overview. A little handheld
// device with an LCD screen; the pet IS the MacCrab logo (the app icon, i.e.
// the maccrab.com crab). Its wellbeing tracks your live posture: thriving and
// dozing when safe, uneasy on an active campaign, alarmed on a critical one —
// shown via a bob/shake, a reaction glyph, a heart meter, and a status line.
// Pure SwiftUI + AppKit (no new assets). Honors Reduce Motion (static pet).

import SwiftUI
import AppKit

struct V2CrabWidget: View {
    enum Mood { case happy, calm, alert, critical }

    let mood: Mood
    var openAlerts: Int = 0
    var criticalCampaigns: Int = 0

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// The brand crab: the running app's icon (maccrab.com logo).
    private let petImage = NSApplication.shared.applicationIconImage

    private var tint: Color {
        switch mood {
        case .critical: return .red
        case .alert: return .orange
        case .happy: return .green
        case .calm: return Color(red: 0.95, green: 0.46, blue: 0.20)   // crab orange
        }
    }

    /// LCD background — a faint retro tint that flashes redder when alarmed.
    private var screenColor: Color {
        switch mood {
        case .critical: return Color(red: 0.99, green: 0.90, blue: 0.90)
        case .alert:    return Color(red: 0.99, green: 0.96, blue: 0.90)
        default:        return Color(red: 0.92, green: 0.96, blue: 0.92)   // pale LCD green
        }
    }

    /// Filled hearts (of 3) — Crabby's "health" drains as threats rise.
    private var hearts: Int {
        switch mood {
        case .happy: return 3
        case .calm: return 3
        case .alert: return 2
        case .critical: return 1
        }
    }

    private var reactionGlyph: String {
        switch mood {
        case .happy: return "😎"
        case .calm: return "💤"
        case .alert: return "❓"
        case .critical: return "❗"
        }
    }

    private var moodLabel: String {
        switch mood {
        case .happy:    return String(localized: "overview.crab.moodHappy", defaultValue: "thriving")
        case .calm:     return String(localized: "overview.crab.moodCalm", defaultValue: "dozing")
        case .alert:    return String(localized: "overview.crab.moodAlert", defaultValue: "uneasy")
        case .critical: return String(localized: "overview.crab.moodCritical", defaultValue: "alarmed")
        }
    }

    private var statusText: String {
        switch mood {
        case .happy:
            return String(localized: "overview.crab.quipHappy", defaultValue: "MacCrab is thriving — all clear! 🦀")
        case .calm:
            return String(localized: "overview.crab.quipCalm", defaultValue: "MacCrab is dozing. Quiet on this Mac.")
        case .alert:
            return String(localized: "overview.crab.quipAlert", defaultValue: "MacCrab is uneasy — watching closely.")
        case .critical:
            return String(localized: "overview.crab.quipCritical",
                          defaultValue: "MacCrab is alarmed! \(criticalCampaigns) active critical campaign\(criticalCampaigns == 1 ? "" : "s")!")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Text(String(localized: "overview.crab.title", defaultValue: "Crabby"))
                    .font(V2Theme.sectionTitle()).foregroundStyle(V2Theme.primaryText)
                Spacer()
                Text(moodLabel.uppercased())
                    .font(V2Theme.meta()).fontWeight(.semibold)
                    .foregroundStyle(tint)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background(tint.opacity(0.14))
                    .clipShape(Capsule())
            }

            device

            Text(statusText)
                .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
        }
        .v2Panel()
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(String(localized: "overview.crab.title", defaultValue: "Crabby")))
        .accessibilityValue(Text("\(moodLabel). \(statusText)"))
    }

    // The handheld shell: an egg-shaped orange device with an LCD screen,
    // a heart meter, and three decorative buttons.
    private var device: some View {
        VStack(spacing: 8) {
            screen
            HStack(spacing: 14) {
                ForEach(0..<3, id: \.self) { _ in
                    Circle()
                        .fill(Color.black.opacity(0.18))
                        .frame(width: 10, height: 10)
                        .overlay(Circle().stroke(Color.white.opacity(0.25), lineWidth: 1))
                }
            }
            .padding(.bottom, 2)
        }
        .padding(14)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 26, style: .continuous)
                .fill(LinearGradient(
                    colors: [tint.opacity(0.95), tint.opacity(0.70)],
                    startPoint: .topLeading, endPoint: .bottomTrailing))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 26, style: .continuous)
                .stroke(Color.black.opacity(0.18), lineWidth: 1)
        )
        .frame(maxWidth: 320)
        .frame(maxWidth: .infinity, alignment: .center)
    }

    private var screen: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12, style: .continuous).fill(screenColor)
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.black.opacity(0.30), lineWidth: 2)

            // Reaction glyph, top-right inside the screen.
            VStack {
                HStack {
                    Spacer()
                    Text(reactionGlyph).font(.system(size: 16))
                }
                Spacer()
            }
            .padding(8)

            // Heart meter, top-left.
            VStack {
                HStack(spacing: 2) {
                    ForEach(0..<3, id: \.self) { i in
                        Image(systemName: i < hearts ? "heart.fill" : "heart")
                            .scaledSystem(9)
                            .foregroundStyle(i < hearts ? Color.red : Color.black.opacity(0.25))
                    }
                    Spacer()
                }
                Spacer()
            }
            .padding(8)

            pet
        }
        .frame(height: 104)
    }

    private var pet: some View {
        ZStack(alignment: .bottom) {
            // little ground shadow
            Ellipse().fill(Color.black.opacity(0.10))
                .frame(width: 56, height: 8)
                .offset(y: -10)
            sprite
        }
    }

    /// The pet glyph: the MacCrab app icon (logo), or 🦀 if the icon is
    /// unavailable (e.g. an unbundled dev run).
    @ViewBuilder
    private var petGlyph: some View {
        if let petImage {
            Image(nsImage: petImage)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: 60, height: 60)
                .offset(y: -10)
        } else {
            Text(verbatim: "🦀")
                .font(.system(size: 46))
                .offset(y: -10)
        }
    }

    @ViewBuilder
    private var sprite: some View {
        if reduceMotion {
            petGlyph
        } else {
            TimelineView(.animation) { tl in
                let m = petTransform(at: tl.date.timeIntervalSinceReferenceDate)
                petGlyph
                    .rotationEffect(.degrees(m.tilt))
                    .offset(x: m.shake, y: -m.bob)
            }
        }
    }

    /// Idle motion per mood (kept OUT of the ViewBuilder closure so the `switch`
    /// isn't parsed as view content). Gentle breathing bob; a livelier hop when
    /// happy; a quick worried shake when critical — all deliberately soft.
    private func petTransform(at t: Double) -> (bob: CGFloat, shake: CGFloat, tilt: Double) {
        switch mood {
        case .happy:    return (abs(sin(t * 2.0)) * 7, 0, sin(t * 2.0) * 4)
        case .calm:     return (sin(t * 1.0) * 3, 0, sin(t * 0.8) * 2)
        case .alert:    return (sin(t * 2.4) * 4, 0, sin(t * 2.4) * 5)
        case .critical: return (0, sin(t * 12) * 3, sin(t * 12) * 4)
        }
    }
}
