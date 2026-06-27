// V2CrabWidget.swift
// "Crabby" — the MacCrab mascot as an Overview widget. He scuttles across the
// card and reacts to live posture: idle when quiet, looking around on alerts,
// claws-up panic on a critical campaign, a happy bob when all-clear. Pure
// SwiftUI (the 🦀 glyph + a TimelineView), no assets. Honors Reduce Motion
// (static crab + the quip). Reads only counts passed in — no data plumbing.

import SwiftUI

struct V2CrabWidget: View {
    enum Mood { case happy, calm, alert, critical }

    let mood: Mood
    var openAlerts: Int = 0
    var criticalCampaigns: Int = 0

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Scuttle speed (radians/sec-ish) — calmer when safe, frantic on critical.
    private var speed: Double {
        switch mood {
        case .calm: return 0.6
        case .happy: return 1.1
        case .alert: return 1.8
        case .critical: return 3.2
        }
    }

    /// MacCrab-orange by default; shifts to the severity colour with the mood.
    private var tint: Color {
        switch mood {
        case .critical: return .red
        case .alert: return .orange
        case .happy: return .green
        case .calm: return Color(red: 0.95, green: 0.46, blue: 0.20)   // crab orange
        }
    }

    private var moodLabel: String {
        switch mood {
        case .happy:    return String(localized: "overview.crab.moodHappy", defaultValue: "happy")
        case .calm:     return String(localized: "overview.crab.moodCalm", defaultValue: "calm")
        case .alert:    return String(localized: "overview.crab.moodAlert", defaultValue: "watching")
        case .critical: return String(localized: "overview.crab.moodCritical", defaultValue: "panic")
        }
    }

    private var quip: String {
        switch mood {
        case .happy:
            return String(localized: "overview.crab.quipHappy", defaultValue: "All clear! Nothing to pinch here. 🦀")
        case .calm:
            return String(localized: "overview.crab.quipCalm", defaultValue: "Just scuttling about. Quiet on this Mac so far…")
        case .alert:
            return String(localized: "overview.crab.quipAlert",
                          defaultValue: "Ooh — \(openAlerts) open alert\(openAlerts == 1 ? "" : "s"). Keeping my eyestalks up.")
        case .critical:
            return String(localized: "overview.crab.quipCritical",
                          defaultValue: "🚨 \(criticalCampaigns) critical campaign\(criticalCampaigns == 1 ? "" : "s")! CLAWS UP! 🦀")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
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
            scene
            Text(quip)
                .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
        }
        .v2Panel()
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(String(localized: "overview.crab.title", defaultValue: "Crabby")))
        .accessibilityValue(Text("\(moodLabel). \(quip)"))
    }

    private var scene: some View {
        ZStack(alignment: .bottom) {
            // A faint sandy floor so Crabby has somewhere to scuttle.
            Capsule()
                .fill(tint.opacity(0.10))
                .frame(height: 6)
                .padding(.horizontal, 10)
                .padding(.bottom, 4)

            GeometryReader { geo in
                let w = geo.size.width
                let amp = max(16, (w - 64) / 2)
                Group {
                    if reduceMotion {
                        crab.frame(width: w, alignment: .center)
                    } else {
                        TimelineView(.animation) { tl in
                            let t = tl.date.timeIntervalSinceReferenceDate
                            let x = sin(t * speed) * amp
                            let facing: CGFloat = cos(t * speed) >= 0 ? 1 : -1   // face travel direction
                            let bob = mood == .happy ? abs(sin(t * 5)) * 9 : 0
                            let shake = mood == .critical ? sin(t * 34) * 3.5 : 0
                            let tilt = sin(t * speed * 2) * (mood == .calm ? 4 : 9)
                            crab
                                .scaleEffect(x: facing, y: 1, anchor: .center)
                                .rotationEffect(.degrees(tilt))
                                .offset(x: x + shake, y: -bob)
                                .frame(width: w, alignment: .center)
                        }
                    }
                }
                .frame(height: geo.size.height, alignment: .bottom)
            }
        }
        .frame(height: 66)
    }

    private var crab: some View {
        Text(verbatim: "🦀")
            .font(.system(size: 38))
            // A soft halo in the mood colour — subtle "aura" that turns red on panic.
            .shadow(color: tint.opacity(mood == .calm ? 0.0 : 0.5), radius: 6)
    }
}
