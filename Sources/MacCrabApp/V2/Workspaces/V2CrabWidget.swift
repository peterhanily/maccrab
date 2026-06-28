// V2CrabWidget.swift
// "Crabby" — a Tamagotchi-style virtual pet whose sprite is the rave.maccrab.com
// PIXEL CRAB (the exact 16×16 pixel art from the site's hero), drawn in a Canvas
// with a different FACE per mood. Health/mood track live posture (active
// campaigns). It's interactive: Pet him (a little heart pops), Acknowledge an
// alarm (he settles back down), or Investigate (jump to the campaign). Honors
// Reduce Motion (no dance). Pure SwiftUI — no assets.

import SwiftUI

struct V2CrabWidget: View {
    enum Mood { case happy, calm, alert, critical }

    let mood: Mood
    var criticalCampaigns: Int = 0
    var canAcknowledge: Bool = false
    var onAcknowledge: () -> Void = {}
    var onInvestigate: () -> Void = {}

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var petting = false

    /// rave accent — #ff5e3a.
    private static let crabOrange = Color(red: 1.0, green: 94.0 / 255.0, blue: 58.0 / 255.0)

    /// The crab body, lifted verbatim from the rave site's 16×16 hero SVG
    /// (rect x,y,w,h). Constant across moods — only the face changes.
    private static let body: [(Int, Int, Int, Int)] = [
        (1, 1, 3, 3), (0, 2, 1, 1), (4, 2, 1, 1), (2, 4, 2, 1),
        (12, 1, 3, 3), (11, 2, 1, 1), (15, 2, 1, 1), (12, 4, 2, 1),
        (6, 4, 1, 1), (9, 4, 1, 1),
        (4, 5, 8, 1), (3, 6, 10, 3), (4, 9, 8, 1),
        (2, 10, 1, 2), (5, 10, 1, 2), (10, 10, 1, 2), (13, 10, 1, 2),
        (1, 12, 1, 1), (4, 12, 1, 1), (11, 12, 1, 1), (14, 12, 1, 1),
    ]

    /// Per-mood face cells (x,y,w,h,color) drawn over the body. White eyes +
    /// black pupils/mouth/brows, stylised into a readable little expression.
    private func face(_ m: Mood) -> [(Int, Int, Int, Int, Color)] {
        let w = Color.white, k = Color.black
        if petting {
            // Smitten: happy eyes + big smile while being petted.
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (5, 8, 1, 1, k), (10, 8, 1, 1, k), (6, 9, 4, 1, k)]
        }
        switch m {
        case .happy:
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (5, 8, 1, 1, k), (10, 8, 1, 1, k), (6, 9, 4, 1, k)]   // bright eyes + U-smile
        case .calm:
            return [(5, 6, 2, 1, k), (9, 6, 2, 1, k),                      // sleepy/closed eyes
                    (7, 8, 2, 1, k)]                                       // tiny content mouth
        case .alert:
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (5, 5, 1, 1, k), (10, 5, 1, 1, k),                     // raised brows
                    (7, 8, 2, 1, k)]                                       // small "o"
        case .critical:
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (4, 5, 2, 1, k), (10, 5, 2, 1, k),                     // angry brows
                    (6, 8, 4, 1, k), (7, 9, 2, 1, k)]                      // open frown
        }
    }

    private var tint: Color {
        switch mood {
        case .critical: return .red
        case .alert: return .orange
        case .happy: return .green
        case .calm: return Self.crabOrange
        }
    }

    private var screenColor: Color {
        switch mood {
        case .critical: return Color(red: 0.99, green: 0.90, blue: 0.90)
        case .alert:    return Color(red: 0.99, green: 0.96, blue: 0.90)
        default:        return Color(red: 0.92, green: 0.96, blue: 0.92)
        }
    }

    private var hearts: Int {
        switch mood { case .happy: 3; case .calm: 3; case .alert: 2; case .critical: 1 }
    }

    private var moodLabel: String {
        if petting { return String(localized: "overview.crab.moodPetted", defaultValue: "loved") }
        switch mood {
        case .happy:    return String(localized: "overview.crab.moodHappy", defaultValue: "thriving")
        case .calm:     return String(localized: "overview.crab.moodCalm", defaultValue: "dozing")
        case .alert:    return String(localized: "overview.crab.moodAlert", defaultValue: "uneasy")
        case .critical: return String(localized: "overview.crab.moodCritical", defaultValue: "alarmed")
        }
    }

    private var statusText: String {
        if petting { return String(localized: "overview.crab.quipPetted", defaultValue: "♥ MacCrab loves the attention!") }
        switch mood {
        case .happy:    return String(localized: "overview.crab.quipHappy", defaultValue: "MacCrab is thriving — all clear! 🦀")
        case .calm:     return String(localized: "overview.crab.quipCalm", defaultValue: "MacCrab is dozing. Quiet on this Mac.")
        case .alert:    return String(localized: "overview.crab.quipAlert", defaultValue: "MacCrab is uneasy — watching closely.")
        case .critical: return String(localized: "overview.crab.quipCritical",
                                      defaultValue: "MacCrab is alarmed! \(criticalCampaigns) active critical campaign\(criticalCampaigns == 1 ? "" : "s").")
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
                    .foregroundStyle(petting ? .pink : tint)
                    .padding(.horizontal, 7).padding(.vertical, 2)
                    .background((petting ? Color.pink : tint).opacity(0.14))
                    .clipShape(Capsule())
            }

            device

            Text(statusText)
                .font(V2Theme.meta()).foregroundStyle(V2Theme.mutedText)
                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
        }
        .v2Panel()
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(String(localized: "overview.crab.title", defaultValue: "Crabby")))
        .accessibilityValue(Text("\(moodLabel). \(statusText)"))
    }

    private var device: some View {
        VStack(spacing: 8) {
            screen
            buttons
        }
        .padding(14)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 26, style: .continuous)
                .fill(LinearGradient(colors: [Self.crabOrange.opacity(0.95), Self.crabOrange.opacity(0.70)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
        )
        .overlay(RoundedRectangle(cornerRadius: 26, style: .continuous).stroke(Color.black.opacity(0.18), lineWidth: 1))
        .frame(maxWidth: 320)
        .frame(maxWidth: .infinity, alignment: .center)
    }

    private var screen: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12, style: .continuous).fill(screenColor)
            RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(Color.black.opacity(0.30), lineWidth: 2)

            // Heart meter (top-left).
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
            Ellipse().fill(Color.black.opacity(0.10)).frame(width: 52, height: 7).offset(y: -8)
            sprite.frame(width: 64, height: 64).offset(y: -6)
        }
    }

    private var crabCanvas: some View {
        Canvas { ctx, size in
            let s = min(size.width, size.height) / 16
            let ox = (size.width - 16 * s) / 2
            let oy = (size.height - 16 * s) / 2
            func cell(_ x: Int, _ y: Int, _ w: Int, _ h: Int, _ color: Color) {
                let r = CGRect(x: ox + CGFloat(x) * s, y: oy + CGFloat(y) * s,
                               width: CGFloat(w) * s, height: CGFloat(h) * s)
                ctx.fill(Path(r), with: .color(color))
            }
            for b in Self.body { cell(b.0, b.1, b.2, b.3, Self.crabOrange) }
            for f in face(petting ? .happy : mood) { cell(f.0, f.1, f.2, f.3, f.4) }
        }
    }

    @ViewBuilder
    private var sprite: some View {
        if reduceMotion {
            crabCanvas
        } else {
            TimelineView(.animation) { tl in
                let m = petTransform(at: tl.date.timeIntervalSinceReferenceDate)
                crabCanvas
                    .scaleEffect(petting ? 1.12 : 1.0)
                    .rotationEffect(.degrees(m.tilt))
                    .offset(x: m.shake, y: -m.bob)
                    .animation(.spring(response: 0.3), value: petting)
            }
        }
    }

    /// Idle motion per mood (kept out of the ViewBuilder closure).
    private func petTransform(at t: Double) -> (bob: CGFloat, shake: CGFloat, tilt: Double) {
        if petting { return (abs(sin(t * 6)) * 6, 0, sin(t * 6) * 8) }   // happy wiggle
        switch mood {
        case .happy:    return (abs(sin(t * 2.0)) * 6, 0, sin(t * 2.0) * 4)
        case .calm:     return (sin(t * 1.0) * 3, 0, sin(t * 0.8) * 2)
        case .alert:    return (sin(t * 2.4) * 4, 0, sin(t * 2.4) * 5)
        case .critical: return (0, sin(t * 12) * 3, sin(t * 12) * 4)
        }
    }

    // Three real device buttons: Pet · Acknowledge · Investigate.
    private var buttons: some View {
        HStack(spacing: 16) {
            deviceButton("hand.tap.fill",
                         help: String(localized: "overview.crab.pet", defaultValue: "Pet Crabby")) {
                petting = true
                Task { try? await Task.sleep(for: .seconds(1.4)); petting = false }
            }
            deviceButton("checkmark.circle.fill",
                         help: String(localized: "overview.crab.acknowledge", defaultValue: "Acknowledge — settle Crabby"),
                         enabled: canAcknowledge,
                         action: onAcknowledge)
            deviceButton("magnifyingglass",
                         help: String(localized: "overview.crab.investigate", defaultValue: "Investigate campaigns"),
                         action: onInvestigate)
        }
        .padding(.bottom, 2)
    }

    private func deviceButton(_ icon: String, help: String, enabled: Bool = true, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .scaledSystem(11, weight: .semibold)
                .foregroundStyle(.white)
                .frame(width: 24, height: 24)
                .background(Color.black.opacity(enabled ? 0.22 : 0.08))
                .clipShape(Circle())
                .overlay(Circle().stroke(Color.white.opacity(0.25), lineWidth: 1))
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.45)
        .help(help)
    }
}
