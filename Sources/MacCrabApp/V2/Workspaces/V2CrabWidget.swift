// V2CrabWidget.swift
// "Crabby" — a Tamagotchi-style EDR companion. The pet is the rave.maccrab.com
// 16×16 PIXEL CRAB (drawn in a Canvas), living in a little scene that reflects
// the Mac's live security state:
//   • weather sky   — clear / cloudy / storm by threat level
//   • event terrain — a tiny hill of the last-8 event buckets he stands on
//   • liveliness    — his bob speeds up with the live event rate
//   • mood beacon    — an antenna bulb (green/orange/red) over his head
//   • AI sidekick    — a little robot appears when an AI agent is active
//   • coverage shield— a shield when protection is healthy
//   • offline        — greyscale + asleep when the engine is disconnected
//   • ambient        — idle blink + a slow breathing sway
// Interactive: Pet (hearts), Feed (a crumb he snaps), Acknowledge (settle an
// alarm), Investigate (jump to the campaign). Pure SwiftUI; Reduce-Motion safe.

import SwiftUI

struct V2CrabWidget: View {
    enum Mood { case happy, calm, alert, critical }

    let mood: Mood
    var criticalCampaigns: Int = 0
    var canAcknowledge: Bool = false
    var eventRate: Double = 0
    var eventBuckets: [Double] = []
    var aiActive: Bool = false
    var protectionHealthy: Bool = false
    var connected: Bool = true
    /// Changes whenever a new alert arrives — drives the one-shot "snap".
    var alertToken: String = ""
    var onAcknowledge: () -> Void = {}
    var onInvestigate: () -> Void = {}
    var onFeed: () -> Void = {}

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.scenePhase) private var scenePhase
    @State private var petting = false
    @State private var feeding = false
    @State private var snapAt: Date? = nil

    // MARK: palette
    private static let crabOrange = Color(red: 1.0, green: 94.0 / 255.0, blue: 58.0 / 255.0)
    private static let aiBlue = Color(red: 96.0 / 255.0, green: 165.0 / 255.0, blue: 250.0 / 255.0)
    private static let shieldGreen = Color(red: 74.0 / 255.0, green: 222.0 / 255.0, blue: 128.0 / 255.0)
    private static let grey = Color(white: 0.55)

    /// Crab body colour — orange normally, grey when the engine is offline.
    private var bodyColor: Color { connected ? Self.crabOrange : Self.grey }

    /// Effective mood for the FACE/scene: offline forces a sleepy grey state.
    private var shownMood: Mood { connected ? mood : .calm }

    private var tint: Color {
        if !connected { return Self.grey }
        switch mood {
        case .critical: return .red
        case .alert: return .orange
        case .happy: return .green
        case .calm: return Self.crabOrange
        }
    }

    private var screenColor: Color {
        if !connected { return Color(white: 0.82) }
        switch mood {
        case .critical: return Color(red: 0.99, green: 0.90, blue: 0.90)
        case .alert:    return Color(red: 0.99, green: 0.96, blue: 0.90)
        default:        return Color(red: 0.92, green: 0.96, blue: 0.92)
        }
    }

    private var hearts: Int {
        if !connected { return 0 }
        switch mood {
        case .happy: return 3
        case .calm: return 3
        case .alert: return 2
        case .critical: return 1
        }
    }

    private var moodLabel: String {
        if !connected { return String(localized: "overview.crab.moodOffline", defaultValue: "offline") }
        if petting { return String(localized: "overview.crab.moodPetted", defaultValue: "loved") }
        switch mood {
        case .happy:    return String(localized: "overview.crab.moodHappy", defaultValue: "thriving")
        case .calm:     return String(localized: "overview.crab.moodCalm", defaultValue: "dozing")
        case .alert:    return String(localized: "overview.crab.moodAlert", defaultValue: "uneasy")
        case .critical: return String(localized: "overview.crab.moodCritical", defaultValue: "alarmed")
        }
    }

    private var statusText: String {
        if !connected { return String(localized: "overview.crab.quipOffline", defaultValue: "MacCrab is asleep — the engine isn't running.") }
        if feeding { return String(localized: "overview.crab.quipFed", defaultValue: "Om nom — Crabby snapped up an event! 🦀") }
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
        .onChange(of: alertToken) { _ in
            guard connected, !alertToken.isEmpty else { return }
            snapAt = Date()
        }
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

            // The animated pixel scene.
            sceneView.padding(.horizontal, 6)

            // Transient SwiftUI overlays.
            if petting { heartsTrail }
            if feeding { crumb }
        }
        .frame(height: 120)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    @ViewBuilder
    private var sceneView: some View {
        // Freeze the per-frame Canvas redraw when motion is off OR the window
        // isn't the active scene (don't burn CPU/battery animating a pet the
        // user can't see).
        if reduceMotion || scenePhase != .active {
            sceneCanvas(t: 0)
        } else {
            TimelineView(.animation) { tl in
                sceneCanvas(t: tl.date.timeIntervalSinceReferenceDate)
            }
        }
    }

    // MARK: - The pixel scene (sky · terrain · props · crab · face)

    private func sceneCanvas(t: Double) -> some View {
        // Liveliness: bob frequency rises with the live event rate.
        let busy = min(max(eventRate / 8.0, 0), 1)
        let freq = 1.0 + busy * 1.6
        let bob: Double = {
            guard connected else { return 0 }
            switch shownMood {
            case .critical: return 0
            case .calm:     return sin(t * 0.9 * freq) * 0.35      // gentle breathing
            default:        return abs(sin(t * 1.4 * freq)) * 0.7
            }
        }()
        let shake: Double = (connected && shownMood == .critical) ? sin(t * 10) * 0.4 : 0
        // Blink ~ every 4.6s for ~120ms (only when eyes are open).
        let blink = connected && (t.truncatingRemainder(dividingBy: 4.6) < 0.12)
        let snapping = snapAt.map { Date().timeIntervalSince($0) < 0.5 } ?? false

        return Canvas { ctx, size in
            let g = size.height / 18.0                 // 18-row virtual grid (sky/crab/terrain)
            let ox = (size.width - 16 * g) / 2
            func cell(_ x: Double, _ y: Double, _ w: Double, _ h: Double, _ c: Color, _ a: Double = 1) {
                ctx.fill(Path(CGRect(x: ox + x * g, y: y * g, width: w * g, height: h * g)),
                         with: .color(c.opacity(a)))
            }

            drawSky(cell)
            drawTerrain(cell)
            if connected, protectionHealthy { drawShield(cell) }
            if connected, aiActive { drawAIBot(cell, t: t) }

            // Crab sits in rows 2…15, nudged by bob/shake.
            let dy = 2.0 + bob
            let dx = shake
            drawBeacon(cell, dx: dx, dy: dy, t: t)
            for b in Self.body {
                cell(Double(b.0) + dx, Double(b.1) + dy, Double(b.2), Double(b.3), bodyColor)
            }
            for f in faceCells(blink: blink, snapping: snapping) {
                cell(Double(f.0) + dx, Double(f.1) + dy, Double(f.2), Double(f.3), f.4)
            }
        }
    }

    // The rave hero crab body (16×16), verbatim.
    private static let body: [(Int, Int, Int, Int)] = [
        (1, 1, 3, 3), (0, 2, 1, 1), (4, 2, 1, 1), (2, 4, 2, 1),
        (12, 1, 3, 3), (11, 2, 1, 1), (15, 2, 1, 1), (12, 4, 2, 1),
        (6, 4, 1, 1), (9, 4, 1, 1),
        (4, 5, 8, 1), (3, 6, 10, 3), (4, 9, 8, 1),
        (2, 10, 1, 2), (5, 10, 1, 2), (10, 10, 1, 2), (13, 10, 1, 2),
        (1, 12, 1, 1), (4, 12, 1, 1), (11, 12, 1, 1), (14, 12, 1, 1),
    ]

    private func faceCells(blink: Bool, snapping: Bool) -> [(Int, Int, Int, Int, Color)] {
        let w = Color.white, k = Color.black
        if !connected {
            return [(5, 6, 2, 1, k), (9, 6, 2, 1, k), (7, 8, 2, 1, k)]   // asleep
        }
        if petting {
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (5, 8, 1, 1, k), (10, 8, 1, 1, k), (6, 9, 4, 1, k)]
        }
        if snapping {   // caught one — wide eyes + gritted mouth
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (6, 8, 4, 1, k)]
        }
        if blink, shownMood == .happy || shownMood == .calm {
            return [(5, 6, 2, 1, k), (9, 6, 2, 1, k), (6, 9, 4, 1, k)]   // blink
        }
        switch shownMood {
        case .happy:
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (5, 8, 1, 1, k), (10, 8, 1, 1, k), (6, 9, 4, 1, k)]
        case .calm:
            return [(5, 6, 2, 1, k), (9, 6, 2, 1, k), (7, 8, 2, 1, k)]
        case .alert:
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (5, 5, 1, 1, k), (10, 5, 1, 1, k), (7, 8, 2, 1, k)]
        case .critical:
            return [(5, 6, 2, 1, w), (9, 6, 2, 1, w), (6, 6, 1, 1, k), (9, 6, 1, 1, k),
                    (4, 5, 2, 1, k), (10, 5, 2, 1, k), (6, 8, 4, 1, k), (7, 9, 2, 1, k)]
        }
    }

    // Mood beacon — an antenna bulb above the crab.
    private func drawBeacon(_ cell: (Double, Double, Double, Double, Color, Double) -> Void, dx: Double, dy: Double, t: Double) {
        guard connected else { return }
        let bulb: Color
        switch shownMood {
        case .happy: bulb = Self.shieldGreen
        case .alert: bulb = .orange
        case .critical: bulb = .red
        case .calm: bulb = Self.grey
        }
        let blinkOn = shownMood == .critical ? (sin(t * 8) > 0) : true
        cell(7.5 + dx, 0.2 + dy, 0.5, 1.2, Self.grey, 1)                                 // stalk
        cell(7.0 + dx, -0.6 + dy, 1.5, 1.0, bulb, blinkOn ? 1 : 0.25)                    // bulb
    }

    // Coverage shield (left margin) when protection is healthy.
    private func drawShield(_ cell: (Double, Double, Double, Double, Color, Double) -> Void) {
        let c = Self.shieldGreen
        cell(0.2, 8, 2.2, 2.6, c, 0.9)
        cell(0.6, 10.6, 1.4, 0.8, c, 0.9)
        cell(1.0, 8.6, 0.6, 1.4, .white, 0.8)   // checkmark stroke
        cell(0.6, 9.4, 0.6, 0.6, .white, 0.8)
    }

    // AI sidekick robot (right margin) when an agent is active.
    private func drawAIBot(_ cell: (Double, Double, Double, Double, Color, Double) -> Void, t: Double) {
        let c = Self.aiBlue
        let blinkOn = sin(t * 3) > -0.3
        cell(13.4, 8, 2.2, 1.8, c, 0.95)                                  // head
        cell(13.0, 8.4, 0.4, 1.0, c, 0.95)                                // left antenna nub
        cell(14.0, 8.4, 0.5, 0.5, .white, blinkOn ? 1 : 0.2)             // eye
        cell(13.4, 9.8, 2.2, 1.4, c, 0.8)                                 // body
        cell(14.2, 7.2, 0.3, 0.8, c, 0.95)                                // antenna
        cell(14.0, 6.8, 0.7, 0.5, Self.shieldGreen, blinkOn ? 1 : 0.3)   // antenna tip
    }

    // Weather sky (top corners) — clear / cloudy / storm.
    private func drawSky(_ cell: (Double, Double, Double, Double, Color, Double) -> Void) {
        guard connected else { return }
        switch shownMood {
        case .happy, .calm:
            // a small sun, top-left corner
            let s = shownMood == .happy ? Self.shieldGreen : Color.yellow
            cell(0.4, 0.2, 1.6, 1.6, s, 0.9)
        case .alert:
            cell(0.2, 0.4, 2.4, 1.0, Self.grey, 0.7)   // cloud
            cell(0.8, 0.0, 1.4, 0.6, Self.grey, 0.6)
        case .critical:
            cell(0.2, 0.2, 2.4, 1.0, Color(white: 0.4), 0.85)   // storm cloud
            cell(1.1, 1.2, 0.5, 1.2, .yellow, 0.95)              // lightning bolt
            cell(0.8, 2.1, 0.5, 0.7, .yellow, 0.95)
        }
    }

    // Event-history terrain (bottom rows) from the last-8 buckets.
    private func drawTerrain(_ cell: (Double, Double, Double, Double, Color, Double) -> Void) {
        let buckets = eventBuckets.suffix(8)
        guard !buckets.isEmpty, let peak = buckets.max(), peak > 0 else {
            cell(0, 17, 16, 0.4, Self.crabOrange, 0.25)   // flat baseline
            return
        }
        let arr = Array(buckets)
        let colW = 16.0 / Double(arr.count)
        for (i, v) in arr.enumerated() {
            let h = 0.4 + (v / peak) * 1.4
            cell(Double(i) * colW, 18 - h, colW - 0.1, h, Self.crabOrange, connected ? 0.30 : 0.15)
        }
    }

    // MARK: - Transient overlays

    private var heartsTrail: some View {
        HStack(spacing: 10) {
            ForEach(0..<3, id: \.self) { i in
                Text(verbatim: "❤️").font(.system(size: 12))
                    .offset(y: petting ? -22 : 6)
                    .opacity(petting ? 0 : 1)
                    .animation(.easeOut(duration: 1.2).delay(Double(i) * 0.18), value: petting)
            }
        }
        .offset(y: -28)
    }

    private var crumb: some View {
        Text(verbatim: "🍪").font(.system(size: 13))
            .offset(y: feeding ? 18 : -34)
            .opacity(feeding ? 0 : 1)
            .animation(.easeIn(duration: 0.8), value: feeding)
    }

    // MARK: - Buttons

    private var buttons: some View {
        HStack(spacing: 14) {
            deviceButton("hand.tap.fill",
                         help: String(localized: "overview.crab.pet", defaultValue: "Pet Crabby")) {
                petting = true
                Task { try? await Task.sleep(for: .seconds(1.4)); petting = false }
            }
            deviceButton("fork.knife",
                         help: String(localized: "overview.crab.feed", defaultValue: "Feed Crabby a stray event")) {
                feeding = true
                onFeed()
                Task { try? await Task.sleep(for: .seconds(1.0)); feeding = false }
            }
            deviceButton("checkmark.circle.fill",
                         help: String(localized: "overview.crab.acknowledge", defaultValue: "Acknowledge — settle Crabby"),
                         enabled: canAcknowledge, action: onAcknowledge)
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
        .accessibilityLabel(Text(help))
    }
}
