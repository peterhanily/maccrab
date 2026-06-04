// V2KpiCard.swift
// Reusable KPI card per spec §5.1 + page-2-design-system mockup.
//
// Composition:
//   title (small, muted)
//   value (large, dominant)
//   trend / delta strip (optional)
//   trailing arrow link (optional)
//   sparkline / mini-visual (optional)

import SwiftUI

public struct V2KpiCard: View {
    public let title: String
    public let value: String
    public let trend: String?
    public let trendKind: V2ChipKind?
    public let icon: String?
    public let iconColor: Color?
    public let footer: String?
    public let action: V2KpiAction?
    public let visual: V2KpiVisual?

    public init(
        title: String,
        value: String,
        trend: String? = nil,
        trendKind: V2ChipKind? = nil,
        icon: String? = nil,
        iconColor: Color? = nil,
        footer: String? = nil,
        action: V2KpiAction? = nil,
        visual: V2KpiVisual? = nil
    ) {
        self.title = title
        self.value = value
        self.trend = trend
        self.trendKind = trendKind
        self.icon = icon
        self.iconColor = iconColor
        self.footer = footer
        self.action = action
        self.visual = visual
    }

    public var body: some View {
        if let action = action {
            Button(action: action.handler) { cardBody(showArrow: true) }
                .buttonStyle(.plain)
                .help(action.label)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(title): \(value). \(action.label).")
        } else {
            cardBody(showArrow: false)
        }
    }

    @ViewBuilder
    private func cardBody(showArrow: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                if let icon {
                    Image(systemName: icon)
                        .scaledSystem(10, weight: .semibold)
                        .foregroundStyle(iconColor ?? V2Theme.mutedText)
                }
                Text(title)
                    .font(V2Theme.cardTitle())
                    .foregroundStyle(V2Theme.mutedText)
                    .textCase(.uppercase)
                    .tracking(0.4)
                Spacer()
                if showArrow {
                    Image(systemName: "arrow.up.forward")
                        .scaledSystem(9, weight: .semibold)
                        .foregroundStyle(V2Theme.tertiaryText)
                }
            }

            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(value)
                    .font(V2Theme.kpiValue())
                    .foregroundStyle(V2Theme.primaryText)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                if let trend, let trendKind {
                    V2StatusChip(trend, kind: trendKind)
                } else if let trend {
                    Text(trend)
                        .font(V2Theme.meta())
                        .foregroundStyle(V2Theme.mutedText)
                }
            }

            if let visual {
                visual.view
                    .frame(height: 22)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            if let footer {
                Text(footer)
                    .font(V2Theme.meta())
                    .foregroundStyle(V2Theme.mutedText)
            }
        }
        .v2Panel()
        .accessibilityElement(children: .combine)
        // v1.11.0 (audit UX LOW): a "—" value rendered VoiceOver as
        // "em dash" / "dash". Render "pending" instead so users hear
        // a meaningful state. Once daemon-side data populates the
        // KPI cards, real values flow through unchanged.
        .accessibilityLabel("\(title)\(value == "—" ? ", pending" : ": \(value)")\(trend.map { ", \($0)" } ?? "")")
    }
}

public struct V2KpiAction {
    public let label: String
    public let handler: () -> Void
    public init(_ label: String, handler: @escaping () -> Void) {
        self.label = label
        self.handler = handler
    }
}

// MARK: - Visual

public enum V2KpiVisual {
    case sparkline(values: [Double], color: Color)
    case bars(values: [Double], color: Color)
    case ratio(parts: [(value: Double, color: Color)])

    @ViewBuilder
    var view: some View {
        switch self {
        case .sparkline(let values, let color):
            V2Sparkline(values: values, color: color)
        case .bars(let values, let color):
            V2BarSparkline(values: values, color: color)
        case .ratio(let parts):
            V2RatioBar(parts: parts)
        }
    }
}

private struct V2Sparkline: View {
    let values: [Double]
    let color: Color

    var body: some View {
        GeometryReader { geo in
            guard values.count >= 2,
                  let minV = values.min(),
                  let maxV = values.max(),
                  maxV > minV
            else {
                return AnyView(Color.clear)
            }
            let path = Path { p in
                let stepX = geo.size.width / CGFloat(values.count - 1)
                for (i, v) in values.enumerated() {
                    let x = CGFloat(i) * stepX
                    let y = geo.size.height * (1 - CGFloat((v - minV) / (maxV - minV)))
                    if i == 0 { p.move(to: .init(x: x, y: y)) }
                    else      { p.addLine(to: .init(x: x, y: y)) }
                }
            }
            let fill = Path { p in
                let stepX = geo.size.width / CGFloat(values.count - 1)
                p.move(to: .init(x: 0, y: geo.size.height))
                for (i, v) in values.enumerated() {
                    let x = CGFloat(i) * stepX
                    let y = geo.size.height * (1 - CGFloat((v - minV) / (maxV - minV)))
                    p.addLine(to: .init(x: x, y: y))
                }
                p.addLine(to: .init(x: geo.size.width, y: geo.size.height))
                p.closeSubpath()
            }
            return AnyView(
                ZStack {
                    fill.fill(LinearGradient(
                        colors: [color.opacity(0.30), color.opacity(0.0)],
                        startPoint: .top, endPoint: .bottom
                    ))
                    path.stroke(color.opacity(0.85), lineWidth: 1.5)
                }
            )
        }
    }
}

private struct V2BarSparkline: View {
    let values: [Double]
    let color: Color

    var body: some View {
        GeometryReader { geo in
            guard let maxV = values.max(), maxV > 0 else {
                return AnyView(Color.clear)
            }
            let count = max(values.count, 1)
            let barWidth = geo.size.width / CGFloat(count) * 0.65
            let gap = geo.size.width / CGFloat(count) * 0.35
            return AnyView(
                HStack(alignment: .bottom, spacing: gap) {
                    ForEach(values.indices, id: \.self) { i in
                        Rectangle()
                            .fill(color.opacity(0.85))
                            .frame(width: barWidth, height: geo.size.height * CGFloat(values[i] / maxV))
                    }
                }
            )
        }
    }
}

private struct V2RatioBar: View {
    let parts: [(value: Double, color: Color)]

    var body: some View {
        GeometryReader { geo in
            let total = max(parts.map { $0.value }.reduce(0, +), 0.0001)
            HStack(spacing: 2) {
                ForEach(parts.indices, id: \.self) { idx in
                    Rectangle()
                        .fill(parts[idx].color)
                        .frame(width: geo.size.width * CGFloat(parts[idx].value / total) - 2)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 3))
        }
    }
}
