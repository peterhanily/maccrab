// ArtifactNetworkView — node-edge visualization.
//
// Each artifact becomes a source node identified by its title-
// role field (or its summary as fallback). The plugin's
// chartHint.edgeField points at the data field whose value
// names the target node. We render a layered layout: source
// nodes on the left, target nodes on the right, edges curved
// between them. Top-N nodes by edge-count keep the canvas
// readable on dense graphs.
//
// rc.15 ships a static layered layout. Force-directed +
// interactive zoom/pan/expand are rc.16 work.

import SwiftUI
import MacCrabForensics

struct ArtifactNetworkView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    private var chartHint: ChartHint? { hint.chart }

    private static let maxSources = 30
    private static let maxTargets = 30

    /// Compute the bipartite graph once per body.
    private var graph: BipartiteGraph {
        Self.build(
            artifacts: artifacts,
            titleField: FieldResolver.field(forRole: .title, in: hint),
            edgeField: chartHint?.edgeField
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header
            if graph.sources.isEmpty || graph.targets.isEmpty {
                emptyState
            } else {
                content
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("\(graph.sources.count) source\(graph.sources.count == 1 ? "" : "s") → \(graph.targets.count) target\(graph.targets.count == 1 ? "" : "s")")
                .font(.system(size: 12, weight: .semibold))
            Spacer()
            Text("\(graph.edges.count) edge\(graph.edges.count == 1 ? "" : "s")")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
    }

    private var emptyState: some View {
        Text(chartHint?.edgeField == nil
             ? "No edgeField declared in this plugin's chart hint."
             : "Not enough nodes + edges to render a graph.")
            .font(.system(size: 11))
            .foregroundStyle(.tertiary)
            .padding(.vertical, 20)
    }

    private var content: some View {
        GeometryReader { geo in
            ZStack {
                edgeLayer(in: geo.size)
                nodeLayer(in: geo.size)
            }
        }
        .frame(minHeight: 320, idealHeight: 480)
    }

    // MARK: - Layout

    private func sourcePosition(_ idx: Int, total: Int, size: CGSize) -> CGPoint {
        let safeTotal = max(total, 1)
        let y = (CGFloat(idx) + 0.5) * (size.height / CGFloat(safeTotal))
        return CGPoint(x: 110, y: y)
    }

    private func targetPosition(_ idx: Int, total: Int, size: CGSize) -> CGPoint {
        let safeTotal = max(total, 1)
        let y = (CGFloat(idx) + 0.5) * (size.height / CGFloat(safeTotal))
        return CGPoint(x: size.width - 110, y: y)
    }

    // MARK: - Layers

    private func edgeLayer(in size: CGSize) -> some View {
        Canvas { ctx, _ in
            for e in graph.edges {
                guard let si = graph.sourceIndex[e.source],
                      let ti = graph.targetIndex[e.target] else { continue }
                let p1 = sourcePosition(si, total: graph.sources.count, size: size)
                let p2 = targetPosition(ti, total: graph.targets.count, size: size)
                var path = Path()
                path.move(to: p1)
                let midX = (p1.x + p2.x) / 2
                path.addCurve(
                    to: p2,
                    control1: CGPoint(x: midX, y: p1.y),
                    control2: CGPoint(x: midX, y: p2.y)
                )
                ctx.stroke(path, with: .color(.secondary.opacity(0.35)), lineWidth: 0.7)
            }
        }
    }

    private func nodeLayer(in size: CGSize) -> some View {
        ZStack {
            ForEach(Array(graph.sources.enumerated()), id: \.element) { idx, src in
                nodeView(label: src, color: .blue,
                         position: sourcePosition(idx, total: graph.sources.count, size: size))
            }
            ForEach(Array(graph.targets.enumerated()), id: \.element) { idx, tgt in
                nodeView(label: tgt, color: .purple,
                         position: targetPosition(idx, total: graph.targets.count, size: size))
            }
        }
    }

    private func nodeView(label: String, color: Color, position: CGPoint) -> some View {
        Text(label)
            .font(.system(size: 10, weight: .medium))
            .lineLimit(1)
            .truncationMode(.middle)
            .padding(.horizontal, 6).padding(.vertical, 3)
            .background(color.opacity(0.18))
            .foregroundStyle(color)
            .cornerRadius(4)
            .frame(maxWidth: 200)
            .position(position)
    }

    // MARK: - Graph build

    private struct Edge: Hashable {
        let source: String
        let target: String
    }

    private struct BipartiteGraph {
        let sources: [String]                  // ordered, capped at maxSources
        let targets: [String]                  // ordered, capped at maxTargets
        let edges: [Edge]
        let sourceIndex: [String: Int]
        let targetIndex: [String: Int]
    }

    private static func build(
        artifacts: [CommittedArtifact],
        titleField: String?,
        edgeField: String?
    ) -> BipartiteGraph {
        var rawEdges: [Edge] = []
        var sourceCounts: [String: Int] = [:]
        var targetCounts: [String: Int] = [:]

        for a in artifacts {
            let srcName: String = {
                if let tf = titleField {
                    let v = FieldResolver.resolve(a, field: tf).displayString()
                    if !v.isEmpty { return v }
                }
                return a.record.summary ?? a.record.contentType
            }()
            guard let ef = edgeField else { continue }
            let v = FieldResolver.resolve(a, field: ef)
            let targets: [String] = {
                switch v {
                case .string(let s) where !s.isEmpty: return [s]
                case .array(let arr):
                    return arr.compactMap {
                        if case .string(let s) = $0, !s.isEmpty { return s }
                        return nil
                    }
                default: return []
                }
            }()
            for tgt in targets {
                rawEdges.append(Edge(source: srcName, target: tgt))
                sourceCounts[srcName, default: 0] += 1
                targetCounts[tgt, default: 0] += 1
            }
        }

        let topSources = Array(sourceCounts.sorted { $0.value > $1.value }
            .prefix(maxSources)
            .map { $0.key })
        let topTargets = Array(targetCounts.sorted { $0.value > $1.value }
            .prefix(maxTargets)
            .map { $0.key })

        let srcSet = Set(topSources)
        let tgtSet = Set(topTargets)
        let filteredEdges = rawEdges.filter { srcSet.contains($0.source) && tgtSet.contains($0.target) }

        var srcIdx: [String: Int] = [:]
        for (i, s) in topSources.enumerated() { srcIdx[s] = i }
        var tgtIdx: [String: Int] = [:]
        for (i, t) in topTargets.enumerated() { tgtIdx[t] = i }

        return BipartiteGraph(
            sources: topSources,
            targets: topTargets,
            edges: filteredEdges,
            sourceIndex: srcIdx,
            targetIndex: tgtIdx
        )
    }
}
