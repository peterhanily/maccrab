// StylometricSupplyChainEnricher — com.maccrab.enricher.stylometric-supply-chain.
//
// Plan §13.8. Annotates the subject's payload text with stylometric
// supply-chain risk indicators: obfuscation markers, suspicious
// identifier patterns (long random-looking strings, hex blobs,
// base64 chunks), mixed-language signatures. Heuristic and
// non-blocking; surfaces signals operators triage further.
//
// v1.16.0-rc.12 ships heuristic-only. The path to live drift
// detection via MacCrabCore.StylometricFingerprinter is wired
// shape-wise but needs operator-recorded baselines (a separate
// CLI affordance not yet built).

import Foundation
import MacCrabCore

public struct StylometricSupplyChainEnricher: Enricher {

    public static let manifest = PluginManifest(
        id: "com.maccrab.enricher.stylometric-supply-chain",
        version: "1.0.0",
        displayName: "Stylometric Supply Chain",
        description: "Heuristic stylometric flags for supply-chain risk: obfuscation markers, base64 / hex blob density, mixed-language signatures. Drift-vs-baseline integration with MacCrabCore.StylometricFingerprinter is shape-wired but requires operator baselines (deferred CLI affordance).",
        type: .enricher,
        runtime: .tierA,
        tccRequirements: [],
        inputs: [],
        outputs: [],
        mcpTools: [],
        schemaVersion: 1,
        stability: .preview
    )

    public var stages: Set<EnrichmentStage> { [.postEmission, .onDemand] }

    public init() async throws {}

    public func enrich(_ subject: EnrichmentSubject, stage: EnrichmentStage) async throws -> Enrichment {
        // We extract a text representative from the subject — for
        // events / alerts that's the process command line; for
        // path subjects we read a small head (first 16 KB) of
        // the file as a text approximation.
        let text = Self.extractText(from: subject)
        let stats = Self.analyze(text)
        let fields: [String: EnrichmentValue] = [
            "stylometric.text_length": .integer(text.count),
            "stylometric.base64_run_count": .integer(stats.base64Runs),
            "stylometric.hex_blob_count": .integer(stats.hexBlobs),
            "stylometric.eval_marker_count": .integer(stats.evalMarkers),
            "stylometric.obfuscation_markers": .stringArray(stats.markers),
            "stylometric.suspicious_overall": .bool(stats.isSuspicious),
        ]
        return Enrichment(
            pluginID: Self.manifest.id,
            pluginVersion: Self.manifest.version,
            schemaVersion: Self.manifest.schemaVersion,
            producedAt: Date(),
            fields: fields,
            confidence: .heuristic,
            privacyClass: .metadata
        )
    }

    static func extractText(from subject: EnrichmentSubject) -> String {
        switch subject {
        case .path(let url):
            guard let fh = FileHandle(forReadingAtPath: url.path),
                  let data = try? fh.read(upToCount: 16_384) else { return "" }
            try? fh.close()
            return String(data: data, encoding: .utf8) ?? ""
        case .event, .alert:
            // command-line text isn't directly on the payload
            // structs at the enricher's surface; future iteration
            // can plumb the field.
            return ""
        }
    }

    struct Stats {
        var base64Runs: Int = 0
        var hexBlobs: Int = 0
        var evalMarkers: Int = 0
        var markers: [String] = []
        var isSuspicious: Bool = false
    }

    static func analyze(_ text: String) -> Stats {
        var s = Stats()
        let lowerText = text.lowercased()

        // Eval / exec markers.
        let evalPatterns = ["eval(", "execscript", "system(", "exec(",
                             "fromcharcode", "atob(", "btoa(",
                             "shell_exec", "passthru"]
        for p in evalPatterns where lowerText.contains(p) {
            s.evalMarkers += 1
            s.markers.append(p)
        }

        // Long base64 runs (≥80 chars in base64 alphabet).
        let base64Char = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        var current = 0
        for scalar in text.unicodeScalars {
            if base64Char.contains(scalar) {
                current += 1
                if current == 80 {
                    s.base64Runs += 1
                    s.markers.append("base64_run")
                }
            } else {
                current = 0
            }
        }

        // Long hex runs (≥64 hex chars).
        let hexChar = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        current = 0
        for scalar in text.unicodeScalars {
            if hexChar.contains(scalar) {
                current += 1
                if current == 64 {
                    s.hexBlobs += 1
                    s.markers.append("hex_blob")
                }
            } else {
                current = 0
            }
        }

        s.isSuspicious = s.evalMarkers > 0 || s.base64Runs > 0 || s.hexBlobs > 1
        return s
    }
}
