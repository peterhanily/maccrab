// LiveTriggerLane.swift
// assessment-framework (P5): Lane 3 — external live triggers. The only lane that
// proves the FULL macOS→EndpointSecurity→engine→alert path: it runs benign-but-
// real triggers on a DISPOSABLE, root/ES-entitled host and observes the alert via
// the product read path (no injection into the sensor — that is the whole point).
//
// This file is the lane STRUCTURE + the safety gate. Actually firing triggers and
// reading back alerts is an ON-DEVICE step that runs only past DisposableHostGuard
// on a sacrificial runner; in any other environment run() refuses, by design.

import Foundation

/// One benign trigger and the alert it must produce.
public struct TriggerManifestEntry: Sendable, Equatable {
    public let technique: String
    public let source: String            // "atomic-red-team" | "tsale-edr-telemetry" | "builtin"
    /// A BENIGN command that exhibits the technique's shape without real harm
    /// (e.g. a reverse-shell string that connects to localhost:1 and fails).
    public let benignCommand: String
    public let expectedRuleId: String
    public let expectedMinSeverity: String

    public init(technique: String, source: String, benignCommand: String,
                expectedRuleId: String, expectedMinSeverity: String) {
        self.technique = technique; self.source = source; self.benignCommand = benignCommand
        self.expectedRuleId = expectedRuleId; self.expectedMinSeverity = expectedMinSeverity
    }
}

public struct LiveTriggerLane: Sendable {

    public enum Outcome: Sendable {
        /// The guard refused — not a disposable host. This is the SAFE default in
        /// any normal environment, and is not a test failure.
        case refused(reason: String)
        /// Ran on a disposable host and produced verdict records (on-device only).
        case ran(verdicts: [VerdictRecord])
    }

    public let guardInputs: DisposableHostGuard.Inputs

    /// Defaults to probing the real environment. Tests inject explicit inputs.
    public init(guardInputs: DisposableHostGuard.Inputs = DisposableHostGuard.probeInputs()) {
        self.guardInputs = guardInputs
    }

    /// Enforces the disposable-host guard, then (on-device) runs the manifest.
    /// In this build the post-guard execution is a documented stub — the trigger
    /// firing + MCP-read observation + signed .maccrabtrace emission is the
    /// ON-DEVICE-VERIFY step on a sacrificial runner.
    public func run(manifest: [TriggerManifestEntry]) -> Outcome {
        switch DisposableHostGuard().evaluate(guardInputs) {
        case .refused(let reason):
            return .refused(reason: reason)
        case .allowed:
            // ON-DEVICE (P5 completion on a disposable runner): for each entry,
            // fire benignCommand, poll the product read path (get_alerts / the
            // heartbeat) for expectedRuleId at >= expectedMinSeverity, build a
            // VerdictRecord with the live latency, and export a signed
            // .maccrabtrace as evidenceRef. Left as a guarded stub here so this
            // lane can never fire on a non-disposable machine.
            return .ran(verdicts: [])
        }
    }

    /// The starter manifest — one entry per technique the offline lane already
    /// scores, so live and offline lanes stay aligned. Benign by construction.
    public static let starterManifest: [TriggerManifestEntry] = [
        TriggerManifestEntry(
            technique: "T1059.004",
            source: "builtin",
            // Connects to a black-hole port on localhost and exits — the command
            // SHAPE matches the reverse-shell rule; no real shell is served.
            benignCommand: "bash -i >& /dev/tcp/127.0.0.1/1 0>&1 || true",
            expectedRuleId: "d1a2b3c4-0042-4000-a000-000000000042",
            expectedMinSeverity: "critical"),
    ]
}
