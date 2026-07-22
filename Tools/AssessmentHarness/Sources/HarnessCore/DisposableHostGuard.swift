// DisposableHostGuard.swift
// assessment-framework (P5): the safety core of the live-trigger lane. Lane 3
// runs benign-but-real attack triggers against the FULL macOS→ES→engine→alert
// path, and the corpus scripts are destructive (they rm events.db, pkill the
// daemon, and rewrite daemon_config.json). So the lane MUST refuse to run
// anywhere except a host explicitly designated disposable — never the
// maintainer's primary machine. This guard is the hard pre-flight gate.
//
// The checks are injected so the decision is pure and unit-testable; the CLI
// wires them to the real environment.

import Foundation

public struct DisposableHostGuard: Sendable {

    public struct Inputs: Sendable {
        /// An explicit operator opt-in: the file /etc/maccrab-assess-disposable
        /// exists, or MACCRAB_ASSESS_DISPOSABLE=1 is set. Absence → refuse.
        public let disposableFlagSet: Bool
        /// A production MacCrab System Extension is activated. Its presence means
        /// this is a real install (likely someone's actual machine) → refuse.
        public let productionSysextActive: Bool
        /// MACCRAB_DATA_DIR is set. Lane 3 must exercise the REAL store; a data-dir
        /// override signals a confused Lane-2 (seeded-store) context → refuse.
        public let dataDirOverridePresent: Bool

        public init(disposableFlagSet: Bool, productionSysextActive: Bool, dataDirOverridePresent: Bool) {
            self.disposableFlagSet = disposableFlagSet
            self.productionSysextActive = productionSysextActive
            self.dataDirOverridePresent = dataDirOverridePresent
        }
    }

    public enum Decision: Sendable, Equatable {
        case allowed
        case refused(reason: String)
        public var isAllowed: Bool { if case .allowed = self { return true } else { return false } }
    }

    public init() {}

    /// Fail-CLOSED: allowed only when the host is explicitly disposable AND no
    /// production sysext is active AND no data-dir override is present. Any doubt
    /// refuses.
    public func evaluate(_ i: Inputs) -> Decision {
        if !i.disposableFlagSet {
            return .refused(reason: "host is not marked disposable — set MACCRAB_ASSESS_DISPOSABLE=1 or create /etc/maccrab-assess-disposable on a sacrificial runner only")
        }
        if i.productionSysextActive {
            return .refused(reason: "a production com.maccrab.agent System Extension is active — refusing to run destructive live triggers against a real install")
        }
        if i.dataDirOverridePresent {
            return .refused(reason: "MACCRAB_DATA_DIR is set — the live lane must use the real store, not a seeded fixture (that is Lane 2)")
        }
        return .allowed
    }

    // MARK: - Real-environment probes (used by the CLI, not by tests)

    public static func probeInputs() -> Inputs {
        let env = ProcessInfo.processInfo.environment
        let flag = env["MACCRAB_ASSESS_DISPOSABLE"] == "1"
            || FileManager.default.fileExists(atPath: "/etc/maccrab-assess-disposable")
        return Inputs(
            disposableFlagSet: flag,
            productionSysextActive: Self.productionSysextActive(),
            dataDirOverridePresent: (env["MACCRAB_DATA_DIR"]?.isEmpty == false)
        )
    }

    /// Best-effort: is a MacCrab sysext activated? Reads `systemextensionsctl list`.
    static func productionSysextActive() -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["systemextensionsctl", "list"]
        let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
        do { try p.run(); p.waitUntilExit() } catch { return false }
        let text = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        // A line for com.maccrab.agent marked activated/enabled.
        return text.split(separator: "\n").contains { line in
            line.contains("com.maccrab.agent") && (line.contains("activated") || line.contains("[activated enabled]"))
        }
    }
}
