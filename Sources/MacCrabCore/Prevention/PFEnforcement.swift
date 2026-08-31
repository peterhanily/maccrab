// PFEnforcement.swift
// MacCrabCore
//
// Is a PF anchor actually enforcing anything?
//
// v1.21.6-rc.45. Every PF-based control in this product — NetworkBlocker,
// ResponseAction.blockNetwork, ManualResponse.blockDestination, PanicButton,
// TravelMode — enforces by running:
//
//     pfctl -a com.maccrab -f /etc/pf.anchors/com.maccrab
//
// That loads rules INTO an anchor. The rules are evaluated only if (a) the
// main ruleset contains a matching `anchor "com.maccrab"` statement and
// (b) PF is enabled. MacCrab arranges NEITHER: there is no `pfctl -e`
// anywhere in the source and nothing writes or patches /etc/pf.conf.
//
// `pfctl -f` exits 0 even when PF is disabled, so every one of those modules
// logged success and published block counts for enforcement that could not
// occur. Measured on an installed host:
//
//     $ pfctl -s info       →  Status: Disabled
//     $ pfctl -s Anchors    →  com.apple            (com.maccrab absent)
//     $ pfctl -a com.maccrab -s rules
//                           →  pfctl: DIOCGETRULES: Invalid argument
//
// For a security product, reporting a block that did not happen is the worst
// failure mode available: the operator stops looking. Until MacCrab either
// registers its anchor and takes a PF enable reference, or moves egress
// control to a NetworkExtension content filter, these modules must report
// themselves as NOT enforcing. This type is the single place that decides.

import Foundation
import os.log

public enum PFEnforcement {

    public struct Status: Sendable, Equatable {
        /// The packet filter itself is running.
        public let pfEnabled: Bool
        /// The main ruleset references our anchor, so rules loaded into it are
        /// actually evaluated.
        public let anchorReachable: Bool
        /// Operator-facing explanation. Never empty.
        public let reason: String

        /// The only question a caller should ask before claiming a block.
        public var enforcing: Bool { pfEnabled && anchorReachable }

        public init(pfEnabled: Bool, anchorReachable: Bool, reason: String) {
            self.pfEnabled = pfEnabled
            self.anchorReachable = anchorReachable
            self.reason = reason
        }
    }

    /// Pure decision, so the reporting contract is testable without pfctl.
    public static func status(
        pfEnabled: Bool,
        anchorReachable: Bool
    ) -> Status {
        let reason: String
        switch (pfEnabled, anchorReachable) {
        case (false, _):
            reason = "PF is disabled on this host — loaded rules are never evaluated"
        case (true, false):
            reason = "PF is enabled but the com.maccrab anchor is not referenced from /etc/pf.conf"
        case (true, true):
            reason = "enforcing"
        }
        return Status(
            pfEnabled: pfEnabled,
            anchorReachable: anchorReachable,
            reason: reason
        )
    }

    private static let logger = Logger(
        subsystem: "com.maccrab.prevention", category: "pf-enforcement"
    )

    /// Probe the live host. Both probes are read-only `pfctl` queries.
    ///
    /// Fails CLOSED: if either probe cannot be run, we report not-enforcing.
    /// An unknown enforcement state must never render as a block.
    public static func probe(anchorName: String) -> Status {
        func run(_ args: [String]) -> (ok: Bool, text: String)? {
            guard let result = BoundedPrivilegedProcessRunner.run(
                executable: "/sbin/pfctl",
                arguments: args,
                timeout: 5,
                maximumOutputBytes: 64 * 1024
            ) else { return nil }
            return (
                result.succeeded,
                String(decoding: result.output, as: UTF8.self)
            )
        }

        guard let info = run(["-s", "info"]) else {
            return status(pfEnabled: false, anchorReachable: false)
        }
        // `pfctl -s info` prints "Status: Enabled" / "Status: Disabled".
        let pfEnabled = info.text.contains("Status: Enabled")

        // Querying an unregistered anchor fails with
        // "pfctl: DIOCGETRULES: Invalid argument".
        let anchorReachable = run(["-a", anchorName, "-s", "rules"])?.ok ?? false

        let resolved = status(pfEnabled: pfEnabled, anchorReachable: anchorReachable)
        if !resolved.enforcing {
            logger.notice(
                "PF anchor \(anchorName, privacy: .public) is NOT enforcing: \(resolved.reason, privacy: .public)"
            )
        }
        return resolved
    }
}
