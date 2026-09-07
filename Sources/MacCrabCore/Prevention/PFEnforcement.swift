// PFEnforcement.swift
// MacCrabCore
//
// Are the packet filter's anchor-evaluation prerequisites verified?
//
// v1.21.6-rc.45. Every PF-based control in this product — NetworkBlocker,
// ResponseAction.blockNetwork, ManualResponse.blockDestination, PanicButton,
// TravelMode — enforces by running:
//
//     pfctl -a <feature-anchor> -f <feature-rules>
//
// That loads rules INTO an anchor. The rules are evaluated only if (a) the
// main ruleset contains a matching anchor statement and
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
        /// An unconditional attachment exists in the active main ruleset and
        /// the requested anchor's rules can be read at observation time.
        public let anchorReachable: Bool
        /// Operator-facing explanation. Never empty.
        public let reason: String

        /// Necessary prerequisites after the caller successfully loads its
        /// intended rules. This snapshot is not a packet-delivery measurement.
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
            reason = "PF is enabled but the requested anchor has no verified unconditional attachment in the active main ruleset; review /etc/pf.conf"
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

    /// Probe the live host using bounded, read-only `pfctl` queries.
    ///
    /// Fails CLOSED: if a required probe fails, we report not-enforcing.
    /// An unknown enforcement state must never render as a block.
    public static func probe(anchorName: String) -> Status {
        probe(anchorName: anchorName) { args in
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
    }

    /// Internal runner seam for ordinary command-result fixtures. No fixture
    /// needs root, a live packet filter, or a firewall configuration change.
    static func probe(
        anchorName: String,
        run: ([String]) -> (ok: Bool, text: String)?
    ) -> Status {
        guard let info = run(["-s", "info"]), info.ok else {
            return status(pfEnabled: false, anchorReachable: false)
        }
        // `pfctl -s info` prints "Status: Enabled" / "Status: Disabled".
        let pfEnabled = info.text.split(separator: "\n").contains {
            $0.range(of: #"^Status:\s+Enabled(?:\s|$)"#, options: .regularExpression) != nil
        }
        guard pfEnabled else { return status(pfEnabled: false, anchorReachable: false) }

        // A populated anchor can be listed without any caller in the root
        // ruleset. Listing its contents is therefore not reachability evidence.
        // Query the active rules, not the on-disk configuration (which may not
        // have been loaded). Product anchors are top-level; nested/conditional
        // attachment policies require operator review and remain unverified.
        let main = run(["-s", "rules"])
        let attached = main?.ok == true && hasUnconditionalRootReference(
            rules: main?.text ?? "", anchorName: anchorName
        )
        let anchorReachable = attached
            && (run(["-a", anchorName, "-s", "rules"])?.ok == true)

        let resolved = status(pfEnabled: pfEnabled, anchorReachable: anchorReachable)
        if !resolved.enforcing {
            logger.notice(
                "PF anchor \(anchorName, privacy: .public) is NOT enforcing: \(resolved.reason, privacy: .public)"
            )
        }
        return resolved
    }

    /// Accept only an unconditional top-level filter attachment. A wildcard
    /// evaluates immediate children, not every anchor with a common prefix.
    /// This checks evaluation prerequisites, not packet delivery or PF state
    /// changes after the observation. See the installed macOS pf.conf(5).
    static func hasUnconditionalRootReference(rules: String, anchorName: String) -> Bool {
        guard !anchorName.isEmpty, !anchorName.contains("/"),
              anchorName.range(of: #"^[A-Za-z0-9_.-]+$"#, options: .regularExpression) != nil
        else { return false }
        var depth = 0
        var found = false
        for rawLine in rules.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if depth == 0, line.hasPrefix("anchor \"") {
                let nameStart = line.index(line.startIndex, offsetBy: 8)
                if let nameEnd = line[nameStart...].firstIndex(of: "\"") {
                    let name = String(line[nameStart..<nameEnd])
                    let tail = line[line.index(after: nameEnd)...]
                        .trimmingCharacters(in: .whitespaces)
                    if ["", "all", "{", "all {"].contains(tail),
                       name == anchorName || name == "/" + anchorName || name == "*" {
                        found = true
                    }
                }
            }
            // pfctl emits balanced inline blocks. Ignore braces inside quoted
            // labels/names; reject incomplete output instead of crediting it.
            let unquoted = line.replacingOccurrences(
                of: #"\"(?:\\.|[^\"\\])*\""#, with: "", options: .regularExpression
            )
            depth += unquoted.filter { $0 == "{" }.count - unquoted.filter { $0 == "}" }.count
            if depth < 0 { return false }
        }
        return found && depth == 0
    }
}
