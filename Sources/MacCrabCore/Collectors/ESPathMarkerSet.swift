// ESPathMarkerSet.swift
// MacCrabCore
//
// v1.22.7 ES ingress throughput. A fixed set of path markers matched over raw
// UTF-8 bytes with `memmem` / `memcmp`, so the Endpoint Security callback can
// classify a NOTIFY_OPEN path WITHOUT decoding the borrowed
// `es_string_token_t` into a String (no allocation, no bridging, no lock).
//
// Built once from the same String lists the worker-stage predicates use
// (`ESCollector.credentialReadPathSubstrings` and friends), so the byte
// matcher and `isCredentialReadPath` / `isAgentContentReadPath` cannot drift;
// `ESIngressAdmissionTests` pins the parity on the allowlist corpora.
//
// Markers are grouped behind gate substrings they all contain ("/Library/",
// "/." …): a path that lacks the gate skips the whole group, so the common
// project-file OPEN costs a handful of `memmem` calls rather than one per
// marker. Grouping is derived automatically from the marker text, never
// hand-maintained.

import Darwin
import EndpointSecurity
import Foundation

struct ESPathMarkerSet: Sendable {
    /// One marker's bytes inside `storage`.
    private struct Marker: Sendable {
        let offset: Int
        let count: Int
    }

    private struct Group: Sendable {
        /// When non-nil, every marker in the group contains this substring, so
        /// a path without it cannot match any of them.
        let gate: Marker?
        let substrings: [Marker]
        let suffixes: [Marker]
    }

    private struct GatedSuffixes: Sendable {
        let gate: Marker
        let suffixes: [Marker]
    }

    /// Gate substrings tried in order; a marker joins the first gate it contains.
    static let defaultGates = ["/Local Extension Settings/", "Application Support/", "/Library/", "/."]

    /// Every marker's UTF-8, back to back, so `matches` pins one buffer for
    /// the whole scan instead of entering a closure per marker.
    private let storage: [UInt8]
    private let groups: [Group]
    /// Suffixes that only count when their gate appears elsewhere in the path
    /// (Chrome `Login Data` under /Google/Chrome/).
    private let gatedSuffixes: [GatedSuffixes]

    init(
        substrings: [String],
        suffixes: [String],
        gatedSuffixes: [(gate: String, suffixes: [String])] = [],
        gates: [String] = ESPathMarkerSet.defaultGates
    ) {
        var storage: [UInt8] = []
        func intern(_ text: String) -> Marker {
            let marker = Marker(offset: storage.count, count: text.utf8.count)
            storage.append(contentsOf: text.utf8)
            return marker
        }
        var bySubstring: [Int: [Marker]] = [:]
        var bySuffix: [Int: [Marker]] = [:]
        var ungatedSubstrings: [Marker] = []
        var ungatedSuffixes: [Marker] = []
        for marker in substrings {
            if let index = gates.firstIndex(where: { marker.contains($0) }) {
                bySubstring[index, default: []].append(intern(marker))
            } else {
                ungatedSubstrings.append(intern(marker))
            }
        }
        for marker in suffixes {
            if let index = gates.firstIndex(where: { marker.contains($0) }) {
                bySuffix[index, default: []].append(intern(marker))
            } else {
                ungatedSuffixes.append(intern(marker))
            }
        }
        var groups: [Group] = [Group(gate: nil, substrings: ungatedSubstrings, suffixes: ungatedSuffixes)]
        for (index, gate) in gates.enumerated() {
            let subs = bySubstring[index] ?? []
            let sufs = bySuffix[index] ?? []
            if subs.isEmpty && sufs.isEmpty { continue }
            groups.append(Group(gate: intern(gate), substrings: subs, suffixes: sufs))
        }
        self.groups = groups
        self.gatedSuffixes = gatedSuffixes.map {
            GatedSuffixes(gate: intern($0.gate), suffixes: $0.suffixes.map(intern))
        }
        self.storage = storage
    }

    /// True iff the raw path bytes contain any substring marker or end with
    /// any suffix marker. Pure byte comparison: no decoding, no allocation.
    func matches(_ path: UnsafeRawBufferPointer) -> Bool {
        guard let base = path.baseAddress, path.count > 0 else { return false }
        let count = path.count
        return storage.withUnsafeBytes { store -> Bool in
            guard let markers = store.baseAddress else { return false }
            func contains(_ marker: Marker) -> Bool {
                marker.count <= count
                    && memmem(base, count, markers + marker.offset, marker.count) != nil
            }
            func hasSuffix(_ marker: Marker) -> Bool {
                marker.count <= count
                    && memcmp(base + (count - marker.count), markers + marker.offset, marker.count) == 0
            }
            for group in groups {
                if let gate = group.gate, !contains(gate) { continue }
                for marker in group.substrings where contains(marker) { return true }
                for marker in group.suffixes where hasSuffix(marker) { return true }
            }
            for gated in gatedSuffixes where contains(gated.gate) {
                for marker in gated.suffixes where hasSuffix(marker) { return true }
            }
            return false
        }
    }

    /// Convenience for a decoded path (worker stage, tests): reads the
    /// String's UTF-8 in place when it is contiguous.
    func matches(_ path: String) -> Bool {
        var copy = path
        return copy.withUTF8 { matches(UnsafeRawBufferPointer($0)) }
    }

    /// Match the `es_string_token_t` of a borrowed ES message in place.
    func matches(_ token: es_string_token_t) -> Bool {
        guard token.length > 0, let data = token.data else { return false }
        return matches(UnsafeRawBufferPointer(start: data, count: token.length))
    }
}
