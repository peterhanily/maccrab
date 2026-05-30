// TraceKeyPinStore.swift
// MacCrabCore
//
// v1.17 (storage-01) — TOFU (trust-on-first-use) pin store for trace
// bundle signing keys. This is the best-guess default anchor source for
// BundleVerifier.Options.pinnedKeyFingerprint when no install/fleet key
// and no operator-supplied --expect-key is available.
//
// Model: keyed by trace_id. The FIRST time a trace_id is verified we
// record the signing-key fingerprint we saw. On every later verify of the
// same trace_id we hand BundleVerifier that pinned fingerprint, so an
// in-place rewrite-and-resign (attacker swaps the embedded key) is caught.
// First-ever verify of an unseen trace_id is trusted (classic TOFU).
//
// The store is a small JSON map written atomically under the support dir.
// It is bounded by the number of distinct (trace_id) values ever verified.

import Foundation

public struct TraceKeyPinStore {

    private let fileURL: URL

    /// `directory` is the support dir, e.g. the same dir that holds the
    /// trace-graph DB. Defaults to the user support dir for ad-hoc CLI use.
    public init(directory: String = NSHomeDirectory() + "/Library/Application Support/MacCrab") {
        self.fileURL = URL(fileURLWithPath: directory)
            .appendingPathComponent("trace_key_pins.json")
    }

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    /// The fingerprint pinned for `traceId`, or nil if this trace_id has
    /// never been verified before.
    public func pinnedFingerprint(forTraceId traceId: String) -> String? {
        load()[traceId]
    }

    /// Record (trust-on-first-use) the fingerprint for `traceId`. No-op if a
    /// pin already exists — callers must NOT overwrite an existing pin, or
    /// the TOFU guarantee is lost.
    public func pinIfAbsent(traceId: String, fingerprint: String) {
        var map = load()
        guard map[traceId] == nil else { return }
        map[traceId] = fingerprint
        save(map)
    }

    // MARK: - Storage

    private func load() -> [String: String] {
        guard let data = try? Data(contentsOf: fileURL) else { return [:] }
        return (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
    }

    private func save(_ map: [String: String]) {
        guard let data = try? JSONEncoder().encode(map) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        // Atomic write; matches the simpler support-dir write style in this
        // codebase. If this store is ever relocated into the privileged
        // /Library path, switch to the O_NOFOLLOW symlink-safe pattern.
        try? data.write(to: fileURL, options: .atomic)
    }
}