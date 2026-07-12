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
//
// A3-03 (root-own the pin store): the pinned trust anchors are what the
// verifier hands `BundleVerifier.pinnedKeyFingerprint`, so the pin FILE is
// itself security-relevant — a writer who can redirect or overwrite it can
// poison the anchor. Writes therefore go through the codebase's O_NOFOLLOW
// privileged-write pattern (temp file created O_EXCL|O_NOFOLLOW at 0o600, then
// atomically rename()d over the target), and reads refuse to follow a symlink.
// When the production store lives under root-owned `/Library/Application
// Support/MacCrab/`, 0o600 + root ownership makes it non-user-writable and a
// non-root process cannot poison it.
//
// Advisory limitation — SAME-HOST / SAME-UID TOFU: this hardening stops
// cross-uid symlink redirection and non-root overwrite, but a process running
// AS the owning uid can still rewrite an owned pin file, and first-ever verify
// of an unseen trace_id is trusted by construction (classic TOFU). The strong
// anchor for those cases is an out-of-band `--expect-key` fingerprint, whose
// behavior is unchanged. Local root remains out of scope (docs/THREAT_MODEL.md).

import Foundation
import Darwin

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
        // O_NOFOLLOW read (SecureFileIO): a symlink planted at the pin path is
        // refused rather than silently followed to an attacker-chosen file.
        // Any failure (missing file, symlink, unreadable) → empty map, so a
        // poisoned/absent file fails safe to "no pins" (first-use TOFU) rather
        // than loading an attacker's map. 1 MiB cap bounds a hostile file.
        guard let data = try? SecureFileIO.readBytes(at: fileURL.path, maxBytes: 1 << 20) else {
            return [:]
        }
        return (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
    }

    private func save(_ map: [String: String]) {
        guard let data = try? JSONEncoder().encode(map) else { return }
        let dir = fileURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // Symlink-safe atomic overwrite (mirrors the codebase's privileged-write
        // pattern): create a fresh temp file with O_EXCL|O_NOFOLLOW at 0o600 via
        // SecureFileIO, then rename() it over the target. rename replaces the
        // destination NAME atomically without following a symlink there, and the
        // 0o600 mode is applied to the temp before it becomes visible, so a
        // reader never observes an over-permissive or partial pin file.
        let tempPath = dir.appendingPathComponent(
            ".tmp-\(UUID().uuidString)-\(fileURL.lastPathComponent)"
        ).path
        do {
            try SecureFileIO.atomicCreate(at: tempPath, data: data, mode: 0o600)
        } catch {
            return
        }
        let renamed = tempPath.withCString { c1 in
            fileURL.path.withCString { c2 in rename(c1, c2) }
        }
        if renamed != 0 {
            // Rename failed (e.g. destination is a directory) — drop the temp
            // rather than leaving it behind.
            try? FileManager.default.removeItem(atPath: tempPath)
        }
    }
}