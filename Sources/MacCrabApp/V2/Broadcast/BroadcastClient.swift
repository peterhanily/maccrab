// BroadcastClient.swift
//
// The broadcast consumer (docs spec §3/§4/§6). DORMANT in this build: the
// shipping app constructs it with `isEnabled == false` and no bundled public
// key, so `fetchNews` short-circuits to nil and the Overview keeps its bundled
// feed — NO network call is made. The verify→validate→map pipeline is fully
// implemented + unit-tested so it can "read safely" once the store + keyholder
// key go live.
//
// Safety properties enforced here:
//  - Ed25519 signature verified over the raw feed bytes BEFORE any parse/render.
//  - Fetch streams with a hard byte ceiling (decompression-bomb defense), a
//    same-host check (redirect/SSRF defense), a version-only User-Agent (no
//    fingerprint leak), no cookies, and a tight deadline.
//  - Anti-rollback high-water mark rejects a stale/replayed sequence.
//  - Future-skew + max-age ceiling bound how long one signed feed can show.
//  - EVERY failure path returns nil → the caller falls back to the bundled feed.

import Foundation
import CryptoKit
import MacCrabCore

/// Injectable transport so the pipeline is unit-testable without a network.
protocol BroadcastTransport {
    func fetch(_ url: URL, maxBytes: Int) async throws -> Data
}

/// Production transport: hardened, ephemeral, pinned-where-available session.
struct SecureBroadcastTransport: BroadcastTransport {
    func fetch(_ url: URL, maxBytes: Int) async throws -> Data {
        var req = URLRequest(url: url)
        req.timeoutInterval = 5
        req.httpShouldHandleCookies = false
        req.setValue("MacCrab/\(MacCrabVersion.current)", forHTTPHeaderField: "User-Agent")

        let (bytes, response) = try await SecureURLSession.shared.bytes(for: req)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw BroadcastError.fetchFailed(http.statusCode)
        }
        // Redirect/SSRF defense: the final host must equal the requested host.
        if let finalHost = response.url?.host?.lowercased(),
           let reqHost = url.host?.lowercased(), finalHost != reqHost {
            throw BroadcastError.redirected
        }
        // Stream with a hard ceiling — abort the moment we exceed it.
        var data = Data()
        data.reserveCapacity(min(maxBytes, 64 * 1024))
        for try await byte in bytes {
            data.append(byte)
            if data.count > maxBytes { throw BroadcastError.oversize }
        }
        return data
    }
}

struct BroadcastClient {
    let baseURL: URL
    let publicKey: Curve25519.Signing.PublicKey?
    let transport: BroadcastTransport
    let trustState: BroadcastTrustStateStore
    /// Opt-in master switch. DEFAULT false — dormant until a future release
    /// wires a visible opt-in + ships a production key.
    let isEnabled: Bool

    init(baseURL: URL,
         publicKey: Curve25519.Signing.PublicKey?,
         transport: BroadcastTransport = SecureBroadcastTransport(),
         trustState: BroadcastTrustStateStore,
         isEnabled: Bool = false) {
        self.baseURL = baseURL
        self.publicKey = publicKey
        self.transport = transport
        self.trustState = trustState
        self.isEnabled = isEnabled
    }

    private var feedURL: URL { baseURL.appendingPathComponent("broadcast.json") }
    private var sigURL: URL { baseURL.appendingPathComponent("broadcast.json.sig") }

    /// Dormant entry point. Returns nil unless the feature is enabled AND a key
    /// is bundled; any fetch/verify/parse failure also returns nil (fail-closed).
    /// Each fetch carries a 5 s request timeout (SecureBroadcastTransport), so
    /// the worst-case wall-clock is bounded without a task-group deadline.
    func fetchNews(now: Date = Date()) async -> [StoreNewsItem]? {
        guard isEnabled, publicKey != nil else { return nil }
        do {
            let feedData = try await transport.fetch(feedURL, maxBytes: BroadcastLimits.fetchByteCeiling)
            let sigData = try await transport.fetch(sigURL, maxBytes: 128)   // 64-byte Ed25519 sig + slack
            return try makeItems(from: feedData, signature: sigData, now: now)
        } catch {
            return nil
        }
    }

    /// Pure pipeline: verify → strict-decode → anti-rollback → sanitize → map.
    /// Throws on any rejection; the caller treats a throw as "keep bundled feed".
    func makeItems(from feedData: Data, signature sigData: Data, now: Date) throws -> [StoreNewsItem] {
        guard let key = publicKey else { throw BroadcastError.noKey }

        // 1. Ed25519 over the EXACT bytes, before anything else touches them.
        guard key.isValidSignature(sigData, for: feedData) else {
            throw BroadcastError.signatureInvalid
        }
        // 2. Size (defense in depth; the transport already capped the stream).
        guard feedData.count <= BroadcastLimits.maxDocumentBytes else {
            throw BroadcastError.oversize
        }
        // 3. Strict decode (rejects unknown keys) + structural caps.
        let feed = try JSONDecoder().decode(BroadcastFeed.self, from: feedData)
        try feed.validateStructure()

        // 4. Reject a future-skewed issuedAt.
        if feed.issuedAt.timeIntervalSince(now) > BroadcastLimits.maxClockSkew {
            throw BroadcastError.badTimestamp("future issuedAt")
        }
        // 5. Anti-rollback.
        switch trustState.evaluate(incoming: feed.sequence) {
        case .rollback(let s, let i): throw BroadcastError.rollback(stored: s, incoming: i)
        case .firstSeen, .accepted: break
        }

        // 6. Map with per-field sanitization + the max-display-age ceiling.
        let ceiling = feed.issuedAt.addingTimeInterval(BroadcastLimits.maxDisplayAge)
        let effectiveExpiry = min(feed.expiresAt ?? ceiling, ceiling)
        var items: [StoreNewsItem] = []
        if now <= effectiveExpiry {
            for raw in feed.items {
                guard let title = BroadcastSanitizer.sanitizeTitle(raw.title),
                      let summary = BroadcastSanitizer.sanitizeSummary(raw.summary) else { continue }
                let badge = raw.badge.flatMap { BroadcastBadge(rawValue: $0)?.rawValue }
                // id is an identity key, not rendered today — but sanitize + cap
                // it defensively so a future view can never surface a hostile id.
                let safeID = String(BroadcastSanitizer.stripDangerous(raw.id).prefix(BroadcastLimits.maxIDChars))
                items.append(StoreNewsItem(id: safeID.isEmpty ? UUID().uuidString : safeID,
                                           title: title, summary: summary, badge: badge))
            }
        }
        // 7. Advance the high-water mark only after fully accepting the feed.
        try? trustState.record(serial: feed.sequence)
        return items
    }

    /// Load the bundled Ed25519 public key (mirrors the catalog key lookup). nil
    /// in this build — no `broadcast.pub` is shipped, which keeps the feature
    /// dormant + fail-closed.
    static func loadBundledKey(bundle: Bundle = .main) -> Curve25519.Signing.PublicKey? {
        let candidates = [
            bundle.url(forResource: "broadcast", withExtension: "pub"),
            bundle.resourceURL?.appendingPathComponent("rave-keys/broadcast.pub"),
            bundle.resourceURL?.appendingPathComponent("MacCrab_MacCrabApp.bundle/broadcast.pub"),
        ].compactMap { $0 }
        for url in candidates {
            if let data = try? Data(contentsOf: url),
               let key = try? Curve25519.Signing.PublicKey(rawRepresentation: data) {
                return key
            }
        }
        return nil
    }
}
