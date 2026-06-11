// RaveInstallLink — O3c (S2-07) parser for `maccrab://install/...` deep links.
//
//   maccrab://install/plugin/<plugin-id>
//   maccrab://install/kit/<kit-id>
//
// SECURITY CONTRACT (the whole point of this type):
//   - The link carries ONLY an id. Never a digest, URL, version, file path,
//     signer key, or any other install parameter. Everything load-bearing is
//     resolved from the PINNED, signature-verified catalog — not the link.
//   - A link whose id fails strict validation is REJECTED (returns nil). The
//     id becomes a directory name + a catalog key, so its shape is part of the
//     security boundary; we reuse PluginInstaller.validatePluginID.
//   - Parsing NEVER triggers an install. The app turns a parsed link into a
//     consent sheet; only an explicit operator confirm proceeds.
//
// This is a pure value type with no I/O so it can be unit-tested exhaustively
// against hostile inputs.

import Foundation
import MacCrabForensics

/// A validated install intent extracted from a `maccrab://install/...` URL.
public struct RaveInstallLink: Equatable, Sendable, Identifiable {
    public enum Kind: String, Equatable, Sendable {
        case plugin
        case kit
    }
    public let kind: Kind
    /// The resolved id. Guaranteed to have passed
    /// `PluginInstaller.validatePluginID` — safe to use as a catalog key and
    /// (for plugins) a directory name.
    public let id: String

    public init(kind: Kind, id: String) {
        self.kind = kind
        self.id = id
    }

    /// Parse + validate. Returns nil for anything that isn't EXACTLY a
    /// `maccrab://install/{plugin|kit}/<valid-id>` with no extra payload.
    ///
    /// Rejected (non-exhaustive): query items, fragments, embedded URLs,
    /// digests, version pins, path traversal, extra path segments, an id that
    /// fails validatePluginID, or a userinfo/port-bearing authority.
    public static func parse(_ url: URL) -> RaveInstallLink? {
        guard url.scheme == V2DeepLink.scheme else { return nil }
        guard url.host == "install" else { return nil }

        // Reject ANY extra payload channel. The contract is "id only", so a
        // link that smuggles a query (?digest=...), a fragment, userinfo, or a
        // port is refused outright rather than ignored — refusing is louder.
        guard url.query == nil, url.fragment == nil else { return nil }
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) {
            if comps.user != nil || comps.password != nil || comps.port != nil {
                return nil
            }
            // queryItems present even with an empty value → reject.
            if let items = comps.queryItems, !items.isEmpty { return nil }
        }

        // Path must be exactly /{plugin|kit}/<id> — two non-empty segments.
        let segments = url.path
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
        guard segments.count == 2 else { return nil }
        guard let kind = Kind(rawValue: segments[0]) else { return nil }
        let rawID = segments[1]

        // The id must survive percent-decoding to itself — a link that relied
        // on percent-encoding to hide a separator (e.g. %2F) is rejected.
        guard let decoded = rawID.removingPercentEncoding, decoded == rawID else {
            return nil
        }

        // Strict id validation — the same boundary the installer enforces.
        // Rejects path separators, traversal, leading dots, control chars, etc.
        do {
            try PluginInstaller.validatePluginID(rawID)
        } catch {
            return nil
        }
        return RaveInstallLink(kind: kind, id: rawID)
    }
}
