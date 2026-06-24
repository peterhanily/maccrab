// BroadcastLinkValidator.swift
//
// Validation for a broadcast item's optional `link` (docs spec §5.4). A link is
// the single highest-risk field — the only non-text affordance — so this is
// deliberately strict and "reject, don't repair". On success it returns the
// validated ASCII host (the ONLY payload-derived string the app may display)
// and the safe URL the app reconstructs; on any doubt it returns nil and the
// item renders without a link.
//
// NOTE: this build does not yet RENDER broadcast links (the news surface is
// text-only), but the validator is implemented + unit-tested so the security
// logic exists and is proven before any link is ever shown.

import Foundation

struct ValidatedLink: Equatable {
    /// ASCII/A-label host, lowercased — safe to display verbatim, and the only
    /// payload-derived component of the app-controlled link label.
    let host: String
    /// The URL the app reconstructs from the validated scheme + host + path —
    /// opened externally (NSWorkspace.open) only on an explicit operator tap.
    let safeURL: URL
}

enum BroadcastLinkValidator {

    /// Publisher's own domains only. `support.apple.com` is intentionally NOT
    /// here — Apple-doc links come from the app's own static guide, never from a
    /// remote broadcast.
    static let allowedHosts: Set<String> = ["maccrab.com", "rave.maccrab.com"]

    /// Returns a ValidatedLink, or nil if the link must be dropped.
    static func validate(_ raw: String) -> ValidatedLink? {
        // Parse twice: URL for the A-label host, URLComponents for authority
        // introspection (user/password/port). Both must agree it's clean.
        guard let url = URL(string: raw),
              let comps = URLComponents(string: raw) else { return nil }

        // Scheme: exactly https.
        guard url.scheme?.lowercased() == "https" else { return nil }

        // No credentials in the authority.
        if comps.user != nil || comps.password != nil { return nil }
        if raw.contains("@") { return nil }

        // Default port only.
        if let port = comps.port, port != 443 { return nil }

        // Host: take the A-label form from URL.host (encoded), lowercase, strip
        // a trailing dot. Reject percent-encoding or any non-host character.
        guard var host = url.host?.lowercased() else { return nil }
        if host.hasSuffix(".") { host.removeLast() }
        if host != host.removingPercentEncoding { return nil }
        let allowedChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-")
        if host.unicodeScalars.contains(where: { !allowedChars.contains($0) }) { return nil }

        // Exact allow-list match — never suffix/prefix/contains.
        guard allowedHosts.contains(host) else { return nil }

        // Reconstruct a safe URL from validated scheme + host (+ path/query the
        // operator can inspect). We deliberately rebuild rather than reuse the
        // raw string so no hidden authority trick rides along.
        var safe = URLComponents()
        safe.scheme = "https"
        safe.host = host
        safe.path = comps.path
        safe.query = comps.query
        guard let safeURL = safe.url else { return nil }

        return ValidatedLink(host: host, safeURL: safeURL)
    }
}
