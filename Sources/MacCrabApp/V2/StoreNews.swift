// StoreNews.swift
//
// Lightweight "store updates & news" feed surfaced on the Overview alongside
// forensics/plugins + the plugin store. v1 is a BUNDLED, curated feed — a
// default install makes NO network request for it, consistent with MacCrab's
// on-device-by-default posture. The model is ready to be backed by a signed,
// fetched feed when the rave store goes live (opt-in, like enrichment).

import Foundation

struct StoreNewsItem: Identifiable, Hashable {
    let id: String
    let title: String
    let summary: String
    /// A short status chip, e.g. "Update" / "New". nil = no chip.
    let badge: String?
}

enum StoreNews {
    /// The bundled feed, parameterized by the running app version so the
    /// "what's new" item stays accurate without a network call.
    static func bundled(appVersion: String) -> [StoreNewsItem] {
        [
            StoreNewsItem(
                id: "store-catalog",
                title: "Signed plugin catalog",
                summary: "Browse the signed forensic-plugin catalog. Installs run fully sandboxed on this Mac.",
                badge: nil),
            StoreNewsItem(
                id: "whats-new",
                title: "What\u{2019}s new in \(appVersion)",
                summary: "Privacy-by-default enrichment (all network feeds off until you opt in), a richer forensics platform, and tighter detection tuning.",
                badge: "Update"),
            StoreNewsItem(
                id: "builtins",
                title: "Built-in scanners, no install",
                summary: "25+ first-party forensic collectors are ready now \u{2014} scan this Mac from the Forensics tab without installing anything.",
                badge: nil),
        ]
    }
}
