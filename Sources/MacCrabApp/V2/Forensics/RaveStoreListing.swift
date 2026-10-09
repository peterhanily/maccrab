// RaveStoreListing.swift
//
// How the plugin catalog browser names, describes and searches an entry. A
// signed catalog entry is named and described by the catalog itself
// (`display_name`, `short_description`), never by MacCrab's local name table.
// A built-in row is not a signed catalog entry, so it keeps MacCrab's local
// name and description. Pure, so the view and the tests share one definition.

import Foundation

enum RaveStoreListing {

    /// The name on the card and in the detail header, also used for sorting.
    static func name(_ e: RaveCatalogEntry, isBuiltin: Bool) -> String {
        if isBuiltin { return ScannerDisplay.name(forPluginID: e.id) }
        let signed = e.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        return signed.isEmpty ? e.id : signed
    }

    /// The signed one-line description of a catalog entry for "What it does".
    /// nil for a built-in row, or when the entry omits it; the caller then
    /// falls back to the local description.
    static func signedDescription(_ e: RaveCatalogEntry, isBuiltin: Bool) -> String? {
        guard !isBuiltin,
              let d = e.shortDescription?.trimmingCharacters(in: .whitespacesAndNewlines),
              !d.isEmpty else { return nil }
        return d
    }

    /// Whether `query` (trimmed, case-insensitive) appears in the entry's name,
    /// id, category, tags or signed description. An empty query matches all.
    static func matches(_ e: RaveCatalogEntry, query: String, isBuiltin: Bool) -> Bool {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return true }
        let hay = ([name(e, isBuiltin: isBuiltin), e.id, e.category ?? "",
                    signedDescription(e, isBuiltin: isBuiltin) ?? ""] + e.tags)
            .joined(separator: " ").lowercased()
        return hay.contains(q)
    }
}
