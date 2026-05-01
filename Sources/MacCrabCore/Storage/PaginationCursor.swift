// PaginationCursor.swift
// MacCrabCore
//
// Keyset cursor for paginating Alerts/Events without OFFSET. Both tables
// are ordered DESC on (timestamp, id); a cursor captures the last row a
// caller saw and the next page query is "give me everything strictly
// before this point in the (timestamp, id) ordering."
//
// Why keyset over OFFSET: OFFSET N scans+discards N rows on every page,
// which gets expensive past page 5 on the events table (frequently >100K
// rows). Keyset is a constant-time index seek regardless of page depth.
// It's also stable under writes — new rows inserted between page fetches
// don't shift the window the user is paging through.

import Foundation

/// Captures the position of the last row returned by a paged store query.
/// Pass back into the same query to fetch the next older page.
///
/// Cursor ordering matches the table sort: (timestamp DESC, id DESC).
/// Two rows with the same timestamp are tie-broken by id (lexicographic
/// on the UUID string), which is stable because primary keys are unique.
public struct PaginationCursor: Sendable, Codable, Equatable, Hashable {
    public let timestamp: Date
    public let id: String

    public init(timestamp: Date, id: String) {
        self.timestamp = timestamp
        self.id = id
    }
}

/// One page of results plus the cursor a caller would pass back to fetch
/// the next page. `nextCursor == nil` means the result set is exhausted
/// — fewer than `limit` rows came back, so there's no more to read.
public struct PagedResults<Item: Sendable>: Sendable {
    public let items: [Item]
    public let nextCursor: PaginationCursor?

    public init(items: [Item], nextCursor: PaginationCursor?) {
        self.items = items
        self.nextCursor = nextCursor
    }
}
