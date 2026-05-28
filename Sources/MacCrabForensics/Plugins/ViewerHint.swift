// ViewerHint — declarative rendering schema for a plugin's
// emitted artifacts. Lets a plugin tell the dashboard how to
// present its output without shipping any UI code.
//
// rc.13 lands the schema + four built-in viewers (table /
// timeline / keyvalue / transcript) + a small layout DSL escape
// hatch. Third-party plugins distributed via the rave catalog
// pick a viewer + a field-role map; the host renders.
//
// Plan reference: docs/PLUGIN-VIEWERHINT.md.
//
// Backwards compatible: every existing OutputSpec works without
// a viewerHint (renderer falls back to the JSON tree view).

import Foundation

/// How an artifact group should be rendered. Lives inside the
/// plugin manifest's OutputSpec so plugins ship their hint
/// alongside the content type declaration.
public struct ViewerHint: Codable, Sendable, Hashable {

    /// Which built-in viewer to use.
    public let viewer: ViewerKind

    /// Map artifact-data field name → semantic role. The viewer
    /// uses this to pick out which fields are the timestamp,
    /// the title, the sender, etc. Example for safari.history_visit:
    ///   `["observed_at": .timestamp, "url": .title, "domain": .subtitle]`
    public let fieldRoles: [String: FieldRole]

    /// For viewer = .table : ordered column field names.
    /// Defaults to the field-role-derived columns + the field
    /// names with role .count / .status not already used.
    public let columns: [String]?

    /// For viewer = .table or .timeline : optional grouping field.
    /// e.g. safari.history_visit grouped by "domain" gives one
    /// timeline row per site.
    public let groupBy: String?

    /// For viewer = .layout : the recursive layout template.
    /// Ignored when viewer != .layout.
    public let template: LayoutNode?

    /// For viewer = .chart : the chart sub-shape + the fields it
    /// reads. Ignored when viewer != .chart.
    public let chart: ChartHint?

    public init(
        viewer: ViewerKind,
        fieldRoles: [String: FieldRole] = [:],
        columns: [String]? = nil,
        groupBy: String? = nil,
        template: LayoutNode? = nil,
        chart: ChartHint? = nil
    ) {
        self.viewer = viewer
        self.fieldRoles = fieldRoles
        self.columns = columns
        self.groupBy = groupBy
        self.template = template
        self.chart = chart
    }

    enum CodingKeys: String, CodingKey {
        case viewer, fieldRoles, columns, groupBy, template, chart
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.viewer = try c.decode(ViewerKind.self, forKey: .viewer)
        self.fieldRoles = try c.decodeIfPresent([String: FieldRole].self, forKey: .fieldRoles) ?? [:]
        self.columns = try c.decodeIfPresent([String].self, forKey: .columns)
        self.groupBy = try c.decodeIfPresent(String.self, forKey: .groupBy)
        self.template = try c.decodeIfPresent(LayoutNode.self, forKey: .template)
        self.chart = try c.decodeIfPresent(ChartHint.self, forKey: .chart)
    }
}

/// Built-in viewer kinds. Adding a new viewer here is a host
/// change — plugins automatically gain access on next release.
public enum ViewerKind: String, Codable, Sendable, CaseIterable {
    /// Sortable, searchable columnar table.
    /// Use for: structured metadata where each artifact is one
    /// row and the operator wants to scan + sort across them
    /// (launchd entries, TCC grants, codesigning binaries).
    case table

    /// Horizontal time axis with markers for each artifact.
    /// Requires a field with role .timestamp.
    /// Use for: anything with a natural time ordering (browser
    /// history, quarantine events, KnowledgeC activity).
    case timeline

    /// Detail panel: nested key-value inspection of one artifact
    /// at a time, with field-role decoration.
    /// Use for: complex single-object analyses (Mach-O parse,
    /// plist analysis, codesign graph node detail).
    case keyvalue

    /// Sender + timestamp + body sequence — feels like reading
    /// a chat or email thread. Requires .sender + .timestamp
    /// + .body field roles.
    /// Use for: iMessage threads, Mail message bodies,
    /// AppleScript invocation history.
    case transcript

    /// Renders the LayoutNode template field. Escape hatch for
    /// plugins whose output doesn't fit table/timeline/keyvalue/
    /// transcript naturally.
    case layout

    /// Visualization viewer. Sub-shape (histogram / bar / network)
    /// declared in the ViewerHint's `chart` field. Falls back to
    /// table if `chart` is nil.
    case chart
}

// MARK: - Chart hint

/// Sub-schema for viewer = .chart. Picks which chart shape to
/// render and which fields drive it.
public struct ChartHint: Codable, Sendable, Hashable {
    public let chartType: ChartType

    /// For histogram: the timestamp field name (host falls back
    /// to record.observedAt if nil).
    public let bucketField: String?

    /// For histogram: bucket granularity.
    public let bucket: HistogramBucket?

    /// For bar: the categorical field name to group by.
    public let groupField: String?

    /// For network: which artifact-data field carries the edge
    /// target. The artifact itself becomes a source node; the
    /// value in edgeField becomes the target node.
    public let edgeField: String?

    public init(
        chartType: ChartType,
        bucketField: String? = nil,
        bucket: HistogramBucket? = nil,
        groupField: String? = nil,
        edgeField: String? = nil
    ) {
        self.chartType = chartType
        self.bucketField = bucketField
        self.bucket = bucket
        self.groupField = groupField
        self.edgeField = edgeField
    }
}

public enum ChartType: String, Codable, Sendable, CaseIterable {
    /// Bar chart of artifact counts per time bucket. Requires
    /// a timestamp field (defaults to record.observedAt).
    case histogram

    /// Bar chart of artifact counts per categorical field.
    /// Top 20 + "Other".
    case bar

    /// Node-edge graph: each artifact is a node; edges drawn
    /// from the artifact to the value in `edgeField`.
    case network
}

public enum HistogramBucket: String, Codable, Sendable {
    case minute, hour, day, week, month
}

/// Semantic role a field plays in the viewer. The plugin
/// declares the map; the viewer reads it to pick which field is
/// which. Adding a new role here is a host change.
public enum FieldRole: String, Codable, Sendable, CaseIterable {
    /// ISO-8601 string or epoch-seconds int — used as the time
    /// axis in timelines and the sort key by default in tables.
    case timestamp
    /// Primary one-line label, prominent in every viewer.
    case title
    /// Secondary one-line label below the title.
    case subtitle
    /// Long-form text body — rendered as a paragraph in
    /// keyvalue / transcript.
    case body
    /// "From whom" — used in transcript viewer to align messages
    /// left vs right and to label rows.
    case sender
    /// Pass / fail / running / etc. — rendered as a status pill.
    case status
    /// Severity (routine / notable / attention / critical).
    /// Drives row color when present.
    case severity
    /// Numeric — surfaced as a prominent figure in keyvalue and
    /// as a right-aligned column in table.
    case count
    /// URL — rendered as a clickable link in any viewer.
    case link
    /// Filesystem path — rendered in monospace with middle
    /// truncation in tables / keyvalue.
    case path
    /// Identifier (hash, GUID, plugin id) — monospace, copyable.
    case identifier
}

// MARK: - Layout DSL

/// Recursive layout template. Plugins that pick viewer = .layout
/// supply a tree of these to describe their custom layout. The
/// host walks the tree and emits SwiftUI views.
///
/// Deliberately small primitive set — escape hatch, not a full
/// UI compiler. If a plugin needs more, the right answer is to
/// add a new ViewerKind to the host (and benefit every plugin).
public indirect enum LayoutNode: Codable, Sendable, Hashable {

    /// A titled section containing children.
    case section(title: String?, children: [LayoutNode])

    /// One labeled row inside a section.
    case row(label: String, field: String, format: LayoutFormat?)

    /// A prominent key-value display (label + big value).
    case headerKV(label: String, field: String, format: LayoutFormat?)

    /// Array field rendered as bulleted list.
    case list(label: String, field: String)

    /// Colored chip / badge — value comes from a field.
    case badge(label: String, field: String, color: String?)

    /// Literal text (no field interpolation — keep it simple).
    case text(content: String)
}

/// Format hint for rendering a field value.
public enum LayoutFormat: String, Codable, Sendable, CaseIterable {
    case plain
    case bold
    case muted
    case monospace
    case path        // monospace + middle truncation
    case date        // localized friendly date
    case isoDate     // ISO-8601 absolute timestamp
    case boolYesNo   // true → "Yes" / false → "No"
    case boolArrow   // true → "→ Sent" / false → "← Received"
    case urlLink     // clickable
    case integerCount
}
