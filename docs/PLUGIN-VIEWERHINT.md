# Plugin viewer hints

This is the guide for plugin authors — first-party or third-party
publishing via the rave catalog — who want their plugin's
output to render with proper graphical layout inside the
MacCrab dashboard.

If your plugin doesn't declare a viewer hint, the dashboard
falls back to a generic JSON tree view. Hint-less plugins
work; they just look bare.

## Why declarative

You can't ship Swift / SwiftUI code that MacCrab dynamically
loads — Swift has no runtime linker, and Tier B subprocess
plugins can't render UI anyway. So plugins describe their
output's shape and the host renders it.

The hint is structurally small: which viewer + which fields
play which role. The host ships 5 viewers; new viewers benefit
every plugin.

## Where the hint lives

Inside the `OutputSpec` in your plugin's manifest:

```swift
public static let manifest = PluginManifest(
    id: "com.example.forensics.coolthing",
    ...
    outputs: [
        OutputSpec(
            contentType: "coolthing.event",
            privacyClass: .metadata,
            viewerHint: ViewerHint(
                viewer: .timeline,
                fieldRoles: [
                    "observed_at": .timestamp,
                    "name":        .title,
                    "source":      .subtitle,
                ]
            )
        ),
    ],
    ...
)
```

One hint per content type. A plugin emitting three content types
declares three hints — one per `OutputSpec`.

## The 5 built-in viewers

### `.table`

Sortable, searchable columnar table. Each artifact is a row.

**Use for:** structured metadata where the operator scans across
many artifacts (launchd entries, TCC grants, codesigning rows,
posture findings, FaceTime calls, file analyses).

**Required roles:** none, but you'll want `.title` and at least
one `.timestamp` or `.status` for the columns to be useful.

**Optional config:**
- `columns`: explicit ordered column list (overrides role-driven defaults)
- `groupBy`: field to group rows by

### `.timeline`

Chronological list grouped by day. Each artifact is a marker
on a vertical time spine.

**Use for:** anything with a natural time ordering (browser
history, downloads, quarantine, KnowledgeC, Biome, iMessage URLs).

**Required roles:** `.timestamp` (host falls back to
`record.observedAt` if no field is declared).

**Optional:**
- `groupBy`: visual subdivider per group value
- `.title`, `.subtitle` for what to show in each marker

### `.keyvalue`

Split view: left panel picks one artifact, right panel shows
all its fields with role-driven formatting (paths in monospace,
URLs as links, timestamps formatted, counts as numerals).

**Use for:** rich single-artifact inspection (codesign graph
node, plist parse, Mach-O analysis, DMG/PKG analysis).

**Required roles:** none, but field-roles drive presentation
order.

### `.transcript`

Chat-bubble layout: sender + timestamp + body. Bubbles align
right when sender is "me" (bool true) and left when "them".

**Use for:** sequence-of-messages content (iMessage threads,
Mail bodies, AppleScript invocations).

**Required roles:** `.sender`, `.timestamp`, `.body` (host
falls back to `summary` for body if absent).

### `.layout`

Escape hatch. Plugin supplies a `LayoutNode` template; host
walks it and renders. Use when none of the above fit.

**Required:** `template` field. See "DSL" below.

## Field roles

The host doesn't read field names — it reads roles. You map
your plugin's field names to roles in the `fieldRoles`
dictionary.

| Role | Use for | Rendered as |
|---|---|---|
| `.timestamp` | ISO-8601 string or epoch int | Sort key + time spine label |
| `.title` | Primary one-line label | Prominent, all viewers |
| `.subtitle` | Secondary label | Below title, secondary color |
| `.body` | Long-form text | Paragraph in KV / transcript |
| `.sender` | "From whom" | Aligns transcript bubbles; bool true = right |
| `.status` | Pass/fail/etc. | Status pill |
| `.severity` | routine/notable/attention/critical | Row tint |
| `.count` | Numeric value | Right-aligned column |
| `.link` | URL | Clickable, accent color |
| `.path` | Filesystem path | Monospace, middle truncated |
| `.identifier` | Hash/GUID/etc. | Monospace, selectable |

You can map multiple fields to the same role. The viewer
picks the first match in priority order.

The host always knows about record-level fields without you
declaring them:
- `observed_at`, `captured_at`
- `summary`
- `plugin_id`, `content_type`, `sha256`, `source_path`

You only need to declare hints for fields inside the
`data` payload.

## Worked example — Safari history

```swift
OutputSpec(
    contentType: "safari.history_visit",
    privacyClass: .metadata,
    viewerHint: ViewerHint(
        viewer: .timeline,
        fieldRoles: [
            "observed_at":         .timestamp,
            "url":                 .title,
            "domain":              .subtitle,
            "title":               .body,
            "visit_count_at_url":  .count,
        ],
        groupBy: "domain"
    )
)
```

Resulting render: one vertical day-grouped timeline, each visit
shows the URL as the prominent label, the domain underneath,
and groups by domain so all visits to the same site cluster.

## DSL — for `.layout`

```swift
viewerHint: ViewerHint(
    viewer: .layout,
    fieldRoles: [:],
    template: .section(
        title: "Process",
        children: [
            .headerKV(label: "Binary",       field: "program_path", format: .path),
            .row(    label: "Signed by",     field: "team_id",      format: .monospace),
            .row(    label: "Runs at load",  field: "run_at_load",  format: .boolYesNo),
            .list(   label: "Arguments",     field: "arguments_json"),
            .badge(  label: "Status",        field: "signing_status", color: "orange"),
            .text(   content: "Inspected by launchd-lite v0.1.0"),
        ]
    )
)
```

Primitives:
- `.section(title, children)` — collapsible group
- `.row(label, field, format?)` — labeled value
- `.headerKV(label, field, format?)` — prominent KV display
- `.list(label, field)` — array field as bulleted list
- `.badge(label, field, color?)` — chip with field value
- `.text(content)` — literal explanatory text

Format options:
`.plain`, `.bold`, `.muted`, `.monospace`, `.path`, `.date`,
`.isoDate`, `.boolYesNo`, `.boolArrow`, `.urlLink`, `.integerCount`.

Keep templates short. If you find yourself wanting more than
12 nodes, you probably want a different `.viewer` instead — or
file an issue against MacCrab asking for a new ViewerKind.

## Fallback behavior

- No `viewerHint` on the OutputSpec → JSON tree view
- `viewer = .layout` without a `template` → JSON tree view
  (and a warning banner)
- Field name in a role mapping doesn't exist in any artifact
  → that role is skipped silently
- Timeline with no `.timestamp` role → falls back to
  `record.observedAt`

## Testing your hint locally

1. Add the `viewerHint` to your OutputSpec
2. Build + run MacCrab
3. Run a scan that exercises your plugin
4. Open the scan from the Past Scans tab
5. Click your plugin's content type in the left sidebar
6. The viewer dispatcher uses your hint

The hint is purely runtime — no manifest schema regeneration
required. Change → build → test.

## Reading the result format

When the dashboard exports your artifacts (CSV / JSON
buttons in the scan detail view), the export includes every
field — not just the ones you declared roles for. The hint is
purely a rendering aid; nothing is hidden because of it.

## Extending the host

If you need a viewer kind that doesn't exist, file an issue
in the MacCrab repo (https://github.com/peterhanily/maccrab/issues)
with:
- Sample content type your plugin emits
- A sketch of the layout you'd want
- Why the existing 5 viewers don't fit

New viewers benefit every plugin author — they ship in the
next MacCrab release without you changing your plugin.
