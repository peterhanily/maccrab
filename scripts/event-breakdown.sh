#!/usr/bin/env bash
# event-breakdown.sh
#
# Diagnostic for events.db insert volume + composition. Used to validate
# EventInsertFilter coverage on real data — runs the same SQL we ran by
# hand on 2026-05-02 to discover the field-measured noise distribution.
#
# Reads /Library/Application Support/MacCrab/events.db by default (the
# root sysext's DB). For the dev-mode user-uid daemon, pass the path
# explicitly:
#
#     ./scripts/event-breakdown.sh ~/Library/Application\ Support/MacCrab/events.db
#
# The system path is root-readable only; invoke under sudo. The user-uid
# path needs no sudo. The script does not write to the DB.

set -euo pipefail

DB="${1:-/Library/Application Support/MacCrab/events.db}"

if [[ ! -f "$DB" ]]; then
    echo "events.db not found at: $DB" >&2
    echo "Pass an explicit path as \$1 if you mean a different one." >&2
    exit 1
fi

if [[ ! -r "$DB" ]]; then
    echo "events.db is not readable as $(whoami): $DB" >&2
    echo "If this is /Library/Application Support/MacCrab/events.db, re-run under sudo." >&2
    exit 1
fi

sqlite3 "$DB" <<'SQL'
.mode column
.headers on
SELECT 'TOTAL' AS bucket,
       COUNT(*) AS n,
       MIN(datetime(timestamp,'unixepoch')) AS oldest,
       MAX(datetime(timestamp,'unixepoch')) AS newest
FROM events;

.print
.print -- Top 15 process_name by count
SELECT process_name,
       COUNT(*) AS n,
       ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM events), 1) AS pct
FROM events
GROUP BY process_name
ORDER BY n DESC
LIMIT 15;

.print
.print -- Top 15 process_path by count
SELECT process_path,
       COUNT(*) AS n,
       ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM events), 1) AS pct
FROM events
GROUP BY process_path
ORDER BY n DESC
LIMIT 15;

.print
.print -- Top 10 event_category by count
SELECT event_category,
       COUNT(*) AS n,
       ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM events), 1) AS pct
FROM events
GROUP BY event_category
ORDER BY n DESC
LIMIT 10;

.print
.print -- Top 15 file_path by count
SELECT file_path, COUNT(*) AS n
FROM events
WHERE file_path IS NOT NULL
GROUP BY file_path
ORDER BY n DESC
LIMIT 15;

.print
.print -- Aggregated tier (event_aggregates table — daily rollups)
SELECT day,
       COUNT(*) AS distinct_buckets,
       SUM(count) AS total_events
FROM event_aggregates
GROUP BY day
ORDER BY day DESC
LIMIT 7;
SQL
