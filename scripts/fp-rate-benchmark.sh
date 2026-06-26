#!/usr/bin/env bash
# fp-rate-benchmark.sh — measure MacCrab's per-rule false-positive RATE on a
# benign machine, so the project can publish real numbers instead of a single
# reference-machine figure.
#
# How to use: run MacCrab normally (detection-only — do NOT arm any response
# actions) for a measurement window (default: the last 28 days of accumulated
# alerts), doing your ordinary work, then run this script. It reads the alert
# store, computes per-rule alerts/day, and emits a privacy-safe JSON summary
# (rule ids + counts + coarse machine metadata only — NEVER event contents,
# paths, or hostnames). See BENCHMARK.md for the methodology and how to submit.
#
# Usage:
#   scripts/fp-rate-benchmark.sh [--days N] [--output FILE] [--db PATH]
set -euo pipefail

DAYS=28
OUTPUT=""
DB=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --days)   DAYS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --db)     DB="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Resolve the alert store: the root System Extension writes to /Library; a
# non-root dev daemon writes to ~/Library.
if [[ -z "$DB" ]]; then
  for cand in "/Library/Application Support/MacCrab/alerts.db" \
              "$HOME/Library/Application Support/MacCrab/alerts.db"; do
    [[ -f "$cand" ]] && { DB="$cand"; break; }
  done
fi
[[ -n "$DB" && -f "$DB" ]] || { echo "ERROR: alerts.db not found (pass --db PATH)" >&2; exit 1; }

OUTPUT="${OUTPUT:-./fp_benchmark_$(date +%Y%m%d).json}"
SINCE=$(( $(date +%s) - DAYS * 86400 ))
OS_VER=$(sw_vers -productVersion 2>/dev/null || echo "?")
ARCH=$(uname -m)

echo "MacCrab FP-rate benchmark"
echo "  store:  $DB"
echo "  window: last ${DAYS} days   (macOS ${OS_VER} / ${ARCH})"
echo ""

# Per-rule counts over the window. Privacy: rule_id + rule_title + count ONLY.
ROWS=$(sqlite3 -separator $'\t' "$DB" \
  "SELECT rule_id, COUNT(*) c, MIN(severity) FROM alerts
   WHERE timestamp > ${SINCE}
   GROUP BY rule_id ORDER BY c DESC;" 2>/dev/null || true)

TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts WHERE timestamp > ${SINCE};" 2>/dev/null || echo 0)
DISTINCT=$(echo "$ROWS" | grep -c $'\t' || true)

echo "  total alerts in window: ${TOTAL}   (${DISTINCT} distinct rules fired)"
echo ""
printf "  %-46s %8s %10s\n" "rule_id" "count" "per_day"
echo "  ----------------------------------------------------------------------"
echo "$ROWS" | while IFS=$'\t' read -r rid c sev; do
  [[ -z "$rid" ]] && continue
  per_day=$(echo "scale=2; $c / $DAYS" | bc 2>/dev/null || echo "?")
  printf "  %-46s %8s %10s\n" "${rid:0:46}" "$c" "$per_day"
done

# Privacy-safe JSON for submission (see CONTRIBUTING_FP_DATA.md).
python3 - "$ROWS" "$DAYS" "$TOTAL" "$OS_VER" "$ARCH" "$OUTPUT" <<'PY'
import sys, json
rows_raw, days, total, os_ver, arch, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
rules = []
for line in rows_raw.splitlines():
    parts = line.split("\t")
    if len(parts) >= 2 and parts[0]:
        rid, c = parts[0], int(parts[1])
        rules.append({"rule_id": rid, "count": c, "per_day": round(c/days, 3)})
payload = {
    "schema": "maccrab.fp_benchmark.v1",
    "window_days": days,
    "total_alerts": total,
    "machine": {"macos": os_ver, "arch": arch},   # coarse metadata only
    "rules": rules,                                # rule ids + counts only — NO contents/paths/hostnames
}
with open(out, "w") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
print(f"\n  Privacy-safe summary written → {out}")
print("  Review it (rule ids + counts only), then submit per docs/CONTRIBUTING_FP_DATA.md.")
PY
