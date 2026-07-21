#!/usr/bin/env bash
# check-promotion.sh — advisory checker for the experimental → stable rule
# promotion bar defined in CONTRIBUTING.md ("Rule Promotion Criteria").
#
# Per rule, evaluates:
#   1. FP soak      — per-rule alerts/day from the newest fp_benchmark_*.json
#                     (scripts/fp-rate-benchmark.sh output): window >= 14 days
#                     AND <= 0.5 alerts/day. Absent from the JSON = 0/day.
#   2. TP trigger   — a fixture/test references the rule (id, filename stem,
#                     or title) in scripts/detection-test.sh,
#                     scripts/campaign-test.sh, or Tests/.
#   3. Eval latency — rule_telemetry.json: not runtime auto-disabled, and
#                     sampled p95 exec time < 50 ms (the engine's eval budget).
#
# ADVISORY ONLY — not wired into CI. Criteria with no local data report
# UNKNOWN instead of failing; overall is then INCOMPLETE (exit 0).
# Overall exit: 0 = PASS or INCOMPLETE, 1 = at least one FAIL.
#
# Usage:
#   scripts/check-promotion.sh <rule-id|rule-filename>     # one rule
#   scripts/check-promotion.sh --all                       # every experimental rule
#   scripts/check-promotion.sh --benchmark FILE <rule>     # explicit benchmark JSON
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed '1d'; }

RULE_ARG=""
ALL=0
BENCHMARK=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)        ALL=1; shift ;;
    --benchmark)  BENCHMARK="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    -*)           echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    *)            [[ -z "$RULE_ARG" ]] && RULE_ARG="$1" || { echo "one rule at a time (or --all)" >&2; exit 2; }; shift ;;
  esac
done
if [[ "$ALL" = "0" && -z "$RULE_ARG" ]]; then usage >&2; exit 2; fi

# ANSI colors — auto-disabled when stdout is not a terminal (piped/redirected).
USE_COLOR=0
[[ -t 1 ]] && USE_COLOR=1

# Newest benchmark JSON: repo root fp_benchmark_YYYYMMDD.json (the
# fp-rate-benchmark.sh default output), unless --benchmark was given.
if [[ -z "$BENCHMARK" ]]; then
  BENCHMARK="$(ls -t "$PROJECT_DIR"/fp_benchmark_*.json 2>/dev/null | head -1 || true)"
fi

# Telemetry snapshot: root sysext support dir first, then non-root dev dir.
TELEMETRY=""
for cand in "/Library/Application Support/MacCrab/rule_telemetry.json" \
            "$HOME/Library/Application Support/MacCrab/rule_telemetry.json"; do
  [[ -r "$cand" ]] && { TELEMETRY="$cand"; break; }
done

MACCRAB_CP_RULE="$RULE_ARG" MACCRAB_CP_ALL="$ALL" \
MACCRAB_CP_BENCHMARK="$BENCHMARK" MACCRAB_CP_TELEMETRY="$TELEMETRY" \
MACCRAB_CP_COLOR="$USE_COLOR" MACCRAB_CP_ROOT="$PROJECT_DIR" \
python3 - <<'PY'
import json, os, re, sys
from pathlib import Path

ROOT = Path(os.environ["MACCRAB_CP_ROOT"])
RULE_ARG = os.environ["MACCRAB_CP_RULE"]
ALL = os.environ["MACCRAB_CP_ALL"] == "1"
BENCHMARK = os.environ["MACCRAB_CP_BENCHMARK"]
TELEMETRY = os.environ["MACCRAB_CP_TELEMETRY"]
COLOR = os.environ["MACCRAB_CP_COLOR"] == "1"

# Promotion bar (keep in sync with CONTRIBUTING.md "Rule Promotion Criteria").
MIN_WINDOW_DAYS = 14
MAX_PER_DAY = 0.5
SLOW_BUDGET_NS = 50_000_000  # RuleEngine slowRuleThresholdNs

def c(code, s):
    return f"\033[{code}m{s}\033[0m" if COLOR else s

MARK = {
    "PASS":    lambda: c("0;32", "PASS   "),
    "FAIL":    lambda: c("0;31", "FAIL   "),
    "UNKNOWN": lambda: c("1;33", "UNKNOWN"),
}

# ── Load the rule corpus (single-event + sequence YAML, graph JSON) ──────────
def parse_yaml_rule(path):
    """Regex header parse — same no-PyYAML approach as generate-coverage-doc.py."""
    text = path.read_text(encoding="utf-8", errors="replace")
    def grab(field):
        m = re.search(rf"^{field}:\s*['\"]?(.+?)['\"]?\s*$", text, re.MULTILINE)
        return m.group(1).strip() if m else ""
    return {"path": path, "stem": path.stem,
            "id": grab("id"), "title": grab("title"),
            "status": grab("status") or "experimental"}

rules = []
rules_dir = ROOT / "Rules"
for p in sorted(rules_dir.rglob("*.yml")):
    rules.append(parse_yaml_rule(p))
for p in sorted((rules_dir / "graph").glob("*.json")):
    try:
        g = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        continue
    rules.append({"path": p, "stem": p.stem, "id": g.get("id", p.stem),
                  "title": g.get("title", ""),
                  "status": g.get("status", "experimental")})

if ALL:
    targets = [r for r in rules if r["status"] == "experimental"]
    if not targets:
        print("No experimental rules found under Rules/ — nothing to check.")
        sys.exit(0)
else:
    want = RULE_ARG.removesuffix(".yml").removesuffix(".json")
    targets = [r for r in rules
               if want in (r["id"], r["stem"]) or RULE_ARG == r["path"].name]
    if not targets:
        print(f"ERROR: no rule matching '{RULE_ARG}' under Rules/ "
              f"(tried id, filename, and filename stem)", file=sys.stderr)
        sys.exit(2)

# ── Data sources (each optional → UNKNOWN, never a crash) ────────────────────
bench = None
if BENCHMARK and Path(BENCHMARK).is_file():
    try:
        bench = json.loads(Path(BENCHMARK).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"warning: could not parse benchmark {BENCHMARK}: {e}", file=sys.stderr)

telem = None
if TELEMETRY:
    try:
        telem = json.loads(Path(TELEMETRY).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"warning: could not parse telemetry {TELEMETRY}: {e}", file=sys.stderr)
telem_by_id = {s["ruleId"]: s for s in (telem or {}).get("stats", [])}
auto_disabled = set((telem or {}).get("autoDisabledRuleIds", []))

# Trigger-fixture corpus: red-team scripts + unit tests.
fixture_files = [ROOT / "scripts" / "detection-test.sh",
                 ROOT / "scripts" / "campaign-test.sh"]
tests_dir = ROOT / "Tests"
if tests_dir.is_dir():
    fixture_files += [p for p in tests_dir.rglob("*") if p.is_file()
                      and p.suffix in (".swift", ".yml", ".yaml", ".json")]
fixture_text = ""
for f in fixture_files:
    try:
        fixture_text += f.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        pass

# ── Evaluate ─────────────────────────────────────────────────────────────────
def evaluate(rule):
    results = []  # (verdict, label, detail)

    # 1. FP soak
    if bench is None:
        results.append(("UNKNOWN", "fp-soak",
                        "no fp_benchmark_*.json found — run scripts/fp-rate-benchmark.sh "
                        "after a soak (or pass --benchmark FILE)"))
    else:
        days = bench.get("window_days", 0)
        entry = next((x for x in bench.get("rules", [])
                      if x.get("rule_id") == rule["id"]), None)
        per_day = entry["per_day"] if entry else 0.0
        if days < MIN_WINDOW_DAYS:
            results.append(("FAIL", "fp-soak",
                            f"benchmark window {days}d < {MIN_WINDOW_DAYS}d required"))
        elif per_day > MAX_PER_DAY:
            results.append(("FAIL", "fp-soak",
                            f"{per_day}/day over {days}d exceeds the {MAX_PER_DAY}/day budget"))
        else:
            note = f"{per_day}/day over {days}d" if entry else \
                   f"0 alerts in the {days}d window (verify the rule was enabled for it)"
            results.append(("PASS", "fp-soak", note))

    # 2. TP trigger
    needles = [rule["id"].lower(), rule["stem"].lower()]
    if rule["title"]:
        needles.append(rule["title"].lower())
    if any(n and n in fixture_text for n in needles):
        results.append(("PASS", "tp-trigger",
                        "referenced in detection-test.sh / campaign-test.sh / Tests/"))
    else:
        results.append(("FAIL", "tp-trigger",
                        "no fixture or test references the rule id, filename, or title — "
                        "add a detection-test.sh fixture or a Tests/ rule test"))

    # 3. Eval latency
    if telem is None:
        results.append(("UNKNOWN", "eval-latency",
                        "no rule_telemetry.json readable — run the daemon, or sudo for "
                        "the /Library support dir"))
    elif rule["id"] in auto_disabled:
        results.append(("FAIL", "eval-latency",
                        "rule was runtime auto-disabled by the eval-budget guard"))
    else:
        stats = telem_by_id.get(rule["id"])
        samples = sorted((stats or {}).get("execSamplesNs", []))
        if not samples:
            results.append(("UNKNOWN", "eval-latency",
                            "no exec samples in rule_telemetry.json (rule not evaluated "
                            "yet — enable it and let the daemon run)"))
        else:
            p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
            if p95 >= SLOW_BUDGET_NS:
                results.append(("FAIL", "eval-latency",
                                f"p95 {p95/1e6:.1f}ms >= 50ms budget "
                                f"({len(samples)} samples)"))
            else:
                results.append(("PASS", "eval-latency",
                                f"p95 {p95/1e6:.3f}ms < 50ms budget "
                                f"({len(samples)} samples)"))
    return results

any_fail = False
for rule in targets:
    print(f"{c('1', rule['stem'])}  ({rule['id']})  status: {rule['status']}")
    if rule["status"] != "experimental":
        print(f"  note: rule is already '{rule['status']}' — criteria shown for reference")
    results = evaluate(rule)
    for verdict, label, detail in results:
        print(f"  {MARK[verdict]()} {label:<13} {detail}")
    verdicts = [v for v, _, _ in results]
    if "FAIL" in verdicts:
        overall, any_fail = c("0;31", "FAIL"), True
    elif "UNKNOWN" in verdicts:
        overall = c("1;33", "INCOMPLETE (insufficient local data)")
    else:
        overall = c("0;32", "PASS — meets the promotion bar")
    print(f"  overall: {overall}")
    print()

print("Advisory only — the promotion bar is defined in CONTRIBUTING.md "
      "(\"Rule Promotion Criteria\").")
sys.exit(1 if any_fail else 0)
PY
