#!/usr/bin/env python3
# generate-coverage-doc.py — Walk Rules/*.yml and emit docs/COVERAGE.md
# with rule-to-MITRE-ATT&CK coverage. Read by both reviewers (proof of
# detection scope) and operators (proof their threats are covered).
#
# v1.8.1: codifies the lesson from external review. We had ~415 rules
# with no published index. Reviewer flagged "what does each rule
# actually catch" as the missing credibility piece.
#
# Output is generated, not hand-edited. Run on every rule change:
#   python3 scripts/generate-coverage-doc.py > docs/COVERAGE.md
#
# Or via make:
#   make coverage-doc

import os
import re
import sys
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "Rules"

# MITRE ATT&CK tactic directory → human-readable label.
TACTIC_LABEL = {
    "ai_safety":         "AI Safety (MacCrab-specific)",
    "collection":        "Collection (TA0009)",
    "command_and_control": "Command & Control (TA0011)",
    "container":         "Container (MacCrab-specific)",
    "credential_access": "Credential Access (TA0006)",
    "defense_evasion":   "Defense Evasion (TA0005)",
    "discovery":         "Discovery (TA0007)",
    "execution":         "Execution (TA0002)",
    "exfiltration":      "Exfiltration (TA0010)",
    "impact":            "Impact (TA0040)",
    "initial_access":    "Initial Access (TA0001)",
    "lateral_movement":  "Lateral Movement (TA0008)",
    "persistence":       "Persistence (TA0003)",
    "privilege_escalation": "Privilege Escalation (TA0004)",
    "supply_chain":      "Supply Chain (Sigma)",
    "tcc":               "TCC / macOS Privacy",
    "wireless":          "Wireless / RF",
    "sequences":         "Sequence Rules (multi-step)",
}

def parse_rule(path):
    """Extract title, id, status, level, tags, description from a rule
    YAML. Tolerant of formatting variations — uses regex rather than a
    YAML parser to avoid a Python-yaml dependency in the build."""
    text = path.read_text(encoding="utf-8", errors="replace")

    def grab(field, multiline=False):
        if multiline:
            m = re.search(rf"^{field}:\s*>\s*\n((?:    .+\n)+)", text, re.MULTILINE)
            if m:
                return " ".join(line.strip() for line in m.group(1).splitlines()).strip()
            m = re.search(rf"^{field}:\s*\|?\s*\n?(.+)$", text, re.MULTILINE)
        else:
            m = re.search(rf"^{field}:\s*['\"]?(.+?)['\"]?\s*$", text, re.MULTILINE)
        return m.group(1).strip() if m else ""

    tags = re.findall(r"^\s+-\s+(attack\.\S+)$", text, re.MULTILINE)
    techniques = sorted({t for t in tags if re.match(r"attack\.t\d+", t)})

    return {
        "filename": path.name,
        "title": grab("title"),
        "id": grab("id"),
        "status": grab("status") or "experimental",
        "level": grab("level") or "medium",
        "description": grab("description", multiline=True),
        "tags": tags,
        "techniques": techniques,
    }


def main():
    if not RULES_DIR.exists():
        print(f"ERROR: {RULES_DIR} not found", file=sys.stderr)
        sys.exit(1)

    by_tactic = defaultdict(list)
    total = 0
    by_status = defaultdict(int)
    by_level = defaultdict(int)
    technique_set = set()

    for tactic_dir in sorted(RULES_DIR.iterdir()):
        if not tactic_dir.is_dir():
            continue
        if tactic_dir.name == "ai_safety":
            tactic = "ai_safety"
        elif tactic_dir.name == "sequences":
            tactic = "sequences"
        else:
            tactic = tactic_dir.name

        for rule_path in sorted(tactic_dir.glob("*.yml")):
            r = parse_rule(rule_path)
            r["tactic"] = tactic
            by_tactic[tactic].append(r)
            total += 1
            by_status[r["status"]] += 1
            by_level[r["level"]] += 1
            for t in r["techniques"]:
                technique_set.add(t.replace("attack.", "").upper())

    print(f"# Detection Coverage")
    print()
    print(f"This page is **generated** from `Rules/*.yml` by")
    print(f"`scripts/generate-coverage-doc.py`. Don't hand-edit — re-run")
    print(f"the script when rules change. Last rebuild: walks every YAML")
    print(f"under `Rules/` and groups by tactic dir + extracts MITRE")
    print(f"ATT&CK technique tags from each rule's `tags:` block.")
    print()
    print(f"## At a glance")
    print()
    print(f"| Metric | Count |")
    print(f"|---|---|")
    print(f"| Rules total | **{total}** |")
    for status in ["stable", "experimental", "deprecated"]:
        if by_status.get(status):
            print(f"| Status: {status} | {by_status[status]} |")
    for level in ["critical", "high", "medium", "low", "informational"]:
        if by_level.get(level):
            print(f"| Severity: {level} | {by_level[level]} |")
    print(f"| Distinct MITRE ATT&CK techniques covered | {len(technique_set)} |")
    print(f"| Tactic directories | {len([t for t in by_tactic if by_tactic[t]])} |")
    print()

    print(f"## Default rule profile")
    print()
    print(f"Since **v1.21.4-alpha** the daemon defaults to the **stable** rule")
    print(f"profile: only `status: stable` rules ship enabled. The")
    print(f"`experimental` / `test` tiers still load — their ids/titles surface")
    print(f"and an operator can enable them individually — but are disabled by")
    print(f"default, keeping the daily false-positive budget honest. Set")
    print(f'`"rule_profile": "all"` in `daemon_config.json` to enable every')
    print(f"non-deprecated rule (the pre-1.21.4 behavior). Per-rule operator")
    print(f"overlays (user_rules) are unaffected by this setting.")
    print()

    print(f"## Caveat")
    print()
    print(f"This is **documented coverage** — what each rule's `tags:`")
    print(f"block declares it matches. It is NOT an executed benchmark")
    print(f"against a labeled malware corpus. False-positive rate per")
    print(f"rule under real workloads is currently measured")
    print(f"opportunistically via field reports + the audit script's")
    print(f"FP-risk pass (rules without `filter:` blocks). A formal")
    print(f"benchmark + FP-rate publication is on the v1.9 roadmap.")
    print()

    print(f"## By tactic")
    print()

    tactic_order = list(TACTIC_LABEL.keys())
    for tactic in tactic_order:
        rules = by_tactic.get(tactic, [])
        if not rules:
            continue
        label = TACTIC_LABEL.get(tactic, tactic.replace("_", " ").title())
        print(f"### {label} ({len(rules)} rules)")
        print()
        print(f"| Rule | Status | Severity | MITRE Techniques |")
        print(f"|---|---|---|---|")
        for r in rules:
            techs = " ".join(t.replace("attack.", "").upper() for t in r["techniques"]) or "—"
            title = r["title"].replace("|", "\\|")
            # Filename trimmed for readability
            print(f"| `{r['filename']}`<br/>{title} | {r['status']} | {r['level']} | {techs} |")
        print()

    print(f"## Full MITRE ATT&CK technique list")
    print()
    print(f"All technique IDs referenced anywhere in the rule corpus:")
    print()
    techs = sorted(technique_set, key=lambda x: (x[1:].split(".")[0], x))
    cols = 6
    for i, t in enumerate(techs):
        if i % cols == 0:
            print("| " + " | ".join(["Technique"] * cols) + " |")
            print("| " + " | ".join(["---"] * cols) + " |")
        print(f"| {t} ", end="")
        if (i + 1) % cols == 0 or i == len(techs) - 1:
            # pad row
            remainder = (i + 1) % cols
            if remainder:
                for _ in range(cols - remainder):
                    print(f"| ", end="")
            print("|")
    print()

    print(f"## How to read this")
    print()
    print(f"- **Rule** column: filename + the rule's declared title.")
    print(f"- **Status** column: `experimental` (still tuning), `stable`")
    print(f"  (production-ready by alpha standards), `deprecated`")
    print(f"  (will be removed; do not enable).")
    print(f"- **Severity**: critical / high / medium / low /")
    print(f"  informational. Drives notification routing + dashboard")
    print(f"  ordering. See `docs/MODULES.md` for the rule engine's")
    print(f"  maturity rating.")
    print(f"- **MITRE Techniques**: technique IDs from")
    print(f"  https://attack.mitre.org. A blank entry means the rule")
    print(f"  detects something MacCrab-specific (e.g., AI Guard")
    print(f"  cluster) that doesn't have a perfect ATT&CK mapping.")
    print()

    print(f"## Related docs")
    print()
    print(f"- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what classes of attacker MacCrab does and doesn't defend against")
    print(f"- [`RESPONSE_SAFETY.md`](RESPONSE_SAFETY.md) — what response actions can fire when these rules trigger")
    print(f"- [`MODULES.md`](MODULES.md) — stable vs experimental subsystem labels")


if __name__ == "__main__":
    main()
