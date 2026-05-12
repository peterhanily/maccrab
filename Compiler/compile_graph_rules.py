#!/usr/bin/env python3
"""
compile_graph_rules.py — convert YAML graph rules to canonical JSON.

v1.11.1 (audit backlog): the v1.10.0 TraceGraph release shipped graph
rules as canonical JSON under Rules/graph/*.json. JSON is verbose to
hand-author when the shape involves nested maps + arrays (nodes /
edges / scope / constraints). This compiler lets rule authors write
YAML in Rules/graph/*.yml and produce the JSON equivalents the
daemon's `GraphRuleEvaluator` already loads.

Conventions:
    - Source files: Rules/graph/<rule_id>.yml
    - Output files: Rules/graph/<rule_id>.json    (sibling)
    - Existing .json files without a matching .yml are left untouched
      (still canonical for rules that were never authored in YAML).

Validation:
    - id, title, severity, type, nodes, edges are required
    - severity must be one of {informational, low, medium, high, critical}
    - type must be "graph"
    - every edge `from` / `to` must reference a key in `nodes`
    - node types must be in the supported v1.10.0 set
    - edges may not reference unknown relation names (loose check —
      the daemon's evaluator validates the strict set)

The schema reference lives at `docs/tracegraph-rule-schema.md`.

Dependencies: PyYAML (pip install pyyaml). Same dep as compile_rules.py.

Usage:
    python3 Compiler/compile_graph_rules.py
    python3 Compiler/compile_graph_rules.py --input-dir Rules/graph --output-dir Rules/graph
    python3 Compiler/compile_graph_rules.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


SUPPORTED_NODE_TYPES = {
    "process", "file", "network", "ai_agent", "persistence",
    "mcp_server", "package_script", "browser_download",
    "code_signature", "user_session", "tcc_permission", "rule", "alert",
}

VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}


def validate(rule: dict, source: Path) -> list[str]:
    """Return a list of error strings; empty list means the rule passes."""
    errors: list[str] = []

    for key in ("id", "title", "severity", "type", "nodes", "edges"):
        if key not in rule:
            errors.append(f"missing required field: {key}")

    if rule.get("type") != "graph":
        errors.append(f"type must be 'graph', got {rule.get('type')!r}")

    if rule.get("severity") not in VALID_SEVERITIES:
        errors.append(
            f"severity must be one of {sorted(VALID_SEVERITIES)}, "
            f"got {rule.get('severity')!r}"
        )

    nodes = rule.get("nodes") or {}
    if not isinstance(nodes, dict) or not nodes:
        errors.append("nodes must be a non-empty map")
        return errors  # bail — subsequent checks reference nodes

    for name, spec in nodes.items():
        ntype = spec.get("type") if isinstance(spec, dict) else None
        if ntype not in SUPPORTED_NODE_TYPES:
            errors.append(
                f"node '{name}' has unsupported type {ntype!r}; "
                f"expected one of {sorted(SUPPORTED_NODE_TYPES)}"
            )

    edges = rule.get("edges") or []
    if not isinstance(edges, list):
        errors.append("edges must be a list")
        return errors

    node_names = set(nodes.keys())
    for i, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{i}] must be a map")
            continue
        f = edge.get("from")
        t = edge.get("to")
        if f not in node_names:
            errors.append(f"edges[{i}].from references unknown node {f!r}")
        if t not in node_names:
            errors.append(f"edges[{i}].to references unknown node {t!r}")
        if not edge.get("relation"):
            errors.append(f"edges[{i}] missing 'relation'")

    return errors


def compile_one(source: Path, out_dir: Path, dry_run: bool) -> tuple[bool, str]:
    """Compile a single YAML rule. Returns (ok, message)."""
    try:
        with source.open("r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return False, f"YAML parse error in {source}: {e}"

    if not isinstance(rule, dict):
        return False, f"{source}: top-level must be a map"

    errors = validate(rule, source)
    if errors:
        joined = "\n  ".join(errors)
        return False, f"{source}: schema errors:\n  {joined}"

    rule_id = rule["id"]
    out_path = out_dir / f"{rule_id}.json"

    if dry_run:
        return True, f"would compile {source.name} → {out_path}"

    # Pretty-printed, stable key order. JSON shape matches what the
    # Swift `GraphRule` Codable expects.
    out_path.write_text(
        json.dumps(rule, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return True, f"compiled {source.name} → {out_path.name}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default="Rules/graph")
    parser.add_argument("--output-dir", default="Rules/graph")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate + print what would be written, don't write")
    args = parser.parse_args()

    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)
    if not in_dir.is_dir():
        print(f"ERROR: {in_dir} is not a directory", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)

    yaml_files = sorted(list(in_dir.glob("*.yml")) + list(in_dir.glob("*.yaml")))
    if not yaml_files:
        print(f"no .yml files in {in_dir} — nothing to do")
        return 0

    fail = 0
    ok = 0
    for src in yaml_files:
        success, msg = compile_one(src, out_dir, args.dry_run)
        prefix = "ok    " if success else "ERROR "
        print(f"{prefix}{msg}", file=sys.stdout if success else sys.stderr)
        if success:
            ok += 1
        else:
            fail += 1

    print(f"\n{ok} compiled, {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
