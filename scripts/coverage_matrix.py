#!/usr/bin/env python3
"""Generate MITRE ATT&CK coverage matrix from MacCrab rules.

Modes:
  coverage_matrix.py [rules_dir]                # text report (default)
  coverage_matrix.py --readme-table [rules_dir] # emit README markdown fragment to stdout
  coverage_matrix.py --update-readme [path] [rules_dir]
                                                # rewrite README.md between COVERAGE-START / COVERAGE-END markers

The --update-readme mode is what `make readme-coverage` and the release
flow call. It re-derives counts from the YAML tree so README never drifts
from the actual rules shipping in a release — the hand-written prose in
v1.10's README went stale within two releases.
"""

import sys
import os
import re
from collections import defaultdict

import yaml

TACTICS = {
    'reconnaissance': 'TA0043',
    'resource_development': 'TA0042',
    'initial_access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege_escalation': 'TA0004',
    'defense_evasion': 'TA0005',
    'credential_access': 'TA0006',
    'discovery': 'TA0007',
    'lateral_movement': 'TA0008',
    'collection': 'TA0009',
    'command_and_control': 'TA0011',
    'exfiltration': 'TA0010',
    'impact': 'TA0040',
}

TACTIC_DISPLAY = {
    'reconnaissance': 'Reconnaissance',
    'resource_development': 'Resource Development',
    'initial_access': 'Initial Access',
    'execution': 'Execution',
    'persistence': 'Persistence',
    'privilege_escalation': 'Privilege Escalation',
    'defense_evasion': 'Defense Evasion',
    'credential_access': 'Credential Access',
    'discovery': 'Discovery',
    'lateral_movement': 'Lateral Movement',
    'collection': 'Collection',
    'command_and_control': 'Command and Control',
    'exfiltration': 'Exfiltration',
    'impact': 'Impact',
}

MARKER_START = '<!-- COVERAGE-START -->'
MARKER_END = '<!-- COVERAGE-END -->'


def scan(rules_dir):
    techniques = defaultdict(list)
    tactics = defaultdict(int)
    total = 0
    sequence_total = 0

    for root, dirs, files in os.walk(rules_dir):
        is_sequence_dir = os.path.basename(root) == 'sequences'
        for f in sorted(files):
            if not f.endswith(('.yml', '.yaml')):
                continue
            filepath = os.path.join(root, f)
            with open(filepath) as fh:
                try:
                    rule = yaml.safe_load(fh)
                except Exception:
                    continue
            if not rule or 'tags' not in rule:
                continue
            total += 1
            if is_sequence_dir:
                sequence_total += 1
            for tag in rule['tags']:
                if re.match(r'attack\.t\d{4}', tag):
                    tid = tag.replace('attack.', '').upper()
                    techniques[tid].append(rule.get('title', 'Unknown'))
                elif tag.startswith('attack.') and not tag.startswith('attack.t'):
                    tactic = tag.replace('attack.', '')
                    tactics[tactic] += 1
    return total, sequence_total, dict(tactics), dict(techniques)


def count_graph(rules_dir):
    """Count graph rules (Rules/graph/*.json). scan() only sees YAML, so the
    6 graph rules are invisible to it — which is exactly why README (YAML-only,
    478) and MODULES (incl. graph, 484) drifted apart."""
    graph_dir = os.path.join(rules_dir, 'graph')
    if not os.path.isdir(graph_dir):
        return 0
    return sum(1 for f in os.listdir(graph_dir) if f.endswith('.json'))


def canonical_counts(rules_dir):
    """The single source of truth for the headline rule decomposition."""
    total_yaml, sequence, _, _ = scan(rules_dir)
    graph = count_graph(rules_dir)
    return {
        'single': total_yaml - sequence,
        'sequence': sequence,
        'graph': graph,
        'grand_total': total_yaml + graph,
    }


# Operator-facing surfaces that quote the headline rule total. --check asserts
# each contains the canonical "<N> rules" so they can never silently drift
# (the historical 478-vs-484 split + ModuleStatus's hardcoded "380+").
COUNT_SURFACES = ['README.md', 'docs/MODULES.md', 'Sources/MacCrabCore/ModuleStatus.swift']


def check_counts(rules_dir):
    c = canonical_counts(rules_dir)
    expected = "%d rules" % c['grand_total']
    print("canonical: %d single + %d sequence + %d graph = %d total"
          % (c['single'], c['sequence'], c['graph'], c['grand_total']))
    bad = [p for p in COUNT_SURFACES
           if os.path.exists(p) and expected not in open(p).read()]
    if bad:
        print("COUNT DRIFT — these surfaces do not contain '%s':" % expected)
        for p in bad:
            print("  - %s" % p)
        sys.exit(1)
    print("OK: all surfaces agree on '%s'" % expected)


def text_report(rules_dir):
    total, sequence_total, tactics, techniques = scan(rules_dir)
    graph = count_graph(rules_dir)
    print("MITRE ATT&CK Coverage Report")
    print("=" * 60)
    print(f"Total rules: {total + graph} ({total - sequence_total} single-event + {sequence_total} sequence + {graph} graph)")
    print(f"Sequence rules: {sequence_total}")
    print(f"Unique techniques: {len(techniques)}")
    print()
    print("Tactics coverage:")
    for tactic, tid in sorted(TACTICS.items(), key=lambda x: x[1]):
        count = tactics.get(tactic, 0)
        bar = '#' * min(count, 40)
        print(f"  {tid} {tactic:25s} {count:3d} {bar}")
    print()
    print("Techniques covered:")
    for tech in sorted(techniques.keys()):
        rules = techniques[tech]
        print(f"  {tech}: {len(rules)} rule(s)")
        for r in rules[:3]:
            print(f"    - {r}")
        if len(rules) > 3:
            print(f"    ... and {len(rules) - 3} more")


def readme_fragment(rules_dir):
    total, sequence_total, tactics, techniques = scan(rules_dir)
    single_event = total - sequence_total
    # scan() only walks the YAML tree, so the graph rules (Rules/graph/*.json)
    # are invisible to it. The README headline total is GRAPH-INCLUSIVE (483 =
    # 436 single + 41 sequence + 6 graph) — count them here and fold them into
    # the total + add a Graph table row, so a `--update-readme` regeneration
    # produces the same 483 the table already shows (not the YAML-only 478,
    # which is what made README and MODULES drift apart historically).
    graph = count_graph(rules_dir)
    grand_total = total + graph
    lines = []
    lines.append('<!-- Auto-generated by `scripts/coverage_matrix.py --update-readme`.')
    lines.append('     Edit the rule YAML, then run `make readme-coverage` to regenerate. -->')
    lines.append('')
    lines.append(f'Rules live under `Rules/<tactic>/` as Sigma-compatible YAML. The current')
    lines.append(f'release ships **{grand_total} rules** ({single_event} single-event + {sequence_total} sequence + {graph} graph)')
    lines.append(f'covering **{len(techniques)} unique MITRE ATT&CK techniques** across the macOS-relevant')
    lines.append('tactics:')
    lines.append('')
    lines.append('| MITRE ID | Tactic | Rule count |')
    lines.append('|---|---|---:|')
    rows = sorted(TACTICS.items(), key=lambda x: x[1])
    for tactic, tid in rows:
        count = tactics.get(tactic, 0)
        if count == 0:
            continue
        lines.append(f'| `{tid}` | {TACTIC_DISPLAY[tactic]} | {count} |')
    lines.append(f'| — | **Sequences** (temporal multi-step) | **{sequence_total}** |')
    lines.append(f'| — | **Graph** (multi-entity TraceGraph) | **{graph}** |')
    lines.append(f'| — | **Total** | **{grand_total}** |')
    lines.append('')
    lines.append('Counts are derived from the YAML tree at release time — see')
    lines.append('[`docs/COVERAGE.md`](docs/COVERAGE.md) for the rule-by-technique')
    lines.append('breakdown. To regenerate this section after editing rules: `make readme-coverage`.')
    return '\n'.join(lines)


def update_readme(readme_path, rules_dir):
    with open(readme_path) as fh:
        content = fh.read()
    fragment = readme_fragment(rules_dir)
    if MARKER_START in content and MARKER_END in content:
        pattern = re.compile(
            re.escape(MARKER_START) + r'.*?' + re.escape(MARKER_END),
            re.DOTALL
        )
        new_content = pattern.sub(
            MARKER_START + '\n' + fragment + '\n' + MARKER_END,
            content
        )
    else:
        heading = '## Rule Coverage by MITRE ATT&CK Tactic'
        if heading not in content:
            raise SystemExit(
                f"refusing to edit {readme_path}: no '{heading}' heading and no markers found"
            )
        before, after = content.split(heading, 1)
        next_section = re.search(r'\n## ', after)
        if not next_section:
            raise SystemExit(f"refusing to edit {readme_path}: no following section found")
        tail = after[next_section.start():]
        new_content = (
            before
            + heading + '\n\n'
            + MARKER_START + '\n' + fragment + '\n' + MARKER_END
            + tail
        )
    if new_content == content:
        return False
    with open(readme_path, 'w') as fh:
        fh.write(new_content)
    return True


def main():
    args = sys.argv[1:]
    if args and args[0] == '--readme-table':
        rules_dir = args[1] if len(args) > 1 else 'Rules'
        print(readme_fragment(rules_dir))
        return
    if args and args[0] == '--update-readme':
        readme_path = args[1] if len(args) > 1 else 'README.md'
        rules_dir = args[2] if len(args) > 2 else 'Rules'
        changed = update_readme(readme_path, rules_dir)
        print(f"{'updated' if changed else 'unchanged'}: {readme_path}")
        return
    if args and args[0] == '--counts':
        rules_dir = args[1] if len(args) > 1 else 'Rules'
        c = canonical_counts(rules_dir)
        print("single=%d sequence=%d graph=%d total=%d"
              % (c['single'], c['sequence'], c['graph'], c['grand_total']))
        return
    if args and args[0] == '--check':
        rules_dir = args[1] if len(args) > 1 else 'Rules'
        check_counts(rules_dir)
        return
    rules_dir = args[0] if args else 'Rules'
    text_report(rules_dir)


if __name__ == '__main__':
    main()
