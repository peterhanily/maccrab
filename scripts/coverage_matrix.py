#!/usr/bin/env python3
"""Generate MITRE ATT&CK coverage matrix from HawkEye rules."""

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


def main():
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else 'Rules'
    techniques = defaultdict(list)  # technique -> [rule titles]
    tactics = defaultdict(int)
    total = 0

    for root, dirs, files in os.walk(rules_dir):
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
            for tag in rule['tags']:
                if re.match(r'attack\.t\d{4}', tag):
                    tid = tag.replace('attack.', '').upper()
                    techniques[tid].append(rule.get('title', 'Unknown'))
                elif tag.startswith('attack.') and not tag.startswith('attack.t'):
                    tactic = tag.replace('attack.', '')
                    tactics[tactic] += 1

    print("MITRE ATT&CK Coverage Report")
    print("=" * 60)
    print(f"Total rules: {total}")
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


if __name__ == '__main__':
    main()
