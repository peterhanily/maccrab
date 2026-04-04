#!/usr/bin/env python3
"""Check for duplicate rule IDs across all MacCrab rules."""

import sys
import os

import yaml


def main():
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else 'Rules'
    ids = {}

    for root, dirs, files in os.walk(rules_dir):
        for f in sorted(files):
            if f.endswith(('.yml', '.yaml')):
                filepath = os.path.join(root, f)
                with open(filepath) as fh:
                    try:
                        rule = yaml.safe_load(fh)
                        if rule and 'id' in rule:
                            rid = str(rule['id'])
                            if rid in ids:
                                print(f"DUPLICATE ID: {rid}")
                                print(f"  File 1: {ids[rid]}")
                                print(f"  File 2: {filepath}")
                                sys.exit(1)
                            ids[rid] = filepath
                    except yaml.YAMLError:
                        pass

    print(f"No duplicate IDs found across {len(ids)} rules")


if __name__ == '__main__':
    main()
