#!/usr/bin/env python3
"""Validate HawkEye Sigma-format detection rules."""

import sys
import os
import re

import yaml

REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'logsource', 'detection', 'level']
VALID_LEVELS = ['informational', 'low', 'medium', 'high', 'critical']
VALID_STATUSES = ['experimental', 'test', 'stable', 'deprecated']
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
)


def validate_rule(filepath):
    errors = []
    with open(filepath) as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [f"YAML parse error: {e}"]

    if not isinstance(rule, dict):
        return ["Not a valid rule (not a YAML mapping)"]

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    # Validate ID format
    if 'id' in rule and not UUID_PATTERN.match(str(rule['id'])):
        errors.append(f"Invalid ID format (must be UUID): {rule['id']}")

    # Validate level
    if 'level' in rule and rule['level'] not in VALID_LEVELS:
        errors.append(f"Invalid level: {rule['level']}")

    # Validate status
    if 'status' in rule and rule['status'] not in VALID_STATUSES:
        errors.append(f"Invalid status: {rule['status']}")

    # Validate logsource has product: macos (for non-sequence rules)
    if 'logsource' in rule:
        ls = rule['logsource']
        if isinstance(ls, dict) and ls.get('product') != 'macos':
            errors.append(
                f"logsource.product must be 'macos', got: {ls.get('product')}"
            )

    # Validate detection has condition
    if 'detection' in rule and isinstance(rule['detection'], dict):
        if 'condition' not in rule['detection']:
            # Sequence rules don't have detection.condition at top level
            if rule.get('type') != 'sequence':
                errors.append("detection block missing 'condition'")

    # Validate tags are attack.* format
    if 'tags' in rule:
        for tag in rule['tags']:
            if not tag.startswith('attack.') and not tag.startswith('baseline.'):
                errors.append(
                    f"Tag should start with 'attack.' or 'baseline.': {tag}"
                )

    return errors


def main():
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else 'Rules'
    total = 0
    failed = 0

    for root, dirs, files in os.walk(rules_dir):
        for f in sorted(files):
            if f.endswith(('.yml', '.yaml')):
                filepath = os.path.join(root, f)
                errors = validate_rule(filepath)
                total += 1
                if errors:
                    failed += 1
                    print(f"FAIL: {filepath}")
                    for e in errors:
                        print(f"  - {e}")

    print(f"\n{total} rules validated, {failed} failed, {total - failed} passed")
    sys.exit(1 if failed > 0 else 0)


if __name__ == '__main__':
    main()
