#!/usr/bin/env python3
"""Validate MacCrab Sigma-format detection rules."""

import sys
import os
import re

import yaml

REQUIRED_FIELDS_SINGLE = ['title', 'id', 'status', 'description', 'logsource', 'detection', 'level']
REQUIRED_FIELDS_SEQUENCE = ['title', 'id', 'status', 'description', 'level', 'type', 'steps', 'trigger']
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

    is_sequence = rule.get('type') == 'sequence'
    required = REQUIRED_FIELDS_SEQUENCE if is_sequence else REQUIRED_FIELDS_SINGLE

    # Check required fields
    for field in required:
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

    if is_sequence:
        # Validate sequence rule structure
        steps = rule.get('steps', [])
        if not isinstance(steps, list) or len(steps) == 0:
            errors.append("Sequence rule must have at least one step")
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                errors.append(f"Step {i} is not a mapping")
                continue
            if 'id' not in step:
                errors.append(f"Step {i} missing 'id'")
            if 'logsource' not in step:
                errors.append(f"Step {i} ('{step.get('id', '?')}') missing 'logsource'")
            if 'detection' not in step:
                errors.append(f"Step {i} ('{step.get('id', '?')}') missing 'detection'")
            ls = step.get('logsource', {})
            if isinstance(ls, dict) and ls.get('product') and ls['product'] != 'macos':
                errors.append(f"Step {i} logsource.product must be 'macos'")
    else:
        # Validate single-event rule structure
        if 'logsource' in rule:
            ls = rule['logsource']
            if isinstance(ls, dict) and ls.get('product') != 'macos':
                errors.append(
                    f"logsource.product must be 'macos', got: {ls.get('product')}"
                )

        if 'detection' in rule and isinstance(rule['detection'], dict):
            if 'condition' not in rule['detection']:
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
