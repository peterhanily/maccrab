#!/usr/bin/env python3
"""
compile_rules.py — Sigma YAML to HawkEye JSON predicate compiler.

Reads Sigma detection rules in YAML format and compiles them to the JSON
predicate format consumed by HawkEye's RuleEngine.

Dependencies:
    - PyYAML (pip install pyyaml)

Usage:
    python3 compile_rules.py --input-dir ./sigma-rules --output-dir ./compiled

Each .yml file in --input-dir (recursively) is parsed. Only rules with
logsource.product == "macos" (or no product specified) are compiled.
One JSON file is written per rule to --output-dir.
"""

import argparse
import json
import os
import re
import sys
import uuid

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required.  Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Sigma field-name to ECS dot-path mapping
# ---------------------------------------------------------------------------

SIGMA_FIELD_MAP = {
    "Image": "process.executable",
    "OriginalFileName": "process.name",
    "CommandLine": "process.commandline",
    "ProcessId": "process.pid",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.commandline",
    "User": "process.user.name",
    "TargetFilename": "file.path",
    "SourceFilename": "file.source_path",
    "DestinationIp": "network.destination.ip",
    "DestinationPort": "network.destination.port",
    "DestinationHostname": "network.destination.hostname",
    "SourceIp": "network.source.ip",
    "SourcePort": "network.source.port",
    "CodeSigningFlags": "process.code_signature.flags",
}


def normalize_field(field_name: str) -> str:
    """Map a Sigma field name to its canonical ECS-style dot-path."""
    return SIGMA_FIELD_MAP.get(field_name, field_name)


# ---------------------------------------------------------------------------
# Modifier parsing
# ---------------------------------------------------------------------------

# Map from Sigma modifier suffixes to our PredicateModifier enum values.
MODIFIER_MAP = {
    "startswith": "startswith",
    "endswith": "endswith",
    "contains": "contains",
    "re": "regex",
    "base64": "contains",   # base64 values are pre-encoded; match as contains.
    "base64offset": "contains",
    "all": None,             # logic modifier, not a comparison
    "exists": "exists",
    "gt": "gt",
    "lt": "lt",
    "gte": "gte",
    "lte": "lte",
}


def parse_field_modifiers(raw_key: str):
    """
    Parse a Sigma field key like  "Image|startswith"  or  "CommandLine|contains|all".

    Returns (field_name, modifier, is_all) where:
        - field_name: the ECS-normalized field name
        - modifier: one of the PredicateModifier values (default "equals")
        - is_all: True when the |all modifier is present (AND across values)
    """
    parts = raw_key.split("|")
    field_name = normalize_field(parts[0])
    modifier = "equals"
    is_all = False

    for mod in parts[1:]:
        mod_lower = mod.lower()
        if mod_lower == "all":
            is_all = True
        elif mod_lower in MODIFIER_MAP and MODIFIER_MAP[mod_lower] is not None:
            modifier = MODIFIER_MAP[mod_lower]
        # Unknown modifiers are silently ignored.

    return field_name, modifier, is_all


def ensure_list(value):
    """Wrap a scalar value in a list; pass lists through unchanged."""
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


# ---------------------------------------------------------------------------
# Detection block parsing
# ---------------------------------------------------------------------------

def parse_selection_map(selection_map: dict, negate: bool = False) -> list[dict]:
    """
    Convert a Sigma selection/filter map into a list of predicate dicts.

    A Sigma selection map expresses AND across fields:
        selection:
            Image|startswith: '/Users/'
            Image|contains: '/Downloads/'

    Each key becomes one predicate. If the value is a list, those are OR-ed
    within the predicate (values array).

    When |all is present, each value becomes its own predicate (all must match).
    """
    predicates = []

    for raw_key, raw_value in selection_map.items():
        field, modifier, is_all = parse_field_modifiers(raw_key)
        values = ensure_list(raw_value)

        if is_all:
            # |all means every value must match -> emit separate predicates
            for v in values:
                predicates.append({
                    "field": field,
                    "modifier": modifier,
                    "values": [v],
                    "negate": negate,
                })
        else:
            predicates.append({
                "field": field,
                "modifier": modifier,
                "values": values,
                "negate": negate,
            })

    return predicates


def parse_selection_list(selection_list: list, negate: bool = False) -> list[dict]:
    """
    Handle a selection that is a list of maps (OR of ANDs in Sigma).

    Example:
        selection:
            - Image|startswith: '/usr/bin/curl'
            - Image|startswith: '/usr/bin/wget'

    Each list element is a map; we flatten into predicates. Since the overall
    condition logic will combine them, we emit all predicates and let the
    condition handle grouping.
    """
    predicates = []
    for item in selection_list:
        if isinstance(item, dict):
            predicates.extend(parse_selection_map(item, negate=negate))
    return predicates


def parse_detection_block(detection: dict):
    """
    Parse the full Sigma detection block.

    Returns (predicates, condition_type) where:
        - predicates: list of predicate dicts
        - condition_type: "all_of" | "any_of" | "one_of_each"
    """
    condition_str = detection.get("condition", "selection")

    # Gather named sections (selection_*, filter_*, etc.)
    sections = {}
    for key, value in detection.items():
        if key == "condition" or key == "timeframe":
            continue
        sections[key] = value

    # Parse condition string to determine which sections to include / negate.
    predicates = []
    condition_type = determine_condition_type(condition_str, sections)

    # Identify which sections are negated (appear after "not").
    negated_sections = set()
    # Simple pattern: "not <section_name>"
    for match in re.finditer(r'\bnot\s+(\w+)', condition_str):
        negated_sections.add(match.group(1))

    # Identify which sections are referenced in the condition.
    referenced = extract_referenced_sections(condition_str, sections)

    for section_name in referenced:
        is_negated = section_name in negated_sections
        section_data = sections.get(section_name)
        if section_data is None:
            continue

        if isinstance(section_data, dict):
            predicates.extend(parse_selection_map(section_data, negate=is_negated))
        elif isinstance(section_data, list):
            predicates.extend(parse_selection_list(section_data, negate=is_negated))

    return predicates, condition_type


def extract_referenced_sections(condition_str: str, sections: dict) -> list[str]:
    """
    Extract the names of sections referenced in the condition string,
    preserving order.

    Handles patterns like:
        "selection and not filter_signed"
        "selection1 or selection2"
        "1 of selection_*"
        "all of selection_*"
        "selection"
    """
    referenced = []

    # Handle wildcard references like "selection_*", "1 of selection_*"
    wildcard_pattern = re.compile(r'(\w+)\*')
    for match in wildcard_pattern.finditer(condition_str):
        prefix = match.group(1)
        for name in sections:
            if name.startswith(prefix) and name not in referenced:
                referenced.append(name)

    # Handle explicit section names.
    # Extract all word tokens that match a known section.
    for token in re.findall(r'\b(\w+)\b', condition_str):
        if token in sections and token not in referenced:
            referenced.append(token)

    # If nothing was referenced, include everything.
    if not referenced:
        for name in sections:
            if name not in referenced:
                referenced.append(name)

    return referenced


def determine_condition_type(condition_str: str, sections: dict) -> str:
    """
    Infer the HawkEye condition type from a Sigma condition string.

    Sigma conditions can be quite complex, but we map common patterns:
        "selection"                       -> all_of (single selection, AND fields)
        "selection and not filter"        -> all_of
        "all of selection_*"              -> all_of
        "selection1 or selection2"        -> any_of
        "1 of selection_*"               -> any_of
        "all of them"                     -> all_of
        "1 of them"                       -> any_of
    """
    cond = condition_str.strip().lower()

    if " or " in cond:
        return "any_of"

    # "1 of ..." -> any_of
    if re.match(r'^\d+\s+of\s+', cond):
        count = int(re.match(r'^(\d+)', cond).group(1))
        if count == 1:
            return "any_of"
        # For "N of ..." with N > 1 we use one_of_each as approximation.
        return "one_of_each"

    if cond.startswith("all of"):
        return "all_of"

    # Default: AND logic (selection, selection and not filter, etc.)
    return "all_of"


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------

def compile_rule(rule_data: dict, source_file: str):
    """
    Compile a single Sigma YAML rule into the HawkEye JSON predicate format.

    Returns the compiled rule dict, or None if the rule should be skipped.
    """
    # --- Logsource filtering ---
    logsource = rule_data.get("logsource", {})
    product = logsource.get("product", "")
    if product and product.lower() != "macos":
        return None

    category = logsource.get("category", "process_creation")

    # --- Basic metadata ---
    rule_id = rule_data.get("id", str(uuid.uuid4()))
    title = rule_data.get("title", "Untitled Rule")
    description = rule_data.get("description", "")
    level = rule_data.get("level", "medium").lower()
    tags = rule_data.get("tags", [])
    falsepositives = rule_data.get("falsepositives", [])
    if falsepositives is None:
        falsepositives = []

    # Validate severity level.
    valid_levels = {"informational", "low", "medium", "high", "critical"}
    if level not in valid_levels:
        level = "medium"

    # --- Detection block ---
    detection = rule_data.get("detection")
    if not detection:
        print(f"  WARNING: No detection block in {source_file}, skipping", file=sys.stderr)
        return None

    predicates, condition_type = parse_detection_block(detection)

    if not predicates:
        print(f"  WARNING: No predicates generated from {source_file}, skipping", file=sys.stderr)
        return None

    return {
        "id": rule_id,
        "title": title,
        "description": description,
        "level": level,
        "tags": tags,
        "logsource": {
            "category": category,
            "product": "macos",
        },
        "predicates": predicates,
        "condition": condition_type,
        "falsepositives": falsepositives,
    }


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def find_yaml_files(input_dir: str) -> list[str]:
    """Recursively find all .yml and .yaml files in the input directory."""
    yaml_files = []
    for root, _dirs, files in os.walk(input_dir):
        for fname in sorted(files):
            if fname.endswith((".yml", ".yaml")):
                yaml_files.append(os.path.join(root, fname))
    return yaml_files


def compile_all(input_dir: str, output_dir: str) -> tuple[int, int, int]:
    """
    Compile all Sigma YAML rules from input_dir and write JSON to output_dir.

    Returns (total_found, compiled, skipped).
    """
    os.makedirs(output_dir, exist_ok=True)

    yaml_files = find_yaml_files(input_dir)
    total = len(yaml_files)
    compiled = 0
    skipped = 0

    for filepath in yaml_files:
        rel_path = os.path.relpath(filepath, input_dir)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                # Support multi-document YAML files (multiple rules per file).
                documents = list(yaml.safe_load_all(f))
        except Exception as exc:
            print(f"  ERROR parsing {rel_path}: {exc}", file=sys.stderr)
            skipped += 1
            continue

        for doc_idx, rule_data in enumerate(documents):
            if not isinstance(rule_data, dict):
                continue

            result = compile_rule(rule_data, rel_path)
            if result is None:
                skipped += 1
                continue

            # Determine output filename.
            base_name = os.path.splitext(os.path.basename(filepath))[0]
            if len(documents) > 1:
                out_name = f"{base_name}_{doc_idx}.json"
            else:
                out_name = f"{base_name}.json"

            out_path = os.path.join(output_dir, out_name)
            with open(out_path, "w", encoding="utf-8") as out_f:
                json.dump(result, out_f, indent=2, ensure_ascii=False)
                out_f.write("\n")

            compiled += 1
            print(f"  OK  {rel_path} -> {out_name}")

    return total, compiled, skipped


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Compile Sigma YAML rules to HawkEye JSON predicate format."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing Sigma .yml rule files (searched recursively).",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write compiled JSON rule files.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"ERROR: Input directory does not exist: {args.input_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Compiling Sigma rules from: {args.input_dir}")
    print(f"Output directory: {args.output_dir}")
    print()

    total, compiled, skipped = compile_all(args.input_dir, args.output_dir)

    print()
    print("=" * 50)
    print(f"  YAML files found:  {total}")
    print(f"  Rules compiled:    {compiled}")
    print(f"  Rules skipped:     {skipped}")
    print("=" * 50)

    if compiled == 0 and total > 0:
        print("\nNo rules were compiled. Check that rules have logsource.product = 'macos'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
