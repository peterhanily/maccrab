#!/usr/bin/env python3
"""
compile_rules.py — Sigma YAML to MacCrab JSON predicate compiler.

Reads Sigma detection rules in YAML format and compiles them to the JSON
predicate format consumed by MacCrab's RuleEngine.

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
# Custom YAML loader that warns on duplicate keys within a mapping
# ---------------------------------------------------------------------------

class _DuplicateKeyChecker(yaml.SafeLoader):
    """SafeLoader subclass that emits warnings for duplicate mapping keys."""
    pass


def _check_duplicate_keys(loader, node):
    """Construct a mapping, warning if any key appears more than once."""
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in mapping:
            mark = key_node.start_mark
            print(
                f"  WARN  Duplicate key '{key}' in {mark.name}:{mark.line + 1} "
                f"(rule: {_current_compile_rule_title}) — second value overwrites first",
                file=sys.stderr,
            )
        mapping[key] = loader.construct_object(value_node)
    return mapping


_DuplicateKeyChecker.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _check_duplicate_keys,
)


# ---------------------------------------------------------------------------
# Sigma field-name to ECS dot-path mapping
# ---------------------------------------------------------------------------

# Module-level variable set by compile_rule() so that warnings from helper
# functions (parse_field_modifiers, etc.) can include the rule title without
# needing to thread it through every call stack frame.
_current_compile_rule_title: str = ""

SIGMA_FIELD_MAP = {
    "Image": "process.executable",
    "OriginalFileName": "process.name",
    "CommandLine": "process.commandline",
    "ProcessId": "process.pid",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.commandline",
    "GrandparentImage": "process.grandparent.executable",
    "User": "process.user.name",
    "TargetFilename": "file.path",
    "SourceFilename": "file.source_path",
    "DestinationIp": "network.destination.ip",
    "DestinationPort": "network.destination.port",
    "DestinationHostname": "network.destination.hostname",
    "SourceIp": "network.source.ip",
    "SourcePort": "network.source.port",
    "CodeSigningFlags": "process.code_signature.flags",
    # ES-framework-provided platform bit. More reliable than SignerType
    # for filtering Apple binaries because it comes from the kernel event
    # directly and doesn't depend on post-hoc code-signing enrichment
    # (which can be nil for short-lived processes like launchctl/
    # system_profiler). Compare against string "true"/"false".
    "PlatformBinary": "process.is_platform_binary",
}


# Fields that are NOT in SIGMA_FIELD_MAP but are known to the RuleEngine
# (resolved via enrichments dict or special-case code). These don't need
# mapping but also shouldn't trigger "unmapped field" warnings.
_KNOWN_PASSTHROUGH_FIELDS = {
    "SignerType", "ParentSignerType", "XPCServiceName",
    # TCC fields (resolved via enrichments in RuleEngine)
    "TCCService", "TCCAllowed", "TCCClient",
    # Network enrichment fields
    "DestinationIsPrivate",
    # File enrichment fields
    "FileAction", "FileContent",
    # Code signing enrichment fields
    "NotarizationStatus", "Architecture",
    # --- Phase 1 enrichment fields (hashes, session, signing) ---
    # Hash fingerprints populated by ProcessHasher/FileHasher enrichers.
    "ProcessSHA256", "ProcessCDHash", "ProcessMD5",
    # Session / login context populated by SessionEnricher.
    "SessionTTY", "SessionLoginUser", "SessionSSHRemoteIP",
    "LaunchSource", "IsSSHLaunched",
    # Extended code-signing fields (issuer chain, cert hashes, ad-hoc flag).
    "SigningCertIssuer", "SigningCertHash", "IsAdhocSigned",
    # Lineage + environment.
    "AncestorDepth", "EnvVarsFlat",
    # Deception tier: honeyfile access markers set by EventEnricher.
    "IsHoneyfile", "HoneyfileType",
}

# Track fields we've already warned about to avoid spam.
_warned_fields: set = set()


def normalize_field(field_name: str) -> str:
    """Map a Sigma field name to its canonical ECS-style dot-path.

    Warns once per unknown field name so rule authors can fix typos or
    add missing mappings.
    """
    if field_name in SIGMA_FIELD_MAP:
        return SIGMA_FIELD_MAP[field_name]
    # Fields already in ECS dot-path form or known passthroughs are fine.
    if "." in field_name or field_name in _KNOWN_PASSTHROUGH_FIELDS:
        return field_name
    if field_name not in _warned_fields:
        _warned_fields.add(field_name)
        print(
            f"  WARN  Unmapped Sigma field '{field_name}' in rule '{_current_compile_rule_title}' "
            f"— will be passed through as-is. Add to SIGMA_FIELD_MAP if this is a typo.",
            file=sys.stderr,
        )
    return field_name


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


def parse_field_modifiers(raw_key: str, rule_title: str = ""):
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
        elif mod_lower not in MODIFIER_MAP:
            # Unknown modifier — warn so rule authors know the predicate logic
            # may not behave as intended. This prevents silent underdetection.
            effective_title = rule_title or _current_compile_rule_title
            rule_ctx = f" in rule '{effective_title}'" if effective_title else ""
            print(
                f"WARNING: Unsupported Sigma modifier '|{mod}' on field '{raw_key}'{rule_ctx} "
                f"— modifier will be IGNORED. The predicate may underdetect.",
                file=sys.stderr,
            )
        # Known-None modifiers (e.g. "all" already handled above) are not warned.

    return field_name, modifier, is_all


def ensure_list(value):
    """Wrap a scalar value in a list; pass lists through unchanged."""
    if isinstance(value, bool):
        print(
            f"  WARN  Boolean value '{value}' used as selection value in rule "
            f"'{_current_compile_rule_title}' — this likely creates an invalid predicate. "
            f"Use a field selector instead.",
            file=sys.stderr,
        )
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

    Returns (predicates, condition_type, condition_tree) where:
        - predicates: list of predicate dicts
        - condition_type: "all_of" | "any_of" | "one_of_each"
        - condition_tree: dict (hierarchical condition) or None
    """
    condition_str = detection.get("condition", "selection")

    # Aggregation expressions (count(), near(), equalsfield(), etc.) appear after
    # a pipe character and are NOT supported by the compiler. Warn immediately so
    # rule authors know the aggregation logic will be silently dropped, potentially
    # causing the rule to fire on fewer (or more) events than intended.
    if "|" in condition_str:
        rule_ctx = f" in rule '{_current_compile_rule_title}'" if _current_compile_rule_title else ""
        agg_part = condition_str.split("|", 1)[1].strip()
        print(
            f"WARNING: Aggregation expression '| {agg_part}'{rule_ctx} is NOT supported "
            f"and will be IGNORED. The condition will be compiled without the aggregation "
            f"(condition string: '{condition_str}'). Rule may under- or over-detect.",
            file=sys.stderr,
        )

    # Gather named sections (selection_*, filter_*, etc.)
    sections = {}
    for key, value in detection.items():
        if key == "condition" or key == "timeframe":
            continue
        sections[key] = value

    # Parse the condition string into an AST.
    ast = _parse_condition_ast(condition_str)

    # Always produce flat predicates + condition_type for backward compat.
    predicates, condition_type = _compile_ast(ast, sections)

    # For complex rules, also produce a hierarchical condition tree.
    condition_tree = None
    if _needs_condition_tree(ast, sections):
        tree_predicates = []
        condition_tree = _ast_to_condition_tree(ast, sections, tree_predicates)
        # Use the tree's predicates instead — they have correct indices.
        predicates = tree_predicates

    return predicates, condition_type, condition_tree


# ---------------------------------------------------------------------------
# Condition tokenizer & parser
# ---------------------------------------------------------------------------

# Token types for the condition lexer.
_TOK_LPAREN = "LPAREN"
_TOK_RPAREN = "RPAREN"
_TOK_AND = "AND"
_TOK_OR = "OR"
_TOK_NOT = "NOT"
_TOK_PIPE = "PIPE"
_TOK_NUM_OF = "NUM_OF"     # "1 of", "3 of"
_TOK_ALL_OF = "ALL_OF"     # "all of"
_TOK_IDENT = "IDENT"       # section name or wildcard like "selection_*"
_TOK_THEM = "THEM"         # "them"
_TOK_EOF = "EOF"


def _tokenize_condition(condition_str: str) -> list[tuple[str, str]]:
    """
    Tokenize a Sigma condition string into a list of (token_type, value) pairs.

    Examples:
        "(selection1 or selection2) and not filter"
        "1 of selection_*"
        "all of them"
        "selection and not filter | count(field) by Image > 5"
    """
    tokens = []
    s = condition_str.strip()
    i = 0

    while i < len(s):
        # Skip whitespace.
        if s[i].isspace():
            i += 1
            continue

        # Pipe — marks the start of an aggregation expression; we stop parsing.
        if s[i] == '|':
            tokens.append((_TOK_PIPE, "|"))
            break

        # Parentheses.
        if s[i] == '(':
            tokens.append((_TOK_LPAREN, "("))
            i += 1
            continue
        if s[i] == ')':
            tokens.append((_TOK_RPAREN, ")"))
            i += 1
            continue

        # Read a word token (alphanumeric, underscore, asterisk, dot for wildcards).
        if s[i].isalnum() or s[i] in ('_', '*'):
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] in ('_', '*', '.')):
                j += 1
            word = s[i:j]
            lower_word = word.lower()

            if lower_word == "and":
                tokens.append((_TOK_AND, "and"))
            elif lower_word == "or":
                tokens.append((_TOK_OR, "or"))
            elif lower_word == "not":
                tokens.append((_TOK_NOT, "not"))
            elif lower_word == "them":
                tokens.append((_TOK_THEM, "them"))
            elif lower_word == "all":
                # Peek ahead for "all of".
                rest = s[j:].lstrip()
                if re.match(r'of\b', rest, re.IGNORECASE):
                    tokens.append((_TOK_ALL_OF, "all of"))
                    # Advance j past the whitespace and "of".
                    of_start = j + (len(s[j:]) - len(s[j:].lstrip()))
                    j = of_start + 2
                else:
                    tokens.append((_TOK_IDENT, word))
            elif lower_word.isdigit():
                # Peek ahead for "<N> of".
                rest = s[j:].lstrip()
                if re.match(r'of\b', rest, re.IGNORECASE):
                    tokens.append((_TOK_NUM_OF, word))
                    of_start = j + (len(s[j:]) - len(s[j:].lstrip()))
                    j = of_start + 2
                else:
                    tokens.append((_TOK_IDENT, word))
            else:
                tokens.append((_TOK_IDENT, word))

            i = j
            continue

        # Skip any other characters (shouldn't happen in valid conditions).
        i += 1

    tokens.append((_TOK_EOF, ""))
    return tokens


# ---------------------------------------------------------------------------
# AST node types
# ---------------------------------------------------------------------------

class _ASTRef:
    """Leaf: reference to a detection section (possibly with wildcard)."""
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name     # e.g. "selection", "filter_*", "them"

    def __repr__(self):
        return f"Ref({self.name})"


class _ASTNot:
    """Unary NOT."""
    __slots__ = ("child",)

    def __init__(self, child):
        self.child = child

    def __repr__(self):
        return f"Not({self.child})"


class _ASTBinOp:
    """Binary AND / OR."""
    __slots__ = ("op", "left", "right")

    def __init__(self, op: str, left, right):
        self.op = op         # "and" or "or"
        self.left = left
        self.right = right

    def __repr__(self):
        return f"BinOp({self.op}, {self.left}, {self.right})"


class _ASTQuantifier:
    """Quantifier: '1 of selection_*', 'all of them', etc."""
    __slots__ = ("quantifier", "target")

    def __init__(self, quantifier: str, target: str):
        self.quantifier = quantifier   # "all" or a numeric string like "1"
        self.target = target           # "selection_*", "them", etc.

    def __repr__(self):
        return f"Quant({self.quantifier}, {self.target})"


# ---------------------------------------------------------------------------
# Recursive-descent parser for Sigma conditions
# ---------------------------------------------------------------------------

class _ConditionParser:
    """
    Parse Sigma condition tokens into an AST.

    Grammar (simplified):
        expr     := or_expr
        or_expr  := and_expr ("or" and_expr)*
        and_expr := unary ("and" unary)*
        unary    := "not" unary | atom
        atom     := "(" expr ")" | quantifier | IDENT
        quantifier := ("all of" | NUM_OF) (IDENT | "them")
    """

    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str]:
        return self.tokens[self.pos]

    def _advance(self) -> tuple[str, str]:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        node = self._or_expr()
        # Ignore anything after a pipe (aggregation expressions).
        return node

    def _or_expr(self):
        left = self._and_expr()
        while self._peek()[0] == _TOK_OR:
            self._advance()  # consume "or"
            right = self._and_expr()
            left = _ASTBinOp("or", left, right)
        return left

    def _and_expr(self):
        left = self._unary()
        while self._peek()[0] == _TOK_AND:
            self._advance()  # consume "and"
            right = self._unary()
            left = _ASTBinOp("and", left, right)
        return left

    def _unary(self):
        if self._peek()[0] == _TOK_NOT:
            self._advance()  # consume "not"
            child = self._unary()
            return _ASTNot(child)
        return self._atom()

    def _atom(self):
        tok_type, tok_val = self._peek()

        if tok_type == _TOK_LPAREN:
            self._advance()  # consume "("
            node = self._or_expr()
            if self._peek()[0] == _TOK_RPAREN:
                self._advance()  # consume ")"
            return node

        if tok_type == _TOK_ALL_OF:
            self._advance()  # consume "all of"
            target_type, target_val = self._advance()
            if target_type == _TOK_THEM:
                return _ASTQuantifier("all", "them")
            return _ASTQuantifier("all", target_val)

        if tok_type == _TOK_NUM_OF:
            num = tok_val
            self._advance()  # consume "<N> of"
            target_type, target_val = self._advance()
            if target_type == _TOK_THEM:
                return _ASTQuantifier(num, "them")
            return _ASTQuantifier(num, target_val)

        if tok_type == _TOK_IDENT:
            self._advance()
            return _ASTRef(tok_val)

        # Fallback: skip unexpected tokens.
        self._advance()
        return _ASTRef("selection")


def _parse_condition_ast(condition_str: str):
    """Parse a Sigma condition string into an AST."""
    tokens = _tokenize_condition(condition_str)
    parser = _ConditionParser(tokens)
    return parser.parse()


# ---------------------------------------------------------------------------
# AST -> predicate list compilation
# ---------------------------------------------------------------------------

def _resolve_section_names(name: str, sections: dict) -> list[str]:
    """
    Resolve a section reference to actual section names.

    Handles wildcards like "selection_*" and the special keyword "them".
    """
    if name == "them":
        return list(sections.keys())

    if "*" in name:
        prefix = name.replace("*", "")
        return [n for n in sections if n.startswith(prefix)]

    if name in sections:
        return [name]

    return []


def _section_predicates(section_name: str, sections: dict,
                        negate: bool = False) -> list[dict]:
    """Build predicate dicts from a single named section."""
    section_data = sections.get(section_name)
    if section_data is None:
        return []
    if isinstance(section_data, dict):
        return parse_selection_map(section_data, negate=negate)
    if isinstance(section_data, list):
        return parse_selection_list(section_data, negate=negate)
    return []


def _merge_predicates_by_field(predicate_lists: list[list[dict]]) -> list[dict]:
    """
    Merge multiple predicate lists (from OR-ed selection blocks) into a single
    list by combining values for identical (field, modifier, negate) tuples.

    This is used when OR-ed selection blocks are combined with outer AND logic.
    The merge unions the value lists so that a match against *any* original
    block's values satisfies the predicate.

    For example, two blocks:
        sel1: TargetFilename|contains: ['/1Password/']  AND  TargetFilename|endswith: ['.sqlite']
        sel2: TargetFilename|contains: ['/Bitwarden/']  AND  TargetFilename|endswith: ['.sqlite', '.db']

    Merge into:
        TargetFilename|contains: ['/1Password/', '/Bitwarden/']
        TargetFilename|endswith: ['.sqlite', '.db']

    Note: this is a *conservative over-approximation* when the blocks have
    different field structures (e.g., sel1 has field A and B, sel2 has only
    field B). In that case, merged field A predicates would require a match
    even for events that should only match sel2. To handle this correctly,
    we only merge when all blocks share the same set of (field, modifier) keys.
    When they differ, we fall back to emitting all predicates as-is for use
    with any_of.
    """
    if not predicate_lists:
        return []

    if len(predicate_lists) == 1:
        return predicate_lists[0]

    # Determine whether all blocks share the same field structure.
    def _field_signature(preds):
        return frozenset((p["field"], p["modifier"]) for p in preds)

    signatures = [_field_signature(pl) for pl in predicate_lists]
    all_same_structure = all(s == signatures[0] for s in signatures)

    if all_same_structure and signatures[0]:
        # Safe to merge: union values for each (field, modifier) key.
        merged = {}
        for preds in predicate_lists:
            for p in preds:
                key = (p["field"], p["modifier"], p["negate"])
                if key not in merged:
                    merged[key] = {
                        "field": p["field"],
                        "modifier": p["modifier"],
                        "values": list(p["values"]),
                        "negate": p["negate"],
                    }
                else:
                    # Union values, preserving order, avoiding duplicates.
                    existing = set(merged[key]["values"])
                    for v in p["values"]:
                        if v not in existing:
                            merged[key]["values"].append(v)
                            existing.add(v)
        return list(merged.values())

    # Blocks have different field structures — cannot safely merge for all_of.
    # Return None to signal the caller to use any_of instead.
    return None


def _collect_and_clauses(node) -> list:
    """Flatten a chain of AND nodes into a list of clauses."""
    if isinstance(node, _ASTBinOp) and node.op == "and":
        return _collect_and_clauses(node.left) + _collect_and_clauses(node.right)
    return [node]


def _collect_or_clauses(node) -> list:
    """Flatten a chain of OR nodes into a list of clauses."""
    if isinstance(node, _ASTBinOp) and node.op == "or":
        return _collect_or_clauses(node.left) + _collect_or_clauses(node.right)
    return [node]


def _is_pure_or_of_refs(node) -> bool:
    """Check whether a node is a pure OR of simple references (no NOT, no nested AND)."""
    if isinstance(node, _ASTRef):
        return True
    if isinstance(node, _ASTBinOp) and node.op == "or":
        return _is_pure_or_of_refs(node.left) and _is_pure_or_of_refs(node.right)
    return False


def _compile_condition(condition_str: str, sections: dict) -> tuple[list[dict], str]:
    """
    Compile a Sigma condition string into (predicates, condition_type).

    Handles the following patterns (and combinations thereof):

    1. Simple reference:
       "selection" → all_of with predicates from selection

    2. AND of references with optional NOT:
       "selection and not filter" → all_of
       "sel1 and sel2 and not filter1 and not filter2" → all_of

    3. Pure OR of references:
       "sel1 or sel2 or sel3" → any_of with all predicates

    4. OR-in-parens AND additional clauses:
       "(sel1 or sel2) and not filter" → all_of, merging OR predicates

    5. AND with nested OR:
       "sel and (sel2 or sel3)" → all_of, merging OR predicates

    6. Quantifiers:
       "1 of selection_*" → any_of
       "all of selection_*" → all_of
       "all of them" → all_of

    7. Pipe/aggregation:
       "selection and not filter | count(X) by Y > N" → parsed up to pipe,
       aggregation is ignored (post-processing)
    """
    ast = _parse_condition_ast(condition_str)
    return _compile_ast(ast, sections)


def _compile_ast(node, sections: dict) -> tuple[list[dict], str]:
    """Recursively compile an AST node into (predicates, condition_type)."""

    # --- Leaf: section reference ---
    if isinstance(node, _ASTRef):
        names = _resolve_section_names(node.name, sections)
        predicates = []
        for name in names:
            predicates.extend(_section_predicates(name, sections, negate=False))
        return predicates, "all_of"

    # --- Quantifier: "1 of X", "all of X" ---
    if isinstance(node, _ASTQuantifier):
        names = _resolve_section_names(node.target, sections)
        predicates = []
        for name in names:
            predicates.extend(_section_predicates(name, sections, negate=False))

        if node.quantifier == "all":
            return predicates, "all_of"
        else:
            return predicates, "any_of"

    # --- NOT ---
    if isinstance(node, _ASTNot):
        # Compile the child and negate all predicates.
        child_preds, child_cond = _compile_ast(node.child, sections)
        negated = []
        for p in child_preds:
            negated.append({
                "field": p["field"],
                "modifier": p["modifier"],
                "values": p["values"],
                "negate": not p["negate"],
            })
        return negated, child_cond

    # --- OR ---
    if isinstance(node, _ASTBinOp) and node.op == "or":
        # Pure OR of references: any_of across all predicates.
        or_clauses = _collect_or_clauses(node)

        all_preds = []
        for clause in or_clauses:
            clause_preds, _ = _compile_ast(clause, sections)
            all_preds.extend(clause_preds)

        return all_preds, "any_of"

    # --- AND ---
    if isinstance(node, _ASTBinOp) and node.op == "and":
        and_clauses = _collect_and_clauses(node)

        # Classify each clause.
        or_groups = []       # Clauses that are OR expressions (or OR under NOT)
        plain_clauses = []   # Simple refs, NOTs, quantifiers

        for clause in and_clauses:
            # Check if this clause is a pure OR group (possibly inside parens).
            if isinstance(clause, _ASTBinOp) and clause.op == "or":
                or_groups.append(clause)
            else:
                plain_clauses.append(clause)

        # Compile plain (non-OR) clauses — these are straightforward AND members.
        plain_preds = []
        for clause in plain_clauses:
            clause_preds, _ = _compile_ast(clause, sections)
            plain_preds.extend(clause_preds)

        # Handle OR groups within the AND.
        if not or_groups:
            # Simple AND of refs/NOTs — all_of.
            return plain_preds, "all_of"

        # We have OR groups combined with AND.  Try to merge the OR predicates.
        for or_group in or_groups:
            or_clauses = _collect_or_clauses(or_group)

            # Build a list of predicate-lists, one per OR clause.
            or_pred_lists = []
            for oc in or_clauses:
                oc_preds, _ = _compile_ast(oc, sections)
                or_pred_lists.append(oc_preds)

            merged = _merge_predicates_by_field(or_pred_lists)

            if merged is not None:
                # Successfully merged — add to the AND set.
                plain_preds.extend(merged)
            else:
                # Cannot merge (different field structures).
                # Best effort: if there are no other AND constraints besides
                # negated filters, we can use any_of for the OR group and
                # emit the filters alongside.  The filters won't be enforced
                # as strictly, but it's better than losing the OR entirely.
                #
                # Check if all plain clauses are negated (filters).
                all_plain_negated = all(p["negate"] for p in plain_preds)
                if all_plain_negated or not plain_preds:
                    # Use any_of: emit all OR predicates + negated filters.
                    # Since any_of requires ANY predicate to match, and negated
                    # predicates match when the field is absent or different,
                    # this isn't perfect but is the best flat approximation.
                    #
                    # Actually, for the common pattern where the only AND
                    # clauses are "not filter", we can do better: duplicate the
                    # negated filter predicates into each OR branch so that
                    # each OR branch becomes a self-contained AND group.
                    # Then use any_of across the augmented branches.
                    #
                    # But since our format is a flat list, we take the pragmatic
                    # approach: emit all OR predicates as any_of.  The filters
                    # are added but in any_of mode, they fire independently.
                    # This is a known limitation logged as a warning.
                    all_or_preds = []
                    for pl in or_pred_lists:
                        all_or_preds.extend(pl)
                    print(
                        f"  WARNING: OR group with heterogeneous field structures "
                        f"combined with AND filters. Filter enforcement may be "
                        f"incomplete in flat predicate format.",
                        file=sys.stderr,
                    )
                    return all_or_preds + plain_preds, "any_of"
                else:
                    # There are non-negated AND clauses alongside the OR group.
                    # Fall back to all_of with all predicates merged.
                    all_or_preds = []
                    for pl in or_pred_lists:
                        all_or_preds.extend(pl)
                    return all_or_preds + plain_preds, "all_of"

        return plain_preds, "all_of"

    # Fallback.
    return [], "all_of"


# ---------------------------------------------------------------------------
# Condition tree builder (hierarchical, preserves boolean structure)
# ---------------------------------------------------------------------------

def _ast_to_condition_tree(node, sections: dict, predicates: list[dict]) -> dict:
    """
    Convert an AST node into a hierarchical condition tree JSON structure.

    Predicates are appended to the `predicates` list as they are encountered.
    The tree references them by index. This preserves the full boolean structure
    of complex Sigma conditions like:
        (selection_a and not filter_b) or ioc_c

    Returns a dict like:
        {"type": "and", "operands": [
            {"type": "group", "rangeStart": 0, "rangeEnd": 2, "mode": "all_of"},
            {"type": "not", "operands": [
                {"type": "group", "rangeStart": 2, "rangeEnd": 4, "mode": "all_of"}
            ]}
        ]}
    """
    # --- Leaf: section reference ---
    if isinstance(node, _ASTRef):
        names = _resolve_section_names(node.name, sections)
        start = len(predicates)
        for name in names:
            predicates.extend(_section_predicates(name, sections, negate=False))
        end = len(predicates)
        if end - start == 1:
            return {"type": "predicate", "index": start}
        return {"type": "group", "rangeStart": start, "rangeEnd": end, "mode": "all_of"}

    # --- Quantifier: "1 of X", "all of X" ---
    if isinstance(node, _ASTQuantifier):
        names = _resolve_section_names(node.target, sections)
        start = len(predicates)
        for name in names:
            predicates.extend(_section_predicates(name, sections, negate=False))
        end = len(predicates)
        mode = "all_of" if node.quantifier == "all" else "any_of"
        return {"type": "group", "rangeStart": start, "rangeEnd": end, "mode": mode}

    # --- NOT ---
    if isinstance(node, _ASTNot):
        child_tree = _ast_to_condition_tree(node.child, sections, predicates)
        return {"type": "not", "operands": [child_tree]}

    # --- OR ---
    if isinstance(node, _ASTBinOp) and node.op == "or":
        or_clauses = _collect_or_clauses(node)
        operands = [_ast_to_condition_tree(c, sections, predicates) for c in or_clauses]
        return {"type": "or", "operands": operands}

    # --- AND ---
    if isinstance(node, _ASTBinOp) and node.op == "and":
        and_clauses = _collect_and_clauses(node)
        operands = [_ast_to_condition_tree(c, sections, predicates) for c in and_clauses]
        return {"type": "and", "operands": operands}

    # Fallback
    return {"type": "and", "operands": []}


def _needs_condition_tree(ast_node, sections=None) -> bool:
    """
    Determine if an AST is complex enough to require a condition tree.

    Simple cases (single ref, pure AND of refs/NOTs, pure OR of refs whose
    referenced sections each produce exactly one predicate) are handled
    fine by the flat condition format. We emit trees for rules that mix
    AND/OR/NOT in ways the flat format can't represent.

    **v1.3.11 fix**: A pure `sel_A or sel_B` previously returned False
    here and was compiled as a flat `any_of`. That broke every rule whose
    selections contained multiple field matches meant to AND together —
    e.g. EDR rule with `selection_defender: Image|endswith: /mdatp` AND
    `CommandLine|contains: live-response`. Flat `any_of` meant any process
    whose commandline just contained "live-response" fired — or worse,
    `CommandLine contains "connect"` matched every xpcproxy and every
    "scan" / "-s" commandline triggered the Wi-Fi attack rule. If any ref
    resolves to a multi-predicate section, force the tree path so the
    intra-selection AND survives compilation.
    """
    if isinstance(ast_node, (_ASTRef, _ASTQuantifier)):
        return False

    if isinstance(ast_node, _ASTNot):
        return _needs_condition_tree(ast_node.child, sections)

    if isinstance(ast_node, _ASTBinOp):
        if ast_node.op == "and":
            # AND of simple refs/NOTs is fine flat
            clauses = _collect_and_clauses(ast_node)
            for c in clauses:
                if isinstance(c, _ASTBinOp) and c.op == "or":
                    # OR inside AND — might need a tree
                    return True
                if isinstance(c, _ASTNot) and isinstance(c.child, _ASTBinOp):
                    return True
            return False

        if ast_node.op == "or":
            # OR of simple refs USED to be fine flat; now we also check
            # whether any referenced section has multiple predicates (i.e.
            # multiple field/value pairs in the selection map). If so we
            # need a tree to preserve intra-selection AND semantics.
            clauses = _collect_or_clauses(ast_node)
            for c in clauses:
                if isinstance(c, _ASTBinOp) and c.op == "and":
                    # AND inside OR — needs a tree
                    return True
                if isinstance(c, _ASTNot):
                    # NOT inside OR needs care
                    return True
                if sections is not None and isinstance(c, _ASTRef):
                    names = _resolve_section_names(c.name, sections)
                    for name in names:
                        preds = _section_predicates(name, sections, negate=False)
                        if len(preds) > 1:
                            return True
            return False

    return False


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

    NOTE: This function is retained for backward compatibility but is no longer
    used by the main compilation path (which uses the AST-based parser).
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
    Infer the MacCrab condition type from a Sigma condition string.

    NOTE: This function is retained for backward compatibility but is no longer
    used by the main compilation path (which uses the AST-based parser).
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
    Compile a single Sigma YAML rule into the MacCrab JSON predicate format.

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

    # Set the module-level title so helper functions can include it in warnings.
    global _current_compile_rule_title
    _current_compile_rule_title = title
    description = rule_data.get("description", "")
    level = rule_data.get("level", "medium").lower()
    tags = rule_data.get("tags", [])
    falsepositives = rule_data.get("falsepositives", [])
    if falsepositives is None:
        falsepositives = []

    # Sigma `status` → runtime `enabled` flag. `deprecated` rules still
    # compile (so their id/title show up in the rule browser and existing
    # suppressions tied to the id keep working), but they ship disabled so
    # the engine skips them in the hot path. This lets us park rules whose
    # detection logic is known-broken without having to delete the file.
    status = (rule_data.get("status") or "experimental").strip().lower()
    enabled = status != "deprecated"

    # Validate severity level.
    valid_levels = {"informational", "low", "medium", "high", "critical"}
    if level not in valid_levels:
        level = "medium"

    # --- Detection block ---
    detection = rule_data.get("detection")
    if not detection:
        print(f"  WARNING: No detection block in {source_file}, skipping", file=sys.stderr)
        return None

    predicates, condition_type, condition_tree = parse_detection_block(detection)

    if not predicates:
        print(f"  WARNING: No predicates generated from {source_file}, skipping", file=sys.stderr)
        return None

    # Lint: process_creation rules in discovery/, execution/, and
    # privilege_escalation/ that match on GENERIC binary names (shells,
    # interpreters, generic CLI tools) should include a PlatformBinary or
    # SignerType:apple filter. These were the #1 FP source in v1.3–v1.4:
    # the code-signing enrichment returns nil for short-lived Apple binaries,
    # silently breaking SignerType filters and letting Apple daemons fire rules
    # written to catch attacker tools.
    #
    # Intentionally does NOT flag rules that match on SPECIFIC named third-party
    # tools (e.g. dscl, profiles, smbutil) — FP for those rules is about who
    # runs the tool (parent context), not whether the tool is a platform binary.
    _GENERIC_BINARY_INDICATORS = {
        "/bash", "/zsh", "/sh", "/fish", "/dash", "/ksh", "/tcsh",
        "/python", "/python3", "/ruby", "/perl", "/node",
        "/osascript", "/swift", "/swiftc",
        "/launchctl",       # generic enough to be fired on by Apple daemons
        "/defaults",        # fired by system preference plists constantly
    }
    if category == "process_creation":
        tactic_dir = os.path.basename(os.path.dirname(source_file))
        if tactic_dir in {"discovery", "execution", "privilege_escalation"}:
            detection_str = str(detection)
            targets_generic_binary = any(
                indicator in detection_str for indicator in _GENERIC_BINARY_INDICATORS
            )
            if targets_generic_binary:
                has_platform_filter = (
                    "PlatformBinary" in detection_str
                    or ("SignerType" in detection_str and "apple" in detection_str.lower())
                    or "filter_platform" in detection_str
                    or "filter_apple" in detection_str
                )
                if not has_platform_filter:
                    print(
                        f"  HINT  '{title}' ({tactic_dir}/) matches generic binaries but "
                        f"has no PlatformBinary/SignerType:apple filter — Apple-binary FP "
                        f"risk (code-sign enrichment may return nil for platform binaries). "
                        f"({os.path.basename(source_file)})",
                        file=sys.stderr,
                    )

    result = {
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
        "enabled": enabled,
    }

    if condition_tree is not None:
        result["condition_tree"] = condition_tree

    return result


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


def _parse_window(window_str) -> float:
    """Parse a window duration string like '10s', '2m', '120s' to seconds."""
    if isinstance(window_str, (int, float)):
        return float(window_str)
    s = str(window_str).strip().lower()
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60
    if s.endswith("h"):
        return float(s[:-1]) * 3600
    return float(s)


_CORRELATION_MAP = {
    "process.same": "processSame",
    "process.lineage": "processLineage",
    "file.path": "filePath",
    "network.endpoint": "networkEndpoint",
    "none": "none",
}


def compile_sequence_rule(rule_data: dict, source_file: str):
    """
    Compile a sequence (temporal-causal) rule into SequenceEngine JSON.

    Sequence rules have type: sequence, steps: [...], window, correlation, etc.
    Returns the compiled dict, or None to skip.
    """
    rule_id = rule_data.get("id", str(uuid.uuid4()))
    title = rule_data.get("title", "Untitled Sequence")
    description = rule_data.get("description", "")
    level = rule_data.get("level", "high").lower()
    tags = rule_data.get("tags", [])
    valid_levels = {"informational", "low", "medium", "high", "critical"}
    if level not in valid_levels:
        level = "high"

    window = _parse_window(rule_data.get("window", "60s"))
    correlation_raw = rule_data.get("correlation", "none")
    correlation = _CORRELATION_MAP.get(correlation_raw, "none")
    ordered = rule_data.get("ordered", True)

    # Parse trigger
    trigger_raw = rule_data.get("trigger", "all")
    if trigger_raw == "all":
        trigger = {"type": "all_steps"}
    elif isinstance(trigger_raw, int):
        trigger = {"type": "any_steps", "value": trigger_raw}
    elif isinstance(trigger_raw, str) and " and " in trigger_raw:
        # "persist and c2" → steps trigger with specific IDs
        step_ids = [s.strip() for s in trigger_raw.split(" and ")]
        trigger = {"type": "steps", "value": step_ids}
    else:
        trigger = {"type": "all_steps"}

    # Parse steps
    yaml_steps = rule_data.get("steps", [])
    if not yaml_steps:
        print(f"  WARNING: No steps in sequence rule {source_file}, skipping", file=sys.stderr)
        return None

    compiled_steps = []
    prev_step_id = None

    for step_data in yaml_steps:
        step_id = step_data.get("id", f"step_{len(compiled_steps)}")
        logsource = step_data.get("logsource", {})
        logsource_cat = logsource.get("category", "process_creation")

        # Compile step's detection block
        detection = step_data.get("detection")
        if not detection:
            print(f"  WARNING: Step '{step_id}' in {source_file} has no detection, skipping rule", file=sys.stderr)
            return None

        predicates, condition_type, _ = parse_detection_block(detection)

        # Parse process relation (e.g., "shell.same", "execute.descendant")
        process_rel = None
        process_str = step_data.get("process")
        if process_str and "." in str(process_str):
            parts = str(process_str).split(".", 1)
            relative_to = parts[0]
            relation = parts[1]
            process_rel = {
                "relation": relation,
                "relativeToStep": relative_to,
            }

        # afterStep: if ordered and there's a previous step, link to it
        after_step = None
        if ordered and prev_step_id is not None:
            after_step = prev_step_id

        compiled_steps.append({
            "id": step_id,
            "logsourceCategory": logsource_cat,
            "predicates": predicates,
            "condition": condition_type,
            "afterStep": after_step,
            "processRelation": process_rel,
        })

        prev_step_id = step_id

    return {
        "id": rule_id,
        "title": title,
        "description": description,
        "level": level,
        "tags": tags,
        "window": window,
        "correlationType": correlation,
        "ordered": ordered,
        "steps": compiled_steps,
        "trigger": trigger,
        "enabled": True,
    }


def _snapshot_previous_output(output_dir: str, archive_root: str, keep: int = 5) -> None:
    """
    Snapshot the current contents of output_dir into
    archive_root/<timestamp>/ before overwriting. Retains the most recent
    `keep` snapshots; older ones are deleted.

    No-op when output_dir is empty or does not exist — there's nothing
    useful to preserve yet.

    Why: `make compile-rules` overwrites compiled_rules/ wholesale. If the
    new corpus has a bug (broken rule, accidentally deleted detection),
    we want a trivial rollback path. A timestamped archive gives ops
    `cp -R compiled_rules.archive/<ts> compiled_rules` as the recovery
    command, with no git history required.
    """
    import shutil
    import time

    if not os.path.isdir(output_dir):
        return
    try:
        entries = os.listdir(output_dir)
    except OSError:
        return
    entries = [e for e in entries if not e.startswith(".")]
    if not entries:
        return

    os.makedirs(archive_root, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    snapshot = os.path.join(archive_root, ts)

    # If two compiles run in the same second, disambiguate with a counter.
    i = 1
    while os.path.exists(snapshot):
        snapshot = os.path.join(archive_root, f"{ts}-{i}")
        i += 1

    try:
        shutil.copytree(output_dir, snapshot,
                        ignore=shutil.ignore_patterns("*.tmp"))
    except Exception as exc:
        print(f"  WARN  Rule archive skipped: {exc}", file=sys.stderr)
        return

    # Prune older snapshots beyond `keep`.
    try:
        snapshots = sorted(
            os.path.join(archive_root, d)
            for d in os.listdir(archive_root)
            if os.path.isdir(os.path.join(archive_root, d))
        )
        for stale in snapshots[:-keep]:
            shutil.rmtree(stale, ignore_errors=True)
    except OSError:
        pass


def compile_all(input_dir: str, output_dir: str) -> tuple[int, int, int]:
    """
    Compile all Sigma YAML rules from input_dir and write JSON to output_dir.

    Before overwriting output_dir, snapshot its previous contents into
    `<output_dir>.archive/<timestamp>/` — keeps the last 5 snapshots so
    a bad compile can be rolled back with `cp -R`.

    Returns (total_found, compiled, skipped).
    """
    # Snapshot the previous compiled corpus (best-effort).
    archive_root = output_dir.rstrip(os.sep) + ".archive"
    _snapshot_previous_output(output_dir, archive_root, keep=5)

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
                # Use _DuplicateKeyChecker to warn on duplicate keys.
                documents = list(yaml.load_all(f, Loader=_DuplicateKeyChecker))
        except Exception as exc:
            print(f"  ERROR parsing {rel_path}: {exc}", file=sys.stderr)
            skipped += 1
            continue

        for doc_idx, rule_data in enumerate(documents):
            if not isinstance(rule_data, dict):
                continue

            # Detect sequence rules (type: sequence) vs standard single-event rules.
            is_sequence = rule_data.get("type", "").lower() == "sequence"

            if is_sequence:
                result = compile_sequence_rule(rule_data, rel_path)
            else:
                result = compile_rule(rule_data, rel_path)

            if result is None:
                skipped += 1
                continue

            # Determine output directory and filename.
            base_name = os.path.splitext(os.path.basename(filepath))[0]
            if len(documents) > 1:
                out_name = f"{base_name}_{doc_idx}.json"
            else:
                out_name = f"{base_name}.json"

            if is_sequence:
                seq_dir = os.path.join(output_dir, "sequences")
                os.makedirs(seq_dir, exist_ok=True)
                out_path = os.path.join(seq_dir, out_name)
            else:
                out_path = os.path.join(output_dir, out_name)

            with open(out_path, "w", encoding="utf-8") as out_f:
                json.dump(result, out_f, indent=2, ensure_ascii=False)
                out_f.write("\n")

            compiled += 1
            tag = "SEQ" if is_sequence else "OK "
            print(f"  {tag} {rel_path} -> {out_name}")

    return total, compiled, skipped


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Compile Sigma YAML rules to MacCrab JSON predicate format."
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
