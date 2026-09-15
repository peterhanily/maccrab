#!/usr/bin/env python3
"""Prove one historical resource measurement remains compatible; never execute it."""
import argparse
import ast
import hashlib
import functools
import json
import os
from pathlib import Path
import stat

ARCHIVE = 'docs/release-provenance/resource-baseline-recorder-v1.py.txt'
RECORDER_SHA = '6871807f08e6477db7525c4f78ae522d3b4296095e2a5560b6a500792ed7f33d'
BASELINE_SHA = 'c3134ac55a0546640fe51db5f547ab819643af83185af5b069bd89deafbfe809'
PRIVATE_EVIDENCE_SHA256 = 'b435df9a74658e1d04d9b152359c725cb86ce6e7465cc06c94e450a48c352ef3'
PRIVATE_CANONICAL_SHA256 = 'c3a8eb418db899b41031dacab7a3fd1322070fd0ceeb9e03fa33bb794ab4b9c7'
ROOTS = ('command_record_resource_baseline', 'validate_resource_baseline')
OLD_GUARD = '        fail("resource baseline recorder bytes differ from the candidate source")'
NEW_GUARD = '''        run_checked(
            [sys.executable, "-I", "-B",
             str(source_root / "scripts/resource-baseline-provenance.py"),
             "--source-root", str(source_root), "--document-sha256",
             sha256_bytes(canonical_json_bytes(document))],
            "resource baseline recorder provenance",
        )'''


class ProvenanceError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ProvenanceError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def read_regular(path, limit=2 * 1024 * 1024):
    require(path.resolve() == path, 'Redirected provenance input')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'Invalid provenance input')
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(raw) == before.st_size, 'Provenance input changed while reading')
    return raw


@functools.lru_cache(maxsize=2)
def source_lines(text):
    return text.encode('utf-8').splitlines(keepends=True)


def source(node, text):
    lines = source_lines(text)
    start, column = node.lineno - 1, node.col_offset
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.decorator_list:
        first = node.decorator_list[0]
        start, column = first.lineno - 1, first.col_offset - 1
    end = node.end_lineno - 1
    if start == end:
        raw = lines[start][column:node.end_col_offset]
    else:
        raw = lines[start][column:] + b''.join(lines[start + 1:end]) + lines[end][:node.end_col_offset]
    return raw.decode('utf-8')


def declaration_key(node, text):
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return (type(node).__name__, node.name)
    if isinstance(node, ast.Assign):
        return ('Assign', *(target.id for target in node.targets))
    return (type(node).__name__, source(node, text))


def module(text):
    tree = ast.parse(text)
    bindings = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            require(all(isinstance(target, ast.Name) for target in node.targets), 'Effectful module assignment')
            names = [target.id for target in node.targets]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            require(all(alias.name != '*' for alias in node.names), 'Wildcard import is unsupported')
            names = [alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)
                     for alias in node.names]
        else:
            names = []
        for name in names:
            existing = bindings.get(name, [])
            require(not existing or isinstance(node, (ast.Import, ast.ImportFrom))
                    and all(isinstance(old, (ast.Import, ast.ImportFrom)) for old in existing),
                    'Duplicate or rebound module symbol: ' + name)
            bindings.setdefault(name, []).append(node)
    return tree, bindings


def normalize_guard(text):
    tree, bindings = module(text)
    nodes = bindings.get('validate_resource_baseline', [])
    require(len(nodes) == 1 and isinstance(nodes[0], ast.FunctionDef), 'Resource validator is missing')
    node = nodes[0]
    body = source(node, text)
    if NEW_GUARD in body:
        require(body.count(NEW_GUARD) == 1 and OLD_GUARD not in body, 'Ambiguous recorder provenance guard')
        lines = text.splitlines(keepends=True)
        segment = ''.join(lines[node.lineno - 1:node.end_lineno])
        return ''.join(lines[:node.lineno - 1]) + segment.replace(NEW_GUARD, OLD_GUARD) + ''.join(lines[node.end_lineno:])
    require(body.count(OLD_GUARD) == 1, 'Unknown recorder provenance guard')
    return text


def closure(bindings):
    pending, seen = list(ROOTS), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        require(name in bindings, 'Missing reference dependency: ' + name)
        seen.add(name)
        for node in bindings[name]:
            # Includes annotations, defaults, decorators, nested functions and
            # complete class bodies. Local-name over-inclusion is conservative.
            pending.extend(item.id for item in ast.walk(node)
                           if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
                           and item.id in bindings and item.id not in seen)
    return seen


def inert_literal(node, *, names=False):
    if isinstance(node, ast.Constant) or names and isinstance(node, ast.Name):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(inert_literal(item, names=names) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and inert_literal(key, names=names) and inert_literal(value, names=names)
                   for key, value in zip(node.keys, node.values))
    return isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)) and inert_literal(node.operand)


def verify_sources(archived_raw, current_raw):
    require(digest(archived_raw) == RECORDER_SHA, 'Historical recorder archive hash differs')
    old = archived_raw.decode('utf-8')
    current = normalize_guard(current_raw.decode('utf-8'))
    old_tree, old_bindings = module(old)
    new_tree, new_bindings = module(current)
    names = closure(old_bindings)
    require(closure(new_bindings) == names, 'Resource measurement dependency closure changed')
    for name in sorted(names):
        require([source(node, old) for node in old_bindings[name]] ==
                [source(node, current) for node in new_bindings[name]],
                'Resource measurement dependency changed: ' + name)
    # CLI construction/dispatch is byte-identical without recursively dragging
    # unrelated subcommands into the measurement dependency closure.
    for name in ('parser', 'main'):
        require([source(node, old) for node in old_bindings[name]] ==
                [source(node, current) for node in new_bindings.get(name, [])],
                'Reference CLI dispatch changed: ' + name)
    imports = lambda tree, text: [source(node, text) for node in tree.body
                                 if isinstance(node, (ast.Import, ast.ImportFrom))]
    require(imports(old_tree, old) == imports(new_tree, current), 'Module imports changed')
    # All four historical classes are in the measurement closure. New classes,
    # executable top-level statements, rebinding and effectful defaults could
    # alter measurement behavior even when the function text stays unchanged.
    require({node.name for node in new_tree.body if isinstance(node, ast.ClassDef)} ==
            {node.name for node in old_tree.body if isinstance(node, ast.ClassDef)}, 'Module classes changed')
    old_other = [source(node, old) for node in old_tree.body
                 if not isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Assign, ast.Import, ast.ImportFrom))]
    new_other = [source(node, current) for node in new_tree.body
                 if not isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Assign, ast.Import, ast.ImportFrom))]
    require(old_other == new_other, 'Module import-time statements changed')
    require(set(old_bindings).issubset(new_bindings), 'Historical module binding removed')
    old_order = [declaration_key(node, old) for node in old_tree.body]
    new_order = [declaration_key(node, current) for node in new_tree.body]
    require([key for key in new_order if key in old_order] == old_order,
            'Historical module declaration order changed')
    for name in new_bindings:
        if name.startswith('__') and name.endswith('__'):
            require(name in old_bindings and
                    [source(node, current) for node in new_bindings[name]] ==
                    [source(node, old) for node in old_bindings[name]],
                    'Interpreter namespace binding changed')
    for node in new_tree.body:
        if isinstance(node, ast.Assign):
            old_nodes = old_bindings.get(node.targets[0].id, [])
            unchanged = any(source(old_node, old) == source(node, current) for old_node in old_nodes)
            require(unchanged or inert_literal(node.value), 'Effectful changed module initializer')
        elif isinstance(node, ast.FunctionDef) and node.name not in names:
            require(not node.decorator_list, 'New import-time function decorator')
            defaults = [*node.args.defaults, *(value for value in node.args.kw_defaults if value is not None)]
            require(all(inert_literal(value, names=True) for value in defaults), 'Effectful function default')
    manifest = {name: [digest(source(node, old).encode()) for node in old_bindings[name]] for name in sorted(names)}
    return {'status': 'EXACT_HISTORICAL_RESOURCE_PROTOCOL_VERIFIED', 'historical_recorder_sha256': RECORDER_SHA,
            'current_recorder_sha256': digest(current_raw), 'dependency_count': len(names),
            'dependency_manifest_sha256': digest(canonical(manifest))}


def verify(source_root, document_sha256, public_policy_document_sha256=None):
    root = Path(source_root).resolve()
    baseline_raw = read_regular(root / 'docs/RELEASE_RESOURCE_BASELINE.json')
    require(digest(baseline_raw) == BASELINE_SHA, 'Only the exact accepted public resource policy is compatible')
    baseline = json.loads(baseline_raw)
    if public_policy_document_sha256 is not None:
        require(digest(canonical(baseline)) == public_policy_document_sha256,
                'Passed public policy document differs from the frozen policy')
    require(baseline.get('private_evidence') == {'sha256': PRIVATE_EVIDENCE_SHA256,
            'canonical_sha256': PRIVATE_CANONICAL_SHA256}, 'Private historical evidence commitment differs')
    require(document_sha256 == PRIVATE_CANONICAL_SHA256,
            'Passed baseline document differs from exact private historical evidence')
    require(baseline.get('recorder') == {'path': 'scripts/candidate-qualification.py', 'sha256': RECORDER_SHA},
            'Historical baseline recorder identity differs')
    archived = read_regular(root / ARCHIVE)
    current = read_regular(root / 'scripts/candidate-qualification.py')
    # Do not quietly carry historical workload executors across a code change.
    for row in baseline['workload']['executors']:
        require(row['path'] in ('scripts/runtime-qualification-workload.sh', 'scripts/test-otlp-curl.sh')
                and digest(read_regular(root / row['path'])) == row['sha256'], 'Historical workload executor changed')
    proof = verify_sources(archived, current)
    proof['baseline_sha256'] = BASELINE_SHA
    proof['private_evidence_sha256'] = PRIVATE_EVIDENCE_SHA256
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--document-sha256', required=True)
    parser.add_argument('--public-policy-document-sha256')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.source_root, args.document_sha256,
                               args.public_policy_document_sha256), sort_keys=True))
    except (ProvenanceError, OSError, ValueError, KeyError, TypeError, SyntaxError) as error:
        parser.exit(1, 'Resource baseline provenance refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
