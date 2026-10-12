#!/usr/bin/env python3
"""Offline controls for historical compatibility, not current baseline acceptance.

Sources are parsed or hashed as data, never executed. No Git history, network,
installed-host probe, private receipt or workload execution is required.
Archived-source compatibility has positive coverage. Full historical integration
does not: the old workload bytes are intentionally not reintroduced as fixtures.
Current integration must reject the changed workload, never claim acceptance.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('resource_provenance', ROOT / 'scripts/resource-baseline-provenance.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
ARCHIVED = (ROOT / P.ARCHIVE).read_bytes()
CURRENT = (ROOT / 'scripts/candidate-qualification.py').read_bytes()


class ResourceBaselineProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Establish the positive control before any mutation test runs.
        P.verify_sources(ARCHIVED, ARCHIVED)

    def reject(self, source):
        with self.assertRaises(P.ProvenanceError):
            P.verify_sources(ARCHIVED, source.encode())

    def altered(self, before, after, raw=ARCHIVED):
        self.assertEqual(P.digest(raw), P.RECORDER_SHA, 'Mutation base must be the verified archive')
        source = raw.decode()
        self.assertTrue(before in source, "Mutation target is absent: " + before)
        return source.replace(before, after, 1)

    def test_exact_archived_source_preserves_reference_protocol(self):
        proof = P.verify_sources(ARCHIVED, ARCHIVED)
        self.assertEqual(proof['status'], 'EXACT_HISTORICAL_RESOURCE_PROTOCOL_VERIFIED')
        self.assertEqual(proof['dependency_count'], 102)
        self.assertEqual(proof['current_recorder_sha256'], P.RECORDER_SHA)

    def test_current_recorder_changed_the_historical_executor_inventory(self):
        with self.assertRaisesRegex(P.ProvenanceError, 'RUNTIME_WORKLOAD_EXECUTORS'):
            P.verify_sources(ARCHIVED, CURRENT)

    def test_only_exact_guard_normalization_is_allowed(self):
        updated = self.altered(P.OLD_GUARD, P.NEW_GUARD, ARCHIVED)
        P.verify_sources(ARCHIVED, updated.encode())
        self.reject(updated.replace('"-I", "-B"', '"-B"', 1))
        self.reject(updated.replace('sha256_bytes(canonical_json_bytes(document))', '"different-document"', 1))

    def test_shared_helper_and_capture_statistic_changes_are_rejected(self):
        for before, after in (
            ('rank = max(1, math.ceil(percentile * len(ordered)))', 'rank = 1'),
            ('return mach_absolute_ticks_to_seconds(now - start)', 'return 999.0'),
            ('span = (times[end] - times[start]).total_seconds()',
             'span = 1.0'),
        ):
            with self.subTest(before=before):
                self.reject(self.altered(before, after))

    def test_resource_constant_and_import_changes_are_rejected(self):
        self.reject(self.altered('MIN_EPOCH_SECONDS = 900.0', 'MIN_EPOCH_SECONDS = 899.0'))
        self.reject(self.altered('import math', 'import math\nimport fractions'))

    def test_decorators_defaults_and_initializers_cannot_run_extra_code(self):
        for added in (
            '\ndef unused_probe(value=print("probe")):\n    pass\n',
            '\n@print("probe")\ndef unused_probe():\n    pass\n',
            '\nEXTRA = print("probe")\n',
            '\nsubprocess.run = None\n',
        ):
            with self.subTest(added=added):
                self.reject(ARCHIVED.decode() + added)
        self.reject(self.altered('@functools.lru_cache(maxsize=1)', '@functools.lru_cache(maxsize=2)'))

    def test_interpreter_bindings_and_top_level_order_are_preserved(self):
        for name in ('__name__', '__builtins__', '__file__', '__package__', '__spec__'):
            with self.subTest(name=name):
                self.reject(ARCHIVED.decode() + '\n' + name + ' = "disabled"\n')
        source = ARCHIVED.decode()
        marker = 'if __name__ == "__main__":'
        at = source.rindex(marker)
        guard = source[at:]
        insertion = source.index('\ndef ')
        self.reject(source[:insertion] + '\n' + guard + '\n' + source[insertion:at])

    def test_missing_dependencies_and_new_builtin_shadowing_are_rejected(self):
        self.reject(self.altered('def percentile_nearest_rank(', 'def renamed_percentile_nearest_rank('))
        self.reject(ARCHIVED.decode() + '\nlen = 3\n')

    def test_archive_bytes_are_not_a_general_old_hash_exception(self):
        with self.assertRaisesRegex(P.ProvenanceError, 'archive hash'):
            P.verify_sources(ARCHIVED + b'\n', ARCHIVED)

    def fixture(self, root):
        payloads = {
            P.ARCHIVE: ARCHIVED,
            'docs/RELEASE_RESOURCE_BASELINE.json': (ROOT / 'docs/RELEASE_RESOURCE_BASELINE.json').read_bytes(),
            'scripts/candidate-qualification.py': ARCHIVED,
            'scripts/runtime-qualification-workload.sh': (ROOT / 'scripts/runtime-qualification-workload.sh').read_bytes(),
            'scripts/test-otlp-curl.sh': (ROOT / 'scripts/test-otlp-curl.sh').read_bytes(),
        }
        for relative, raw in payloads.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o600)  # Inert private fixture data, never executable.
        return json.loads((root / 'docs/RELEASE_RESOURCE_BASELINE.json').read_bytes())['private_evidence']['canonical_sha256']

    def test_current_workload_bytes_cannot_reuse_the_historical_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            document_hash = self.fixture(root)
            public = json.loads((root / 'docs/RELEASE_RESOURCE_BASELINE.json').read_bytes())
            for row in public['workload']['executors']:
                with self.subTest(relative=row['path']):
                    self.assertNotEqual(P.digest((root / row['path']).read_bytes()), row['sha256'])
            with self.assertRaisesRegex(P.ProvenanceError, 'Historical workload executor changed'):
                P.verify(root, document_hash)

    def test_public_document_bindings_reject_before_stale_workloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            document_hash = self.fixture(root)
            # This is intentionally not a passing historical workload fixture.
            # Specific early-guard messages distinguish the mutation from the
            # unchanged, independently asserted stale-workload rejection.
            with self.assertRaisesRegex(P.ProvenanceError, 'Historical workload executor changed'):
                P.verify(root, document_hash)
            public = json.loads((root / 'docs/RELEASE_RESOURCE_BASELINE.json').read_bytes())
            public_hash = P.digest(P.canonical(public))
            with self.assertRaisesRegex(P.ProvenanceError, 'Historical workload executor changed'):
                P.verify(root, document_hash, public_hash)
            public['limits']['gui_p95_percent'] += 1
            with self.assertRaisesRegex(P.ProvenanceError, 'Passed public policy document'):
                P.verify(root, document_hash, P.digest(P.canonical(public)))
            with self.assertRaisesRegex(P.ProvenanceError, 'Passed baseline document'):
                P.verify(root, '0' * 64)
            target = root / 'docs/RELEASE_RESOURCE_BASELINE.json'
            target.write_bytes(target.read_bytes() + b'\n')
            with self.assertRaisesRegex(P.ProvenanceError, 'exact accepted public resource policy'):
                P.verify(root, document_hash)

    def test_redirected_reference_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            document_hash = self.fixture(root)
            target = root / P.ARCHIVE
            moved = target.with_suffix('.retained')
            target.rename(moved)
            target.symlink_to(moved.name)
            with self.assertRaisesRegex(P.ProvenanceError, 'Redirected provenance input'):
                P.verify(root, document_hash)


if __name__ == '__main__':
    unittest.main()
