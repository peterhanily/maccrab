#!/usr/bin/env python3
"""Controls for the single historical reference protocol compatibility proof."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('resource_provenance', ROOT / 'scripts/resource-baseline-provenance.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
ARCHIVED = (ROOT / P.ARCHIVE).read_bytes()
CURRENT = (ROOT / 'scripts/candidate-qualification.py').read_bytes()


class ResourceBaselineProvenanceTests(unittest.TestCase):
    def reject(self, source):
        with self.assertRaises(P.ProvenanceError):
            P.verify_sources(ARCHIVED, source.encode())

    def altered(self, before, after, raw=CURRENT):
        source = raw.decode()
        self.assertTrue(before in source, "Mutation target is absent: " + before)
        return source.replace(before, after, 1)

    def test_actual_drain_only_changes_preserve_reference_protocol(self):
        proof = P.verify_sources(ARCHIVED, CURRENT)
        self.assertEqual(proof['status'], 'EXACT_HISTORICAL_RESOURCE_PROTOCOL_VERIFIED')
        self.assertEqual(proof['dependency_count'], 102)
        self.assertEqual(P.verify_sources(ARCHIVED, ARCHIVED)['dependency_manifest_sha256'],
                         proof['dependency_manifest_sha256'])

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
                self.reject(CURRENT.decode() + added)
        self.reject(self.altered('@functools.lru_cache(maxsize=1)', '@functools.lru_cache(maxsize=2)'))

    def test_interpreter_bindings_and_top_level_order_are_preserved(self):
        for name in ('__name__', '__builtins__', '__file__', '__package__', '__spec__'):
            with self.subTest(name=name):
                self.reject(CURRENT.decode() + '\n' + name + ' = "disabled"\n')
        source = CURRENT.decode()
        marker = 'if __name__ == "__main__":'
        at = source.rindex(marker)
        guard = source[at:]
        insertion = source.index('\ndef ')
        self.reject(source[:insertion] + '\n' + guard + '\n' + source[insertion:at])

    def test_missing_dependencies_and_new_builtin_shadowing_are_rejected(self):
        self.reject(self.altered('def percentile_nearest_rank(', 'def renamed_percentile_nearest_rank('))
        self.reject(CURRENT.decode() + '\nlen = 3\n')

    def test_archive_bytes_are_not_a_general_old_hash_exception(self):
        with self.assertRaisesRegex(P.ProvenanceError, 'archive hash'):
            P.verify_sources(ARCHIVED + b'\n', CURRENT)

    def fixture(self, root):
        for relative in (P.ARCHIVE, 'docs/RELEASE_RESOURCE_BASELINE.json',
                         'scripts/candidate-qualification.py', 'scripts/runtime-qualification-workload.sh',
                         'scripts/test-otlp-curl.sh'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return json.loads((root / 'docs/RELEASE_RESOURCE_BASELINE.json').read_bytes())['private_evidence']['canonical_sha256']

    def test_exact_document_workload_and_archive_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            document_hash = self.fixture(root)
            self.assertEqual(P.verify(root, document_hash)['baseline_sha256'], P.BASELINE_SHA)
            public = json.loads((root / 'docs/RELEASE_RESOURCE_BASELINE.json').read_bytes())
            public_hash = P.digest(P.canonical(public))
            self.assertEqual(P.verify(root, document_hash, public_hash)['baseline_sha256'], P.BASELINE_SHA)
            public['limits']['gui_p95_percent'] += 1
            with self.assertRaisesRegex(P.ProvenanceError, 'Passed public policy document'):
                P.verify(root, document_hash, P.digest(P.canonical(public)))
            with self.assertRaisesRegex(P.ProvenanceError, 'Passed baseline document'):
                P.verify(root, '0' * 64)
            for relative, message in (
                ('docs/RELEASE_RESOURCE_BASELINE.json', 'exact accepted public resource policy'),
                (P.ARCHIVE, 'archive hash'),
                ('scripts/runtime-qualification-workload.sh', 'workload executor'),
            ):
                with self.subTest(relative=relative):
                    target = root / relative
                    previous = target.read_bytes()
                    target.write_bytes(previous + b'\n')
                    with self.assertRaisesRegex(P.ProvenanceError, message):
                        P.verify(root, document_hash)
                    target.write_bytes(previous)

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
