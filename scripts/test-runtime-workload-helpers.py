#!/usr/bin/python3
"""Offline helpers only: private fixtures, mocked HTTP, no live workload/alert."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


directories = module('owned_directories', 'runtime-workload-directories.py')
otlp = module('otlp_smoke', 'otlp-smoke.py')
qualification = module('qualification', 'candidate-qualification.py')
TRACE, SPAN = '1' * 32, '2' * 16


class OwnedDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maccrab-owned-dir-test.')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.path = self.base / 'owned'

    def test_created_tree_cleanup_preserves_sibling(self):
        receipt = directories.create_owned(self.path)
        (self.path / 'nested').mkdir()
        (self.path / 'nested/file').write_text('synthetic')
        (self.base / 'keep').write_text('keep')
        directories.remove_owned(self.path, receipt)
        self.assertFalse(self.path.exists())
        self.assertEqual((self.base / 'keep').read_text(), 'keep')

    def test_preexisting_tree_never_yields_a_receipt(self):
        self.path.mkdir()
        (self.path / 'keep').write_text('existing fixture')
        with self.assertRaises(FileExistsError):
            directories.create_owned(self.path)
        self.assertEqual((self.path / 'keep').read_text(), 'existing fixture')

    def test_replaced_root_is_not_removed(self):
        receipt = directories.create_owned(self.path)
        moved = self.base / 'original'
        self.path.rename(moved)
        self.path.mkdir()
        (self.path / 'keep').write_text('replacement fixture')
        with self.assertRaisesRegex(ValueError, 'replaced'):
            directories.remove_owned(self.path, receipt)
        self.assertTrue(moved.is_dir())
        self.assertTrue((self.path / 'keep').exists())

    def test_child_symlink_is_not_followed(self):
        receipt = directories.create_owned(self.path)
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('keep')
        (self.path / 'link').symlink_to(outside, target_is_directory=True)
        directories.remove_owned(self.path, receipt)
        self.assertEqual((outside / 'keep').read_text(), 'keep')

    def test_root_symlink_and_malformed_receipt_refuse_cleanup(self):
        receipt = directories.create_owned(self.path)
        for invalid in ('', '1:2', '1:2:3:4', 'x:y:z'):
            with self.subTest(receipt=invalid), self.assertRaises(ValueError):
                directories.remove_owned(self.path, invalid)
        alias = self.base / 'alias'
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            directories.remove_owned(alias, receipt)
        self.assertTrue(self.path.is_dir())


class OTLPSmokeTests(unittest.TestCase):
    def test_acceptance_only_cannot_claim_secret_verification(self):
        with mock.patch.object(otlp.sys, 'argv', ['otlp-smoke.py', '--receiver-only', '--secret-test']), \
                mock.patch.object(otlp, 'post') as post, \
                mock.patch.object(otlp.sys, 'stderr'), self.assertRaises(SystemExit) as error:
            otlp.main()
        self.assertEqual(error.exception.code, 2)
        post.assert_not_called()

    def test_http_connect_and_total_deadlines_are_fixed(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b'200', stderr=b'')
        with mock.patch.object(otlp.subprocess, 'run', return_value=completed) as run:
            self.assertEqual(otlp.post(4318, b'fixture'), 200)
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[:2], ['/usr/bin/curl', '--disable'])
        self.assertEqual(command[command.index('--connect-timeout') + 1], '2')
        self.assertEqual(command[command.index('--max-time') + 1], '5')
        self.assertEqual(command[-1], 'http://127.0.0.1:4318/v1/traces')
        self.assertEqual(kwargs['timeout'], 7)

    def test_transport_failure_never_means_acceptance(self):
        for exit_code, output in ((7, b'000'), (28, b'200'), (0, b'000000')):
            result = subprocess.CompletedProcess([], exit_code, stdout=output, stderr=b'')
            with mock.patch.object(otlp.subprocess, 'run', return_value=result), self.assertRaises(ValueError):
                otlp.post(4318, b'fixture')

    def test_payload_contains_exact_fresh_identifiers(self):
        body = otlp.payload(TRACE, SPAN)
        self.assertIn(bytes.fromhex(TRACE), body)
        self.assertIn(bytes.fromhex(SPAN), body)
        self.assertNotIn(otlp.SECRET_BY_VALUE.encode(), body)
        with self.assertRaises(ValueError):
            otlp.payload('0' * 32, SPAN)

    def test_exact_query_cannot_be_satisfied_by_unrelated_row(self):
        with tempfile.TemporaryDirectory(prefix='maccrab-otlp-query-test.') as temporary:
            path = Path(temporary).resolve() / 'traces.db'
            connection = sqlite3.connect(path)
            connection.execute('CREATE TABLE spans(trace_id TEXT, span_id TEXT, span_name TEXT, service_name TEXT, attributes_json TEXT)')
            connection.execute('INSERT INTO spans VALUES(?,?,?,?,?)', ('3' * 32, '4' * 16, 'unrelated', 'private', '{"do_not_print":"unrelated"}'))
            connection.commit()
            row, evidence = otlp.exact_row(path, TRACE, SPAN)
            self.assertIsNone(row)
            self.assertTrue(evidence['read_only'])
            connection.execute('INSERT INTO spans VALUES(?,?,?,?,?)', (TRACE, SPAN, otlp.SPAN_NAME, otlp.SERVICE_NAME, 'opaque-encrypted-attributes'))
            connection.commit()
            row, _ = otlp.exact_row(path, TRACE, SPAN)
            self.assertTrue(otlp.verify_row(row, TRACE, SPAN))
            self.assertEqual(len(row), 4)  # Ordinary proof never loads attributes.
            alias = path.parent / 'alias.db'
            alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'redirected'):
                otlp.exact_row(alias, TRACE, SPAN)
            connection.close()

    def test_sanitizer_requires_both_key_and_value_redaction(self):
        good = {'api_key': '[REDACTED]', 'user_note': 'leaked [ANTHROPIC_KEY] into a comment',
                'full_command': 'echo curl-smoke-test'}
        row = [TRACE, SPAN, otlp.SPAN_NAME, otlp.SERVICE_NAME, json.dumps(good)]
        self.assertTrue(otlp.verify_row(row, TRACE, SPAN, True))
        for key, raw in (('api_key', otlp.SECRET_BY_KEY), ('user_note', otlp.SECRET_BY_VALUE)):
            changed = dict(good, **{key: raw})
            with self.subTest(key=key), self.assertRaises(ValueError):
                otlp.verify_row(row[:4] + [json.dumps(changed)], TRACE, SPAN, True)
        with self.assertRaisesRegex(ValueError, 'unverified'):
            otlp.verify_row(row[:4] + ['encrypted-not-decrypted'], TRACE, SPAN, True)
        with self.assertRaises(ValueError):
            otlp.verify_row(['3' * 32] + row[1:], TRACE, SPAN, True)

    def test_missing_exact_span_times_out_without_false_pass(self):
        with mock.patch.object(otlp, 'exact_row', return_value=(None, {})) as query, \
                mock.patch.object(otlp.time, 'monotonic', side_effect=[0, 6]), \
                mock.patch.object(otlp.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'did not persist'):
                otlp.verify(Path('/not-accessed-fixture'), TRACE, SPAN)
        sleep.assert_not_called()
        self.assertEqual(query.call_args.kwargs['deadline'], 5)

    def test_query_refuses_an_already_expired_shared_deadline(self):
        with mock.patch.object(otlp.time, 'monotonic', return_value=6):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                otlp.exact_row(Path('/not-accessed-fixture'), TRACE, SPAN, deadline=5)


class RecorderOTLPProofTests(unittest.TestCase):
    def fixture(self):
        output = 'OTLP_IDENTITY: trace_id=%s span_id=%s secret_test=0\n' % (TRACE, SPAN)
        output += 'OTLP_ACCEPTED: trace_id=%s span_id=%s persistence_proven=false\n' % (TRACE, SPAN)
        return {'output': output, 'output_sha256': qualification.sha256_bytes(output.encode()),
                'completed_at': '2026-10-10T20:10:00Z',
                'otlp_persistence': {'trace_id': TRACE, 'span_id': SPAN, 'matched_rows': 1,
                    'persistence_proven': True, 'sanitizer_verified': False,
                    'observed_at': '2026-10-10T20:20:00Z',
                    'database': {'path': '/Library/Application Support/MacCrab/traces.db',
                        'owner_uid': 0, 'mode': 0o640, 'device': 1, 'inode': 2,
                        'read_only': True, 'no_follow': True}}}

    def test_exact_bound_proof_is_accepted(self):
        # 0640 is the mode TraceStore gives an installed traces.db.
        for mode in (0o640, 0o600):
            row = self.fixture()
            row['otlp_persistence']['database']['mode'] = mode
            with self.subTest(mode=oct(mode)):
                qualification.validate_workload_otlp_persistence(row)

    def test_other_span_and_aggregate_count_are_not_proof(self):
        for change in ({'span_id': '3' * 16}, {'matched_rows': 0}, {'matched_rows': True},
                       {'persistence_proven': False}, {'sanitizer_verified': True}):
            row = self.fixture()
            row['otlp_persistence'].update(change)
            with self.subTest(change=change), self.assertRaises(qualification.QualificationError):
                qualification.validate_workload_otlp_persistence(row)

    def test_incomplete_or_duplicated_submission_is_rejected(self):
        for output in ('', self.fixture()['output'].splitlines()[0] + '\n',
                       self.fixture()['output'] * 2):
            with self.subTest(output=output), self.assertRaises(qualification.QualificationError):
                qualification.workload_otlp_identity(output)

    def test_unsafe_database_or_old_proof_is_rejected(self):
        for changes in ({'read_only': False}, {'no_follow': False}, {'owner_uid': 501}, {'mode': 0o644},
                        {'mode': 0o660}, {'mode': 0o740}, {'mode': 0o2640}):
            row = self.fixture()
            row['otlp_persistence']['database'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(qualification.QualificationError):
                qualification.validate_workload_otlp_persistence(row)
        row = self.fixture()
        row['otlp_persistence']['observed_at'] = '2026-10-10T20:09:00Z'
        with self.assertRaises(qualification.QualificationError):
            qualification.validate_workload_otlp_persistence(row)


if __name__ == '__main__':
    unittest.main(verbosity=2)
