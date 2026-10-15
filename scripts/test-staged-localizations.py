#!/usr/bin/env python3
"""Offline private-fixture tests; never optimize source, installed, or staged data."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('staged_localizations',
                                            BASE / 'scripts/optimize-staged-localizations.py')
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class StagedLocalizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maccrab-localization-test-', dir='/private/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def resources(self, name='Fixture.app'):
        root = self.root / name / 'Contents/Resources'
        root.mkdir(parents=True)
        return root

    def populate(self, root):
        strings = b'/* ' + b'ordinary comment ' * 400 + b' */\n"plain" = "value";\n'
        dictionary = {'count': {'NSStringLocalizedFormatKey': '%#@n@', 'n': {
            'NSStringFormatSpecTypeKey': 'NSStringPluralRuleType',
            'NSStringFormatValueTypeKey': 'lld', 'one': '%lld item', 'other': '%lld items'}}}
        plural = plistlib.dumps(dictionary).replace(b'<dict>', b'<!-- ' + b'comment ' * 650 + b' -->\n<dict>', 1)
        for locale in HELPER.LOCALES:
            directory = root / (locale + '.lproj')
            directory.mkdir()
            (directory / 'Localizable.strings').write_bytes(strings)
            (directory / 'Localizable.stringsdict').write_bytes(plural)
        return root

    @staticmethod
    def bytes_by_path(root):
        return {str(path.relative_to(root)): path.read_bytes() for path in root.glob('*.lproj/*')
                if path.is_file() and not path.is_symlink()}

    def test_lexer_preserves_literal_bytes_order_unicode_and_comment_like_values(self):
        source = ('/* ordinary */\n"key\\\"" = "https://example.invalid/*x*/ // y \\n \\U263A ☃";'
                  '\n// line comment\n"same" = "first"; "same" = "second";').encode()
        compact, tokens = HELPER.minify_strings(source)
        self.assertEqual(compact, b''.join(tokens))
        self.assertEqual(HELPER.minify_strings(compact), (compact, tokens))
        self.assertEqual(tokens[0], b'"key\\\""')
        self.assertEqual(tokens[2], '"https://example.invalid/*x*/ // y \\n \\U263A ☃"'.encode())
        self.assertEqual(tokens[4::4], (b'"same"', b'"same"'))
        self.assertEqual(tokens[6::4], (b'"first"', b'"second"'))

    def test_lexer_refuses_malformed_or_unknown_tokens(self):
        cases = (b'', b'/* missing end', b'"missing end', b'"trailing\\',
                 b'key="value";', b'"key":"value";', b'"key"="value"',
                 b'"key"="value";;', b'"a" "b" = ;', b'\xff', b'{}')
        for data in cases:
            with self.subTest(data=data), self.assertRaises((ValueError, UnicodeError)):
                HELPER.minify_strings(data)

    def test_lexer_bounds_size_and_assignment_count(self):
        with patch.dict(HELPER.TABLE_LIMITS, {'Localizable.strings': 8}):
            with self.assertRaisesRegex(ValueError, 'bound'):
                HELPER.minify_strings(b'"key"="value";')
        with patch.object(HELPER, 'MAX_ASSIGNMENTS', 1):
            with self.assertRaisesRegex(ValueError, 'bound'):
                HELPER.minify_strings(b'"a"="b";"c"="d";')

    def test_converter_refuses_stderr_nonzero_oversize_and_is_bounded(self):
        for result in (subprocess.CompletedProcess([], 0, b'{}', b'warning'),
                       subprocess.CompletedProcess([], 1, b'{}', b''),
                       subprocess.CompletedProcess([], 0, b'x' * 9, b'')):
            with self.subTest(result=result.returncode), patch.object(HELPER, 'MAX_TOTAL_BYTES', 8), \
                    patch.object(HELPER.subprocess, 'run', return_value=result) as run:
                with self.assertRaises(ValueError):
                    HELPER.plutil(b'a', 'json')
                self.assertEqual(run.call_args.kwargs['timeout'], 10)
                self.assertEqual(run.call_args.args[0][0], '/usr/bin/plutil')

    def test_changed_decoded_content_is_rejected_before_replace(self):
        with patch.object(HELPER, 'decoded', side_effect=[{'key': 'before'}, {'key': 'after'}]):
            with self.assertRaisesRegex(ValueError, 'content changed'):
                HELPER.candidate(b'"key"="before";', 'Localizable.strings')

    def test_all_private_tables_match_decoded_content_and_preserve_modes(self):
        root = self.populate(self.resources())
        before = self.bytes_by_path(root)
        for path in root.glob('*.lproj/*'):
            path.chmod(0o640)
        report = HELPER.optimize(root)
        self.assertEqual((report['locales'], report['tables']), (14, 28))
        self.assertGreater(report['saved_allocated_kib'], 0)
        self.assertTrue(all(row['replaced'] for row in report['results']))
        for relative, original in before.items():
            path = root / relative
            final = path.read_bytes()
            self.assertEqual(HELPER.decoded(original, path.name), HELPER.decoded(final, path.name))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            if path.name.endswith('.stringsdict'):
                self.assertTrue(final.startswith(b'bplist00'))
            else:
                self.assertEqual(HELPER.minify_strings(original)[1], HELPER.minify_strings(final)[1])
        self.assertFalse(list(root.glob('*.lproj/.maccrab-localization-*')))
        second = HELPER.optimize(root)
        self.assertEqual(second['saved_allocated_kib'], 0)
        self.assertTrue(all(not row['replaced'] for row in second['results']))

    def test_no_size_or_allocated_saving_preserves_original_inode_and_bytes(self):
        root = self.resources()
        path = root / 'Localizable.strings'
        original = b' /*comment*/ "a" = "b";'
        path.write_bytes(original)
        descriptor = os.open(root, HELPER.DIRECTORY_FLAGS)
        self.addCleanup(os.close, descriptor)
        before, data = HELPER.read_table(descriptor, path.name)
        for proposed in (original + b' ', b'"a"="b";'):
            with self.subTest(proposed=proposed):
                self.assertFalse(HELPER.replace_if_smaller(descriptor, path.name, before, data, proposed))
                self.assertEqual(path.stat().st_ino, before.st_ino)
                self.assertEqual(path.read_bytes(), original)
        self.assertEqual(set(os.listdir(root)), {path.name})

    def test_invalid_last_table_leaves_every_input_unchanged(self):
        root = self.populate(self.resources())
        (root / 'zh-Hant.lproj/Localizable.stringsdict').write_bytes(b'not a plist')
        before = self.bytes_by_path(root)
        with self.assertRaises(ValueError):
            HELPER.optimize(root)
        self.assertEqual(self.bytes_by_path(root), before)

    def test_exact_locale_set_and_locale_entry_set_are_required(self):
        for alteration in ('missing-locale', 'extra-locale', 'wrong-case', 'extra-file', 'missing-file'):
            with self.subTest(alteration=alteration):
                root = self.populate(self.resources(alteration + '.app'))
                if alteration == 'missing-locale':
                    shutil.rmtree(root / 'de.lproj')
                elif alteration == 'extra-locale':
                    (root / 'xx.lproj').mkdir()
                elif alteration == 'wrong-case':
                    (root / 'de.lproj').rename(root / 'DE.lproj')
                elif alteration == 'extra-file':
                    (root / 'de.lproj/extra').write_bytes(b'ordinary')
                else:
                    (root / 'de.lproj/Localizable.strings').unlink()
                before = self.bytes_by_path(root)
                with self.assertRaises(ValueError):
                    HELPER.optimize(root)
                self.assertEqual(self.bytes_by_path(root), before)

    def test_root_ancestor_locale_and_file_symlinks_are_refused(self):
        actual = self.populate(self.resources())
        link = self.root / 'Linked.app'
        link.symlink_to(actual.parent.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            HELPER.optimize(link / 'Contents/Resources')
        resources_link = self.resources('ResourcesLink.app')
        resources_link.rmdir()
        resources_link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError):
            HELPER.optimize(resources_link)
        locale = actual / 'de.lproj'
        saved = self.root / 'saved-locale'
        locale.rename(saved)
        locale.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(ValueError):
            HELPER.optimize(actual)
        locale.unlink()
        saved.rename(locale)
        table = locale / 'Localizable.strings'
        saved_file = self.root / 'saved-table'
        table.rename(saved_file)
        table.symlink_to(saved_file)
        with self.assertRaises(OSError):
            HELPER.optimize(actual)

    def test_fifo_directory_and_hardlinked_tables_are_refused_without_blocking(self):
        for kind in ('fifo', 'directory', 'hardlink'):
            with self.subTest(kind=kind):
                root = self.populate(self.resources(kind + '.app'))
                path = root / 'de.lproj/Localizable.strings'
                path.unlink()
                if kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'directory':
                    path.mkdir()
                else:
                    other = self.root / 'other-table'
                    other.write_bytes(b'"a"="b";')
                    os.link(other, path)
                with self.assertRaises(ValueError):
                    HELPER.optimize(root)

    def test_size_bound_and_mid_validation_change_abort_before_replacement(self):
        root = self.populate(self.resources())
        before = self.bytes_by_path(root)
        with patch.object(HELPER, 'MAX_TOTAL_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'bound'):
                HELPER.optimize(root)
        self.assertEqual(self.bytes_by_path(root), before)
        original_candidate = HELPER.candidate
        changed = False

        def change_own_fixture(data, filename):
            nonlocal changed
            result = original_candidate(data, filename)
            if not changed:
                changed = True
                (root / 'de.lproj/Localizable.strings').write_bytes(b'"new"="fixture";')
            return result

        with patch.object(HELPER, 'candidate', side_effect=change_own_fixture):
            with self.assertRaisesRegex(ValueError, 'changed'):
                HELPER.optimize(root)
        after = self.bytes_by_path(root)
        changed_key = 'de.lproj/Localizable.strings'
        self.assertEqual({key: value for key, value in before.items() if key != changed_key},
                         {key: value for key, value in after.items() if key != changed_key})

    def test_command_line_stage_binding_refuses_installed_or_source_paths(self):
        fixed = BASE / '.build/maccrab-stage'
        for staging in (fixed, Path('/private/tmp/maccrab-release-12345')):
            resources = staging / 'MacCrab.app/Contents/Resources'
            self.assertEqual(HELPER.stage_resources(staging, resources), resources)
        for staging, resources in (
                ('/Applications', '/Applications/MacCrab.app/Contents/Resources'),
                ('/tmp/maccrab-release-123', '/tmp/maccrab-release-123/MacCrab.app/Contents/Resources'),
                ('/private/tmp/maccrab-release-test', '/private/tmp/maccrab-release-test/MacCrab.app/Contents/Resources'),
                (fixed, BASE / 'Sources/MacCrabApp/Resources'),
                (fixed, fixed / 'Other.app/Contents/Resources')):
            with self.subTest(staging=str(staging)), self.assertRaises(ValueError):
                HELPER.stage_resources(staging, resources)
        with self.assertRaises(ValueError):
            HELPER.open_resources(BASE / 'Sources/MacCrabApp/Resources')

    def test_real_fourteen_locale_private_copy_has_exact_semantics_and_no_source_changes(self):
        source = Path(os.environ.get('MACCRAB_LOCALIZATION_TEST_RESOURCES',
                                    BASE / 'Sources/MacCrabApp/Resources'))
        root = self.resources('RealFixture.app')
        source_hashes = {}
        for locale in sorted(HELPER.LOCALES):
            destination = root / (locale + '.lproj')
            destination.mkdir()
            for filename in HELPER.TABLE_LIMITS:
                original = source / destination.name / filename
                self.assertTrue(original.is_file() and not original.is_symlink())
                source_hashes[original] = hashlib.sha256(original.read_bytes()).hexdigest()
                shutil.copyfile(original, destination / filename)
        before = self.bytes_by_path(root)
        report = HELPER.optimize(root)
        self.assertEqual(report['tables'], 28)
        self.assertGreater(report['saved_allocated_kib'], 0)
        for relative, data in before.items():
            final = root / relative
            self.assertEqual(HELPER.decoded(data, final.name), HELPER.decoded(final.read_bytes(), final.name))
            if final.name.endswith('.strings'):
                self.assertEqual(HELPER.minify_strings(data)[1], HELPER.minify_strings(final.read_bytes())[1])
        for path, digest in source_hashes.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        print('Real locale private-copy result: ' + json.dumps({
            'tables': report['tables'], 'saved_allocated_kib': report['saved_allocated_kib'],
            'replaced_strings': sum(row['replaced'] and row['table'] == 'Localizable.strings'
                                    for row in report['results']),
            'replaced_stringsdict': sum(row['replaced'] and row['table'] == 'Localizable.stringsdict'
                                        for row in report['results'])}, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
