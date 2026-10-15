#!/usr/bin/env python3
"""Offline SDK-trim checks; only task-owned temporary fixture trees are used."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location('sparkle_sdk_trim', Path(__file__).with_name('trim-staged-sparkle-sdk.py'))
trim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trim)


def inventory(root):
    result = {}
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in folders + files:
            path = Path(directory) / name
            key = str(path.relative_to(root))
            if path.is_symlink():
                result[key] = ('link', os.readlink(path))
            elif path.is_dir():
                result[key] = ('directory',)
            else:
                result[key] = ('file', path.read_bytes())
    return result


class SparkleSDKTrimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='maccrab-sdk-trim-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.framework = self.root / trim.STAGED_FRAMEWORK
        self.version = self.framework / 'Versions' / 'B'
        self.version.mkdir(parents=True)
        (self.framework / 'Versions' / 'Current').symlink_to('B')
        (self.version / 'Sparkle').write_bytes(b'private fake runtime, never executable')
        for name in trim.SDK_DIRECTORIES:
            directory = self.version / name
            directory.mkdir()
            (self.framework / name).symlink_to('Versions/Current/' + name)
            names = sorted(trim.MODULE_MAPS) if name == 'Modules' else ['One.h', 'Two.h']
            for leaf in names:
                (directory / leaf).write_bytes(b'SDK fixture only\n')
        for name in ('Resources/en.lproj/Sparkle.strings', 'XPCServices/Installer.xpc/Contents/MacOS/Installer',
                     'Updater.app/Contents/MacOS/Updater', 'Autoupdate', '_CodeSignature/CodeResources'):
            path = self.version / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'preserve exact runtime fixture bytes:' + name.encode())
        (self.framework / 'Sparkle').symlink_to('Versions/Current/Sparkle')
        (self.framework / 'Resources').symlink_to('Versions/Current/Resources')
        self.dependency = self.root / '.build/artifacts/sparkle/Sparkle/Sparkle.framework'
        self.dependency.mkdir(parents=True)
        (self.dependency / 'PinnedArtifact').write_bytes(b'never change dependency')

    def refused_without_mutation(self, framework=None):
        before = inventory(self.root)
        with self.assertRaises((OSError, ValueError)):
            trim.trim_sdk(framework or self.framework, self.root)
        self.assertEqual(inventory(self.root), before)

    def test_complete_runtime_and_dependency_preservation(self):
        before = inventory(self.root)
        sdk_paths = [str((self.version / name).relative_to(self.root)) for name in trim.SDK_DIRECTORIES]
        aliases = {str((self.framework / name).relative_to(self.root)) for name in trim.SDK_DIRECTORIES}
        expected = {key: value for key, value in before.items()
                    if key not in aliases and not any(key == prefix or key.startswith(prefix + '/') for prefix in sdk_paths)}
        report = trim.trim_sdk(self.framework, self.root)
        self.assertEqual(inventory(self.root), expected)
        self.assertEqual(report['removed_sdk_files'], 6)
        self.assertEqual(report['removed_sdk_directories'], 3)
        self.assertEqual(report['removed_sdk_aliases'], 3)

    def test_wrong_alias_in_last_directory_prevents_all_deletion(self):
        alias = self.framework / 'Modules'
        alias.unlink()
        alias.symlink_to('../../outside')
        self.refused_without_mutation()

    def test_ordinary_file_instead_of_alias_is_rejected(self):
        alias = self.framework / 'Headers'
        alias.unlink()
        alias.write_bytes(b'not a link')
        self.refused_without_mutation()

    def test_nested_or_symlink_entries_are_rejected(self):
        for kind in ('directory', 'symlink', 'unexpected-file'):
            with self.subTest(kind=kind):
                entry = self.version / 'Modules' / 'Unexpected.h'
                if kind == 'directory':
                    entry.mkdir()
                elif kind == 'symlink':
                    entry.symlink_to(self.dependency / 'PinnedArtifact')
                else:
                    entry.write_bytes(b'not an allowed module map')
                self.refused_without_mutation()
                entry.rmdir() if kind == 'directory' else entry.unlink()

    def test_symlink_sdk_directory_is_rejected(self):
        directory = self.version / 'Modules'
        saved = self.version / 'SavedModules'
        directory.rename(saved)
        directory.symlink_to('SavedModules')
        self.refused_without_mutation()

    def test_current_link_must_be_exact(self):
        current = self.framework / 'Versions' / 'Current'
        current.unlink()
        current.symlink_to('./B')
        self.refused_without_mutation()

    def test_missing_last_directory_and_empty_directory_fail_before_deletion(self):
        directory = self.version / 'Modules'
        for child in directory.iterdir():
            child.unlink()
        self.refused_without_mutation()
        directory.rmdir()
        self.refused_without_mutation()

    def test_dependency_and_alternate_targets_are_refused(self):
        self.refused_without_mutation(self.dependency)
        self.refused_without_mutation(self.version)
        self.refused_without_mutation(Path('relative/Sparkle.framework'))

    def test_symlink_staging_ancestor_is_rejected(self):
        stage = self.root / '.build/maccrab-stage'
        saved = self.root / '.build/stage-saved'
        stage.rename(saved)
        stage.symlink_to('stage-saved')
        self.refused_without_mutation()

    def test_file_count_and_byte_bounds_fail_before_deletion(self):
        with mock.patch.object(trim, 'MAX_FILES', 1):
            self.refused_without_mutation()
        with mock.patch.object(trim, 'MAX_BYTES', 1):
            self.refused_without_mutation()

    def test_missing_runtime_binary_is_refused(self):
        (self.version / 'Sparkle').unlink()
        self.refused_without_mutation()

    def test_all_stages_layout_and_invalid_pid_are_bounded(self):
        temp_parent = self.root / 'test-private-tmp'
        temp_parent.mkdir()
        stage = temp_parent / 'maccrab-release-12345'
        (self.root / '.build/maccrab-stage').rename(stage)
        framework = stage / trim.FRAMEWORK_SUFFIX
        before = inventory(self.root)
        with mock.patch.object(trim, 'TEMP_STAGE_PARENT', temp_parent):
            invalid = temp_parent / 'maccrab-release-0'
            stage.rename(invalid)
            invalid_before = inventory(self.root)
            with self.assertRaises(ValueError):
                trim.trim_sdk(invalid / trim.FRAMEWORK_SUFFIX, self.root, invalid)
            self.assertEqual(inventory(self.root), invalid_before)
            invalid.rename(stage)
            report = trim.trim_sdk(framework, self.root, stage)
        self.assertEqual(report['removed_sdk_files'], 6)
        for name, contents in inventory(self.root).items():
            self.assertEqual(contents, before[name])
        self.assertEqual((self.dependency / 'PinnedArtifact').read_bytes(), b'never change dependency')


if __name__ == '__main__':
    unittest.main()
