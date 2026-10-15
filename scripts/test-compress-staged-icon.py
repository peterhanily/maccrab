#!/usr/bin/env python3
"""Offline/private-copy tests; no installed paths, subprocesses or network."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import zlib

SPEC = importlib.util.spec_from_file_location('icon_subject', Path(__file__).with_name('compress-staged-icon.py'))
ICON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ICON)
SOURCE_ICON = ICON.PROJECT_ROOT / 'Sources/MacCrabApp/Resources/AppIcon.icns'


def png_chunk(kind, payload):
    return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload) & 0xffffffff)


class IconCompressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = SOURCE_ICON.read_bytes()
        assert ICON.sha256(cls.original) == ICON.ORIGINAL_SHA256
        cls.compact = ICON.prepare(cls.original)

    @classmethod
    def tearDownClass(cls):
        assert SOURCE_ICON.read_bytes() == cls.original, 'read-only source icon changed'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maccrab-icon-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.stage = self.root / '.build/maccrab-stage'
        self.icon = self.stage / ICON.ICON_SUFFIX
        self.icon.parent.mkdir(parents=True)
        self.icon.write_bytes(self.original)
        self.icon.chmod(0o640)
        patch = mock.patch.object(ICON, 'PROJECT_ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def assert_refused_unchanged(self, stage=None, icon=None):
        before = self.icon.read_bytes()
        with self.assertRaises((ValueError, OSError)):
            ICON.optimize(stage or self.stage, icon or self.icon)
        self.assertEqual(self.icon.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.icon.parent.iterdir()), ['AppIcon.icns'])

    def test_exact_pin_shrink_idempotency_all_representation_and_metadata_bytes(self):
        self.assertEqual(len(self.compact), 886141)
        self.assertEqual(ICON.sha256(self.compact), ICON.COMPACT_SHA256)
        self.assertEqual(ICON.prepare(self.compact), self.compact)
        old, new = ICON.icns_elements(self.original), ICON.icns_elements(self.compact)
        self.assertEqual([kind for kind, _ in old], list(ICON.ELEMENTS))
        for (old_kind, old_chunk), (new_kind, new_chunk) in zip(old, new):
            self.assertEqual(old_kind, new_kind)
            if old_kind != b'ic10':
                self.assertEqual(old_chunk, new_chunk)
        old_png = ICON.png_chunks(dict(old)[b'ic10'][8:])
        new_png = ICON.png_chunks(dict(new)[b'ic10'][8:])
        self.assertEqual([chunk for kind, chunk in old_png if kind != b'IDAT'],
                         [chunk for kind, chunk in new_png if kind != b'IDAT'])
        self.assertEqual(sum(kind == b'IDAT' for kind, _ in old_png), 33)
        self.assertEqual(sum(kind == b'IDAT' for kind, _ in new_png), 1)
        for chunks in (old_png, new_png):
            filtered = ICON.inflate(b''.join(chunk[8:-4] for kind, chunk in chunks if kind == b'IDAT'))
            self.assertEqual(len(filtered), 4195328)
            self.assertEqual(hashlib.sha256(filtered).hexdigest(), ICON.FILTERED_SHA256)

    def test_unpinned_changes_refused_before_structure_or_any_file_write(self):
        for value in (b'', self.original + b'\0', self.original[:-1], b'x' + self.original[1:]):
            with self.subTest(length=len(value)):
                with mock.patch.object(ICON, 'icns_elements', side_effect=AssertionError('must reject pin first')):
                    with self.assertRaisesRegex(ValueError, 'byte-pinned'):
                        ICON.prepare(value)
        self.icon.write_bytes(self.original + b'\0')
        self.assert_refused_unchanged()

    def test_icns_lengths_inventory_and_table_of_contents_refused(self):
        variants = [self.original[:-1], self.original + b'x', b'xxxx' + self.original[4:]]
        changed = bytearray(self.original)
        changed[8:12] = b'TOC '
        variants.append(bytes(changed))
        changed = bytearray(self.original)
        changed[12:16] = struct.pack('>I', 7)
        variants.append(bytes(changed))
        changed = bytearray(self.original)
        changed[8:12] = b'ic10'
        variants.append(bytes(changed))
        for value in variants:
            with self.subTest(prefix=value[:16]), self.assertRaises(ValueError):
                ICON.icns_elements(value)

    def test_png_crc_order_duplicate_and_metadata_changes_refused(self):
        png = dict(ICON.icns_elements(self.original))[b'ic10'][8:]
        chunks = ICON.png_chunks(png)
        variants = [png[:-1], png + b'x']
        changed = bytearray(png)
        changed[-1] ^= 1
        variants.append(bytes(changed))
        variants.append(ICON.PNG_SIGNATURE + b''.join(chunk for _, chunk in chunks[1:]))
        variants.append(ICON.PNG_SIGNATURE + b''.join(chunk for _, chunk in chunks) + png_chunk(b'IEND', b''))
        variants.append(ICON.PNG_SIGNATURE + chunks[0][1] + png_chunk(b'iCCP', b'changed')
                        + b''.join(chunk for _, chunk in chunks[2:]))
        for value in variants:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                ICON.png_chunks(value)

    def test_inflate_is_exact_and_bounded_without_accepting_trailing_streams(self):
        chunks = ICON.png_chunks(dict(ICON.icns_elements(self.compact))[b'ic10'][8:])
        stream = b''.join(chunk[8:-4] for kind, chunk in chunks if kind == b'IDAT')
        for value in (b'', stream[:-1], stream + b'x', stream + stream,
                      zlib.compress(b'\0' * (ICON.FILTERED_BYTES + 1)), zlib.compress(b'different')):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                ICON.inflate(value)

    def test_compressor_drift_refused(self):
        with mock.patch.object(ICON.zlib, 'compress', return_value=b'not a stream'):
            self.assert_refused_unchanged()

    def test_real_private_copy_atomic_mode_preserving_shrink_and_noop(self):
        before = self.icon.stat()
        report = ICON.optimize(self.stage, self.icon)
        self.assertTrue(report['changed'])
        self.assertGreaterEqual(report['saved_allocated_kib'], 128)
        self.assertEqual(self.icon.read_bytes(), self.compact)
        self.assertEqual(stat.S_IMODE(self.icon.stat().st_mode), stat.S_IMODE(before.st_mode))
        self.assertEqual((self.icon.stat().st_uid, self.icon.stat().st_gid), (before.st_uid, before.st_gid))
        self.assertNotEqual(self.icon.stat().st_ino, before.st_ino)
        again = ICON.optimize(self.stage, self.icon)
        self.assertFalse(again['changed'])
        self.assertEqual(again['saved_allocated_kib'], 0)
        self.assertEqual(sorted(p.name for p in self.icon.parent.iterdir()), ['AppIcon.icns'])

    def test_reject_source_arbitrary_target_and_relative_or_parent_paths(self):
        self.assert_refused_unchanged(icon=SOURCE_ICON)
        self.assert_refused_unchanged(stage=self.root, icon=self.root / ICON.ICON_SUFFIX)
        self.assert_refused_unchanged(stage=Path('.build/maccrab-stage'), icon=Path('AppIcon.icns'))
        self.assert_refused_unchanged(stage=self.stage / '..' / 'maccrab-stage')
        self.assert_refused_unchanged(icon=self.icon.with_name('Other.icns'))

    def test_symlink_or_hardlink_leaf_refused(self):
        saved = self.root / 'saved.icns'
        self.icon.rename(saved)
        self.icon.symlink_to(saved)
        self.assert_refused_unchanged()
        self.icon.unlink()
        os.link(saved, self.icon)
        self.assert_refused_unchanged()
        self.assertEqual(saved.read_bytes(), self.original)

    def test_symlink_directory_ancestor_refused(self):
        moved = self.root / 'saved-stage'
        self.stage.rename(moved)
        self.stage.symlink_to(moved, target_is_directory=True)
        self.assert_refused_unchanged()

    def test_group_writable_stage_and_icon_refused(self):
        self.stage.chmod(0o775)
        self.assert_refused_unchanged()
        self.stage.chmod(0o755)
        self.icon.chmod(0o664)
        self.assert_refused_unchanged()

    def test_changed_input_before_replacement_fails_and_preserves_change(self):
        original_verify = ICON.verify_binding
        calls = []
        def change(stage, icon, directory):
            original_verify(stage, icon, directory)
            calls.append(1)
            if len(calls) == 2:
                self.icon.write_bytes(b'test-owned replacement; do not overwrite')
        with mock.patch.object(ICON, 'verify_binding', side_effect=change):
            with self.assertRaisesRegex(ValueError, 'changed before replacement'):
                ICON.optimize(self.stage, self.icon)
        self.assertEqual(self.icon.read_bytes(), b'test-owned replacement; do not overwrite')
        self.assertEqual(sorted(p.name for p in self.icon.parent.iterdir()), ['AppIcon.icns'])

    def test_atomic_replace_failure_keeps_original_and_cleans_only_own_temporary(self):
        with mock.patch.object(ICON.os, 'replace', side_effect=OSError('synthetic failure')):
            self.assert_refused_unchanged()

    def test_swapped_named_temporary_is_never_published_or_deleted(self):
        verify = ICON.verify_binding
        calls, exchanged = [], []
        def swap(stage, icon, directory):
            verify(stage, icon, directory)
            calls.append(1)
            if len(calls) == 2:
                path = next(self.icon.parent.glob('.maccrab-icon-*'))
                other = self.root / 'test-owned-exchange'
                other.write_bytes(self.compact)
                other.chmod(0o640)
                os.replace(other, path)
                exchanged.append(path)
        with mock.patch.object(ICON, 'verify_binding', side_effect=swap):
            with self.assertRaisesRegex(ValueError, 'changed before replacement') as raised:
                ICON.optimize(self.stage, self.icon)
        self.assertEqual(self.icon.read_bytes(), self.original)
        self.assertEqual(len(exchanged), 1)
        self.assertEqual(exchanged[0].read_bytes(), self.compact)
        self.assertIsInstance(raised.exception.__cause__, ValueError)
        self.assertIn('temporary icon changed', str(raised.exception.__cause__))

    def test_all_stages_positive_pid_path_supported_but_zero_refused(self):
        parent = self.root / 'private-tmp'
        parent.mkdir()
        stage = parent / 'maccrab-release-12345'
        self.stage.rename(stage)
        icon = stage / ICON.ICON_SUFFIX
        with mock.patch.object(ICON, 'TEMP_STAGE_PARENT', parent):
            report = ICON.optimize(stage, icon)
            self.assertTrue(report['changed'])
            zero = parent / 'maccrab-release-0'
            stage.rename(zero)
            with self.assertRaises(ValueError):
                ICON.optimize(zero, zero / ICON.ICON_SUFFIX)
            self.assertEqual((zero / ICON.ICON_SUFFIX).read_bytes(), self.compact)


if __name__ == '__main__':
    unittest.main(verbosity=2)
