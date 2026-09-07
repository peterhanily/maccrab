#!/usr/bin/env python3
"""Ordinary structural regressions for the localization release check."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('localization_check', Path(__file__).with_name('check-localizations.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class LocalizationContracts(unittest.TestCase):
    def test_reordered_arguments_keep_position_and_width(self):
        self.assertEqual(check.format_signature('%lld scanners · %@'), check.format_signature('%2$@ · %1$lld scanners'))
        self.assertNotEqual(check.format_signature('%lld'), check.format_signature('%d'))
        self.assertNotEqual(check.format_signature('%llu'), check.format_signature('%lld'))

    def test_missing_argument_and_conflicting_reuse_are_detected(self):
        self.assertNotEqual(check.format_signature('%lld %@'), check.format_signature('%lld'))
        with self.assertRaisesRegex(ValueError, 'conflicting types'):
            check.format_signature('%1$lld %1$@')
        with self.assertRaisesRegex(ValueError, 'mixed positional'):
            check.format_signature('%1$lld %lld')

    def test_literal_percentage_does_not_consume_an_argument(self):
        self.assertEqual(check.format_signature('100%% · %@'), {1: '@'})
        self.assertEqual(check.format_signature('100%'), {})

    def test_catalog_duplicates_and_bad_unicode_escape_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Localizable.strings'
            path.write_text('"key" = "one";\n"key" = "two";\n')
            with self.assertRaisesRegex(ValueError, 'duplicate key'):
                check.parse_strings(path)
            path.write_text(r'"key" = "ATT\u0026CK";')
            with self.assertRaisesRegex(ValueError, 'unsupported catalog escape'):
                check.parse_strings(path)
            path.write_text('"key" = "ATT&CK ≥";')
            self.assertEqual(check.parse_strings(path), {'key': 'ATT&CK ≥'})

    def test_comments_do_not_create_source_references(self):
        source = '// localized: "ignored"\n/* nested /* comment */ ignored */\nString(localized: "real", defaultValue: "https://example.test")'
        stripped = check.strip_swift_comments(source)
        self.assertNotIn('ignored', stripped)
        self.assertIn('https://example.test', stripped)
        self.assertIn('localized: "real"', stripped)

    def test_nested_interpolation_is_one_argument(self):
        segments, _ = check.swift_literal(r'"Updated \(formatter.string(from: date))"', 0)
        self.assertEqual(segments, [{'text': 'Updated '}, {'expression': 'formatter.string(from: date)'}, {'text': ''}])

    def test_leading_interpolation_does_not_hide_visible_prose(self):
        source = r'''Text("\(items.count) results")
Text("\(items.count) event\(items.count == 1 ? "" : "s")")
Text("7 days")
Text("(not a list)")
Text("\(items.count)")
Text(verbatim: "trace_id")
Text(String(localized: "results", defaultValue: "Results: \(items.count)"))
// Text("ignored")'''
        self.assertEqual(check.unlocalized_ui_copy(source), [
            (1, 'unlocalized Text prose'), (2, 'unlocalized Text prose'),
            (3, 'unlocalized Text prose'), (4, 'unlocalized Text prose')])

    def test_lifecycle_helper_copy_is_checked_at_the_caller(self):
        source = '''lifecycleDegradedBanner(state,
    title: "Needs attention",
    workLabel: String(localized: "work", defaultValue: "Task"),
    impact: "Work is incomplete")
otherHelper(title: "protocol_identifier")'''
        self.assertEqual(check.unlocalized_ui_copy(source), [
            (2, 'unlocalized lifecycle title'), (4, 'unlocalized lifecycle impact')])

    def test_duplicate_plural_keys_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Localizable.stringsdict'
            path.write_text('<plist version="1.0"><dict><key>same</key><string>a</string><key>same</key><string>b</string></dict></plist>')
            with self.assertRaisesRegex(ValueError, 'duplicate stringsdict key'):
                check.parse_plurals(path)


if __name__ == '__main__':
    unittest.main()
