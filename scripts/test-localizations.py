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
    def test_literal_scan_reports_its_boundaries_not_complete_coverage(self):
        self.assertFalse(check.LITERAL_SCAN_SCOPE['complete_ui_localization_audit'])
        self.assertEqual(check.LITERAL_SCAN_SCOPE['checked'],
                         ['Text', 'Button', 'ProgressView', 'lifecycleDegradedBanner', 'V2EmptyState'])
        for boundary in ['Toggle', 'Picker', 'Menu', 'help/accessibility modifiers', 'dynamic values']:
            self.assertIn(boundary, check.LITERAL_SCAN_SCOPE['not_checked'])

    def test_changed_cross_references_and_product_terms_match_their_headings(self):
        resources = Path(__file__).resolve().parents[1] / 'Sources/MacCrabApp/Resources'
        for locale in ['ru', 'it', 'sv']:
            table = check.parse_strings(resources / f'{locale}.lproj/Localizable.strings')
            for key in ['system.dataSourceOffline', 'system.dataSourceMock']:
                self.assertIn(table['system.actionsSection'], table[key], (locale, key))
        for locale in ['ja', 'ko', 'zh-Hans', 'zh-Hant', 'nl', 'sv']:
            table = check.parse_strings(resources / f'{locale}.lproj/Localizable.strings')
            self.assertIn('Agent Trace', table['system.otlpLifecycleDegradedTitle'])
            self.assertIn('Agent Trace', table['system.otlpLifecycleSummary'])
        for locale in ['sv', 'zh-Hans']:
            table = check.parse_strings(resources / f'{locale}.lproj/Localizable.strings')
            self.assertIn(table['overview.qaSystemHealth'], table['alerts.daemonStaleDetail'])

    def test_new_alert_copy_keeps_workspace_terminology(self):
        resources = Path(__file__).resolve().parents[1] / 'Sources/MacCrabApp/Resources'
        stems = {'de': 'Warn', 'nl': 'waarschuwing', 'ko': '경고', 'zh-Hant': '警示'}
        obsolete = {'de': 'Warnmeld', 'nl': 'melding', 'ko': '알림', 'zh-Hant': '警報'}
        keys = ['alerts.loading', 'alerts.readPartial', 'alerts.readDeferred',
                'alerts.readUnavailable', 'alerts.readFailed', 'alerts.cachedNotice',
                'alerts.cachedRefreshing', 'alerts.readDetails', 'alerts.emptyOpenBody']
        for locale, term in stems.items():
            table = check.parse_strings(resources / f'{locale}.lproj/Localizable.strings')
            for key in keys:
                self.assertIn(term.casefold(), table[key].casefold(), (locale, key))
                self.assertNotIn(obsolete[locale].casefold(), table[key].casefold(), (locale, key))

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

    def test_retry_loading_and_empty_state_copy_are_not_blind_spots(self):
        source = '''Button("Retry") {}
ProgressView("Loading items…")
V2EmptyState(title: "Unavailable", body: "The read is incomplete.", icon: "tray")
Button(String(localized: "common.retry", defaultValue: "Retry")) {}
ProgressView(String(localized: "loading", defaultValue: "Loading…"))
V2EmptyState(title: localizedTitle, body: error, icon: "tray")
// Button("ignored")
deviceButton("hand.tap.fill")'''
        self.assertEqual(check.unlocalized_ui_copy(source), [
            (1, 'unlocalized Button prose'), (2, 'unlocalized ProgressView prose'),
            (3, 'unlocalized empty-state title'), (3, 'unlocalized empty-state body')])

    def test_empty_state_localized_and_nested_defaults_are_not_literal_arguments(self):
        source = '''V2EmptyState(
    title: String(localized: "title", defaultValue: "An unavailable title"),
    body: String(localized: "body", defaultValue: "A nested (message)"), icon: "tray")'''
        self.assertEqual(check.unlocalized_ui_copy(source), [])


if __name__ == '__main__':
    unittest.main()
