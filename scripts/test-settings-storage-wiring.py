#!/usr/bin/python3
"""Offline mutations of production source, plus the real PASS 1 shell boundary.

No Swift execution, preferences, microphone, engine, or installed store access.
Temporary shell fixtures contain a stand-in source guard, never a live app.
"""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'settings_storage_audit', ROOT / 'scripts/check-settings-storage-wiring.py'
)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class SettingsStorageWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {name: (ROOT / relative).read_text() for name, relative in AUDIT.FILES.items()}

    def changed(self, file, before, after):
        self.assertEqual(self.sources[file].count(before), 1, 'mutation must target exactly one source edge')
        sources = dict(self.sources)
        sources[file] = sources[file].replace(before, after, 1)
        return sources

    def refuses(self, file, before, after, reason):
        errors = AUDIT.check(self.changed(file, before, after))
        self.assertTrue(any(reason in error for error in errors), errors)

    def test_current_production_wiring_is_the_positive_control(self):
        self.assertEqual(AUDIT.check(self.sources), [])

    def test_each_storage_control_must_use_its_selected_field_binding(self):
        for field in AUDIT.FIELDS:
            with self.subTest(field=field):
                self.refuses('view', f'storageBinding(.{field}, ${field})', f'${field}',
                             f'storage control {field} bypasses')

    def test_default_closure_is_not_mistaken_for_function_body(self):
        source = AUDIT.Source('static func save(persist: () -> Void = { defaultWrite() }) { actualSave() }')
        body = source.block(r'\bfunc\s+save\s*\(')
        self.assertTrue(body.matches(r'\bactualSave\('))
        self.assertFalse(body.matches(r'\bdefaultWrite\('))

    def test_binding_cannot_bypass_the_production_session(self):
        self.refuses('view', 'storageSession.binding(', 'unreviewedSession.binding(',
                     'storageBinding must use the production session')

    def test_binding_setter_cannot_drop_save_or_dependency_forwarding(self):
        self.refuses('edits', 'try SettingsStorageEdits.save(', 'try otherSave(',
                     'setter does not persist')
        self.refuses('edits', 'at: url, persist: persist, queueReload: queueReload',
                     'at: url, persist: persist, queueReload: { true }',
                     'must forward persistence and reload dependencies')

    def test_missing_write_and_comment_or_string_decoys_are_rejected(self):
        for replacement in ('', '// try persist(data, url)', 'let unused = "try persist(data, url)"'):
            with self.subTest(replacement=replacement):
                self.refuses('edits', 'try persist(data, url)', replacement,
                             'storage save has no durable write')

    def test_production_persistence_must_remain_atomic(self):
        self.refuses('edits', 'var persist: (Data, URL) throws -> Void = { try $0.write(to: $1, options: .atomic) }',
                     'var persist: (Data, URL) throws -> Void = { try $0.write(to: $1) }',
                     'must default to atomic persistence')

    def test_persistence_must_precede_preferences(self):
        sources = self.changed('edits', 'try persist(data, url)', '')
        original = 'return queueReload() ? .reloadQueued : .savedAwaitingReload'
        self.assertEqual(sources['edits'].count(original), 1)
        sources['edits'] = sources['edits'].replace(original, 'try persist(data, url)\n        ' + original)
        self.assertIn('storage save must persist before preferences and reload', AUDIT.check(sources))

    def test_saved_edit_must_reach_display_preferences(self):
        self.refuses('edits', 'updateDisplayPreferences(\n            priorValues.merging(',
                     'discardPreferences(\n            priorValues.merging(',
                     'must publish the saved edit to display preferences')

    def test_missing_reload_at_session_and_save_are_rejected(self):
        self.refuses('view', 'queueReload: { V2DaemonControl.reloadDetectionRules() }',
                     'queueReload: { true }', 'session reload callback missing')
        self.refuses('edits', 'return queueReload() ? .reloadQueued : .savedAwaitingReload',
                     'return .savedAwaitingReload', 'must request reload and distinguish queue failure')

    def test_writer_and_daemon_must_agree_on_override_path(self):
        for file in ('edits', 'config'):
            with self.subTest(file=file):
                self.refuses(file, '"Library/Application Support/MacCrab/user_overrides.json"',
                             '"Library/Application Support/MacCrab/unused_overrides.json"',
                             'override' if file == 'edits' else 'per-user overrides path')

    def test_each_daemon_storage_consumer_is_required(self):
        for field in AUDIT.FIELDS:
            with self.subTest(field=field):
                self.refuses('config', f'config.storage.{field} = v',
                             f'config.storage.{field} = 0', f'daemon override consumer missing for {field}')

    def test_appearance_cannot_save_or_skip_hydration(self):
        self.refuses('edits', 'try SettingsStorageEdits.hydrate(', 'try SettingsStorageEdits.save(',
                     'storage appearance must hydrate')
        self.refuses('view', 'try storageSession.appear(', 'try otherSession.appear(',
                     'hydration bypasses the production appearance seam')

    def test_legacy_preferences_remain_display_migrations(self):
        for key in ('retentionDays', 'maxDatabaseSizeMB'):
            # maxDatabaseSizeMB also appears in provenance classification; the
            # mutation targets the actual legacy migration binding specifically.
            variable = 'legacyRetention' if key == 'retentionDays' else 'legacyCap'
            with self.subTest(key=key):
                self.refuses('view', f'if let {variable} = defaults.object(forKey: "{key}") as? Int',
                             f'if let {variable} = defaults.object(forKey: "removed.{key}") as? Int',
                             f'legacy display migration missing for {key}')

    def test_manual_prune_requires_the_selected_threshold_inside_confirmation(self):
        original = 'Task { await appState.pruneAlerts(olderThanDays: retentionWindowDays) }'
        self.refuses('view', original, 'Task { await appState.pruneAlerts(olderThanDays: 0) }',
                     'manual-prune selection has no confirmed action consumer')
        sources = self.changed('view', original, '// action removed')
        sources['view'] += '\nfunc unusedDecoy() { ' + original + ' }\n'
        self.assertIn('manual-prune selection has no confirmed action consumer', AUDIT.check(sources))

    def test_unknown_appstorage_is_still_blocking(self):
        original = '@AppStorage("retentionWindowDays")'
        self.refuses('view', original,
                     '@AppStorage("storage.unreviewed") private var unreviewed = 10\n    ' + original,
                     'unclassified @AppStorage key storage.unreviewed')

    def test_comments_and_string_literals_do_not_declare_unknown_preferences(self):
        sources = dict(self.sources)
        sources['view'] += '\n// @AppStorage("unreviewed")\nlet text = "@AppStorage(\\"unreviewed\\")"\n'
        self.assertEqual(AUDIT.check(sources), [])

    def test_existing_nonstorage_named_sync_checks_remain_blocking(self):
        self.refuses('view', 'func syncLLMConfig()', 'func noLongerSyncLLMConfig()',
                     'missing Settings sync function syncLLMConfig')

    def test_inbox_signal_and_storage_application_edges_are_required(self):
        self.refuses('control', 'return writeReloadRulesRequest(inboxDir: source.directory + "/inbox")',
                     'return false', 'reload no longer reaches the selected-engine inbox')
        self.refuses('timers', '        kill(getpid(), SIGHUP)\n    }', '        discardReload()\n    }',
                     'reload requests no longer reach the signal handler')
        self.refuses('signals', 'let freshConfig = DaemonConfig.load(from: state.supportDir)',
                     'let freshConfig = previousConfig', 'no longer reads fresh daemon configuration')
        self.refuses('signals', 'let newStorage = freshConfig.storage.clampedToSafeFloors()',
                     'let newStorage = state.storage', 'must derive from fresh configuration with safe floors')
        self.refuses('signals', 'state.storage = newStorage', 'discardStorage(newStorage)',
                     'reload handler no longer applies storage configuration')

    def test_missing_or_malformed_source_fails_closed(self):
        sources = dict(self.sources)
        sources.pop('edits')
        self.assertTrue(AUDIT.check(sources))
        sources = dict(self.sources)
        sources['edits'] = 'struct SettingsStorageSession { "unterminated'
        self.assertTrue(AUDIT.check(sources))

    def test_pass_one_cannot_print_success_after_helper_failure(self):
        audit = (ROOT / 'scripts/pre-release-audit.sh').read_text()
        start = audit.index('section "PASS 1 — Settings → daemon orphan audit"')
        end = audit.index('# PASS 1b —', start)
        block = audit[start:end]
        harness = '''ERRORS=0
section() { :; }
ok() { printf 'SUCCESS: %s\\n' "$*"; }
err() { ERRORS=$((ERRORS + 1)); printf 'FAILURE: %s\\n' "$*"; }
''' + block + '\nexit "$ERRORS"\n'
        with tempfile.TemporaryDirectory(prefix='maccrab-settings-audit-fixture.') as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            helper = root / 'scripts/check-settings-storage-wiring.py'
            for status in (0, 1):
                with self.subTest(status=status):
                    helper.write_text(f'raise SystemExit({status})\n')
                    result = subprocess.run(['/bin/bash', '-c', harness], cwd=root,
                                            env={'PATH': '/usr/bin:/bin', 'REPO_ROOT': directory},
                                            text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    self.assertEqual('SUCCESS:' in result.stdout, status == 0)
                    self.assertEqual('FAILURE:' in result.stdout, status != 0)

    def test_fixtures_are_part_of_ordinary_ci(self):
        self.assertIn('scripts/test-settings-storage-wiring.py',
                      (ROOT / 'scripts/ci-local.sh').read_text())


if __name__ == '__main__':
    unittest.main()
