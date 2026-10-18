#!/usr/bin/python3
"""Source-contract checks, not a substitute for native visual/VoiceOver tests.

Health summaries and consequences stay outside collapsed diagnostic details.
No installed app, preferences, or user stores are opened by these tests.
"""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    'clarity_swift_source', Path(__file__).with_name('check-settings-storage-wiring.py'))
source_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_guard)


class HealthCopyContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source_guard.Source((ROOT / 'Sources/MacCrabApp/V2/Workspaces/V2SystemWorkspace.swift').read_text())

    def body(self, name, function=True):
        kind = 'func' if function else 'var'
        return self.source.block(r'\b' + kind + r'\s+' + name + r'\b')

    def assert_summary_outside_details(self, body, visible, diagnostic):
        detail = body.block(r'\bDisclosureGroup\(')
        self.assertIn(diagnostic, detail.text)
        self.assertNotIn(visible, detail.text)
        self.assertLess(body.text.index(visible), body.text.index('DisclosureGroup('))
        self.assertIn('textSelection(.enabled)', detail.text)

    def test_lifecycle_impact_remains_visible_and_counters_remain_available(self):
        self.assert_summary_outside_details(
            self.body('lifecycleDegradedBanner'), 'Text(impact)', 'ui.final.lifecycleDetail')

    def test_trace_coverage_consequence_remains_visible(self):
        self.assert_summary_outside_details(
            self.body('otlpReceiverLifecycleBanner'), 'system.otlpLifecycleSummary',
            'system.otlpLifecycleDegradedDetail')

    def test_evidence_warning_preserves_all_three_states(self):
        body = self.body('alertEvidenceTransitionBanner')
        for state in ['Measurement', 'Capture', 'Reserve']:
            for role in ['Title', 'Summary']:
                self.assertIn('system.alertEvidence' + state + role, body.text)
        self.assertIn('budget.legacyTransitionMeasurementFailed == true', body.code)
        self.assertIn('budget.captureDegraded', body.code)
        self.assert_summary_outside_details(body, 'Text(summary)', 'system.alertEvidenceTransitionDetail')
        simultaneous = body.block(r'\bif\s+transitionFailed\s*&&\s*captureDegraded')
        self.assertIn('system.alertEvidenceCaptureSummary', simultaneous.text)
        self.assertLess(body.code.index('if transitionFailed && captureDegraded'),
                        body.code.index('DisclosureGroup('))

    def test_source_details_do_not_hide_errors_or_change_reconnect_target(self):
        body = self.body('dataSourceCard', function=False)
        detail = body.block(r'\bDisclosureGroup\(')
        self.assertIn('system.dataSourceLive', detail.text)
        self.assertIn('system.sourceSession', detail.text)
        self.assertNotIn('system.lastError', detail.text)
        self.assertLess(body.text.index('system.lastError'), body.text.index('DisclosureGroup('))
        self.assertIn('state.connectLiveData()', body.code)
        for key in ['system.dataSourceConnected', 'system.dataSourceOffline', 'system.dataSourceMock']:
            self.assertIn(key, body.text)

    def test_audit_status_and_records_are_not_hidden_in_help(self):
        body = self.body('auditTrailCard', function=False)
        self.assert_summary_outside_details(body, 'system.auditSummary', 'system.auditDesc')
        detail = body.block(r'\bDisclosureGroup\(')
        self.assertNotIn('auditStatus', detail.code)
        self.assertNotIn('auditLines', detail.code)
        self.assertIn('Text(auditStatus)', body.code)
        self.assertIn('auditLines.enumerated()', body.code)

    def test_shorter_detection_intros_still_explain_row_action_and_mcp_flag(self):
        source = source_guard.Source((ROOT / 'Sources/MacCrabApp/V2/Workspaces/V2DetectionWorkspace.swift').read_text())
        browser = source.block(r'\bvar\s+browserTab\b').text
        mcp = source.block(r'\bvar\s+mcpTab\b').text
        self.assertIn('Select a row for permissions and risk factors.', browser)
        self.assertIn('Servers launched from temporary folders are flagged; select a row for details.', mcp)
        self.assertIn('browserInventoryCoverageWarning(coverage)', browser)


if __name__ == '__main__':
    unittest.main()
