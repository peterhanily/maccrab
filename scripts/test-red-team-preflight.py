#!/usr/bin/env python3
"""Test only copied legacy-simulation preflights, never simulation bodies.

Every executed script ends at an inert marker immediately after the exact
production preflight. Validate the prefix before copying/executing it: a guard
regression must not expose HOME, shell redirections, absolute commands or live
processes. These are accidental-invocation safeguards, not isolation evidence.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


BASE = Path(__file__).resolve().parent.parent
START = '# BEGIN MACCRAB_DISPOSABLE_HOST_PREFLIGHT'
END = '# END MACCRAB_DISPOSABLE_HOST_PREFLIGHT'
MAKE_START = '# BEGIN MACCRAB_DISPOSABLE_HOST_MAKE_ACK'
MAKE_END = '# END MACCRAB_DISPOSABLE_HOST_MAKE_ACK'
MARKER = '__MACCRAB_INERT_PREFLIGHT_BOUNDARY__'
NAMES = ('detection-test.sh', 'campaign-test.sh')

# Deliberately small reviewed shell language: diagnostics, argument checks and
# boolean assignments only. New executable syntax requires safety review before
# any fixture can execute it. Indentation and diagnostic wording are not pinned.
GUARD_LINES = {
    'maccrab_refuse_simulation() {', '}', 'exit 64',
    'if [ "${1:-}" != "--disposable-host" ]; then',
    'maccrab_refuse_simulation', 'fi', 'shift',
    'if [ "$#" -ne 0 ]; then',
    'SUSTAINED=false', 'MANAGE_DAEMON=false',
    'for arg in "$@"; do', 'case "$arg" in',
    '--sustained) SUSTAINED=true ;;', '--daemon) MANAGE_DAEMON=true ;;',
    '*) maccrab_refuse_simulation ;;', 'esac', 'done',
}


def marked_region(source, start, end):
    lines = source.splitlines()
    if lines.count(start) != 1 or lines.count(end) != 1:
        raise ValueError('expected exactly one ordered marker pair')
    first, last = lines.index(start), lines.index(end)
    if first >= last:
        raise ValueError('reversed marker pair')
    return lines, first, last


def checked_prefix(source):
    lines, first, last = marked_region(source, START, END)
    if not lines or lines[0] != '#!/bin/bash':
        raise ValueError('expected pinned shell')
    for line in lines[:first]:
        text = line.strip()
        if text and not text.startswith('#') and text not in ('set -euo pipefail', 'set -uo pipefail'):
            raise ValueError('executable code before preflight')
    for line in lines[first + 1:last]:
        text = line.strip()
        if not text or text.startswith('#') or text in GUARD_LINES:
            continue
        # Static, single-quoted diagnostics to stderr cannot expand commands.
        if re.fullmatch(r"printf '%s\\n' '[^']*' >&2", text):
            continue
        raise ValueError('unreviewed executable syntax inside preflight')
    if not '\n'.join(lines[last + 1:]).lstrip().startswith('SCRIPT_DIR='):
        raise ValueError('preflight boundary must immediately precede path discovery')
    return '\n'.join(lines[:last + 1]) + '\n'


def checked_make_fragment(source):
    lines, first, last = marked_region(source, MAKE_START, MAKE_END)
    block = [line.strip() for line in lines[first + 1:last] if line.strip()]
    if block != [
        'ifeq ($(MACCRAB_DISPOSABLE_HOST),1)',
        'override MACCRAB_SIMULATION_ACK := --disposable-host',
        'else', 'override MACCRAB_SIMULATION_ACK :=', 'endif',
    ]:
        raise ValueError('Make acknowledgement must require exact explicit 1')
    recipes = []
    for target, expected in (
        ('test-detection', './scripts/detection-test.sh $(MACCRAB_SIMULATION_ACK)'),
        ('test-campaign', './scripts/campaign-test.sh $(MACCRAB_SIMULATION_ACK) $(if $(SUSTAINED),--sustained,)'),
    ):
        matches = list(re.finditer(r'^' + target + r':\n((?:\t[^\n]*\n)+)', source, re.M))
        if len(matches) != 1 or matches[0].group(1).splitlines() != ['\t' + expected]:
            raise ValueError('simulation target must invoke only its guarded entrypoint')
        recipes.append(matches[0].group(0))
    return 'SHELL := /bin/bash\n' + '\n'.join(block) + '\n' + '\n'.join(recipes)


class RedTeamPreflightTests(unittest.TestCase):
    def setUp(self):
        self.sources = {name: (BASE / 'scripts' / name).read_text() for name in NAMES}
        # Check every prefix before any subprocess can execute one.
        self.prefixes = {name: checked_prefix(source) for name, source in self.sources.items()}
        self.make_source = (BASE / 'Makefile').read_text()
        self.make_fragment = checked_make_fragment(self.make_source)
        self.temporary = tempfile.TemporaryDirectory(prefix='maccrab-preflight-', dir='/private/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'scripts').mkdir()
        for name, prefix in self.prefixes.items():
            self.write_prefix(name, prefix)
        (self.root / 'Makefile').write_text(self.make_fragment)
        self.sentinel = self.root / 'owned-sentinel'
        self.sentinel.write_bytes(b'unchanged fixture data\n')
        self.fake_bin = self.root / 'fake-bin'
        self.fake_bin.mkdir()
        for command in ('dirname', 'mkdir', 'rm', 'pkill', 'swift', 'python3', 'curl'):
            path = self.fake_bin / command
            path.write_text("#!/bin/bash\nprintf '%s\\n' 'UNEXPECTED_EXTERNAL_COMMAND' >&2\nexit 99\n")
            path.chmod(0o700)

    def write_prefix(self, name, prefix):
        suffix = "printf '%s\\n' '" + MARKER + "'\n"
        if name == 'campaign-test.sh':
            suffix += 'printf \'%s\\n\' "$SUSTAINED:$MANAGE_DAEMON"\n'
        path = self.root / 'scripts' / name
        path.write_text(prefix + suffix + 'exit 0\n')
        path.chmod(0o700)

    @staticmethod
    def environment(path=''):
        excluded = {'BASH_ENV', 'ENV', 'MAKEFLAGS', 'MFLAGS', 'MAKEFILES', 'GNUMAKEFLAGS', 'MAKEOVERRIDES',
                    'MACCRAB_DISPOSABLE_HOST', 'MACCRAB_SIMULATION_ACK', 'SUSTAINED'}
        result = {key: value for key, value in os.environ.items()
                  if key not in excluded and not key.startswith('BASH_FUNC_')}
        result['PATH'] = path
        result['LC_ALL'] = 'C'
        return result  # HOME is deliberately unchanged, never redirected.

    def run_fixture(self, name, arguments, path=''):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result = subprocess.run(['/bin/bash', str(self.root / 'scripts' / name), *arguments],
                                cwd=self.root, env=self.environment(path),
                                capture_output=True, text=True, timeout=5)
        after = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after, 'preflight must not mutate even its owned fixture')
        return result

    def assert_refusal(self, result):
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        for text in ('REFUSED:', '--disposable-host', 'disposable Mac/VM', 'does not verify isolation'):
            self.assertIn(text, result.stderr)
        self.assertNotIn(MARKER, result.stdout + result.stderr)
        self.assertNotIn('UNEXPECTED_EXTERNAL_COMMAND', result.stdout + result.stderr)

    def test_production_guard_precedes_discovery_and_traps(self):
        for name in NAMES:
            self.assertNotIn('SCRIPT_DIR=', self.prefixes[name])
            self.assertNotIn('trap ', self.prefixes[name])
            self.assertNotIn('$HOME', self.prefixes[name])

    def test_prefix_extraction_rejects_missing_duplicate_and_reversed_markers(self):
        source = self.sources[NAMES[0]]
        variants = [source.replace(START, ''), source.replace(END, ''),
                    source.replace(START, START + '\n' + START),
                    source.replace(END, END + '\n' + END),
                    source.replace(START, '__TEMP__').replace(END, START).replace('__TEMP__', END)]
        for variant in variants:
            with self.subTest(variant=variant[:50]), self.assertRaises(ValueError):
                checked_prefix(variant)

    def test_prefix_extraction_rejects_pre_guard_side_effects(self):
        source = self.sources[NAMES[0]]
        for effect in ('pwd', 'trap cleanup EXIT', 'SCRIPT_DIR="$(pwd)"', 'touch /never-executed'):
            with self.subTest(effect=effect), self.assertRaises(ValueError):
                checked_prefix(source.replace(START, effect + '\n' + START))

    def test_prefix_extraction_rejects_unreviewed_guard_syntax(self):
        source = self.sources[NAMES[0]]
        for effect in ('/bin/echo not-executed', 'printf x > /never-executed', 'eval "$arg"', '$(pwd)'):
            with self.subTest(effect=effect), self.assertRaises(ValueError):
                checked_prefix(source.replace(END, effect + '\n' + END))

    def test_missing_ack_refuses_without_external_commands(self):
        for name in NAMES:
            for path in ('', str(self.fake_bin)):
                with self.subTest(name=name, path=bool(path)):
                    self.assert_refusal(self.run_fixture(name, [], path))

    def test_ack_must_be_first(self):
        for name in NAMES:
            for first in ('--sustained', '--daemon', '--', '--disposable-host=1', 'unexpected'):
                with self.subTest(name=name, first=first):
                    self.assert_refusal(self.run_fixture(name, [first, '--disposable-host']))

    def test_unsupported_trailing_arguments_refuse(self):
        for name in NAMES:
            bad = ['--unknown', '--', '--daemon=false', '1']
            if name == 'detection-test.sh':
                bad += ['--sustained', '--daemon']
            for argument in bad:
                with self.subTest(name=name, argument=argument):
                    self.assert_refusal(self.run_fixture(name, ['--disposable-host', argument]))

    def test_duplicate_ack_refuses(self):
        for name in NAMES:
            self.assert_refusal(self.run_fixture(name, ['--disposable-host', '--disposable-host']))

    def test_detection_ack_reaches_only_inert_boundary(self):
        result = self.run_fixture('detection-test.sh', ['--disposable-host'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, MARKER + '\n')
        self.assertEqual(result.stderr, '')

    def test_campaign_known_options_reach_only_inert_boundary(self):
        for options, expected in (([], 'false:false'), (['--sustained'], 'true:false'),
                                  (['--daemon'], 'false:true'),
                                  (['--sustained', '--daemon'], 'true:true'),
                                  (['--daemon', '--sustained'], 'true:true')):
            with self.subTest(options=options):
                result = self.run_fixture('campaign-test.sh', ['--disposable-host', *options])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, MARKER + '\n' + expected + '\n')
                self.assertEqual(result.stderr, '')

    def test_negative_control_detects_removed_guard_without_real_body(self):
        gate = 'if [ "${1:-}" != "--disposable-host" ]; then\n    maccrab_refuse_simulation\nfi\nshift\n'
        for name in NAMES:
            self.assertEqual(self.prefixes[name].count(gate), 1)
            self.write_prefix(name, self.prefixes[name].replace(gate, ''))
            result = self.run_fixture(name, [])
            self.assertEqual(result.returncode, 0)
            self.assertIn(MARKER, result.stdout)
            with self.assertRaises(AssertionError):
                self.assert_refusal(result)

    def make(self, target, *assignments):
        return subprocess.run(['/usr/bin/make', '--no-print-directory', target, *assignments],
                              cwd=self.root, env=self.environment(), capture_output=True,
                              text=True, timeout=5)

    def test_make_default_and_non_one_values_do_not_acknowledge(self):
        for target in ('test-detection', 'test-campaign'):
            for value in (None, '', '0', 'false', 'yes', '1 extra'):
                arguments = [] if value is None else ['MACCRAB_DISPOSABLE_HOST=' + value]
                with self.subTest(target=target, value=value):
                    result = self.make(target, *arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('REFUSED:', result.stderr)
                    self.assertNotIn(MARKER, result.stdout + result.stderr)

    def test_make_explicit_one_places_ack_before_supported_options(self):
        for target in ('test-detection', 'test-campaign'):
            result = self.make(target, 'MACCRAB_DISPOSABLE_HOST=1', 'SUSTAINED=1')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(MARKER + '\n', result.stdout)
            if target == 'test-campaign':
                self.assertIn('true:false\n', result.stdout)

    def test_make_internal_ack_override_is_not_an_implicit_optin(self):
        result = self.make('test-detection', 'MACCRAB_DISPOSABLE_HOST=0',
                           'MACCRAB_SIMULATION_ACK=--disposable-host')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(MARKER, result.stdout + result.stderr)

    def test_make_contract_rejects_extra_commands_before_execution(self):
        for variant in (
            self.make_source.replace('ifeq ($(MACCRAB_DISPOSABLE_HOST),1)', 'ifneq ($(MACCRAB_DISPOSABLE_HOST),)'),
            self.make_source.replace('test-detection:\n', 'test-detection:\n\t/bin/echo never-executed\n'),
        ):
            with self.assertRaises(ValueError):
                checked_make_fragment(variant)

    def test_environment_does_not_redirect_home_or_load_shell_hooks(self):
        environment = self.environment()
        self.assertEqual(environment.get('HOME'), os.environ.get('HOME'))
        self.assertNotIn('BASH_ENV', environment)
        self.assertNotIn('ENV', environment)
        self.assertNotIn('MAKEFILES', environment)


if __name__ == '__main__':
    unittest.main()
