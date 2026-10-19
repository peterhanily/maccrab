#!/usr/bin/python3
"""Source-only Settings wiring guard; never reads preferences or installed data.

This checks the explicit production edges, not successful engine application.
Behavioral persistence/failure coverage remains in StorageSettingsEditTests;
StorageSettingsConsumerTests exercises saved bytes through the daemon reader.
Comments and string contents cannot impersonate declarations or call sites.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location(
    "settings_audit_swift_literals", Path(__file__).with_name("check-localizations.py")
)
LEXER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEXER)

FIELDS = (
    "eventsHotTierMinutes", "eventsMaxSizeMB", "alertsRetentionDays",
    "alertsMaxSizeMB", "evidenceMaxSizeMB", "campaignsRetentionDays",
    "campaignsMaxSizeMB",
)
UI_KEYS = {
    "pollIntervalSeconds", "launchAtLogin", "forensics.catalogBaseURL",
    "forensics.retentionDays",
}
# Keep the existing non-storage orphan classifications and named-sync checks.
SYNC_GROUPS = {
    "syncAlertNotificationConfig": ("alertNotifications", "minAlertSeverity"),
    "syncLLMConfig": (
        "llm.provider", "llm.ollamaURL", "llm.ollamaModel", "llm.openaiURL",
        "llm.model", "llm.enabled", "llm.approvedRemoteEndpoint",
    ),
    "syncWebhookConfig": (
        "webhookSlackURL", "webhookTeamsURL", "webhookDiscordURL",
        "webhookPagerDutyKey", "webhookMinSeverity",
    ),
    "syncEnrichmentOverrides": (
        "enrich.threatIntel", "enrich.vulnScan", "enrich.packageFreshness",
        "enrich.certTransparency",
    ),
}
FILES = {
    "view": "Sources/MacCrabApp/Views/SettingsView.swift",
    "edits": "Sources/MacCrabApp/Views/SettingsStorageEdits.swift",
    "control": "Sources/MacCrabApp/V2/V2DaemonControl.swift",
    "config": "Sources/MacCrabAgentKit/DaemonConfig.swift",
    "timers": "Sources/MacCrabAgentKit/DaemonTimers.swift",
    "signals": "Sources/MacCrabAgentKit/SignalHandlers.swift",
}


class Source:
    def __init__(self, raw: str):
        self.text = LEXER.strip_swift_comments(raw)
        mask = list(self.text)
        pos = 0
        while pos < len(self.text):
            if self.text[pos] == '"':
                _, end = LEXER.swift_literal(self.text, pos, strict=False)
                mask[pos:end] = ['\n' if char == '\n' else ' ' for char in self.text[pos:end]]
                pos = end
            else:
                pos += 1
        self.code = ''.join(mask)

    def matches(self, pattern: str):
        # Patterns may include literal arguments, but must begin in real code.
        return [match for match in re.finditer(pattern, self.text, re.MULTILINE)
                if self.code[match.start():match.start() + 1].strip()]

    def entire(self, pattern: str) -> bool:
        # Fail closed on extra executable statements, argument overrides,
        # alternate returns and dead/unused decoy calls. Whitespace and comments
        # are intentionally irrelevant; this is a narrow source-shape guard,
        # not a Swift control-flow analyser or installed-application proof.
        return re.fullmatch(r'\s*' + pattern + r'\s*', self.text, re.MULTILINE) is not None

    def block(self, declaration: str) -> "Source":
        starts = self.matches(declaration)
        if len(starts) != 1:
            raise ValueError(f"expected one declaration matching {declaration}, found {len(starts)}")
        # A function signature may contain a default closure argument. Its
        # brace is not the function body; walk past balanced argument lists.
        declaration_code = self.code[starts[0].start():starts[0].end()]
        parentheses = declaration_code.count('(') - declaration_code.count(')')
        start = -1
        for pos in range(starts[0].end(), len(self.code)):
            if self.code[pos] == '(':
                parentheses += 1
            elif self.code[pos] == ')':
                parentheses -= 1
            elif self.code[pos] == '{' and parentheses == 0:
                start = pos
                break
        if start < 0:
            raise ValueError(f"missing body for {declaration}")
        depth = 1
        for pos in range(start + 1, len(self.code)):
            if self.code[pos] == '{':
                depth += 1
            elif self.code[pos] == '}':
                depth -= 1
                if depth == 0:
                    return Source(self.text[start + 1:pos])
        raise ValueError(f"unterminated body for {declaration}")


def check(sources: dict[str, str]) -> list[str]:
    errors = []
    try:
        parsed = {name: Source(sources[name]) for name in FILES}
        view, edits = parsed['view'], parsed['edits']

        def require(source: Source, pattern: str, label: str):
            if not source.matches(pattern):
                errors.append(label)

        def forbid(source: Source, pattern: str, label: str):
            if source.matches(pattern):
                errors.append(label)

        classified = UI_KEYS | {'retentionWindowDays'} | {'storage.' + field for field in FIELDS}
        for function, keys in SYNC_GROUPS.items():
            classified.update(keys)
            require(view, rf'\bfunc\s+{function}\s*\(', f"missing Settings sync function {function}")
        for match in view.matches(r'@AppStorage\(\s*"([^"\\]+)"'):
            if match[1] not in classified:
                errors.append(f"unclassified @AppStorage key {match[1]}")

        general = view.block(r'\bvar\s+generalTab\s*:\s*some\s+View')
        binding = view.block(r'\bfunc\s+storageBinding\s*\(')
        session = view.block(r'\bvar\s+storageSession\s*:\s*SettingsStorageSession')
        hydrate = view.block(r'\bfunc\s+hydrateStorageOverrides\s*\(')
        migration = view.block(r'\bfunc\s+migrateLegacyStorageKeys\s*\(')
        session_type = edits.block(r'\bstruct\s+SettingsStorageSession\b')
        session_binding = session_type.block(r'\bfunc\s+binding\s*\(')
        appearance = session_type.block(r'\bfunc\s+appear\s*\(')
        save = edits.block(r'\bstatic\s+func\s+save\s*\(')
        config = parsed['config'].block(r'\bfunc\s+applyUserOverrides\s*\(')

        for field in FIELDS:
            require(view, rf'@AppStorage\(\s*"storage\.{field}"\s*\)\s+private\s+var\s+{field}\s*:',
                    f"missing storage preference declaration {field}")
            require(general, rf'\bstorageBinding\(\s*\.{field}\s*,\s*\${field}\s*\)',
                    f"storage control {field} bypasses its explicit binding")
            forbid(view, rf'\.onChange\(\s*of\s*:\s*{field}\b',
                   f"storage preference notification writes policy for {field}")
            require(config, rf'\bif\s+let\s+v\s*=\s*storage\["{field}"\]\s+as\?\s+Int\s*\{{\s*config\.storage\.{field}\s*=\s*v\s*\}}',
                    f"daemon override consumer missing for {field}")

        if not binding.entire(
            r'(?:return\s+)?storageSession\.binding\(\s*field\s*,\s*display\s*:\s*value\s*,'
            r'\s*displayedEnvelopeMiB\s*:\s*\{\s*eventsMaxSizeMB\s*\}\s*,'
            r'\s*onSave\s*:\s*showStorageSaveResult\s*\)'
        ):
            errors.append('storageBinding must use the production session with the selected field/display')
        if not session.entire(
            r'(?:return\s+)?SettingsStorageSession\(\s*preferences\s*:\s*\.standard\s*,'
            r'\s*url\s*:\s*SettingsStorageEdits\.overridesURL\s*,'
            r'\s*queueReload\s*:\s*\{\s*V2DaemonControl\.reloadDetectionRules\(\s*\)\s*\}\s*\)'
        ):
            errors.append('storage session must return exactly the production constructor, with no persistence override and the real reload callback')
        require(session_binding, r'\bBinding\(\s*get\s*:\s*\{\s*display\.wrappedValue\s*\}\s*,\s*set\s*:\s*\{\s*value\s+in',
                'storage session must save only from the explicit binding setter')
        require(session_binding, r'\btry\s+SettingsStorageEdits\.save\(\s*field\s*:\s*field\s*,\s*value\s*:\s*value\s*,',
                'storage binding setter does not persist the selected edit')
        require(session_binding, r'\bpreferences\s*:\s*preferences\s*,\s*at\s*:\s*url\s*,\s*persist\s*:\s*persist\s*,\s*queueReload\s*:\s*queueReload',
                'storage binding must forward persistence and reload dependencies')
        if not session_binding.entire(
            r'(?:return\s+)?Binding\(\s*get\s*:\s*\{\s*display\.wrappedValue\s*\}\s*,'
            r'\s*set\s*:\s*\{\s*value\s+in\s+onSave\(\s*Result\s*\{'
            r'\s*try\s+SettingsStorageEdits\.save\(\s*field\s*:\s*field\s*,'
            r'\s*value\s*:\s*value\s*,\s*displayedEnvelopeMiB\s*:\s*displayedEnvelopeMiB\(\s*\)\s*,'
            r'\s*preferences\s*:\s*preferences\s*,\s*at\s*:\s*url\s*,'
            r'\s*persist\s*:\s*persist\s*,\s*queueReload\s*:\s*queueReload\s*\)\s*\}\s*\)\s*\}\s*\)'
        ):
            errors.append('storage binding must return the actual save-backed binding, without dead or alternate setters')
        require(session_type, r'\bvar\s+persist\s*:[^=]+?=\s*\{\s*try\s+\$0\.write\(\s*to\s*:\s*\$1\s*,\s*options\s*:\s*\.atomic\s*\)\s*\}',
                'production storage session must default to atomic persistence')
        require(save, r'\btry\s+persist\(\s*data\s*,\s*url\s*\)', 'storage save has no durable write')
        require(save, r'\bupdateDisplayPreferences\(\s*priorValues\.merging\(\s*changed\s*,',
                'storage save must publish the saved edit to display preferences')
        require(save, r'\breturn\s+queueReload\(\s*\)\s*\?\s*\.reloadQueued\s*:\s*\.savedAwaitingReload',
                'storage save must request reload and distinguish queue failure')
        writes = save.matches(r'\btry\s+persist\(')
        reloads = save.matches(r'\bqueueReload\(')
        preferences = save.matches(r'\bupdateDisplayPreferences\(')
        if writes and reloads and preferences and not writes[0].start() < preferences[0].start() < reloads[0].start():
            errors.append('storage save must persist before preferences and reload')
        require(edits.block(r'\bvar\s+overridesURL\s*:\s*URL'),
                r'\.appendingPathComponent\(\s*"Library/Application Support/MacCrab/user_overrides.json"\s*\)',
                'storage writer path no longer matches the daemon override path')
        require(config, r'\bhome\.appending\(\s*"Library/Application Support/MacCrab/user_overrides.json"\s*\)',
                'daemon no longer reads the per-user overrides path')

        require(general, r'\.onAppear\s*\{\s*migrateLegacyStorageKeys\(\s*\)\s+hydrateStorageOverrides\(\s*\)\s*\}',
                'Settings appearance must migrate display keys then hydrate without saving')
        require(hydrate, r'\btry\s+storageSession\.appear\(', 'Settings hydration bypasses the production appearance seam')
        require(appearance, r'\btry\s+SettingsStorageEdits\.hydrate\(', 'storage appearance must hydrate display preferences')
        for label, source in [('migration', migration), ('hydration', hydrate), ('appearance', appearance)]:
            forbid(source, r'\b(?:save|persist|queueReload|reloadDetectionRules)\s*\(',
                   f'Settings {label} must not write policy or request reload')
        for key, variable in (('retentionDays', 'legacyRetention'), ('maxDatabaseSizeMB', 'legacyCap')):
            require(migration, rf'\bif\s+let\s+{variable}\s*=\s*defaults\.object\(\s*forKey\s*:\s*"{key}"\s*\)\s+as\?\s+Int',
                    f'legacy display migration missing for {key}')
            forbid(view, rf'@AppStorage\(\s*"{key}"', f'legacy key {key} became an unreviewed live control')

        require(view, r'\bPicker\([^\n]+selection\s*:\s*\$retentionWindowDays\s*\)',
                'manual-prune threshold is not bound to its picker')
        manual_confirmation = view.block(
            r'\.confirmationDialog\(\s*String\(\s*localized\s*:\s*"settings\.retention\.confirmTitle"'
        )
        require(manual_confirmation, r'\bTask\s*\{\s*await\s+appState\.pruneAlerts\(\s*olderThanDays\s*:\s*retentionWindowDays\s*\)\s*\}',
                'manual-prune selection has no confirmed action consumer')
        dashboard_reload = parsed['control'].block(r'\bfunc\s+reloadDetectionRules\(\s*source\s*:')
        require(dashboard_reload, r'\breturn\s+writeReloadRulesRequest\(\s*inboxDir\s*:\s*source\.directory\s*\+\s*"/inbox"\s*\)',
                'dashboard reload no longer reaches the selected-engine inbox')
        reload_handler = parsed['timers'].block(r'\bfunc\s+handleReloadRulesRequests\s*\(')
        require(reload_handler, r'\bkill\(\s*getpid\(\s*\)\s*,\s*SIGHUP\s*\)',
                'authorized reload requests no longer reach the signal handler')
        signal_reload = parsed['signals'].block(r'\bsigHupSource\.setEventHandler\b')
        require(signal_reload, r'\blet\s+freshConfig\s*=\s*DaemonConfig\.load\(\s*from\s*:\s*state\.supportDir\s*\)',
                'reload handler no longer reads fresh daemon configuration')
        require(signal_reload, r'\blet\s+newStorage\s*=\s*freshConfig\.storage\.clampedToSafeFloors\(\s*\)',
                'reload storage must derive from fresh configuration with safe floors')
        require(signal_reload, r'\bstate\.storage\s*=\s*newStorage', 'reload handler no longer applies storage configuration')
    except (KeyError, ValueError) as error:
        errors.append(f'Settings source scan failed: {error}')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        errors = check({name: (args.source_root / relative).read_text() for name, relative in FILES.items()})
    except (OSError, UnicodeError) as error:
        errors = [f'Settings source unavailable: {error}']
    for error in errors:
        print('Settings audit: ' + error, file=sys.stderr)
    if not errors:
        print('Settings source wiring: seven explicit storage edits, legacy display migration, manual prune, and other classified bindings verified (not installed application evidence)')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
