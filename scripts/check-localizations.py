#!/usr/bin/env python3
"""Check shipped catalogs, source defaults, printf contracts, and live plurals.

This checks structural correctness; it does not certify translation quality or
visual layout. Run native-language and packaged UI review separately.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
import plistlib
import re
import sys
import xml.etree.ElementTree as ET

LOCALES = {'en', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'nl', 'pl', 'pt-BR', 'ru', 'sv', 'zh-Hans', 'zh-Hant'}
PLURAL_CATEGORIES = {
    **{locale: {'one', 'other'} for locale in ('en', 'de', 'nl', 'sv')},
    **{locale: {'one', 'many', 'other'} for locale in ('es', 'fr', 'it', 'pt-BR')},
    **{locale: {'other'} for locale in ('ja', 'ko', 'zh-Hans', 'zh-Hant')},
    **{locale: {'one', 'few', 'many', 'other'} for locale in ('pl', 'ru')},
}
FORMAT = re.compile(r'%(?:(?P<position>[1-9]\d*)\$)?[-+#0]*(?:\d+)?(?:\.\d+)?(?P<type>ll[diuoxX]|l[diuoxX]|[diuoxX@fFeEgGaAcCsSpn])')
PLURAL_TOKEN = re.compile(r'%(?:(?P<position>[1-9]\d*)\$)?#@(?P<name>[A-Za-z_][A-Za-z_0-9]*)@')


def swift_literal(source: str, start: int, *, strict: bool = True):
    quote = '"""' if source.startswith('"""', start) else '"'
    if not source.startswith(quote, start):
        raise ValueError('expected Swift string literal')
    pos = start + len(quote)
    segments, text = [], ''
    while pos < len(source):
        if source.startswith(quote, pos):
            segments.append({'text': text})
            return segments, pos + len(quote)
        char = source[pos]
        if char != '\\':
            text += char
            pos += 1
            continue
        if pos + 1 >= len(source):
            break
        if source[pos + 1] == '(':
            segments.append({'text': text})
            text = ''
            begin = pos + 2
            pos, depth = begin, 1
            while depth and pos < len(source):
                if source[pos] == '"':
                    _, pos = swift_literal(source, pos, strict=strict)
                    continue
                if source[pos] == '(':
                    depth += 1
                elif source[pos] == ')':
                    depth -= 1
                pos += 1
            if depth:
                raise ValueError('unterminated Swift interpolation')
            segments.append({'expression': source[begin:pos - 1]})
            continue
        if source.startswith('\\u{', pos):
            end = source.index('}', pos)
            text += chr(int(source[pos + 3:end], 16))
            pos = end + 1
            continue
        code = source[pos + 1]
        escapes = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', '"': '"', "'": "'", '\\': '\\'}
        if code == '\n':
            pos += 2
            while pos < len(source) and source[pos] in ' \t':
                pos += 1
            continue
        if code not in escapes and strict:
            raise ValueError(f'unsupported Swift escape \\{code}')
        text += escapes.get(code, '\\' + code)
        pos += 2
    raise ValueError('unterminated Swift literal')


def strip_swift_comments(source: str) -> str:
    """Preserve literals and positions while removing nested Swift comments."""
    output = list(source)
    pos = 0
    while pos < len(source):
        if source[pos] == '"':
            _, pos = swift_literal(source, pos, strict=False)
        elif source.startswith('//', pos):
            end = source.find('\n', pos)
            end = len(source) if end < 0 else end
            output[pos:end] = ' ' * (end - pos)
            pos = end
        elif source.startswith('/*', pos):
            begin, depth = pos, 1
            pos += 2
            while depth and pos < len(source):
                if source.startswith('/*', pos):
                    depth += 1
                    pos += 2
                elif source.startswith('*/', pos):
                    depth -= 1
                    pos += 2
                else:
                    pos += 1
            output[begin:pos] = ['\n' if c == '\n' else ' ' for c in source[begin:pos]]
        else:
            pos += 1
    return ''.join(output)


def source_defaults(root: Path):
    refs = collections.defaultdict(list)
    for path in sorted((root / 'Sources/MacCrabApp').rglob('*.swift')):
        source = strip_swift_comments(path.read_text())
        for match in re.finditer(r'localized:\s*"([^"\\]+)"', source):
            tail = re.match(r'\s*,\s*defaultValue:\s*', source[match.end():])
            ref = {'file': str(path.relative_to(root))}
            if tail:
                pos = match.end() + tail.end()
                ref['segments'], _ = swift_literal(source, pos)
            refs[match.group(1)].append(ref)
    return refs


def parse_strings(path: Path) -> dict[str, str]:
    source = path.read_text(encoding='utf-8-sig')
    pos, result = 0, {}

    def skip():
        nonlocal pos
        while pos < len(source):
            if source[pos].isspace():
                pos += 1
            elif source.startswith('/*', pos):
                end = source.find('*/', pos + 2)
                if end < 0:
                    raise ValueError('unterminated catalog comment')
                pos = end + 2
            elif source.startswith('//', pos):
                end = source.find('\n', pos + 2)
                pos = len(source) if end < 0 else end + 1
            else:
                break

    def quoted():
        nonlocal pos
        if pos >= len(source) or source[pos] != '"':
            raise ValueError(f'expected quoted string at byte {pos}')
        pos += 1
        text = ''
        while pos < len(source):
            char = source[pos]
            pos += 1
            if char == '"':
                return text
            if char != '\\':
                text += char
                continue
            if pos >= len(source):
                break
            code = source[pos]
            pos += 1
            escapes = {'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}
            if code == 'U' and re.fullmatch('[0-9a-fA-F]{4}', source[pos:pos + 4]):
                text += chr(int(source[pos:pos + 4], 16))
                pos += 4
            elif code in escapes:
                text += escapes[code]
            else:
                raise ValueError(f'unsupported catalog escape \\{code}; use a literal Unicode character')
        raise ValueError('unterminated catalog string')

    while True:
        skip()
        if pos == len(source):
            return result
        key = quoted()
        skip()
        if pos >= len(source) or source[pos] != '=':
            raise ValueError(f'missing = after {key}')
        pos += 1
        skip()
        value = quoted()
        skip()
        if pos >= len(source) or source[pos] != ';':
            raise ValueError(f'missing ; after {key}')
        pos += 1
        if key in result:
            raise ValueError(f'duplicate key {key}')
        result[key] = value


def format_signature(value: str) -> dict[int, str]:
    """Return argument positions/types, preserving ABI width and signedness."""
    signature, sequential, pos = {}, 1, 0
    modes = set()
    while pos < len(value):
        if value.startswith('%%', pos):
            pos += 2
            continue
        match = FORMAT.match(value, pos)
        if not match:
            pos += 1
            continue
        kind = match['type']
        if kind in ('n', 's', 'S', 'p'):
            raise ValueError(f'unsupported catalog conversion %{kind}')
        position = int(match['position']) if match['position'] else sequential
        modes.add(bool(match['position']))
        if not match['position']:
            sequential += 1
        if position in signature and signature[position] != kind:
            raise ValueError(f'argument {position} has conflicting types')
        signature[position] = kind
        pos = match.end()
    if len(modes) > 1:
        raise ValueError('mixed positional and sequential format arguments')
    if signature and set(signature) != set(range(1, max(signature) + 1)):
        raise ValueError('format argument positions have gaps')
    return signature


def parse_plurals(path: Path):
    # plistlib accepts duplicate keys; explicitly reject them before decoding.
    document = ET.fromstring(path.read_bytes())
    for node in document.iter('dict'):
        keys = [child.text for child in node if child.tag == 'key']
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate stringsdict key')
    return plistlib.loads(path.read_bytes())


def unlocalized_ui_copy(source: str):
    """Catch visible Text prose even when interpolation precedes the words.

    Dynamic values remain a semantic-review boundary. The known lifecycle
    helper is checked at its call sites because its three arguments are UI copy.
    Exact evidence, identifiers and numeric-only labels are not translated.
    """
    clean = strip_swift_comments(source)
    findings = []
    for match in re.finditer(r'(?<![A-Za-z0-9_])Text\(\s*"', clean):
        start = clean.index('"', match.start(), match.end())
        segments, _ = swift_literal(clean, start)
        if re.search(r'[A-Za-z]', ''.join(part.get('text', '') for part in segments)):
            findings.append((clean.count('\n', 0, start) + 1, 'unlocalized Text prose'))
    for call in re.finditer(r'\blifecycleDegradedBanner\(', clean):
        pos, depth = call.end(), 1
        while pos < len(clean) and depth:
            if clean[pos] == '"':
                _, pos = swift_literal(clean, pos)
                continue
            if clean[pos] == '(':
                depth += 1
            elif clean[pos] == ')':
                depth -= 1
            pos += 1
        arguments = clean[call.end():pos]
        for argument in re.finditer(r'\b(title|workLabel|impact):\s*"', arguments):
            line = clean.count('\n', 0, call.end() + argument.start()) + 1
            findings.append((line, f'unlocalized lifecycle {argument[1]}'))
    return findings


def check(root: Path):
    errors = []
    resources = root / 'Sources/MacCrabApp/Resources'
    tables, plurals = {}, {}
    for folder in sorted(resources.glob('*.lproj')):
        locale = folder.stem
        try:
            tables[locale] = parse_strings(folder / 'Localizable.strings')
            plurals[locale] = parse_plurals(folder / 'Localizable.stringsdict')
        except (ValueError, OSError, ET.ParseError, plistlib.InvalidFileException) as error:
            errors.append(f'{locale}: {error}')
    if set(tables) != LOCALES:
        errors.append(f'catalog locales differ: missing {sorted(LOCALES - tables.keys())}, extra {sorted(tables.keys() - LOCALES)}')
    english = tables.get('en', {})
    english_plurals = plurals.get('en', {})
    for locale, table in tables.items():
        missing, extra = english.keys() - table.keys(), table.keys() - english.keys()
        if missing or extra:
            errors.append(f'{locale}: {len(missing)} missing keys {sorted(missing)[:8]}, {len(extra)} extra keys {sorted(extra)[:8]}')
        for key in english.keys() & table.keys():
            if english[key] and not table[key]:
                errors.append(f'{locale}:{key}: empty translation')
            try:
                if format_signature(english[key]) != format_signature(table[key]):
                    errors.append(f'{locale}:{key}: printf argument mismatch')
            except ValueError as error:
                errors.append(f'{locale}:{key}: {error}')
        plural_table = plurals.get(locale, {})
        if plural_table.keys() != english_plurals.keys():
            errors.append(f'{locale}: plural key parity mismatch')
        for key, entry in plural_table.items():
            try:
                if key not in table:
                    raise ValueError('plural has no fallback .strings row')
                tokens = list(PLURAL_TOKEN.finditer(entry['NSStringLocalizedFormatKey']))
                if len(tokens) != 1 or tokens[0]['position'] not in (None, '1'):
                    raise ValueError('expected one count plural in argument position 1')
                token = tokens[0]
                variable = entry[token['name']]
                if variable['NSStringFormatSpecTypeKey'] != 'NSStringPluralRuleType' or variable['NSStringFormatValueTypeKey'] != 'lld':
                    raise ValueError('expected signed Int count contract')
                categories = set(variable) - {'NSStringFormatSpecTypeKey', 'NSStringFormatValueTypeKey'}
                if categories != PLURAL_CATEGORIES[locale]:
                    raise ValueError(f'plural categories {sorted(categories)} do not match {sorted(PLURAL_CATEGORIES[locale])}')
                for category in categories:
                    expanded = entry['NSStringLocalizedFormatKey'][:token.start()] + variable[category] + entry['NSStringLocalizedFormatKey'][token.end():]
                    if format_signature(expanded) != format_signature(table[key]):
                        raise ValueError(f'{category} plural argument mismatch')
            except (ValueError, KeyError, TypeError) as error:
                errors.append(f'{locale}:{key}: {error}')
    try:
        for source in sorted((root / 'Sources/MacCrabApp').rglob('*.swift')):
            for line, reason in unlocalized_ui_copy(source.read_text()):
                errors.append(f'source:{source.relative_to(root)}:{line}: {reason}')
        refs = source_defaults(root)
        contracts = json.loads((root / 'scripts/localization-format-contracts.json').read_text())['contracts']
        seen_contracts = set()
        for key, references in refs.items():
            if key not in english:
                errors.append(f'source:{key}: missing English default')
                continue
            for reference in references:
                if 'segments' not in reference:
                    continue
                segments = reference['segments']
                expressions = [segment['expression'] for segment in segments if 'expression' in segment]
                contract = contracts.get(key, [])
                if expressions:
                    seen_contracts.add(key)
                if expressions != [argument['expression'] for argument in contract]:
                    errors.append(f'source:{key}: interpolation changed; review its format contract')
                    continue
                types = iter(argument['type'] for argument in contract)
                value = ''.join('%' + next(types) if 'expression' in segment else segment['text'].replace('%', '%%') if expressions else segment['text'] for segment in segments)
                if value != english[key]:
                    errors.append(f'source:{key}: English catalog differs from source default')
        for key in contracts.keys() - seen_contracts:
            errors.append(f'source:{key}: unused interpolation contract')
        for key in english_plurals.keys() - refs.keys():
            errors.append(f'source:{key}: unused plural contract')
    except (ValueError, OSError, KeyError) as error:
        errors.append(f'source scan: {error}')
    return errors, {'locales': len(tables), 'english_keys': len(english), 'plural_keys': len(english_plurals), 'errors': len(errors), 'native_language_review': 'NOT_PERFORMED', 'packaged_visual_review': 'NOT_PERFORMED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--json', action='store_true', help='emit a machine-readable structural check result')
    args = parser.parse_args()
    errors, summary = check(args.root.resolve())
    if args.json:
        print(json.dumps({'summary': summary, 'errors': errors}, ensure_ascii=False, indent=2))
    else:
        print(f"Localization: {summary['locales']} locales, {summary['english_keys']} English keys, {summary['plural_keys']} plural keys; {len(errors)} error(s)")
        for error in errors:
            print(error)
        print('Native-language and packaged visual reviews are not certified by this check.')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
