#!/usr/bin/env python3
"""Offline Foundation lookup/format parity; compile only a tiny private fixture.

No SwiftPM, installed app, staging tree, user preferences or runtime store is
accessed. Original resource tables are read-only; all bundles and the Objective-C
executable live in one task-owned temporary directory. -fno-modules avoids a
Clang module-cache build. Both subprocesses have explicit finite deadlines.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest


BASE = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('localization_optimizer',
                                            BASE / 'scripts/optimize-staged-localizations.py')
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
COUNTS = (0, 1, 2, 3, 4, 5, 11, 12, 21, 22, 25, 101, 102, 111, 1000, 1000000)
FIXTURE_SOURCE = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc != 2) return 2;
    NSError *error = nil;
    NSData *data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]];
    NSDictionary *manifest = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:&error] : nil;
    if (!manifest || error) return 3;
    NSUInteger lookups = 0, formats = 0, controls = 0;
    for (NSDictionary *row in manifest[@"rows"]) {
      NSBundle *original = [NSBundle bundleWithPath:row[@"original"]];
      NSBundle *optimized = [NSBundle bundleWithPath:row[@"optimized"]];
      if (!original || !optimized) return 4;
      for (NSString *key in row[@"keys"]) {
        NSString *left = [original localizedStringForKey:key value:@"__MISSING_PARITY_KEY__" table:@"Localizable"];
        NSString *right = [optimized localizedStringForKey:key value:@"__MISSING_PARITY_KEY__" table:@"Localizable"];
        if ([left isEqualToString:@"__MISSING_PARITY_KEY__"] || [left isEqualToString:key] ||
            ![left isEqualToString:right]) return 5;
        lookups++;
        for (NSNumber *value in manifest[@"counts"]) {
          long long count = value.longLongValue;
          NSString *a = [NSString localizedStringWithFormat:left, count, @"fixture-value", @"fixture-third"];
          NSString *b = [NSString localizedStringWithFormat:right, count, @"fixture-value", @"fixture-third"];
          if (![a isEqualToString:b] || [a containsString:@"#@"] || [a containsString:@"__MISSING_PARITY_KEY__"]) return 6;
          if ([row[@"positive_control"] boolValue] && (count == 1 || count == 2)) {
            NSString *expected = count == 1 ? @"ONE 1 fixture-value" : @"MANY 2 fixture-value";
            if (![a isEqualToString:expected]) return 7;
            controls++;
          }
          formats++;
        }
      }
    }
    if (controls != 2) return 8;
    NSDictionary *result = @{@"bundle_pairs": @([manifest[@"rows"] count]),
      @"lookup_pairs": @(lookups), @"formatted_pairs": @(formats),
      @"positive_plural_controls": @(controls)};
    NSData *resultData = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:&error];
    if (!resultData || error) return 9;
    fwrite(resultData.bytes, 1, resultData.length, stdout);
    fputc('\n', stdout);
  }
  return 0;
}
'''


class FoundationLocalizationParity(unittest.TestCase):
    def test_all_real_plural_keys_and_positive_branch_controls(self):
        source = BASE / 'Sources/MacCrabApp/Resources'
        source_hashes = {}
        with tempfile.TemporaryDirectory(prefix='maccrab-foundation-localization-') as directory:
            root = Path(directory).resolve()
            rows = []
            real_key_count = 0

            def bundle_pair(label, locale, strings, dictionary, keys, positive=False):
                pair = []
                for variant, compact in (('Original', False), ('Optimized', True)):
                    resources = root / (variant + '-' + label + '.bundle') / 'Contents/Resources'
                    localized = resources / (locale + '.lproj')
                    localized.mkdir(parents=True)
                    info = resources.parent / 'Info.plist'
                    info.write_bytes(plistlib.dumps({'CFBundleIdentifier': 'test.maccrab.' + variant + '.' + label,
                                                   'CFBundleDevelopmentRegion': locale,
                                                   'CFBundlePackageType': 'BNDL'}))
                    for filename, data in (('Localizable.strings', strings), ('Localizable.stringsdict', dictionary)):
                        final = HELPER.candidate(data, filename) if compact else data
                        if compact and filename.endswith('.stringsdict'):
                            self.assertTrue(final.startswith(b'bplist00'))
                        (localized / filename).write_bytes(final)
                    # An explicit lproj bundle prevents the host language from
                    # silently selecting English for every locale's lookup.
                    pair.append(str(localized))
                rows.append({'original': pair[0], 'optimized': pair[1],
                             'keys': keys, 'positive_control': positive})

            for locale in sorted(HELPER.LOCALES):
                tables = {}
                for filename, limit in HELPER.TABLE_LIMITS.items():
                    path = source / (locale + '.lproj') / filename
                    self.assertTrue(path.is_file() and not path.is_symlink())
                    data = path.read_bytes()
                    self.assertLessEqual(len(data), limit)
                    source_hashes[path] = hashlib.sha256(data).hexdigest()
                    tables[filename] = data
                decoded = plistlib.loads(tables['Localizable.stringsdict'])
                self.assertTrue(decoded)
                for value in decoded.values():
                    self.assertEqual(value['NSStringLocalizedFormatKey'], '%1$#@count@')
                    self.assertEqual(value['count']['NSStringFormatValueTypeKey'], 'lld')
                    self.assertEqual(value['count']['NSStringFormatSpecTypeKey'], 'NSStringPluralRuleType')
                keys = sorted(decoded)
                real_key_count += len(keys)
                bundle_pair(locale, locale, tables['Localizable.strings'], tables['Localizable.stringsdict'], keys)

            control = {'parity.control': {'NSStringLocalizedFormatKey': '%1$#@count@', 'count': {
                'NSStringFormatSpecTypeKey': 'NSStringPluralRuleType', 'NSStringFormatValueTypeKey': 'lld',
                'one': 'ONE %1$lld %2$@', 'other': 'MANY %1$lld %2$@'}}}
            bundle_pair('positive-control', 'en', b'"ordinary" = "fixture";',
                        plistlib.dumps(control), ['parity.control'], positive=True)
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps({'rows': rows, 'counts': COUNTS}))
            objc, executable = root / 'foundation-parity.m', root / 'foundation-parity'
            objc.write_text(FIXTURE_SOURCE)
            environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TMPDIR': str(root)}
            compiled = subprocess.run(['/usr/bin/clang', '-fobjc-arc', '-fno-modules', '-framework', 'Foundation',
                                       str(objc), '-o', str(executable)], capture_output=True,
                                      timeout=60, env=environment)
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode(errors='replace'))
            self.assertFalse(compiled.stderr, compiled.stderr.decode(errors='replace'))
            completed = subprocess.run([str(executable), str(manifest)], capture_output=True,
                                       timeout=30, env=environment)
            self.assertEqual(completed.returncode, 0, 'Foundation parity failure code ' + str(completed.returncode))
            self.assertFalse(completed.stderr, completed.stderr.decode(errors='replace'))
            result = json.loads(completed.stdout)
            self.assertEqual(result['bundle_pairs'], len(HELPER.LOCALES) + 1)
            self.assertEqual(result['lookup_pairs'], real_key_count + 1)
            self.assertEqual(result['formatted_pairs'], (real_key_count + 1) * len(COUNTS))
            self.assertEqual(result['positive_plural_controls'], 2)
            for path, digest in source_hashes.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            result.update({'source_tables_unchanged': len(source_hashes), 'real_locales': len(HELPER.LOCALES),
                           'source_table_hashes': {str(path.relative_to(source)): digest
                                                   for path, digest in sorted(source_hashes.items())},
                           'fixture_source_sha256': hashlib.sha256(FIXTURE_SOURCE.encode()).hexdigest(),
                           'scope': 'private NSBundle lookup and NSString plural formatting parity; no GUI or installed data'})
            print('Foundation localization parity: ' + json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
