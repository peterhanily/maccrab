#!/usr/bin/env python3
"""Lossless, pre-signing optimization of an assembled app's localization tables.

This never accepts the source Resources directory. It preserves .strings quoted
tokens byte-for-byte and in order; .stringsdict may use Apple's binary plist
representation. Every candidate must decode identically through plutil. All
candidates are validated before replacements begin, and each replacement is
atomic. A later I/O failure still aborts the build, not a transaction rollback.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

LOCALES = frozenset(('de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'nl', 'pl',
                     'pt-BR', 'ru', 'sv', 'zh-Hans', 'zh-Hant'))
TABLE_LIMITS = {'Localizable.strings': 2 * 1024 * 1024,
                'Localizable.stringsdict': 256 * 1024}
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ASSIGNMENTS = 10000
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def minify_strings(data):
    """Return compact bytes plus the unchanged ordered literal/punctuation tokens."""
    if len(data) > TABLE_LIMITS['Localizable.strings']:
        raise ValueError('strings input exceeds bound')
    data.decode('utf-8', errors='strict')
    tokens = []
    index = 0
    while index < len(data):
        value = data[index]
        if value in b' \t\r\n':
            index += 1
        elif data[index:index + 2] == b'//':
            end = data.find(b'\n', index + 2)
            index = len(data) if end < 0 else end + 1
        elif data[index:index + 2] == b'/*':
            end = data.find(b'*/', index + 2)
            if end < 0:
                raise ValueError('unterminated comment')
            index = end + 2
        elif value == ord('"'):
            start = index
            index += 1
            while index < len(data):
                if data[index] == ord('\\'):
                    index += 2
                    if index > len(data):
                        raise ValueError('truncated quoted escape')
                elif data[index] == ord('"'):
                    index += 1
                    tokens.append(data[start:index])
                    break
                else:
                    index += 1
            else:
                raise ValueError('unterminated quoted literal')
        elif value in b'=;':
            tokens.append(data[index:index + 1])
            index += 1
        else:
            raise ValueError('unexpected outside-literal token')
        if len(tokens) > MAX_ASSIGNMENTS * 4:
            raise ValueError('strings assignment count exceeds bound')
    if not tokens or len(tokens) % 4:
        raise ValueError('incomplete assignment')
    for index in range(0, len(tokens), 4):
        key, equals, value, semicolon = tokens[index:index + 4]
        if not (key.startswith(b'"') and key.endswith(b'"') and equals == b'='
                and value.startswith(b'"') and value.endswith(b'"') and semicolon == b';'):
            raise ValueError('invalid assignment grammar')
    return b''.join(tokens), tuple(tokens)


def plutil(data, format_name):
    if format_name not in ('json', 'binary1') or len(data) > MAX_TOTAL_BYTES:
        raise ValueError('invalid bounded conversion')
    result = subprocess.run(['/usr/bin/plutil', '-convert', format_name, '-o', '-', '--', '-'],
                            input=data, capture_output=True, timeout=10,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    if result.returncode or result.stderr or len(result.stdout) > MAX_TOTAL_BYTES:
        # Never include localization values or tool output in diagnostics.
        raise ValueError('plutil conversion failed or exceeded output bound')
    return result.stdout


def decoded(data, filename):
    value = json.loads(plutil(data, 'json'))
    if not isinstance(value, dict) or not value:
        raise ValueError('localization table is not a nonempty dictionary')

    def valid(item):
        return isinstance(item, str) or (isinstance(item, dict) and all(
            isinstance(key, str) and valid(child) for key, child in item.items()))

    if not valid(value):
        raise ValueError('localization table has an unsupported value kind')
    if filename == 'Localizable.strings' and not all(isinstance(item, str)
                                                    for item in value.values()):
        raise ValueError('strings table has a non-string value')
    return value


def candidate(data, filename):
    original = decoded(data, filename)
    if filename == 'Localizable.strings':
        compact, tokens = minify_strings(data)
        second, compact_tokens = minify_strings(compact)
        if second != compact or tokens != compact_tokens:
            raise ValueError('quoted literal bytes/order changed')
    elif filename == 'Localizable.stringsdict':
        compact = plutil(data, 'binary1')
        if not compact.startswith(b'bplist00'):
            raise ValueError('binary conversion did not produce a binary plist')
    else:
        raise ValueError('unexpected localization filename')
    if decoded(compact, filename) != original:
        raise ValueError('decoded localization content changed')
    return compact


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_resources(path):
    path = Path(path)
    if (not path.is_absolute() or '..' in path.parts or path.name != 'Resources'
            or path.parent.name != 'Contents' or not path.parent.parent.name.endswith('.app')):
        raise ValueError('expected an absolute assembled .app/Contents/Resources path')
    descriptor = os.open('/', DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_table(directory, filename):
    descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        limit = TABLE_LIMITS[filename]
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('localization entry is not a single-link regular file')
        if before.st_size <= 0 or before.st_size > limit:
            raise ValueError('localization input size exceeds bound')
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        if len(data) != before.st_size or identity(os.fstat(descriptor)) != identity(before):
            raise ValueError('localization input changed during read')
        return before, data
    finally:
        os.close(descriptor)


def replace_if_smaller(directory, filename, before, original, compact):
    if len(compact) >= len(original):
        return False
    temporary = '.maccrab-localization-' + secrets.token_hex(16)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
    temporary_identity = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(compact)
            handle.flush()
            os.fchmod(handle.fileno(), stat.S_IMODE(before.st_mode))
            os.fsync(handle.fileno())
            allocated = os.fstat(handle.fileno()).st_blocks
        if allocated >= before.st_blocks:
            return False
        current, current_bytes = read_table(directory, filename)
        if identity(current) != identity(before) or current_bytes != original:
            raise ValueError('localization input changed before replacement')
        os.replace(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        return True
    finally:
        if temporary is not None:
            current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (temporary_identity.st_dev,
                                                  temporary_identity.st_ino):
                raise ValueError('private temporary entry changed')
            os.unlink(temporary, dir_fd=directory)


def optimize(resources):
    """Internal fixture seam; command-line callers additionally enforce stage binding."""
    with ExitStack() as stack:
        root = open_resources(resources)
        stack.callback(os.close, root)
        root_identity = os.fstat(root)
        entries = os.listdir(root)
        if {name for name in entries if name.endswith('.lproj')} != {
                locale + '.lproj' for locale in LOCALES}:
            raise ValueError('assembled locale set differs from the 14 supported locales')
        for name in entries:
            mode = os.stat(name, dir_fd=root, follow_symlinks=False).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ValueError('Resources contains a symlink or unsupported entry kind')
        plans = []
        directories = []
        total = 0
        for locale in sorted(LOCALES):
            name = locale + '.lproj'
            directory = os.open(name, DIRECTORY_FLAGS, dir_fd=root)
            stack.callback(os.close, directory)
            directories.append((name, directory, os.fstat(directory)))
            if set(os.listdir(directory)) != set(TABLE_LIMITS):
                raise ValueError('locale contains missing or unexpected entries')
            for filename in sorted(TABLE_LIMITS):
                before, data = read_table(directory, filename)
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise ValueError('localization total exceeds bound')
                plans.append((locale, directory, filename, before, data, candidate(data, filename)))
        # Recheck the root, directory bindings and EVERY source before replacing any.
        verified_root = open_resources(resources)
        try:
            current_root = os.fstat(verified_root)
            if (current_root.st_dev, current_root.st_ino) != (root_identity.st_dev, root_identity.st_ino):
                raise ValueError('Resources identity changed')
        finally:
            os.close(verified_root)
        for name, directory, initial in directories:
            current = os.stat(name, dir_fd=root, follow_symlinks=False)
            if identity(current) != identity(initial) or set(os.listdir(directory)) != set(TABLE_LIMITS):
                raise ValueError('locale directory changed before optimization')
        for _, directory, filename, before, data, _ in plans:
            current, current_bytes = read_table(directory, filename)
            if identity(current) != identity(before) or current_bytes != data:
                raise ValueError('localization input changed before optimization')
        rows = []
        for locale, directory, filename, before, data, compact in plans:
            replaced = replace_if_smaller(directory, filename, before, data, compact)
            after, final = read_table(directory, filename)
            expected = compact if replaced else data
            if final != expected or stat.S_IMODE(after.st_mode) != stat.S_IMODE(before.st_mode):
                raise ValueError('localization readback differs')
            rows.append({'locale': locale, 'table': filename, 'replaced': replaced,
                         'before_bytes': len(data), 'after_bytes': len(final),
                         'before_allocated_kib': before.st_blocks // 2,
                         'after_allocated_kib': after.st_blocks // 2,
                         'before_sha256': hashlib.sha256(data).hexdigest(),
                         'after_sha256': hashlib.sha256(final).hexdigest()})
        return {'locales': len(LOCALES), 'tables': len(rows), 'results': rows,
                'saved_allocated_kib': sum(row['before_allocated_kib'] - row['after_allocated_kib']
                                           for row in rows)}


def stage_resources(staging_dir, resources):
    staging_dir, resources = Path(staging_dir), Path(resources)
    single_stage = PROJECT_ROOT / '.build/maccrab-stage'
    all_stages = re.fullmatch(r'/private/tmp/maccrab-release-[1-9][0-9]*', str(staging_dir))
    if staging_dir != single_stage and all_stages is None:
        raise ValueError('not a supported release staging directory')
    if resources != staging_dir / 'MacCrab.app/Contents/Resources':
        raise ValueError('resources are not the exact staged app localization root')
    return resources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging-dir', required=True)
    parser.add_argument('--resources', required=True)
    args = parser.parse_args()
    try:
        result = optimize(stage_resources(args.staging_dir, args.resources))
    except (OSError, ValueError, subprocess.SubprocessError, RecursionError):
        parser.exit(1, 'ERROR: staged localization validation/optimization failed\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
