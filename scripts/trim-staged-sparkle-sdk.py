#!/usr/bin/env python3
"""Remove SDK-only files from the copied Sparkle framework before re-signing.

The authenticated SwiftPM artifact is never a target. This is a serial staging
operation, not a concurrent-writer security boundary. Every target is validated
before the first unlink; no recursive deletion or symlink traversal is used.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat


FRAMEWORK_SUFFIX = Path('MacCrab.app/Contents/Frameworks/Sparkle.framework')
STAGED_FRAMEWORK = Path('.build/maccrab-stage') / FRAMEWORK_SUFFIX
TEMP_STAGE_PARENT = Path('/private/tmp')
SDK_DIRECTORIES = ('Headers', 'PrivateHeaders', 'Modules')
MODULE_MAPS = frozenset(('module.modulemap', 'module.private.modulemap'))
MAX_FILES = 256
MAX_BYTES = 4 * 1024 * 1024


def identity(path):
    value = path.lstat()
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def ordinary_directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError('expected an ordinary SDK/staging directory')


def preflight(framework, project_root, staging_dir=None):
    """Return a complete bounded deletion plan, without changing any file."""
    project_root = Path(project_root)
    framework = Path(framework)
    if not project_root.is_absolute() or project_root.resolve(strict=True) != project_root:
        raise ValueError('project root must be absolute and canonical')
    stage = Path(staging_dir) if staging_dir is not None else project_root / '.build/maccrab-stage'
    single_stage = stage == project_root / '.build/maccrab-stage'
    all_stages = stage.parent == TEMP_STAGE_PARENT and re.fullmatch(r'maccrab-release-[1-9][0-9]*', stage.name)
    if not (single_stage or all_stages) or stage.resolve(strict=True) != stage:
        raise ValueError('unsupported or noncanonical release staging directory')
    expected = stage / FRAMEWORK_SUFFIX
    if framework != expected or framework.resolve(strict=True) != expected:
        raise ValueError('only the canonical copied staged framework is allowed')
    # resolve(strict=True) above rejects any symlink along this fixed suffix.
    cursor = project_root if single_stage else TEMP_STAGE_PARENT
    ordinary_directory(cursor)
    for part in expected.relative_to(cursor).parts:
        cursor = cursor / part
        ordinary_directory(cursor)
    version = framework / 'Versions' / 'B'
    ordinary_directory(framework / 'Versions')
    ordinary_directory(version)
    current = framework / 'Versions' / 'Current'
    if not stat.S_ISLNK(current.lstat().st_mode) or os.readlink(current) != 'B':
        raise ValueError('unexpected framework Current link')
    runtime = version / 'Sparkle'
    if not stat.S_ISREG(runtime.lstat().st_mode):
        raise ValueError('missing ordinary Sparkle runtime binary')

    anchors = [(path, identity(path)) for path in (framework, framework / 'Versions', version, current, runtime)]
    aliases, directories, leaves = [], [], []
    total_bytes = 0
    for name in SDK_DIRECTORIES:
        alias, directory = framework / name, version / name
        if not stat.S_ISLNK(alias.lstat().st_mode) or os.readlink(alias) != 'Versions/Current/' + name:
            raise ValueError('unexpected SDK alias link')
        ordinary_directory(directory)
        aliases.append((alias, identity(alias)))
        directories.append((directory, identity(directory)))
        children = sorted(directory.iterdir())
        if not children:
            raise ValueError('unexpected empty SDK directory')
        for child in children:
            details = child.lstat()
            allowed = child.name in MODULE_MAPS if name == 'Modules' else child.name.endswith('.h')
            if not stat.S_ISREG(details.st_mode) or not allowed:
                raise ValueError('unexpected SDK entry; nothing was removed')
            leaves.append((child, identity(child)))
            total_bytes += details.st_size
            if len(leaves) > MAX_FILES or total_bytes > MAX_BYTES:
                raise ValueError('SDK deletion plan exceeds its fixed bounds')
    return anchors, aliases, directories, leaves, total_bytes


def trim_sdk(framework, project_root, staging_dir=None):
    anchors, aliases, directories, leaves, total_bytes = preflight(framework, project_root, staging_dir)
    # A second complete check ensures a late invalid entry cannot be discovered
    # only after another directory has already been trimmed. The build owns this
    # stage exclusively; unexpected concurrent changes still fail visibly.
    for path, original in anchors + aliases + directories + leaves:
        if identity(path) != original:
            raise ValueError('staged framework changed after preflight')
    for path, original in leaves:
        if identity(path) != original:
            raise ValueError('SDK entry changed before unlink')
        path.unlink()
    for path, _ in directories:
        path.rmdir()  # Fails rather than traversing an unexpected late entry.
    for path, original in aliases:
        if identity(path) != original:
            raise ValueError('SDK alias changed before unlink')
        path.unlink()
    return {'removed_sdk_files': len(leaves), 'removed_sdk_bytes': total_bytes,
            'removed_sdk_directories': len(directories), 'removed_sdk_aliases': len(aliases)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--framework', required=True)
    parser.add_argument('--staging-dir', required=True)
    args = parser.parse_args()
    if any(str(Path(value)) != value for value in (args.framework, args.staging_dir)):
        parser.error('arguments must use normalized absolute paths')
    try:
        result = trim_sdk(Path(args.framework), Path(__file__).resolve(strict=True).parent.parent,
                          Path(args.staging_dir))
    except (OSError, ValueError) as error:
        parser.exit(1, 'ERROR: staged Sparkle SDK trim refused: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
