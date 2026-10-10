#!/usr/bin/python3
"""Create/remove only a workload-owned directory, bound by device/inode/uid.

Removal walks open directory descriptors, never follows symlinks, and refuses a
replacement root. An interrupted create may leave an empty directory; it must
never authorize cleanup of a directory whose ownership receipt was not returned.
"""
import argparse
import os
from pathlib import Path
import re
import stat
import sys


def identity(info):
    return info.st_dev, info.st_ino, info.st_uid


def open_directory(path, *, dir_fd=None):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                   dir_fd=dir_fd)


def create_owned(path):
    path = Path(path)
    os.mkdir(path, 0o700)  # A pre-existing path is never claimed.
    descriptor = open_directory(path)
    try:
        info = os.fstat(descriptor)
        if identity(info) != identity(os.lstat(path)) or info.st_uid != os.geteuid():
            raise ValueError('created directory identity changed')
        return ':'.join(str(value) for value in identity(info))
    finally:
        os.close(descriptor)


def remove_owned(path, receipt):
    if not re.fullmatch(r'[0-9]+:[0-9]+:[0-9]+', receipt):
        raise ValueError('missing or malformed directory ownership receipt')
    expected = tuple(int(value) for value in receipt.split(':'))
    path = Path(path)
    descriptor = open_directory(path)
    try:
        info = os.fstat(descriptor)
        if identity(info) != expected or info.st_uid != os.geteuid():
            raise ValueError('refusing cleanup of an unowned or replaced directory')
        def drain(directory):
            for name in os.listdir(directory):
                entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode):
                    child = open_directory(name, dir_fd=directory)
                    try:
                        opened = os.fstat(child)
                        if identity(opened) != identity(entry) or opened.st_dev != expected[0]:
                            raise ValueError('cleanup child identity or filesystem changed')
                        drain(child)
                        if identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != identity(opened):
                            raise ValueError('cleanup child directory was replaced')
                        os.rmdir(name, dir_fd=directory)
                    finally:
                        os.close(child)
                else:
                    # unlink removes the entry itself, including a symlink;
                    # it never traverses or deletes a link destination.
                    os.unlink(name, dir_fd=directory)
        drain(descriptor)
        current = os.lstat(path)
        if not stat.S_ISDIR(current.st_mode) or identity(current) != expected:
            raise ValueError('cleanup root was replaced; replacement retained')
        os.rmdir(path)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('create', 'remove'))
    parser.add_argument('path', type=Path)
    parser.add_argument('receipt', nargs='?')
    args = parser.parse_args()
    allowed = ((Path('/private/tmp'), r'maccrab-runtime-alert\.[0-9a-f]{32}'),
               (Path('/Users/Shared'), r'MacCrabQualificationRuntime-[0-9a-f]{32}'))
    if not any(args.path.parent == parent and parent.resolve() == parent and
               re.fullmatch(pattern, args.path.name) for parent, pattern in allowed):
        parser.error('path is not a fixed run-owned workload directory')
    if (args.action == 'remove') != (args.receipt is not None):
        parser.error('only removal requires an ownership receipt')
    if args.action == 'create':
        print(create_owned(args.path))
    else:
        remove_owned(args.path, args.receipt)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print('Workload directory operation refused: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
