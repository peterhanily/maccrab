#!/usr/bin/env python3
"""Recompress one pinned ic10 PNG stream in a private, pre-signing app stage.

This is not a general image optimizer: only the reviewed icon and its exact
deterministic compressed form are accepted. All other ICNS elements and all
non-IDAT PNG chunks remain byte-identical. No pixels, profiles or resolutions
are removed. Use only in an exclusively owned, serial release staging tree.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import sys
import zlib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMP_STAGE_PARENT = Path('/private/tmp')
ICON_SUFFIX = Path('MacCrab.app/Contents/Resources/AppIcon.icns')
ORIGINAL_SHA256 = 'ff369902730ec16f2464160b814cd9807fde38be4612e510457c4d9fa89398c0'
COMPACT_SHA256 = 'bf6efb327d49ddc768c2134b8f93f109b3a957faa06b5abb5fc4d30335b8becf'
FILTERED_SHA256 = '7e697ced074fe0cbb7bec94ec45edb1cbea9393a944bd7529b9249bd03b1dbea'
NON_IDAT_SHA256 = '3acc6cb75916a698cd83e61714de07f45354c3b949016256a5dd25478318be91'
ORIGINAL_BYTES, COMPACT_BYTES = 1024144, 886141
MAX_ICON_BYTES, FILTERED_BYTES, MAX_PNG_CHUNKS = 2 * 1024 * 1024, 4195328, 64
ELEMENTS = (b'ic12', b'ic07', b'ic13', b'ic08', b'ic14', b'ic09', b'ic05', b'ic10', b'ic11', b'info')
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def icns_elements(data):
    require(8 <= len(data) <= MAX_ICON_BYTES and data[:4] == b'icns', 'invalid ICNS envelope')
    require(struct.unpack('>I', data[4:8])[0] == len(data), 'ICNS length mismatch')
    offset, elements = 8, []
    while offset < len(data):
        require(len(elements) < len(ELEMENTS) and len(data) - offset >= 8, 'ICNS element bound')
        kind, size = data[offset:offset + 4], struct.unpack('>I', data[offset + 4:offset + 8])[0]
        require(kind != b'TOC ', 'ICNS table of contents is unsupported')
        require(8 <= size <= len(data) - offset, 'invalid ICNS element length')
        elements.append((kind, data[offset:offset + size]))
        offset += size
    require(tuple(kind for kind, _ in elements) == ELEMENTS, 'ICNS element inventory changed')
    return elements


def png_chunks(data):
    require(data.startswith(PNG_SIGNATURE), 'ic10 is not PNG')
    offset, chunks = 8, []
    while offset < len(data):
        require(len(chunks) < MAX_PNG_CHUNKS and len(data) - offset >= 12, 'PNG chunk bound')
        size = struct.unpack('>I', data[offset:offset + 4])[0]
        require(size <= MAX_ICON_BYTES and size + 12 <= len(data) - offset, 'invalid PNG chunk length')
        kind = data[offset + 4:offset + 8]
        chunk = data[offset:offset + size + 12]
        require(zlib.crc32(chunk[4:-4]) & 0xffffffff == struct.unpack('>I', chunk[-4:])[0], 'PNG CRC mismatch')
        chunks.append((kind, chunk))
        offset += size + 12
    kinds = tuple(kind for kind, _ in chunks)
    require(len(kinds) >= 6 and kinds[:4] == (b'IHDR', b'iCCP', b'cICP', b'eXIf')
            and kinds[-1] == b'IEND' and all(kind == b'IDAT' for kind in kinds[4:-1]),
            'PNG chunk order or inventory changed')
    require(chunks[0][1][8:-4] == struct.pack('>IIBBBBB', 1024, 1024, 8, 6, 0, 0, 0)
            and chunks[-1][1][8:-4] == b'', 'PNG shape changed')
    require(sha256(b''.join(chunk for kind, chunk in chunks if kind != b'IDAT')) == NON_IDAT_SHA256,
            'PNG metadata changed')
    return chunks


def inflate(stream):
    require(0 < len(stream) <= MAX_ICON_BYTES, 'PNG compressed stream bound')
    decoder = zlib.decompressobj()
    try:
        filtered = decoder.decompress(stream, FILTERED_BYTES + 1)
    except zlib.error as error:
        raise ValueError('invalid PNG compression') from error
    require(len(filtered) == FILTERED_BYTES and decoder.eof and not decoder.unused_data
            and not decoder.unconsumed_tail, 'PNG inflated stream bound or trailing bytes')
    require(sha256(filtered) == FILTERED_SHA256, 'PNG filtered image bytes changed')
    return filtered


def prepare(data):
    """Pure, bounded proposal. Never writes files or invokes native image APIs."""
    digest = sha256(data)
    require((len(data), digest) in ((ORIGINAL_BYTES, ORIGINAL_SHA256), (COMPACT_BYTES, COMPACT_SHA256)),
            'icon is not an approved byte-pinned input')
    elements = icns_elements(data)
    original_png = dict(elements)[b'ic10'][8:]
    chunks = png_chunks(original_png)
    filtered = inflate(b''.join(chunk[8:-4] for kind, chunk in chunks if kind == b'IDAT'))
    compressed = zlib.compress(filtered, level=9)
    require(inflate(compressed) == filtered, 'compression changed filtered image data')
    idat = (struct.pack('>I', len(compressed)) + b'IDAT' + compressed
            + struct.pack('>I', zlib.crc32(b'IDAT' + compressed) & 0xffffffff))
    compact_png = PNG_SIGNATURE + b''.join(chunk for _, chunk in chunks[:4]) + idat + chunks[-1][1]
    compact_element = b'ic10' + struct.pack('>I', len(compact_png) + 8) + compact_png
    body = b''.join(compact_element if kind == b'ic10' else element for kind, element in elements)
    compact = b'icns' + struct.pack('>I', len(body) + 8) + body
    require((len(compact), sha256(compact)) == (COMPACT_BYTES, COMPACT_SHA256),
            'compressor did not produce the approved deterministic output')
    compact_elements = icns_elements(compact)
    require(all(old == new for old, new in zip(elements, compact_elements) if old[0] != b'ic10'),
            'non-target ICNS elements changed')
    compact_chunks = png_chunks(compact_png)
    require([chunk for kind, chunk in chunks if kind != b'IDAT'] ==
            [chunk for kind, chunk in compact_chunks if kind != b'IDAT'], 'non-IDAT chunks changed')
    require(len(compact) < len(data) or compact == data, 'icon did not shrink')
    return compact


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def stage_icon(staging_dir, icon):
    stage, icon = Path(staging_dir), Path(icon)
    single = PROJECT_ROOT / '.build/maccrab-stage'
    all_stages = stage.parent == TEMP_STAGE_PARENT and re.fullmatch(r'maccrab-release-[1-9][0-9]*', stage.name)
    require(stage.is_absolute() and '..' not in stage.parts and (stage == single or all_stages),
            'not a supported release staging directory')
    require(icon == stage / ICON_SUFFIX, 'icon is not the exact staged app icon')
    return stage, icon


def open_resources(stage, icon):
    """Pin each path component without following links; stage subtree is owned."""
    descriptor = os.open('/', DIRECTORY_FLAGS)
    current = Path('/')
    try:
        for component in icon.parent.parts[1:]:
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= component
            if current == stage or stage in current.parents:
                info = os.fstat(descriptor)
                require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0,
                        'staging directory is not exclusively owned')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_icon(directory, filename='AppIcon.icns'):
    require(filename == 'AppIcon.icns' or re.fullmatch(r'\.maccrab-icon-[0-9a-f]{32}', filename),
            'unexpected icon entry name')
    descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) & 0o022 == 0, 'icon is not an owned single-link regular file')
        require(0 < before.st_size <= MAX_ICON_BYTES, 'icon input bound')
        chunks, remaining = [], MAX_ICON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        require(len(data) == before.st_size and file_identity(os.fstat(descriptor)) == file_identity(before),
                'icon changed while reading')
        return before, data
    finally:
        os.close(descriptor)


def verify_binding(stage, icon, directory):
    check = open_resources(stage, icon)
    try:
        current, pinned = os.fstat(check), os.fstat(directory)
        require((current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino), 'staged directory binding changed')
    finally:
        os.close(check)


def optimize(staging_dir, icon):
    stage, icon = stage_icon(staging_dir, icon)
    directory = open_resources(stage, icon)
    temporary, temporary_identity = None, None
    try:
        before, original = read_icon(directory)
        compact = prepare(original)
        verify_binding(stage, icon, directory)
        if compact != original:
            temporary = '.maccrab-icon-' + secrets.token_hex(16)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            temporary_identity = os.fstat(descriptor)
            with os.fdopen(descriptor, 'wb') as output:
                require(temporary_identity.st_gid == before.st_gid, 'temporary icon group differs')
                output.write(compact)
                output.flush()
                os.fchmod(output.fileno(), stat.S_IMODE(before.st_mode))
                os.fsync(output.fileno())
                require(os.fstat(output.fileno()).st_blocks < before.st_blocks, 'allocated icon footprint did not shrink')
            verify_binding(stage, icon, directory)
            current, current_bytes = read_icon(directory)
            require(file_identity(current) == file_identity(before) and current_bytes == original,
                    'icon changed before replacement')
            named_temp, temp_bytes = read_icon(directory, temporary)
            require((named_temp.st_dev, named_temp.st_ino) ==
                    (temporary_identity.st_dev, temporary_identity.st_ino)
                    and named_temp.st_gid == before.st_gid
                    and stat.S_IMODE(named_temp.st_mode) == stat.S_IMODE(before.st_mode)
                    and temp_bytes == compact, 'private temporary icon changed before replacement')
            os.replace(temporary, 'AppIcon.icns', src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
        verify_binding(stage, icon, directory)
        after, readback = read_icon(directory)
        require(readback == compact and after.st_gid == before.st_gid
                and stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode),
                'icon replacement readback differs')
        require(after.st_blocks <= before.st_blocks, 'allocated icon footprint increased')
        return {'changed': compact != original, 'before_bytes': len(original), 'after_bytes': len(compact),
                'before_sha256': sha256(original), 'after_sha256': sha256(compact),
                'saved_allocated_kib': (before.st_blocks - after.st_blocks) // 2,
                'filtered_sha256': FILTERED_SHA256, 'non_idat_sha256': NON_IDAT_SHA256}
    finally:
        original_error = sys.exc_info()[1]
        try:
            if temporary is not None:
                current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                require((current.st_dev, current.st_ino) == (temporary_identity.st_dev, temporary_identity.st_ino),
                        'private temporary icon changed')
                os.unlink(temporary, dir_fd=directory)
        except BaseException as cleanup_error:
            if original_error is not None:
                raise original_error from cleanup_error
            raise
        finally:
            os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging-dir', required=True)
    parser.add_argument('--icon', required=True)
    args = parser.parse_args()
    try:
        result = optimize(args.staging_dir, args.icon)
    except (OSError, ValueError, zlib.error):
        parser.exit(1, 'ERROR: staged icon validation/compression failed\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
