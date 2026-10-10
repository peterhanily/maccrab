#!/usr/bin/python3
"""Bounded OTLP smoke test with exact-ID, read-only persistence verification.

--receiver-only is acceptance only. --secret-test requires readable plaintext
attributes or fails closed: ciphertext is not evidence of successful redaction.
No stored attribute value or unrelated span is ever printed.
"""
import argparse
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time

CONNECT_SECONDS = 2
HTTP_SECONDS = 5
VERIFY_SECONDS = 5
SECRET_BY_KEY = 'sk-ant-' + 'A' * 25
SECRET_BY_VALUE = 'sk-ant-SYNTHETIC-' + 'B' * 25
SPAN_NAME = 'claude_code.tool.execution'
SERVICE_NAME = 'claude-code'


def valid_id(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value) and int(value, 16) != 0


def varint(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number, value):
    return varint(number << 3 | 2) + varint(len(value)) + value


def text(number, value):
    return field(number, value.encode('utf-8'))


def attribute(key, value):
    return text(1, key) + field(2, text(1, value))


def payload(trace_id, span_id, secret_test=False):
    if not valid_id(trace_id, 32) or not valid_id(span_id, 16):
        raise ValueError('invalid synthetic span identity')
    now = time.time_ns()
    attributes = [('tool_name', 'Bash'), ('full_command', 'echo curl-smoke-test'),
                  ('duration_ms', '42'), ('gen_ai.system', 'anthropic'),
                  ('gen_ai.request.model', 'claude-3.5-sonnet')]
    if secret_test:
        attributes += [('api_key', SECRET_BY_KEY), ('user_note', 'leaked ' + SECRET_BY_VALUE + ' into a comment')]
    span = field(1, bytes.fromhex(trace_id)) + field(2, bytes.fromhex(span_id))
    span += field(4, bytes.fromhex('fedcba9876543210')) + text(5, SPAN_NAME)
    span += varint(7 << 3 | 1) + struct.pack('<Q', now - 1_000_000_000)
    span += varint(8 << 3 | 1) + struct.pack('<Q', now)
    span += b''.join(field(9, attribute(k, v)) for k, v in attributes)
    scope = field(1, text(1, 'claude_code.otel')) + field(2, span)
    resource = field(1, attribute('service.name', SERVICE_NAME))
    return field(1, field(1, resource) + field(2, scope))


def post(port, body):
    command = ['/usr/bin/curl', '--disable', '--silent', '--show-error', '--noproxy', '*',
               '--connect-timeout', str(CONNECT_SECONDS), '--max-time', str(HTTP_SECONDS),
               '--proto', '=http', '--output', '/dev/null', '--write-out', '%{http_code}',
               '--request', 'POST', '--header', 'Content-Type: application/x-protobuf',
               '--data-binary', '@-', 'http://127.0.0.1:%d/v1/traces' % port]
    result = subprocess.run(command, input=body, capture_output=True,
                            timeout=HTTP_SECONDS + 2, check=False)
    code = result.stdout.decode('ascii', errors='strict')
    if result.returncode != 0 or not re.fullmatch('[1-5][0-9]{2}', code):
        raise ValueError('bounded loopback request failed; no acceptance proven')
    return int(code)


def exact_row(database, trace_id, span_id, include_attributes=False, *, deadline=None):
    """One bound SELECT via SQLite READONLY|NOFOLLOW, retaining live WAL visibility."""
    if not valid_id(trace_id, 32) or not valid_id(span_id, 16):
        raise ValueError('invalid exact span identity')
    if deadline is None:
        deadline = time.monotonic() + VERIFY_SECONDS
    if time.monotonic() >= deadline:
        raise ValueError('exact trace verification deadline exceeded')
    database = Path(database)
    if database.resolve(strict=True) != database:
        raise ValueError('trace database path is redirected')
    library_path = ctypes.util.find_library('sqlite3')
    if not library_path:
        raise ValueError('system SQLite library unavailable')
    sql = ctypes.CDLL(library_path)
    signatures = {
        'sqlite3_open_v2': ([ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_char_p], ctypes.c_int),
        'sqlite3_close_v2': ([ctypes.c_void_p], ctypes.c_int),
        'sqlite3_prepare_v2': ([ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p], ctypes.c_int),
        'sqlite3_bind_text': ([ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p], ctypes.c_int),
        'sqlite3_step': ([ctypes.c_void_p], ctypes.c_int),
        'sqlite3_column_text': ([ctypes.c_void_p, ctypes.c_int], ctypes.c_void_p),
        'sqlite3_column_bytes': ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        'sqlite3_column_type': ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        'sqlite3_finalize': ([ctypes.c_void_p], ctypes.c_int),
        'sqlite3_busy_timeout': ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        getattr(sql, name).argtypes, getattr(sql, name).restype = arguments, result
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)
    sql.sqlite3_progress_handler.argtypes = [ctypes.c_void_p, ctypes.c_int, callback_type, ctypes.c_void_p]
    sql.sqlite3_progress_handler.restype = None
    progress = callback_type(lambda _: int(time.monotonic() >= deadline))
    handle, statement = ctypes.c_void_p(), ctypes.c_void_p()
    descriptor = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('trace database is not regular')
        if sql.sqlite3_open_v2(os.fsencode(database), ctypes.byref(handle), 0x1 | 0x01000000, None):
            raise ValueError('read-only no-follow trace database open failed')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('exact trace verification deadline exceeded')
        sql.sqlite3_busy_timeout(handle, min(100, max(1, int(remaining * 1000))))
        sql.sqlite3_progress_handler(handle, 1000, progress, None)
        columns = b'trace_id,span_id,span_name,service_name'
        if include_attributes:
            columns += b',attributes_json'
        query = b'SELECT ' + columns + b' FROM spans WHERE trace_id=?1 AND span_id=?2 LIMIT 2'
        if sql.sqlite3_prepare_v2(handle, query, -1, ctypes.byref(statement), None):
            raise ValueError('exact trace query could not be prepared')
        for index, value in enumerate((trace_id, span_id), 1):
            encoded = value.encode('ascii')
            if sql.sqlite3_bind_text(statement, index, encoded, len(encoded), ctypes.c_void_p(-1)):
                raise ValueError('exact trace query binding failed')
        rows = []
        while True:
            code = sql.sqlite3_step(statement)
            if code == 101:
                break
            if code != 100:
                raise ValueError('exact trace query failed')
            row = []
            for column in range(5 if include_attributes else 4):
                if sql.sqlite3_column_type(statement, column) == 5:
                    row.append(None)
                    continue
                pointer = sql.sqlite3_column_text(statement, column)
                count = sql.sqlite3_column_bytes(statement, column)
                if count < 0 or count > 65536 or (count and not pointer):
                    raise ValueError('exact trace field exceeds verification bound')
                row.append(ctypes.string_at(pointer, count).decode('utf-8'))
            rows.append(row)
        after = os.lstat(database)
        if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('trace database identity changed during query')
        if len(rows) > 1:
            raise ValueError('exact trace identity is not unique')
        if time.monotonic() >= deadline:
            raise ValueError('exact trace verification deadline exceeded')
        evidence = {'path': str(database), 'owner_uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode),
                    'device': info.st_dev, 'inode': info.st_ino, 'read_only': True, 'no_follow': True}
        return (rows[0] if rows else None), evidence
    finally:
        if statement.value:
            sql.sqlite3_finalize(statement)
        if handle.value:
            sql.sqlite3_close_v2(handle)
        os.close(descriptor)


def verify_row(row, trace_id, span_id, secret_test=False):
    if row is None:
        return False
    if len(row) != (5 if secret_test else 4) or row[:4] != [trace_id, span_id, SPAN_NAME, SERVICE_NAME]:
        raise ValueError('persisted synthetic span identity/content mismatch')
    if secret_test:
        try:
            attributes = json.loads(row[4])
        except (ValueError, TypeError):
            raise ValueError('sanitizer unverified: attributes encrypted or malformed; approved decrypted verification required')
        if not isinstance(attributes, dict) or attributes.get('api_key') != '[REDACTED]' \
                or attributes.get('user_note') != 'leaked [ANTHROPIC_KEY] into a comment' \
                or attributes.get('full_command') != 'echo curl-smoke-test':
            raise ValueError('synthetic sanitizer assertions failed')
        if SECRET_BY_KEY in row[4] or SECRET_BY_VALUE in row[4]:
            raise ValueError('synthetic secret persisted without redaction')
    return True


def verify(database, trace_id, span_id, secret_test=False):
    deadline = time.monotonic() + VERIFY_SECONDS
    while True:
        row, evidence = exact_row(database, trace_id, span_id, secret_test, deadline=deadline)
        if verify_row(row, trace_id, span_id, secret_test):
            return {'trace_id': trace_id, 'span_id': span_id, 'matched_rows': 1,
                    'persistence_proven': True, 'sanitizer_verified': secret_test,
                    'database': evidence}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('exact synthetic span did not persist before verification deadline')
        time.sleep(min(.1, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=4318)
    parser.add_argument('--secret-test', action='store_true')
    parser.add_argument('--receiver-only', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--trace-id')
    parser.add_argument('--span-id')
    parser.add_argument('--database', type=Path)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('port must be in 1..65535')
    if args.receiver_only and (args.secret_test or args.verify_only):
        parser.error('acceptance-only mode cannot claim sanitizer or persistence verification')
    if args.verify_only != (args.trace_id is not None and args.span_id is not None) \
            or (not args.verify_only and (args.trace_id is not None or args.span_id is not None)):
        parser.error('exact trace/span IDs are required only with --verify-only')
    trace_id, span_id = (args.trace_id, args.span_id) if args.verify_only else (os.urandom(16).hex(), os.urandom(8).hex())
    if not args.verify_only:
        post(args.port, b'')
        print('OTLP_IDENTITY: trace_id=%s span_id=%s secret_test=%d' % (trace_id, span_id, args.secret_test), flush=True)
        if post(args.port, payload(trace_id, span_id, args.secret_test)) != 200:
            raise ValueError('receiver did not accept the synthetic span')
        print('OTLP_ACCEPTED: trace_id=%s span_id=%s persistence_proven=false' % (trace_id, span_id), flush=True)
    if args.receiver_only:
        return
    database = args.database
    if database is None:
        choices = [Path('/Library/Application Support/MacCrab/traces.db'),
                   Path.home() / 'Library/Application Support/MacCrab/traces.db']
        database = next((path for path in choices if path.exists()), None)
    if database is None:
        raise ValueError('trace database unavailable; acceptance is not persistence')
    print(json.dumps(verify(database, trace_id, span_id, args.secret_test), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('OTLP verification failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
