#!/usr/bin/python3
"""Run one CI phase with a deadline and retained log/result, including on failure."""

import argparse
import datetime
import json
import math
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def positive_seconds(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("deadline must be finite and positive")
    return result


def run_phase(args):
    started = time.monotonic()
    record = {
        "schema_version": 1,
        "phase": args.label,
        "started_at": utc_now(),
        "timeout_seconds": args.timeout_seconds,
        "grace_seconds": args.grace_seconds,
        "log": str(Path(args.log).resolve()),
        "status": "RUNNING",
    }
    result_path = Path(args.result)

    def save():
        temporary = result_path.with_suffix(result_path.suffix + ".tmp")
        temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        temporary.replace(result_path)

    save()  # A killed runner leaves an explicit RUNNING record, never a pass.
    process = None
    interrupted = None

    def interrupt(signum, _frame):
        nonlocal interrupted
        interrupted = signum

    previous = {sig: signal.signal(sig, interrupt)
                for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}

    def stop_group():
        # The phase owns a new session. Terminate descendants even if the
        # immediate process exits first (e.g. a shell waiting for a compiler).
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        until = time.monotonic() + args.grace_seconds
        while time.monotonic() < until:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(min(0.1, max(0, until - time.monotonic())))
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

    try:
        with open(args.log, "wb") as output:
            try:
                process = subprocess.Popen(args.command, stdout=output,
                                           stderr=subprocess.STDOUT,
                                           start_new_session=True)
            except OSError as error:
                output.write(("Unable to start phase: " + str(error) + "\n").encode())
                record.update(status="FAILED", exit_code=127)
            else:
                deadline = started + args.timeout_seconds
                while process.poll() is None and interrupted is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        process.wait(timeout=min(0.2, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                if interrupted is not None:
                    stop_group()
                    record.update(status="INTERRUPTED", exit_code=128 + interrupted,
                                  signal=interrupted)
                elif process.poll() is None:
                    stop_group()
                    output.write(b"\nCI phase exceeded its deadline; process group terminated.\n")
                    record.update(status="TIMED_OUT", exit_code=124)
                else:
                    code = process.returncode
                    record.update(status="PASSED" if code == 0 else "FAILED",
                                  exit_code=code if code >= 0 else 128 - code)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        record.update(completed_at=utc_now(),
                      elapsed_seconds=round(time.monotonic() - started, 6))
        save()
    return record["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--timeout-seconds", type=positive_seconds, default=1800)
    parser.add_argument("--grace-seconds", type=positive_seconds, default=15)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a phase command is required")
    return run_phase(args)


if __name__ == "__main__":
    sys.exit(main())
