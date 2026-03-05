"""Small helpers for standalone dump scripts."""

import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def convert_ad_timestamp(timestamp):
    """Convert AD filetime timestamp to UTC datetime."""
    if timestamp in (None, 0):
        return None
    base_date = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return base_date + timedelta(microseconds=timestamp / 10)


def fmt_datetime(value):
    return value.isoformat() if value else ""


def write_rows(rows, output_file=None, sort_rows=False):
    if not rows:
        return

    if sort_rows and len(rows) > 1:
        header = rows[0]
        data = sorted(rows[1:])
        rows = [header] + data

    if output_file:
        with open(output_file, "w", encoding="utf-8") as out_file:
            out_file.write(os.linesep.join(rows))
        print(f"[+] Output written to {output_file}")
    else:
        for line in rows:
            print(line)


def valid_directory(path):
    """Return a writable directory path, creating it if needed."""
    resolved = Path(path)
    if not resolved.exists():
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise argparse.ArgumentTypeError(f"Could not create directory: {resolved}. {exc}")
    elif not resolved.is_dir():
        raise argparse.ArgumentTypeError(f"The path {resolved} exists but is not a directory.")
    return resolved
