#!/usr/bin/env python3
"""
exciftool.py - small wrapper around exiftool for CTF-TOOLS

Usage:
  python exciftool.py FILE_OR_DIR [--recursive] [--output OUTFILE] [--raw-args "-Tags -to -pass"]

What it does:
 - Verifies exiftool is installed (https://exiftool.org/).
 - Runs exiftool with sane defaults (-j for JSON output) and prints pretty JSON.
 - Can process a single file or a directory (optionally recursive).
 - Writes output to stdout or to an output file.

This is intended for use in CTF workflows where quickly extracting metadata in JSON
is helpful for automated tooling.
"""

from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

__version__ = "0.1"


def find_exiftool() -> str | None:
    """Return the path to exiftool executable or None if not found."""
    for name in ("exiftool",):
        path = shutil.which(name)
        if path:
            return path
    return None


def run_exiftool(exe: str, paths: list[str], recursive: bool, raw_args: list[str]) -> list:
    """Run exiftool and return parsed JSON output (list of dicts).

    exiftool supports printing JSON with -j flag. We pass any raw args the user
    provided after constructing the base command.
    """
    cmd = [exe, "-j"]
    if recursive:
        cmd.append("-r")
    # add any additional user-supplied args
    cmd.extend(raw_args)
    # Add paths
    cmd.extend(paths)

    try:
        proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("exiftool returned non-zero exit code.", file=sys.stderr)
        if e.stderr:
            sys.stderr.write(e.stderr.decode(errors="replace"))
        raise

    out = proc.stdout.decode(errors="replace").strip()
    if not out:
        return []

    # exiftool -j outputs JSON array(s). There may be multiple JSON objects.
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        # fall back: try to parse line-delimited JSON entries
        items = []
        for line in out.splitlines():
            try:
                items.append(json.loads(line))
            except Exception:
                # If we can't parse, include the raw text as an entry
                items.append({"_raw": line})
        return items
    return data


def write_output(data: list, outpath: Path | None) -> None:
    pretty = json.dumps(data, indent=2, ensure_ascii=False)
    if outpath:
        outpath.write_text(pretty, encoding="utf-8")
        print(f"Wrote metadata to {outpath}")
    else:
        print(pretty)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="exciftool - simple exiftool wrapper returning JSON")
    p.add_argument("paths", nargs="+", help="File(s) or directory(ies) to analyze")
    p.add_argument("-r", "--recursive", action="store_true", help="If a path is a directory, recurse into it (passes -r to exiftool)")
    p.add_argument("-o", "--output", help="Write output JSON to this file (default: stdout)")
    p.add_argument("--raw-args", default="", help="Additional arguments to pass to exiftool (quoted string). Example: \"-G -a\"")
    p.add_argument("--version", action="store_true", help="Show version and exit")
    return p.parse_args()


def normalize_paths(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if p == "-":
            out.append("-")
            continue
        pp = Path(p)
        if not pp.exists():
            print(f"Warning: path does not exist: {p}", file=sys.stderr)
        out.append(str(pp))
    return out


def main() -> int:
    args = parse_args()
    if args.version:
        print(f"exciftool version {__version__}")
        return 0

    exe = find_exiftool()
    if not exe:
        print("exiftool binary not found. Please install exiftool (https://exiftool.org/).", file=sys.stderr)
        return 2

    raw_args = []
    if args.raw_args:
        # naive split; users should quote carefully
        raw_args = args.raw_args.split()

    paths = normalize_paths(args.paths)

    try:
        data = run_exiftool(exe, paths, args.recursive, raw_args)
    except subprocess.CalledProcessError:
        return 3

    outpath = Path(args.output) if args.output else None
    write_output(data, outpath)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
