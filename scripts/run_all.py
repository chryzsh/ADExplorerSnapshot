#!/usr/bin/env python3
# Run all dump scripts against a snapshot and save output to a structured folder
# Output structure:
#   <output_dir>/
#     subnets.txt
#     dns.txt
#     dfs.txt
#     phonenumbers.txt
#     attributes/
#       objs.txt
#     certs/
#       certs.txt
#     gpo/
#       gpo.txt
#     interesting/
#       computers.txt, users.txt, groups.txt, ...

import argparse
import subprocess
import sys
import os

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

SCRIPTS = [
    {
        "name": "subnets",
        "script": "subnets_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "subnets.txt")],
        "deps": [],
    },
    {
        "name": "dns (adidns)",
        "script": "adidns_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "dns.txt")],
        "deps": ["adidnsdump"],
    },
    {
        "name": "dfs",
        "script": "dfs_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "dfs.txt")],
        "deps": [],
    },
    {
        "name": "phone numbers",
        "script": "telephonenumbers_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "phonenumbers.txt")],
        "deps": [],
    },
    {
        "name": "certificates",
        "script": "cert_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "certs")],
        "deps": ["certipy"],
    },
    {
        "name": "GPOs",
        "script": "gpo_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "gpo")],
        "deps": ["certipy"],
    },
    {
        "name": "interesting data",
        "script": "interestingdata_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "interesting")],
        "deps": [],
    },
]

def check_dep(module_name):
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Run all ADExplorerSnapshot dump scripts and save output to a structured folder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("snapshot", help="Path to the snapshot .dat file")
    parser.add_argument("-o", "--output", default="snapshot_dump", help="Output directory (default: snapshot_dump)")
    args = parser.parse_args()

    snapshot = os.path.abspath(args.snapshot)
    outdir = os.path.abspath(args.output)

    if not os.path.isfile(snapshot):
        print(f"[-] Snapshot file not found: {snapshot}")
        sys.exit(1)

    os.makedirs(outdir, exist_ok=True)
    print(f"[*] Output directory: {outdir}")
    print(f"[*] Snapshot: {snapshot}")
    print()

    passed = 0
    failed = 0
    skipped = 0

    for entry in SCRIPTS:
        name = entry["name"]
        script = os.path.join(SCRIPTS_DIR, entry["script"])
        script_args = entry["args"](snapshot, outdir)

        # check optional dependencies
        missing = [d for d in entry["deps"] if not check_dep(d)]
        if missing:
            print(f"[!] Skipping {name} (missing: {', '.join(missing)})")
            skipped += 1
            continue

        print(f"[*] Running {name}...")
        try:
            result = subprocess.run(
                [sys.executable, script] + script_args,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print(f"[-] {name} failed:")
                # show last few lines of stderr to keep it readable
                for line in result.stderr.strip().splitlines()[-5:]:
                    print(f"    {line}")
                failed += 1
            else:
                print(f"[+] {name} done")
                passed += 1
        except Exception as e:
            print(f"[-] {name} error: {e}")
            failed += 1

    print()
    print(f"[*] Complete: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"[*] Results in: {outdir}")

if __name__ == "__main__":
    main()
