#!/usr/bin/env python3
# Run all dump scripts against a snapshot and save output to a structured folder
# Output structure:
#   <output_dir>/
#     subnets.txt
#     dns.txt
#     dfs.txt
#     phonenumbers.txt
#     delegation.txt
#     dcsync_rights.txt
#     gmsa.txt
#     shadowcred.txt
#     laps_extended.txt
#     tier0_membership.txt
#     stale_risky.txt
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
        "name": "delegation",
        "script": "delegation_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "delegation.txt")],
        "deps": ["certipy"],
    },
    {
        "name": "dcsync rights",
        "script": "dcsync_rights_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "dcsync_rights.txt")],
        "deps": ["certipy"],
    },
    {
        "name": "gmsa",
        "script": "gmsa_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "gmsa.txt")],
        "deps": ["certipy"],
    },
    {
        "name": "shadow credentials",
        "script": "shadowcred_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "shadowcred.txt")],
        "deps": [],
    },
    {
        "name": "laps (legacy + windows)",
        "script": "laps_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "laps_extended.txt")],
        "deps": [],
    },
    {
        "name": "tier0 membership",
        "script": "tier0_membership_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "tier0_membership.txt")],
        "deps": [],
    },
    {
        "name": "stale and risky objects",
        "script": "stale_and_risky_objects_dump.py",
        "args": lambda snap, outdir: [snap, "-o", os.path.join(outdir, "stale_risky.txt")],
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
    parser.add_argument(
        "--html-report",
        nargs="?",
        const="report.html",
        default=None,
        help="Generate static HTML report after all scripts. Optional output path (default: <output>/report.html).",
    )
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
                stderr=subprocess.PIPE,
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
        except OSError as e:
            print(f"[-] {name} error: {e}")
            failed += 1

    print()
    print(f"[*] Complete: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"[*] Results in: {outdir}")

    if args.html_report:
        report_script = os.path.join(SCRIPTS_DIR, "html_report.py")
        report_path = args.html_report
        if args.html_report == "report.html":
            report_path = os.path.join(outdir, "report.html")
        elif not os.path.isabs(report_path):
            report_path = os.path.abspath(report_path)

        print(f"[*] Generating HTML report: {report_path}")
        result = subprocess.run(
            [sys.executable, report_script, outdir, "-o", report_path],
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            print("[-] HTML report generation failed:")
            for line in result.stderr.strip().splitlines()[-5:]:
                print(f"    {line}")
        else:
            print(f"[+] HTML report written: {report_path}")

if __name__ == "__main__":
    main()
