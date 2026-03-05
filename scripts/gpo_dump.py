# Script to dump GPO information
# author: @oddvarmoe

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adexpsnapshot import ADExplorerSnapshot
from rich.progress import track
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timezone
from certipy.lib.security import CertificateSecurity
from security_aces import security_to_bloodhound_aces
from pathlib import Path
import argparse
import os
import logging

def valid_directory(path):
    """Check if the provided path is a valid directory or create it if it does not exist."""
    path = Path(path) 
    if not path.exists():
        # Attempt to create the directory
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # If creation fails, raise an argparse error
            raise argparse.ArgumentTypeError(f"Could not create directory: {path}. {str(e)}")
    elif not path.is_dir():
        # If the path exists but is not a directory, raise an error
        raise argparse.ArgumentTypeError(f"The path {path} exists but is not a directory.")
    return path

parser = argparse.ArgumentParser(add_help=True, description="Script to dump interesting stuff from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_folder", required=True, type=valid_directory, help="Folder to save output to")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

# Out streams
out_gpo = []

for idx, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    if 'grouppolicycontainer' in obj.classes:
        name = ADUtils.get_entry_property(obj, 'name')
        displayname = ADUtils.get_entry_property(obj, 'displayname')
        gpcfilesyspath = ADUtils.get_entry_property(obj, 'gpcfilesyspath')
        flags = ADUtils.get_entry_property(obj, 'flags')
        if flags == 0:
            flags = str(flags) + " (GPO is enabled)"
        elif flags == 1:
            flags = str(flags) + " (User part of GPO is disabled)"
        elif flags == 2:
            flags = str(flags) + " (Computer part of GPO is disabled)"
        elif flags == 3:
            flags = str(flags) + " (GPO is disabled)"
        gpcmachineextensionnames = ADUtils.get_entry_property(obj, 'gpcmachineextensionnames')
        versionnumber = ADUtils.get_entry_property(obj, 'versionnumber')
        # Extract user and computer versions
        user_version = versionnumber >> 16
        computer_version = versionnumber & 0xFFFF

        # Convert to human readable timestamp
        whenchanged = datetime.fromtimestamp(ADUtils.get_entry_property(obj, 'whenchanged'), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        whencreated = datetime.fromtimestamp(ADUtils.get_entry_property(obj, 'whencreated'), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        security = CertificateSecurity(ADUtils.get_entry_property(obj, "nTSecurityDescriptor", raw=True))

        aces = security_to_bloodhound_aces(security, ades)

        out_gpo.append(f"-----------------------------------------")
        out_gpo.append(f"Displayname: {displayname}")
        out_gpo.append(f"Name: {name}")
        out_gpo.append(f"gPCFileSysPath: {gpcfilesyspath}")
        out_gpo.append(f"Flags: {flags}")
        out_gpo.append(f"gPCMachineExtensionNames: {gpcmachineextensionnames}")
        out_gpo.append(f"versionNumber: {versionnumber} (UserVersion: {user_version} / ComputerVersion: {computer_version})")
        out_gpo.append(f"whenChanged: {whenchanged}")
        out_gpo.append(f"whenCreated: {whencreated}")
        out_gpo.append(f"Aces:")
        for ace in aces:
            out_gpo.append(f"{ace}")

if args.output_folder:
    if out_gpo:
        with open(Path(args.output_folder / "gpo.txt"), "w", encoding="utf-8") as outFile_gpo:
            outFile_gpo.write(os.linesep.join(map(str, out_gpo)))

    logging.info(f"Output written to files in {args.output_folder}")
