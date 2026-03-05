# Script to dump gMSA/sMSA data

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from rich.progress import track

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import ensure_list, write_rows
from security_aces import extract_security_sids, resolve_principal

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to extract gMSA/sMSA accounts and managed password readers from an AD Explorer snapshot",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

rows = [
    "account_type||samaccountname||distinguishedname||objectsid||serviceprincipalnames||password_reader_sids||password_readers||managedpasswordid_present"
]

for _, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    classes = {str(c).lower() for c in obj.classes}
    is_gmsa = "msds-groupmanagedserviceaccount" in classes
    is_smsa = "msds-managedserviceaccount" in classes
    if not is_gmsa and not is_smsa:
        continue

    account_type = "gMSA" if is_gmsa else "sMSA"
    samaccountname = ADUtils.get_entry_property(obj, "samaccountname", "") or ""
    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""
    object_sid = ADUtils.get_entry_property(obj, "objectsid", "") or ""
    serviceprincipalnames = ";".join(str(x) for x in ensure_list(ADUtils.get_entry_property(obj, "serviceprincipalname", default=[])))
    managed_password_id_present = bool(ADUtils.get_entry_property(obj, "msDS-ManagedPasswordId", raw=True))

    readers_raw = ADUtils.get_entry_property(obj, "msDS-GroupMSAMembership", raw=True)
    reader_sids = extract_security_sids(readers_raw)
    resolved_readers = []
    for sid in reader_sids:
        principal_sid, principal_name, principal_type, _ = resolve_principal(ades, sid)
        resolved_readers.append(f"{principal_name} ({principal_type}) [{principal_sid}]")

    rows.append(
        f"{account_type}||{samaccountname}||{distinguished_name}||{object_sid}||{serviceprincipalnames}||{';'.join(reader_sids)}||{';'.join(sorted(resolved_readers))}||{managed_password_id_present}"
    )

write_rows(rows, args.output_file, sort_rows=True)
