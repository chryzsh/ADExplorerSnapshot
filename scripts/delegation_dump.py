# Script to dump delegation-relevant settings

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from rich.progress import track

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import ensure_list, write_rows
from security_aces import extract_security_sids, resolve_principal

UAC_TRUSTED_FOR_DELEGATION = 0x80000

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to extract unconstrained/constrained delegation and RBCD data from an AD Explorer snapshot",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

rows = [
    "delegation_type||object_type||samaccountname||dnshostname||distinguishedname||objectsid||detail||principal_sid||principal_name||principal_type||principal_dn"
]

for _, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    resolved = ADUtils.resolve_ad_entry(obj)
    obj_type = resolved.get("type", "")

    samaccountname = ADUtils.get_entry_property(obj, "samaccountname", "") or ""
    dnshostname = ADUtils.get_entry_property(obj, "dnshostname", "") or ""
    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""
    object_sid = ADUtils.get_entry_property(obj, "objectsid", "") or ""
    user_account_control = ADUtils.get_entry_property(obj, "useraccountcontrol", 0) or 0

    if user_account_control & UAC_TRUSTED_FOR_DELEGATION:
        rows.append(
            f"unconstrained||{obj_type}||{samaccountname}||{dnshostname}||{distinguished_name}||{object_sid}||TRUSTED_FOR_DELEGATION||||||||"
        )

    for target in ensure_list(ADUtils.get_entry_property(obj, "msDS-AllowedToDelegateTo", default=[])):
        rows.append(
            f"constrained||{obj_type}||{samaccountname}||{dnshostname}||{distinguished_name}||{object_sid}||{target}||||||||"
        )

    rbcd_raw = ADUtils.get_entry_property(obj, "msDS-AllowedToActOnBehalfOfOtherIdentity", raw=True)
    if rbcd_raw:
        rbcd_sids = extract_security_sids(rbcd_raw)
        if not rbcd_sids:
            rows.append(
                f"rbcd||{obj_type}||{samaccountname}||{dnshostname}||{distinguished_name}||{object_sid}||descriptor_parse_failed||||||||"
            )
            continue

        for sid in rbcd_sids:
            principal_sid, principal_name, principal_type, principal_dn = resolve_principal(ades, sid)
            rows.append(
                f"rbcd||{obj_type}||{samaccountname}||{dnshostname}||{distinguished_name}||{object_sid}||msDS-AllowedToActOnBehalfOfOtherIdentity||{principal_sid}||{principal_name}||{principal_type}||{principal_dn}"
            )

write_rows(rows, args.output_file, sort_rows=True)
