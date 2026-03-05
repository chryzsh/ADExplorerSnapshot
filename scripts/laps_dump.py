# Script to dump legacy LAPS and Windows LAPS attributes

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from rich.progress import track

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import convert_ad_timestamp, ensure_list, fmt_datetime, write_rows

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to extract legacy LAPS and Windows LAPS attributes from an AD Explorer snapshot",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

rows = [
    "samaccountname||dnshostname||distinguishedname||legacy_password||legacy_expiration||windows_password||windows_expiration||encrypted_password_present||encrypted_password_history_count||encrypted_dsrm_password_present||encrypted_dsrm_password_history_count"
]

for _, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    resolved = ADUtils.resolve_ad_entry(obj)
    if resolved.get("type", "") != "Computer":
        continue

    samaccountname = ADUtils.get_entry_property(obj, "samaccountname", "") or ""
    dnshostname = ADUtils.get_entry_property(obj, "dnshostname", "") or ""
    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""

    legacy_password = ADUtils.get_entry_property(obj, "ms-Mcs-AdmPwd", "") or ""
    legacy_expiration = convert_ad_timestamp(ADUtils.get_entry_property(obj, "ms-Mcs-AdmPwdExpirationTime"))

    windows_password = ADUtils.get_entry_property(obj, "msLAPS-Password", "") or ""
    windows_expiration = convert_ad_timestamp(ADUtils.get_entry_property(obj, "msLAPS-PasswordExpirationTime"))

    encrypted_password = ADUtils.get_entry_property(obj, "msLAPS-EncryptedPassword", raw=True)
    encrypted_password_history = [x for x in ensure_list(ADUtils.get_entry_property(obj, "msLAPS-EncryptedPasswordHistory", default=[], raw=True)) if x]
    encrypted_dsrm_password = ADUtils.get_entry_property(obj, "msLAPS-EncryptedDSRMPassword", raw=True)
    encrypted_dsrm_password_history = [x for x in ensure_list(ADUtils.get_entry_property(obj, "msLAPS-EncryptedDSRMPasswordHistory", default=[], raw=True)) if x]

    has_any = any(
        [
            legacy_password,
            legacy_expiration is not None,
            windows_password,
            windows_expiration is not None,
            encrypted_password,
            encrypted_password_history,
            encrypted_dsrm_password,
            encrypted_dsrm_password_history,
        ]
    )
    if not has_any:
        continue

    rows.append(
        f"{samaccountname}||{dnshostname}||{distinguished_name}||{legacy_password}||{fmt_datetime(legacy_expiration)}||{windows_password}||{fmt_datetime(windows_expiration)}||{bool(encrypted_password)}||{len(encrypted_password_history)}||{bool(encrypted_dsrm_password)}||{len(encrypted_dsrm_password_history)}"
    )

write_rows(rows, args.output_file, sort_rows=True)
