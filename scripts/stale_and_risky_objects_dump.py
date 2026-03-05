# Script to dump stale and risky AD objects

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from datetime import datetime, timezone
from rich.progress import track

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import convert_ad_timestamp, fmt_datetime, write_rows

UAC_ACCOUNTDISABLE = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to identify stale and risky user/computer objects from an AD Explorer snapshot",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
parser.add_argument("--stale-days", type=int, default=90, help="Days since last logon to classify object as stale (default: 90)")
parser.add_argument("--computer-stale-days", type=int, default=90, help="Days since last logon to classify computer object as stale (default: 90)")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

snapshot_time = datetime.fromtimestamp(ades.snap.header.filetimeUnix, tz=timezone.utc)

rows = [
    "category||object_type||samaccountname||distinguishedname||objectsid||enabled||admincount||lastlogontimestamp||pwdlastset||details"
]


def is_stale(lastlogon, threshold_days):
    if lastlogon is None:
        return True
    return (snapshot_time - lastlogon).days > threshold_days


for _, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    resolved = ADUtils.resolve_ad_entry(obj)
    object_type = resolved.get("type", "")
    if object_type not in {"User", "Computer"}:
        continue

    samaccountname = ADUtils.get_entry_property(obj, "samaccountname", "") or ""
    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""
    object_sid = ADUtils.get_entry_property(obj, "objectsid", "") or ""

    user_account_control = ADUtils.get_entry_property(obj, "useraccountcontrol", 0) or 0
    enabled = not bool(user_account_control & UAC_ACCOUNTDISABLE)
    admincount = ADUtils.get_entry_property(obj, "admincount", 0) or 0

    lastlogontimestamp = convert_ad_timestamp(ADUtils.get_entry_property(obj, "lastlogontimestamp"))
    pwdlastset = convert_ad_timestamp(ADUtils.get_entry_property(obj, "pwdlastset"))
    serviceprincipalname = ADUtils.get_entry_property(obj, "serviceprincipalname")

    stale_days = args.computer_stale_days if object_type == "Computer" else args.stale_days
    if is_stale(lastlogontimestamp, stale_days):
        details = f"lastLogonTimestamp older than {stale_days} days" if lastlogontimestamp else "missing lastLogonTimestamp"
        rows.append(
            f"stale_{object_type.lower()}||{object_type}||{samaccountname}||{distinguished_name}||{object_sid}||{enabled}||{admincount}||{fmt_datetime(lastlogontimestamp)}||{fmt_datetime(pwdlastset)}||{details}"
        )

    if not enabled and admincount == 1:
        rows.append(
            f"disabled_privileged||{object_type}||{samaccountname}||{distinguished_name}||{object_sid}||{enabled}||{admincount}||{fmt_datetime(lastlogontimestamp)}||{fmt_datetime(pwdlastset)}||adminCount=1 and disabled"
        )

    if user_account_control & UAC_PASSWD_NOTREQD:
        rows.append(
            f"password_not_required||{object_type}||{samaccountname}||{distinguished_name}||{object_sid}||{enabled}||{admincount}||{fmt_datetime(lastlogontimestamp)}||{fmt_datetime(pwdlastset)}||PASSWD_NOTREQD"
        )

    if user_account_control & UAC_TRUSTED_FOR_DELEGATION:
        rows.append(
            f"unconstrained_delegation||{object_type}||{samaccountname}||{distinguished_name}||{object_sid}||{enabled}||{admincount}||{fmt_datetime(lastlogontimestamp)}||{fmt_datetime(pwdlastset)}||TRUSTED_FOR_DELEGATION"
        )

    if user_account_control & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION:
        rows.append(
            f"protocol_transition_delegation||{object_type}||{samaccountname}||{distinguished_name}||{object_sid}||{enabled}||{admincount}||{fmt_datetime(lastlogontimestamp)}||{fmt_datetime(pwdlastset)}||TRUSTED_TO_AUTH_FOR_DELEGATION"
        )

    if object_type == "User" and serviceprincipalname and lastlogontimestamp is None:
        rows.append(
            f"never_loggedon_service_account||{object_type}||{samaccountname}||{distinguished_name}||{object_sid}||{enabled}||{admincount}||||{fmt_datetime(pwdlastset)}||SPN set and no lastLogonTimestamp"
        )

write_rows(rows, args.output_file, sort_rows=True)
