# Script to dump nested Tier-0 group membership

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from collections import deque
from rich.progress import track

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import ensure_list, write_rows

TARGET_RIDS = {"512", "518", "519", "544", "548", "549", "550", "551"}
TARGET_NAMES = {
    "administrators",
    "account operators",
    "backup operators",
    "dnsadmins",
    "domain admins",
    "enterprise admins",
    "enterprise key admins",
    "key admins",
    "print operators",
    "schema admins",
    "server operators",
}

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to expand nested membership for Tier-0 groups from an AD Explorer snapshot",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

group_members = {}
group_meta = {}
seed_groups = set()

for _, obj in track(enumerate(ades.snap.objects), description="Indexing groups", total=ades.snap.header.numObjects):
    resolved = ADUtils.resolve_ad_entry(obj)
    if resolved.get("type", "") != "Group":
        continue

    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""
    cn = ADUtils.get_entry_property(obj, "cn", "") or ""
    samaccountname = ADUtils.get_entry_property(obj, "samaccountname", "") or ""
    object_sid = ADUtils.get_entry_property(obj, "objectsid", "") or ""
    members = [str(x) for x in ensure_list(ADUtils.get_entry_property(obj, "member", default=[]))]

    group_members[distinguished_name] = members
    group_meta[distinguished_name] = {
        "cn": cn,
        "samaccountname": samaccountname,
        "objectsid": object_sid,
    }

    rid = object_sid.split("-")[-1] if object_sid else ""
    if rid in TARGET_RIDS or cn.lower() in TARGET_NAMES or samaccountname.lower() in TARGET_NAMES:
        seed_groups.add(distinguished_name)

rows = ["seed_group||seed_group_dn||member_type||member_name||member_sid||member_dn||via_group"]
seen_rows = set()

for seed_dn in sorted(seed_groups):
    seed_name = group_meta.get(seed_dn, {}).get("samaccountname") or group_meta.get(seed_dn, {}).get("cn") or seed_dn

    queue = deque([seed_dn])
    visited_groups = set()

    while queue:
        current_group_dn = queue.popleft()
        if current_group_dn in visited_groups:
            continue
        visited_groups.add(current_group_dn)

        for member_dn in group_members.get(current_group_dn, []):
            idx = ades.dncache.get(member_dn)
            if idx is None:
                row = (
                    seed_name,
                    seed_dn,
                    "Unknown",
                    "",
                    "",
                    member_dn,
                    current_group_dn,
                )
            else:
                member_obj = ades.snap.getObject(idx)
                member_resolved = ADUtils.resolve_ad_entry(member_obj)
                member_type = member_resolved.get("type", "")
                member_name = ADUtils.get_entry_property(member_obj, "samaccountname", "") or ADUtils.get_entry_property(member_obj, "name", "") or ""
                member_sid = ADUtils.get_entry_property(member_obj, "objectsid", "") or ""
                member_dn_resolved = ADUtils.get_entry_property(member_obj, "distinguishedName", "") or member_dn

                row = (
                    seed_name,
                    seed_dn,
                    member_type,
                    member_name,
                    member_sid,
                    member_dn_resolved,
                    current_group_dn,
                )

                if member_type == "Group" and member_dn_resolved in group_members and member_dn_resolved not in visited_groups:
                    queue.append(member_dn_resolved)

            if row not in seen_rows:
                seen_rows.add(row)
                rows.append("||".join(row))

write_rows(rows, args.output_file, sort_rows=True)
