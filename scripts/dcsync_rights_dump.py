# Script to dump DCSync-relevant rights

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from rich.progress import track

from certipy.lib.security import ActiveDirectorySecurity

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import write_rows
from security_aces import resolve_principal

DCSYNC_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to extract DCSync-capable rights from domain naming context ACLs",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

rows = ["naming_context||principal_sid||principal_name||principal_type||principal_dn||rights||dcsync_level"]


def _to_rights_list(rights_value):
    if rights_value is None:
        return []
    try:
        return [str(x) for x in list(rights_value)]
    except TypeError:
        if hasattr(rights_value, "to_list"):
            return [str(x) for x in rights_value.to_list()]
        return [str(rights_value)]


def _matched_rights(rights):
    matches = []
    extended_rights = {str(x).lower() for x in rights.get("extended_rights", [])}
    for guid, display_name in DCSYNC_RIGHTS.items():
        if guid in extended_rights:
            matches.append(display_name)

    rights_list = {str(x) for x in _to_rights_list(rights.get("rights"))}
    if "GenericAll" in rights_list:
        matches.append("GenericAll")

    return sorted(set(matches))


def _dcsync_level(matches):
    as_set = set(matches)
    if "GenericAll" in as_set:
        return "GenericAll"
    if {
        "DS-Replication-Get-Changes",
        "DS-Replication-Get-Changes-All",
    }.issubset(as_set):
        return "Full"
    return "Partial"


for _, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""
    object_sid = ADUtils.get_entry_property(obj, "objectsid")

    if "domain" not in obj.classes or not object_sid:
        continue

    raw_sd = ADUtils.get_entry_property(obj, "nTSecurityDescriptor", raw=True)
    if not raw_sd:
        continue

    try:
        security = ActiveDirectorySecurity(raw_sd)
    except Exception:
        rows.append(f"{distinguished_name}|||||descriptor_parse_failed|Error")
        continue

    for sid, rights in security.aces.items():
        matches = _matched_rights(rights)
        if not matches:
            continue

        principal_sid, principal_name, principal_type, principal_dn = resolve_principal(ades, sid)
        rights_text = ",".join(matches)
        rows.append(
            f"{distinguished_name}||{principal_sid}||{principal_name}||{principal_type}||{principal_dn}||{rights_text}||{_dcsync_level(matches)}"
        )

write_rows(rows, args.output_file, sort_rows=True)
