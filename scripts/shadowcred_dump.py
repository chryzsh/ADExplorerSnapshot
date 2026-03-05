# Script to dump shadow credential exposure

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from rich.progress import track

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils

from report_utils import ensure_list, write_rows

parser = argparse.ArgumentParser(
    add_help=True,
    description="Script to extract objects with msDS-KeyCredentialLink (shadow credentials) from an AD Explorer snapshot",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

rows = ["object_type||samaccountname||name||distinguishedname||objectsid||keycredential_count||total_blob_bytes"]

for _, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    key_credential_link = ensure_list(ADUtils.get_entry_property(obj, "msDS-KeyCredentialLink", default=[], raw=True))
    key_credential_link = [blob for blob in key_credential_link if blob]
    if not key_credential_link:
        continue

    resolved = ADUtils.resolve_ad_entry(obj)
    object_type = resolved.get("type", "")
    samaccountname = ADUtils.get_entry_property(obj, "samaccountname", "") or ""
    name = ADUtils.get_entry_property(obj, "name", "") or ""
    distinguished_name = ADUtils.get_entry_property(obj, "distinguishedName", "") or ""
    object_sid = ADUtils.get_entry_property(obj, "objectsid", "") or ""

    total_blob_bytes = 0
    for blob in key_credential_link:
        if isinstance(blob, (bytes, bytearray)):
            total_blob_bytes += len(blob)
        else:
            total_blob_bytes += len(str(blob).encode("utf-8"))

    rows.append(
        f"{object_type}||{samaccountname}||{name}||{distinguished_name}||{object_sid}||{len(key_credential_link)}||{total_blob_bytes}"
    )

write_rows(rows, args.output_file, sort_rows=True)
