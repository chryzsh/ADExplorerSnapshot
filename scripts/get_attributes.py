# Script to dump specific AD attributes
# author: @knavesec

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adexpsnapshot import ADExplorerSnapshot
from rich.progress import track
from bloodhound.ad.utils import ADUtils
from report_utils import convert_ad_timestamp
import argparse

parser = argparse.ArgumentParser(add_help=True, description="Script to dump selected AD attributes from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-a", "--attributes", required=True, action="append", nargs="*", help="Attributes to extract")
parser.add_argument("-t", "--type", required=False, default=None, help="Object type (User, Computer, Group, Base), optional and case-sensitive")
parser.add_argument("-o", "--output_file", required=False, default="objs.txt", help="Output file path (default: objs.txt)")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

# ty stack overflow for reducing a 2d array
attrs = [j for sub in args.attributes for j in sub]

out_list = []
out_list.append("||".join(attrs))

for obj in track(ades.snap.objects, description="Processing objects", total=ades.snap.header.numObjects):
    # get computers
    object_resolved = ADUtils.resolve_ad_entry(obj)
    if object_resolved['type'] == args.type or args.type is None:
        obj_out = []
        for attr in attrs:
            if attr in ['lastlogontimestamp', 'whencreated', 'pwdlastset']:
                obj_out.append(str(convert_ad_timestamp(ADUtils.get_entry_property(obj, attr))))
            else:
                val = ADUtils.get_entry_property(obj, attr)
                obj_out.append(str(val) if val is not None else "")
        if obj_out:
            out_list.append("||".join(obj_out))

with open(args.output_file, "w", encoding="utf-8") as outFile:
    outFile.write(os.linesep.join(out_list))
print(f"[+] Output written to {args.output_file}")
