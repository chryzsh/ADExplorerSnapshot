# Script to dump DFS link paths and their target servers
# Author: @snovvcrash

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import xml.etree.ElementTree as ET

from bloodhound.ad.utils import ADUtils
from adexpsnapshot import ADExplorerSnapshot

parser = argparse.ArgumentParser(add_help=True, description="Script to extract DFS link paths and target servers from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, '.')
ades.preprocessCached()

findDN = f',CN=Dfs-Configuration,CN=System,{ades.rootdomain}'.lower()

dfs_pairs = []
for key, val in ades.dncache.items():
    if key.lower().endswith(findDN):
        entry = ades.snap.getObject(val)
        dfs_pairs.append((
            ADUtils.get_entry_property(entry, 'msDFS-TargetListv2', None, raw=True),
            ADUtils.get_entry_property(entry, 'msDFS-LinkPathv2', None, raw=True)
        ))

namespace = {'ns': 'http://schemas.microsoft.com/dfs/2007/03'}

out = []
for target_list, link_path in dfs_pairs:
    if link_path is not None:
        try:
            xml_data = target_list.decode('utf-16le')
            root = ET.fromstring(xml_data)
            targets = [t.text for t in root.findall("ns:target", namespace)]
        except Exception as e:
            print(f'[-] {e}')
        else:
            joined_targets = '\n             '.join(targets)
            block = f'--------------------------------------------------------------------------------\nLink path:   {link_path}\nTarget list: {joined_targets}'
            print(block)
            out.append(block)

if args.output_file:
    with open(args.output_file, "w") as outFile:
        outFile.write(os.linesep.join(out))
    print()
    print("[+]", f"Output written to {args.output_file}")
