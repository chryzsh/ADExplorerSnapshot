# Script to dump subnets and IPs
# author: Signum21

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils
import ipaddress
import argparse
import os

parser = argparse.ArgumentParser(add_help=True, description="Script to extract subnets and IPs from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-p", "--parse_ips", required=False, help="Expand subnets in corresponding IPs", action="store_true")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()
out = []

def get_site_name(dn):
    """Resolve the site name for a subnet object via its siteObject attribute."""
    idx = ades.dncache.get(dn)
    if idx is None:
        return "Unknown"
    obj = ades.snap.getObject(idx)
    site_dn = ADUtils.get_entry_property(obj, 'siteObject', default='')
    if site_dn:
        # siteObject is a DN like CN=SiteName,CN=Sites,CN=Configuration,DC=...
        return site_dn.split(",")[0].split("=")[1]
    return "Unknown"

for domain in ades.domains:
    print()
    print("[+]",f"Searching inside domain {domain.replace('DC=', '').replace(',', '.')}")
    findSub = f",CN=Subnets,CN=Sites,CN=Configuration,{domain}".lower()

    for k,v in ades.dncache.items():
        if k.lower().endswith(findSub):
            subnet = k.split(",")[0].split("=")[1]
            site = get_site_name(k)

            if not args.parse_ips:
                line = f"{subnet}\t{site}"
                if not args.output_file:
                    print(line)
                out.append(line)
            else:
                sub_ips = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
                print("[+]",f"Parsing subnet {subnet} (Site: {site})")

                for ip in sub_ips:
                    line = f"{ip}\t{site}"
                    if line not in out:
                        if not args.output_file:
                            print(ip)
                        out.append(line)

if args.output_file:
    outFile = open(args.output_file, "w")
    outFile.write(os.linesep.join(out))
    print()
    print("[+]",f"Output written to {args.output_file}")
