# Script to dump subnets and IPs
# author: Signum21

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils
import ipaddress
import argparse

parser = argparse.ArgumentParser(add_help=True, description="Script to extract subnets and IPs from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-p", "--parse_ips", required=False, help="Expand subnets in corresponding IPs", action="store_true")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

from collections import defaultdict

def get_site_name(dn):
    """Resolve the site name for a subnet object via its siteObject attribute."""
    idx = ades.dncache.get(dn)
    if idx is None:
        return "Unknown"
    obj = ades.snap.getObject(idx)
    site_dn = ADUtils.get_entry_property(obj, 'siteObject', default='')
    if site_dn:
        return site_dn.split(",")[0].split("=")[1]
    return "Unknown"

for domain in ades.domains:
    print()
    print("[+]",f"Searching inside domain {domain.replace('DC=', '').replace(',', '.')}")
    findSub = f",CN=Subnets,CN=Sites,CN=Configuration,{domain}".lower()

    sites = defaultdict(list)
    for k,v in ades.dncache.items():
        if k.lower().endswith(findSub):
            subnet = k.split(",")[0].split("=")[1]
            site = get_site_name(k)
            sites[site].append(subnet)

    out = []
    for site in sorted(sites.keys()):
        subnets = sorted(sites[site], key=lambda s: ipaddress.ip_network(s, strict=False).network_address)
        out.append(f"\n[Site: {site}]")
        print(f"\n[Site: {site}]")
        for subnet in subnets:
            if args.parse_ips:
                for ip in ipaddress.IPv4Network(subnet):
                    out.append(f"  {ip}")
                    print(f"  {ip}")
            else:
                out.append(f"  {subnet}")
                print(f"  {subnet}")

if args.output_file:
    outFile = open(args.output_file, "w")
    outFile.write(os.linesep.join(out))
    print()
    print("[+]",f"Output written to {args.output_file}")
