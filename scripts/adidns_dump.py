# Script to dump ADIDNS records
# note: Supports legacy DNS zones only. Naming contexts for (Domain|Forest)DnsZones are not being saved in the snapshot
# author: dust-life

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils
from adidnsdump import dnsdump

parser = argparse.ArgumentParser(add_help=True, description="Script to extract ADIDNS records from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, '.')
ades.preprocessCached()

findDN = [
    f',CN=MicrosoftDNS,CN=System,{ades.domain_dn}'.lower(),
    f',CN=MicrosoftDNS,DC=ForestDnsZones,{ades.forest_dn}'.lower(),
    f',CN=MicrosoftDNS,DC=DomainDnsZones,{ades.domain_dn}'.lower(),
]

out = []
for k,v in ades.dncache.items():
    for dn in findDN:
        if k.lower().endswith(dn.lower()):
            entry = ades.snap.getObject(v)
            for address in ADUtils.get_entry_property(entry, 'dnsRecord', [], raw=True):
                dr = dnsdump.DNS_RECORD(address)
                if dr['Type'] == 1:
                    address = dnsdump.DNS_RPC_RECORD_A(dr['Data'])
                    line = f"[+] Type: {dnsdump.RECORD_TYPE_MAPPING[dr['Type']]} name: {k.split(',')[0].split('=')[1]} value: {address.formatCanonical()}"
                elif dr['Type'] in [a for a in dnsdump.RECORD_TYPE_MAPPING if dnsdump.RECORD_TYPE_MAPPING[a] in ['CNAME', 'NS', 'PTR']]:
                    address = dnsdump.DNS_RPC_RECORD_NODE_NAME(dr['Data'])
                    line = f"[+] Type: {dnsdump.RECORD_TYPE_MAPPING[dr['Type']]} name: {k.split(',')[0].split('=')[1]} value: {address[list(address.fields)[0]].toFqdn()}"
                elif dr['Type'] == 28:
                    address = dnsdump.DNS_RPC_RECORD_AAAA(dr['Data'])
                    line = f"[+] Type: {dnsdump.RECORD_TYPE_MAPPING[dr['Type']]} name: {k.split(',')[0].split('=')[1]} value: {address.formatCanonical()}"
                elif dr['Type'] not in [a for a in dnsdump.RECORD_TYPE_MAPPING if dnsdump.RECORD_TYPE_MAPPING[a] in ['A', 'AAAA', 'CNAME', 'NS']]:
                    line = f"[+] name: {k.split(',')[0].split('=')[1]} Unexpected record type seen: {dr['Type']}"
                else:
                    continue
                print(line)
                out.append(line)

if args.output_file:
    with open(args.output_file, "w", encoding="utf-8") as outFile:
        outFile.write(os.linesep.join(out))
    print()
    print("[+]", f"Output written to {args.output_file}")
