# Script to dump Certificate information
# author: @oddvarmoe

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adexpsnapshot import ADExplorerSnapshot
from rich.progress import track
from bloodhound.ad.utils import ADUtils
from certipy.lib.constants import *
from certipy.lib.security import CertificateSecurity
from certipy.commands.find import filetime_to_str
from security_aces import security_to_bloodhound_aces
from pathlib import Path
import argparse
import os
import logging

def valid_directory(path):
    """Check if the provided path is a valid directory or create it if it does not exist."""
    path = Path(path) 
    if not path.exists():
        # Attempt to create the directory
        try:
            path.mkdir(parents=True, exist_ok=True)
            #print(f"Directory created at {path}")
        except OSError as e:
            # If creation fails, raise an argparse error
            raise argparse.ArgumentTypeError(f"Could not create directory: {path}. {str(e)}")
    elif not path.is_dir():
        # If the path exists but is not a directory, raise an error
        raise argparse.ArgumentTypeError(f"The path {path} exists but is not a directory.")
    return path

parser = argparse.ArgumentParser(add_help=True, description="Script to dump interesting stuff from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_folder", required=True, type=valid_directory, help="Folder to save output to")
parser.add_argument("-e", "--enabled", required=False, help="Only get enabled templates", action="store_true")
args = parser.parse_args()

# Console will be automatically initialized with setup_logging() when omitted
ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

# Out streams
out_certs = []

for idx, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    object_resolved = ADUtils.resolve_ad_entry(obj)
    
    if 'pkicertificatetemplate' in obj.classes:
        name = ADUtils.get_entry_property(obj, 'name')
        if args.enabled:
            if (name in ades.certtemplates) == False:
                continue
            
        # Enable check if cert is under any CA (e.g. enabled)
        enabled = name in ades.certtemplates
        object_identifier = ADUtils.get_entry_property(obj, 'objectGUID')
        validity_period = filetime_to_str(ADUtils.get_entry_property(obj, 'pKIExpirationPeriod'))
        renewal_period = filetime_to_str(ADUtils.get_entry_property(obj, 'pKIOverlapPeriod'))
        
        schema_version = ADUtils.get_entry_property(obj, 'msPKI-Template-Schema-Version', 0)

        certificate_name_flag = ADUtils.get_entry_property(obj, 'msPKI-Certificate-Name-Flag', 0)
        certificate_name_flag = CertificateNameFlag(int(certificate_name_flag))

        enrollment_flag = ADUtils.get_entry_property(obj, 'msPKI-Enrollment-Flag', 0)
        enrollment_flag = EnrollmentFlag(int(enrollment_flag))

        authorized_signatures_required = int(ADUtils.get_entry_property(obj, 'msPKI-RA-Signature', 0))

        application_policies = ADUtils.get_entry_property(obj, 'msPKI-RA-Application-Policies', raw=True, default=[])
        application_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                application_policies,
            )
        )

        extended_key_usage = ADUtils.get_entry_property(obj, "pKIExtendedKeyUsage", default=[])
        extended_key_usage = list(
            map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, extended_key_usage)
        )

        client_authentication = (
            any(
                eku in extended_key_usage
                for eku in [
                    "Client Authentication",
                    "Smart Card Logon",
                    "PKINIT Client Authentication",
                    "Any Purpose",
                ]
            )
            or len(extended_key_usage) == 0
        )

        enrollment_agent = (
            any(
                eku in extended_key_usage
                for eku in [
                    "Certificate Request Agent",
                    "Any Purpose",
                ]
            )
            or len(extended_key_usage) == 0
        )

        enrollee_supplies_subject = any(
            flag in certificate_name_flag
            for flag in [
                CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT,
            ]
        )

        requires_manager_approval = (
            EnrollmentFlag.PEND_ALL_REQUESTS in enrollment_flag
        )

        security = CertificateSecurity(ADUtils.get_entry_property(obj, "nTSecurityDescriptor", raw=True))

        aces = security_to_bloodhound_aces(security, ades)

        # Could be useful later if we want to output to JSON
        # certtemplate = {
        #     'Properties': {
        #         'highvalue': (
        #         enabled
        #         and any(
        #             [
        #             all(
        #                 [
        #                 enrollee_supplies_subject,
        #                 not requires_manager_approval,
        #                 client_authentication,
        #                 ]
        #             ),
        #             all([enrollment_agent, not requires_manager_approval]),
        #             ]
        #         )
        #         ),
        #     'name': "%s@%s"
        #     % (
        #         ADUtils.get_entry_property(obj, "CN").upper(),
        #         domainname
        #     ),
        #     'type': 'Certificate Template',
        #     'domain': domainname,
        #     'Schema Version': schema_version,
        #     'Template Name': ADUtils.get_entry_property(obj, 'CN'),
        #     'Display Name': ADUtils.get_entry_property(obj, 'displayName'),
        #     'Client Authentication': client_authentication,
        #     'Enrollee Supplies Subject': enrollee_supplies_subject,
        #     'Extended Key Usage': extended_key_usage,
        #     'Requires Manager Approval': requires_manager_approval,
        #     'Validity Period': validity_period,
        #     'Renewal Period': renewal_period,
        #     'Certificate Name Flag': certificate_name_flag.to_str_list(),
        #     'Enrollment Flag': enrollment_flag.to_str_list(),
        #     'Authorized Signatures Required': authorized_signatures_required,
        #     'Application Policies': application_policies,
        #     'Enabled': enabled,
        #     'Certificate Authorities': list(ades.certtemplates[name]),
        #     },          
        #     'ObjectIdentifier': object_identifier.lstrip("{").rstrip("}"), 
        #     'Aces': aces,
        # }
        out_certs.append(f"-----------------------------------------")
        out_certs.append(f"Enabled: {enabled}")
        out_certs.append(f"CA Name: {list(ades.certtemplates[name])}")
        out_certs.append(f"Template Name: {ADUtils.get_entry_property(obj, 'CN')}")
        out_certs.append(f"Display Name: {ADUtils.get_entry_property(obj, 'displayName')}")
        out_certs.append(f"Schema Version: {schema_version}")        
        out_certs.append(f"Validity Period: {validity_period}")
        out_certs.append(f"Renewal Period: {renewal_period}")
        out_certs.append(f"Client Authentication: {client_authentication}")        
        out_certs.append(f"Enrollee Supplies Subject: {enrollee_supplies_subject}")
        out_certs.append(f"Enrollment Flag: {enrollment_flag.to_str_list()}")
        out_certs.append(f"Authorized Signatures Required: {authorized_signatures_required}")
        out_certs.append(f"Extended Key Usage: {extended_key_usage}")
        out_certs.append(f"Requires Manager Approval: {requires_manager_approval}")
        out_certs.append(f"Certificate Name Flag: {certificate_name_flag.to_str_list()}")
        out_certs.append(f"Application Policies: {application_policies}")
        out_certs.append(f"Aces:")
        for ace in aces:
            out_certs.append(f"{ace}")
        out_certs.append("\n")

if args.output_folder:
    if out_certs:
        with open(Path(args.output_folder / "certs.txt"), "w", encoding="utf-8") as outFile_certs:
            outFile_certs.write(os.linesep.join(out_certs))

    logging.info(f"Output written to files in {args.output_folder}")
