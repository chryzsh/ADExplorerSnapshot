# Script to dump interesting AD stuff
# author: @oddvarmoe

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adexpsnapshot import ADExplorerSnapshot
from rich.progress import track
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timedelta, timezone
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

def convert_ad_timestamp(timestamp):
    if timestamp is None:
        return None
    base_date = datetime(1601, 1, 1, tzinfo=timezone.utc) # Base date for Windows File Time (January 1, 1601)
    return base_date + timedelta(microseconds=timestamp / 10) # Convert the timestamp (in 100-nanosecond intervals) to microseconds (/10) and add to base date
    

parser = argparse.ArgumentParser(add_help=True, description="Script to dump interesting stuff from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_folder", required=True, type=valid_directory, help="Folder to save output to")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

# Get snapshot time
snapshot_time = datetime.fromtimestamp(ades.snap.header.filetimeUnix, tz=timezone.utc)

# Out streams
out_computers = []
out_active_servers = []
out_users = []
out_sccm = []
out_sccm_potential_pxe = [] 
out_groups = []
out_printers = []
out_shares = []
out_laps = []
out_asreproast = []
out_unconstraineddelegation = []
out_userspn = []
out_plaintextpwd = []
out_pwdnotreqd = []
out_precreated = []
out_sql_systems = []
out_technologies = []

# Technology variables
technologies_sccm = False
technologies_laps = False
technologies_adcs = False
technologies_exchange = False
technologies_adfs = False

# Attributes to check for plaintext passwords
plaintext_pwd_attributes = ['UserPassword','UnixUserPassword','unicodePwd','msSFU30Password','orclCommonAttribute','os400Password']


# Add headers
out_computers.append("samaccountname||dnshostname||description||distinguishedName||operatingsystem||operatingsystemversion||useraccountcontrol||lastlogontimestamp||logoncount||pwdlastset||objectsid||memberof")
out_active_servers.append("samaccountname||dnshostname||operatingsystem||operatingsystemversion||description||lastlogontimestamp")
out_users.append("samaccountname||distinguishedName||description||useraccountcontrol||lastlogontimestamp||logoncount||pwdlastset||badpwdcount||badpasswordtime||objectsid||memberof||msds_allowedtoactonbehalfofotheridentity||title")
out_groups.append("cn||samaccountname||distinguishedName||description||objectsid||member||memberof")
out_sccm.append("mssmsmpname||dnshostname||distinguishedname||mssmssitecode||mssmsversion")
out_sccm_potential_pxe.append("distinguishedname")
out_printers.append("name||uncname||distinguishedname||servername||location||drivername||driverversion")
out_shares.append("name||uncname||distinguishedname")
out_laps.append("dnshostname||ms_mcs_admpwd||ms_mcs_admpwdexpirationtime")
out_asreproast.append("samaccountname||distinguishedName||lastlogontimestamp")
out_unconstraineddelegation.append("samaccountname||dnshostname||distinguishedName")
out_userspn.append("samaccountname||distinguishedName||serviceprincipalname||pwdlastset||logoncount")
out_plaintextpwd.append("samaccountname||distinguishedName||attribute")
out_pwdnotreqd.append("samaccountname||distinguishedName||useraccountcontrol||logoncount")
out_precreated.append("samaccountname||useraccountcontrol||pwdlastset||whencreated||description")
out_sql_systems.append("samaccountname||dnshostname||operatingsystem||operatingsystemversion||description||lastlogontimestamp")
out_technologies.append("technology||notes")

for idx, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    # get computers
    object_resolved = ADUtils.resolve_ad_entry(obj)
    if object_resolved['type'] == 'Computer':
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        dnshostname = ADUtils.get_entry_property(obj, 'dnshostname')
        description = ADUtils.get_entry_property(obj, 'description')
        distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
        operatingsystem = ADUtils.get_entry_property(obj, 'operatingsystem')
        operatingsystemversion = ADUtils.get_entry_property(obj, 'operatingsystemversion')
        useraccountcontrol = ADUtils.get_entry_property(obj, 'useraccountcontrol')
        lastlogontimestamp = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'lastlogontimestamp'))
        whencreated = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'whencreated'))
        pwdlastset = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'pwdlastset'))
        objectsid = ADUtils.get_entry_property(obj, 'objectsid')
        memberof = ADUtils.get_entry_property(obj, 'memberof')
        msds_allowedtoactonbehalfofotheridentity = ADUtils.get_entry_property(obj, 'msds-allowedtoactonbehalfofotheridentity')
        serviceprincipalname = ADUtils.get_entry_property(obj, 'serviceprincipalname')
        logoncount = ADUtils.get_entry_property(obj, 'logoncount')
        
        if serviceprincipalname:
            # Ensure serviceprincipalname is a list or iterable before checking for "MSSQLSvc"
            if isinstance(serviceprincipalname, str):
                serviceprincipalname = [serviceprincipalname] 
            
            if any("MSSQLSvc" in spn for spn in serviceprincipalname): # Can easily add more things to output based on SPN
                out_sql_systems.append(f"{samaccountname}||{dnshostname}||{operatingsystem}||{operatingsystemversion}||{description}||{lastlogontimestamp}")

        # Active servers
        if operatingsystem and 'server' in operatingsystem.lower():
            if lastlogontimestamp is not None and (snapshot_time - lastlogontimestamp) <= timedelta(days=30):
                out_active_servers.append(f"{samaccountname}||{dnshostname}||{operatingsystem}||{operatingsystemversion}||{description}||{lastlogontimestamp}")
        
        # LAPS
        ms_mcs_admpwd = ADUtils.get_entry_property(obj, 'ms-Mcs-AdmPwd')
        if ms_mcs_admpwd:
            ms_mcs_admpwdexpirationtime = ADUtils.get_entry_property(obj, 'ms-Mcs-AdmPwdExpirationTime')
            out_laps.append(f"{dnshostname}||{ms_mcs_admpwd}||{ms_mcs_admpwdexpirationtime}")
            technologies_laps = True
        
        # Check for asreproast
        if useraccountcontrol is not None and useraccountcontrol & 4194304:
            out_asreproast.append(f"{samaccountname}||{distinguishedName}||{lastlogontimestamp}")
        
        # Check for unconstrained delegation
        if useraccountcontrol is not None and useraccountcontrol & 524288:
            out_unconstraineddelegation.append(f"{samaccountname}||{dnshostname}||{distinguishedName}")

        # Check for pwdnotreqd
        if useraccountcontrol is not None and useraccountcontrol & 32:
            out_pwdnotreqd.append(f"{samaccountname}||{distinguishedName}||{useraccountcontrol}||{logoncount}")
        
        # Check for pre created computer accounts 
        if not lastlogontimestamp:
            out_precreated.append(f"{samaccountname}||{useraccountcontrol}||{pwdlastset}||{whencreated}||{description}")
        
        out_computers.append(f"{samaccountname}||{dnshostname}||{description}||{distinguishedName}||{operatingsystem}||{operatingsystemversion}||{useraccountcontrol}||{lastlogontimestamp}||{logoncount}||{pwdlastset}||{objectsid}||{memberof}||{msds_allowedtoactonbehalfofotheridentity}")

    # # get users
    elif object_resolved['type'] == 'User':
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
        description = ADUtils.get_entry_property(obj, 'description')
        useraccountcontrol = ADUtils.get_entry_property(obj, 'useraccountcontrol')
        lastlogontimestamp = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'lastlogontimestamp'))
        logoncount = ADUtils.get_entry_property(obj, 'logoncount')
        pwdlastset = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'pwdlastset'))
        badpwdcount = ADUtils.get_entry_property(obj, 'badpwdcount')
        badpasswordtime = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'badpasswordtime'))
        objectsid = ADUtils.get_entry_property(obj, 'objectsid')
        memberof = ADUtils.get_entry_property(obj, 'memberof')
        msds_allowedtoactonbehalfofotheridentity = ADUtils.get_entry_property(obj, 'msds-allowedtoactonbehalfofotheridentity')
        title = ADUtils.get_entry_property(obj, 'title')

        # Check for asreproast
        if useraccountcontrol is not None and useraccountcontrol & 4194304:
            out_asreproast.append(f"{samaccountname}||{distinguishedName}||{lastlogontimestamp}")
        
        # Check for service principal names / Kerberoast
        serviceprincipalname = ADUtils.get_entry_property(obj, 'serviceprincipalname')
        if serviceprincipalname:
            out_userspn.append(f"{samaccountname}||{distinguishedName}||{serviceprincipalname}||{pwdlastset}||{logoncount}")
        
        # Check special attributes (Potential plaintext passwords)
        for attr in plaintext_pwd_attributes:
            if ADUtils.get_entry_property(obj, attr):
                out_plaintextpwd.append(f"{samaccountname}||{distinguishedName}||{attr}:{ADUtils.get_entry_property(obj, attr)}")

        # Check for pwdnotreqd
        if useraccountcontrol is not None and useraccountcontrol & 32:
            out_pwdnotreqd.append(f"{samaccountname}||{distinguishedName}||{useraccountcontrol}||{logoncount}")

        out_users.append(f"{samaccountname}||{distinguishedName}||{description}||{useraccountcontrol}||{lastlogontimestamp}||{logoncount}||{pwdlastset}||{badpwdcount}||{badpasswordtime}||{objectsid}||{memberof}||{msds_allowedtoactonbehalfofotheridentity}||{title}")
        
    # get groups
    elif object_resolved['type'] == 'Group':
        cn = ADUtils.get_entry_property(obj, 'cn')
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
        description = ADUtils.get_entry_property(obj, 'description')
        objectsid = ADUtils.get_entry_property(obj, 'objectsid')
        member = ADUtils.get_entry_property(obj, 'member')
        memberof = ADUtils.get_entry_property(obj, 'memberof')
        out_groups.append(f"{cn}||{samaccountname}||{distinguishedName}||{description}||{objectsid}||{member}||{memberof}")
    
    elif object_resolved['type'] == 'Base':
        if "connectionPoint" in ADUtils.get_entry_property(obj, 'objectClass', "0"): 
            if "-Remote-Installation-Services" in ADUtils.get_entry_property(obj, 'cn', "0"): 
                _, server_dn = ADUtils.get_entry_property(obj, 'distinguishedName', "0").split(',', 1)
                out_sccm_potential_pxe.append(server_dn)
        # get sccm mp
        if "mSSMSManagementPoint" in ADUtils.get_entry_property(obj, 'objectClass', "0"): 
            mssmsmpname = ADUtils.get_entry_property(obj, 'mssmsmpname')
            dnshostname = ADUtils.get_entry_property(obj, 'dnshostname')
            distinguishedname = ADUtils.get_entry_property(obj, 'distinguishedName')
            mssmssitecode = ADUtils.get_entry_property(obj, 'mssmssitecode')
            mssmsversion = ADUtils.get_entry_property(obj, 'mssmsversion')
            out_sccm.append(f"{mssmsmpname}||{dnshostname}||{distinguishedname}||{mssmssitecode}||{mssmsversion}")
            technologies_sccm = True
            
        # get printers
        if "printQueue" in ADUtils.get_entry_property(obj, 'objectClass', "0"):
            name = ADUtils.get_entry_property(obj, 'name')
            uncname = ADUtils.get_entry_property(obj, 'uncname')
            distinguishedname = ADUtils.get_entry_property(obj, 'distinguishedname')
            servername = ADUtils.get_entry_property(obj, 'servername')
            location = ADUtils.get_entry_property(obj, 'location')
            drivername = ADUtils.get_entry_property(obj, 'drivername')
            driverversion = ADUtils.get_entry_property(obj, 'driverversion')
            out_printers.append(f"{name}||{uncname}||{distinguishedname}||{servername}||{location}||{drivername}||{driverversion}")
            
        # get shares
        if "volume" in ADUtils.get_entry_property(obj, 'objectClass', "0"):
            name = ADUtils.get_entry_property(obj, 'name')
            uncname = ADUtils.get_entry_property(obj, 'uncname')
            distinguishedname = ADUtils.get_entry_property(obj, 'distinguishedname')
            out_shares.append(f"{name}||{uncname}||{distinguishedname}")

    technologies_adcs = technologies_adcs or 'pkicertificatetemplate' in obj.classes
    technologies_exchange = technologies_exchange or 'msexchexchangeserver' in obj.classes
    technologies_adfs = technologies_adfs or 'deviceregistrationservice' in obj.classes

if args.output_folder:
    if technologies_laps:
        out_technologies.append("LAPS||Check laps.txt")
    if technologies_sccm:
        out_technologies.append("SCCM||Check sccm.txt")
    if technologies_adcs:
        out_technologies.append("ADCS||ADCS Container found (run cert_dump script)")
    if technologies_exchange:
        out_technologies.append("Exchange||Local Exchange server")
    if technologies_adfs:
        out_technologies.append("ADFS||ADFS is installed")

    output_files = {
        "computers.txt": out_computers,
        "active_servers.txt": out_active_servers,
        "users.txt": out_users,
        "sccm.txt": out_sccm,
        "groups.txt": out_groups,
        "printers.txt": out_printers,
        "shares.txt": out_shares,
        "laps.txt": out_laps,
        "asreproast.txt": out_asreproast,
        "unconstraineddelegation.txt": out_unconstraineddelegation,
        "userspn.txt": out_userspn,
        "plaintextpwd.txt": out_plaintextpwd,
        "pwdnotreqd.txt": out_pwdnotreqd,
        "precreated.txt": out_precreated,
        "sccm_potential_pxe.txt": out_sccm_potential_pxe,
        "sql_systems.txt": out_sql_systems,
        "technologies.txt": out_technologies,
    }

    for filename, lines in output_files.items():
        if lines:
            with open(Path(args.output_folder / filename), "w", encoding="utf-8") as output_file:
                output_file.write(os.linesep.join(lines))

    logging.info(f"Output written to files in {args.output_folder}")
