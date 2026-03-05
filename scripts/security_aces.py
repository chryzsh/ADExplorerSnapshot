"""Shared ACL conversion helpers for dump scripts."""

from bloodhound.ad.utils import ADUtils
from certipy.lib.constants import EXTENDED_RIGHTS_MAP


def _resolve_principal(ades, sid):
    if sid in ADUtils.WELLKNOWN_SIDS:
        domain_sid = f"{ADUtils.ldap2domain(ades.rootdomain).upper()}-{sid}"
        principal_type = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
        principal_accountname = ADUtils.WELLKNOWN_SIDS[sid][0]
        return domain_sid, principal_type, principal_accountname

    try:
        entry = ades.snap.getObject(ades.sidcache[sid])
        resolved_entry = ADUtils.resolve_ad_entry(entry)
        principal_type = resolved_entry["type"]
        principal_accountname = ADUtils.get_entry_property(entry, "SamAccountName")
        return sid, principal_type, principal_accountname
    except KeyError:
        return sid, "Unknown", "Unknown"


def _to_rights_list(rights_value):
    if rights_value is None:
        return []

    try:
        return list(rights_value)
    except TypeError:
        return rights_value.to_list()


def security_to_bloodhound_aces(security, ades):
    aces = []

    owner_sid = security.owner
    _, owner_type, owner_name = _resolve_principal(ades, owner_sid)
    aces.append(
        {
            "Principal AccountName": owner_name,
            "PrincipalSID": owner_sid,
            "PrincipalType": owner_type,
            "RightName": "Owner",
            "IsInherited": False,
        }
    )

    for sid, rights in security.aces.items():
        principal_sid, principal_type, principal_accountname = _resolve_principal(ades, sid)

        for right in _to_rights_list(rights.get("rights")):
            aces.append(
                {
                    "Principal AccountName": principal_accountname,
                    "PrincipalSID": principal_sid,
                    "PrincipalType": principal_type,
                    "RightName": str(right),
                    "IsInherited": False,
                }
            )

        for extended_right in rights.get("extended_rights", []):
            right_name = (
                EXTENDED_RIGHTS_MAP[extended_right].replace("-", "")
                if extended_right in EXTENDED_RIGHTS_MAP
                else extended_right
            )
            aces.append(
                {
                    "Principal AccountName": principal_accountname,
                    "PrincipalSID": principal_sid,
                    "PrincipalType": principal_type,
                    "RightName": right_name,
                    "IsInherited": False,
                }
            )

    return aces
