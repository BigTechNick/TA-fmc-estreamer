# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer_events.py - the binary event records other than connection events.

  * Correlation (policy violation) events, record 112, data block 156 ("Correlation
    Event for 5.4+").
  * Malware events from AMP for Endpoints (FireAMP), record 125, data block 80
    ("Malware Event Data Block 7.0+").
  * VPN login and logoff, records 170 and 171: a discovery event header and a User
    Login Information data block 167 ("6.2+") holding a VPN Session block 166.

Layouts from Cisco's public "Secure Firewall Management Center eStreamer Integration
Guide" (7.2), checked against an FMC 7.6.6. Each decode_*() returns a dict of the
record's fields (the guide's names); *_fields() add names from the metadata tables
and give the Splunk event (CIM field names where the Common Information Model has
one, else the Cisco Security Cloud app's style); fmc_estreamer_cef gives the CEF line.
"""
import json
import re
import struct

import fmc_estreamer_protocol as proto
from fmc_estreamer_protocol import DecodeError, ip_text, string_value, uuid_text

RECORD_CORRELATION = 112
RECORD_MALWARE = 125
RECORD_VPN_LOGIN = 170
RECORD_VPN_LOGOFF = 171

_FMT = {"B": "B", "H": "H", "L": "L", "Q": "Q", "uuid": "16s", "ip": "16s", "ip4": "4s", "h20": "20s"}


class Block:
    """A fixed layout: runs of fixed-size fields (one struct each) and string blocks."""

    def __init__(self, spec):
        self.steps, run = [], []
        for item in spec.split() + ["-:end"]:
            name, kind = item.split(":")
            if kind in ("str", "end"):
                if run:
                    st = struct.Struct(">" + "".join(_FMT[k] for _, k in run))
                    self.steps.append(("fixed", st, tuple(run)))
                    run = []
                if kind == "str":
                    self.steps.append(("str", name, None))
            else:
                run.append((name, kind))

    def decode(self, data, off, out):
        end = len(data)
        for step, a, b in self.steps:
            if step == "str":
                if off + 8 > end:
                    raise DecodeError(f"{a}: string block past end of record")
                _, length = struct.unpack_from(">LL", data, off)
                if length < 8 or off + length > end:
                    raise DecodeError(f"{a}: string block length {length} invalid")
                out[a] = string_value(data[off + 8: off + length])
                off += length
                continue
            if off + a.size > end:
                raise DecodeError(f"{b[0][0]}: field past end of record")
            for (name, kind), value in zip(b, a.unpack_from(data, off)):
                if kind == "uuid":
                    value = uuid_text(value)
                elif kind == "ip":
                    value = ip_text(value)
                elif kind in ("ip4", "h20"):
                    value = value.hex()
                out[name] = value
            off += a.size
        return off


# ---- correlation event, data block 156
CORRELATION_156 = Block("""
blockType:L blockLength:L deviceId:L eventSecond:L eventId:L policyId:L ruleId:L priority:L
description:str eventType:B eventDeviceId:L signatureId:L signatureGeneratorId:L triggerEventSecond:L
triggerEventMicrosecond:L deviceEventId:L eventDefinedMask:L eventImpactFlags:B ipProtocol:B
networkProtocol:H sourceIp:ip4 sourceHostType:B sourceVlanId:H sourceOsUuid:uuid sourceCriticality:H
sourceUserId:L sourcePort:H sourceServerId:L destinationIp:ip4 destinationHostType:B destinationVlanId:H
destinationOsUuid:uuid destinationCriticality:H destinationUserId:L destinationPort:H destinationServiceId:L
impact:B blocked:B intrusionPolicy:uuid ruleAction:L netbios:str urlCategory:L urlReputation:L url:str
clientId:L clientVersion:str acPolicyRevision:uuid acRuleId:L ingressInterface:uuid egressInterface:uuid
ingressZone:uuid egressZone:uuid sourceIpAddress:ip destinationIpAddress:ip sourceCountry:H
destinationCountry:H siPolicy:uuid securityContext:uuid sslPolicyId:uuid sslRuleId:L sslActualAction:L
sslFlowStatus:L sslCertificateFingerprint:h20
""")

# ---- malware event (AMP for Endpoints), data block 80
MALWARE_80 = Block("""
blockType:L blockLength:L agentUuid:uuid cloudUuid:uuid malwareEventTimestamp:L eventTypeId:L
eventSubtypeId:L detectorId:B detectionName:str user:str fileName:str filePath:str fileShaHash:str
fileSize:L fileType:L fileTimestamp:L parentFileName:str parentFileShaHash:str eventDescription:str
deviceId:L connectionInstance:H connectionCounter:H connectionEventTimestamp:L direction:B
sourceIpAddress:ip destinationIpAddress:ip applicationId:L userId:L accessControlPolicyUuid:uuid
disposition:B retroDisposition:B uri:str sourcePort:H destinationPort:H sourceCountry:H
destinationCountry:H webApplicationId:L clientApplicationId:L action:B protocol:B threatScore:B
iocNumber:H securityContext:uuid sslCertificateFingerprint:h20 sslActualAction:H sslFlowStatus:H
archiveSha:str archiveName:str archiveDepth:B httpResponse:L ingressVrfName:str egressVrfName:str
""")

# ---- VPN login / logoff: user login information block 167 and VPN session block 166
USER_LOGIN_167 = Block("""
blockType:L blockLength:L timestamp:L ipv4Address:L userName:str domain:str userId:L realmId:L
endpointProfileId:L securityGroupId:L protocol:L port:H rangeStart:H startPort:H endPort:H email:str
ipv6Address:ip locationIpv6Address:ip loginType:B authType:B reportedBy:str description:str
""")
VPN_SESSION_166 = Block("""
vpnBlockType:L vpnBlockLength:L sessionIndex:L vpnType:B groupPolicy:str connectionProfile:str
clientIpAddress:ip clientCountry:H clientOperatingSystem:str clientApplication:str
connectionDuration:L bytesTransmitted:Q bytesReceived:Q
""")

DISPOSITIONS = {1: "Clean", 2: "Unknown", 3: "Malware", 4: "Unavailable", 5: "Custom Signature"}
FILE_DIRECTIONS = {1: "Download", 2: "Upload"}
FILE_ACTIONS = {1: "Detect", 2: "Block", 3: "Malware Cloud Lookup", 4: "Malware Block", 5: "Malware Allow List",
                6: "Cloud Lookup Timeout", 7: "Custom Detection", 8: "Custom Detection Block",
                9: "Archive Block (Depth Exceeded)", 10: "Archive Block (Encrypted)",
                11: "Archive Block (Failed to Inspect)"}
VPN_TYPES = {0: "Unknown", 1: "Cisco IKEv1 Client", 2: "AnyConnect IKEv1 Client", 3: "AnyConnect SSL",
             4: "WebVPN Clientless", 5: "Site to Site IKEv2", 6: "Site to Site IKEv2", 7: "Generic IKEv2 RA Client"}
AUTH_TYPES = {0: "No Authorization Required", 1: "Passive Authentication", 2: "Captive Portal",
              3: "Captive Portal Guest", 4: "Captive Portal Failed", 5: "VPN Authentication"}
USER_PROTOCOLS = {165: "FTP", 426: "SIP", 547: "AIM", 683: "IMAP", 710: "LDAP", 767: "NTP",
                  773: "Oracle Database", 788: "POP3", 1755: "MDNS"}

# Correlation "blocked" codes (Integration Guide) -> text, as earlier CEF exports wrote them.
CORRELATION_BLOCKED = {0: "No", 1: "Yes", 2: "Would", 3: "Partially Dropped", 4: "Block",
                       5: "Would be Blocked", 6: "Partial Block", 7: "Drop", 8: "Would Drop", 9: "Reject",
                       10: "Would be Rejected", 11: "Rejected", 12: "Would be Rejected", 13: "Rewrite",
                       14: "Would be Rewritten"}
CORRELATION_TRIGGERS = {1: "intrusion", 2: "host discovery", 3: "user", 4: "connection", 5: "host input",
                        6: "white list", 7: "malware", 8: "file"}


def impact_from_flags(bits):
    """Impact level 1 (red) .. 4 (blue) from the impact flag bits, 0 when unknown (Integration Guide)."""
    if bits & 0b11011000:
        return 1
    if bits & 0b00000110 == 0b00000110:
        return 2
    if bits & 0b00000010:
        return 3
    if bits & 0b00000001:
        return 4
    return 0


def decode_correlation(data):
    rtype, rlen, ats, _cs, off = proto.record_header(data)
    if rtype != RECORD_CORRELATION:
        raise DecodeError(f"record type {rtype} is not a correlation event")
    btype = struct.unpack_from(">L", data, off)[0] if off + 4 <= len(data) else None
    if btype != 156:
        raise DecodeError(f"correlation event data block {btype} is not one this version reads")
    rec = {"recordType": rtype, "archiveTimestamp": ats}
    end = CORRELATION_156.decode(data, off, rec)
    rec["unread"] = len(data) - end
    return rec


def decode_malware(data):
    rtype, _rlen, ats, _cs, off = proto.record_header(data)
    if rtype != RECORD_MALWARE:
        raise DecodeError(f"record type {rtype} is not a malware event")
    btype = struct.unpack_from(">L", data, off)[0] if off + 4 <= len(data) else None
    if btype != 80:
        raise DecodeError(f"malware event data block {btype} is not one this version reads")
    rec = {"recordType": rtype, "archiveTimestamp": ats}
    end = MALWARE_80.decode(data, off, rec)
    rec["unread"] = len(data) - end
    return rec


_DISCOVERY = struct.Struct(">LL6sBBLLLLLL")


def decode_vpn(data):
    """VPN login (170) or logoff (171): discovery header, block 167, VPN session block 166."""
    rtype, _rlen, ats, _cs, off = proto.record_header(data)
    if rtype not in (RECORD_VPN_LOGIN, RECORD_VPN_LOGOFF):
        raise DecodeError(f"record type {rtype} is not a VPN login or logoff")
    if off + 40 > len(data):
        raise DecodeError("VPN record shorter than the discovery header")
    (device, _legacy_ip, _mac, has_ipv6, _pad, event_sec, event_usec, event_type, event_subtype,
     _x1, _x2) = _DISCOVERY.unpack_from(data, off)
    off += 40
    rec = {"recordType": rtype, "archiveTimestamp": ats, "deviceId": device, "eventSecond": event_sec,
           "eventMicrosecond": event_usec, "eventType": event_type, "eventSubtype": event_subtype}
    if has_ipv6 == 1:
        rec["hostIpAddr"] = proto.ip_text(data[off:off + 16])
        off += 16
    if off + 8 > len(data):
        raise DecodeError("VPN record has no data block")
    btype, blen = struct.unpack_from(">LL", data, off)
    if btype != 167:
        raise DecodeError(f"user login data block {btype} is not one this version reads")
    block_end = off + blen
    if block_end > len(data):
        raise DecodeError("user login block past end of record")
    end = USER_LOGIN_167.decode(data[:block_end], off, rec)
    if end + 8 <= block_end and struct.unpack_from(">L", data, end)[0] == 166:
        end = VPN_SESSION_166.decode(data[:block_end], end, rec)
    rec["unread"] = len(data) - end
    return rec


def _user(t, ident):
    if not ident:
        return None
    return t["users"].get(ident) or str(ident)


def correlation_fields(rec, names, fmc_host):
    """
    Correlation (policy violation) event -> Splunk event dict. Fields the Cisco Security
    Cloud app aliases on cisco:sfw:estreamer (InitiatorIP AS src, ...) carry its source
    names, so its search-time rules make the CIM fields (an alias with AS would blank a
    CIM-named field we wrote ourselves), also where only that app runs at search time.
    """
    t = names.t
    device = rec.get("eventDeviceId")
    rev = rec.get("acPolicyRevision")
    proto_name = t["ipProtocols"].get(rec.get("ipProtocol"))
    ev = {
        "time": rec.get("eventSecond") or rec.get("archiveTimestamp"),
        "EventType": "CorrelationEvent",
        "type": "alert",
        "EventID": rec.get("eventId"),                                     # -> id, event_id
        "CorrelationRule": t["corrRules"].get(rec.get("ruleId")) or str(rec.get("ruleId")),
        # The Cisco Security Cloud app fills signature only from IntrusionRuleMessage (or ThreatName):
        # the rule name goes there too, so signature is set where only that app runs at search time.
        "IntrusionRuleMessage": t["corrRules"].get(rec.get("ruleId")) or str(rec.get("ruleId")),
        "CorrelationRuleID": rec.get("ruleId"),
        "CorrelationPolicy": t["corrPolicies"].get(rec.get("policyId")) or str(rec.get("policyId")),
        "CorrelationPolicyID": rec.get("policyId"),
        "description": rec.get("description"),
        "priority": rec.get("priority"),
        "impact": rec.get("impact"),
        "Blocked": CORRELATION_BLOCKED.get(rec.get("blocked"), rec.get("blocked")),
        "TriggerEventType": CORRELATION_TRIGGERS.get(rec.get("eventType"), rec.get("eventType")),
        "TriggerEventSecond": rec.get("triggerEventSecond"),
        "InitiatorIP": rec.get("sourceIpAddress"), "InitiatorPort": rec.get("sourcePort"),        # -> src, src_port
        "ResponderIP": rec.get("destinationIpAddress"), "ResponderPort": rec.get("destinationPort"),  # -> dest
        "Protocol": proto_name.lower() if isinstance(proto_name, str) else rec.get("ipProtocol"),  # -> transport
        "user": _user(t, rec.get("sourceUserId")), "user_id": rec.get("sourceUserId"),
        "dest_user": _user(t, rec.get("destinationUserId")), "dest_user_id": rec.get("destinationUserId"),
        "ClientApplication": t["clientApps"].get(rec.get("clientId")) if rec.get("clientId") else None,
        "URL": rec.get("url"),                                             # -> url
        "url_category": t["urlCategories"].get(rec.get("urlCategory")) if rec.get("urlCategory") else None,
        "url_reputation": t["urlReputations"].get(rec.get("urlReputation")) if rec.get("urlReputation") else None,
        "IngressInterface": t["interfaces"].get(rec.get("ingressInterface")),
        "EgressInterface": t["interfaces"].get(rec.get("egressInterface")),
        "IngressZone": t["securityZones"].get(rec.get("ingressZone")),
        "EgressZone": t["securityZones"].get(rec.get("egressZone")),
        "InitiatorCountry": t["geolocations"].get(rec.get("sourceCountry")),
        "ResponderCountry": t["geolocations"].get(rec.get("destinationCountry")),
        "FirewallPolicy": t["acPolicies"].get((device, rev)) if rev else None,
        "FirewallRule": t["acRules"].get((rev, rec.get("acRuleId"))) if rec.get("acRuleId") else None,
        "vlan_id": rec.get("sourceVlanId") or None,
        "Device": t["devices"].get(device) if device is not None else None,
        "DeviceID": device,
        "SourceHost": fmc_host,
        "archive_ts": rec.get("archiveTimestamp"),
    }
    return _set(ev)


def _set(ev):
    return {k: v for k, v in ev.items() if not _unset(v)}


_ZERO_TEXT = re.compile(r"^(?:0{8}-0{4}-0{4}-0{4}-0{12}|0\.0\.0\.0|::|0{16,})$")   # zero UUID, address, hash


def _unset(v):
    """None, "", 0, and all-zero UUIDs, addresses and hashes carry nothing; other text is kept."""
    if v is None or v == "":
        return True
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return v == 0
    if isinstance(v, str):
        return bool(_ZERO_TEXT.match(v))
    return False


def _proto_name(t, number):
    name = t["ipProtocols"].get(number) if number else None
    return name.lower() if isinstance(name, str) else (number or None)


def malware_fields(rec, names, fmc_host):
    """
    Malware (AMP for Endpoints / FireAMP) event -> Splunk event dict, with the source names
    the Cisco Security Cloud app maps to CIM Malware fields (ThreatName -> signature,
    FileName -> file_name, FileSHA256 -> file_hash, FileAction -> action, InitiatorIP -> src, ...).
    """
    t = names.t
    device = rec.get("deviceId")
    action = rec.get("action")
    rev = rec.get("accessControlPolicyUuid")
    ev = {
        "time": rec.get("malwareEventTimestamp") or rec.get("archiveTimestamp"),
        "EventType": "MalwareEvent",
        "ThreatName": rec.get("detectionName"),
        "IntrusionRuleMessage": rec.get("detectionName"),     # -> signature (as for policy violations)
        "MalwareEventType": t["malwareEventTypes"].get(rec.get("eventTypeId")) or rec.get("eventTypeId"),
        "MalwareEventSubtype": t["malwareEventSubtypes"].get(rec.get("eventSubtypeId")) or rec.get("eventSubtypeId"),
        "Detector": t["ampDetectors"].get(rec.get("detectorId")) or rec.get("detectorId"),
        "description": rec.get("eventDescription"),
        "FileAction": FILE_ACTIONS.get(action, action),
        "disposition": DISPOSITIONS.get(rec.get("disposition")),
        "RetroDisposition": DISPOSITIONS.get(rec.get("retroDisposition")),
        "ThreatScore": rec.get("threatScore"),
        "FileName": rec.get("fileName"), "file_path": rec.get("filePath"),
        "FileSHA256": rec.get("fileShaHash"), "FileSize": rec.get("fileSize"),
        "FileType": t["ampFileTypes"].get(rec.get("fileType")) or rec.get("fileType"),
        "FileCreateTime": rec.get("fileTimestamp"),
        "ParentFileName": rec.get("parentFileName"), "ParentFileSHA256": rec.get("parentFileShaHash"),
        "ArchiveFileName": rec.get("archiveName"), "ArchiveSHA": rec.get("archiveSha"),
        "ArchiveDepth": rec.get("archiveDepth"),
        "InitiatorIP": rec.get("sourceIpAddress"), "InitiatorPort": rec.get("sourcePort"),
        "ResponderIP": rec.get("destinationIpAddress"), "ResponderPort": rec.get("destinationPort"),
        "Protocol": _proto_name(t, rec.get("protocol")),
        "FileDirection": FILE_DIRECTIONS.get(rec.get("direction")),
        "user": rec.get("user") or (t["users"].get(rec.get("userId")) if rec.get("userId") else None),
        "user_id": rec.get("userId"),
        "Application": t["appProtocols"].get(rec.get("applicationId")) if rec.get("applicationId") else None,
        "ClientApplication": t["clientApps"].get(rec.get("clientApplicationId")) if rec.get("clientApplicationId") else None,
        "WebApplication": t["payloads"].get(rec.get("webApplicationId")) if rec.get("webApplicationId") else None,
        "URI": rec.get("uri"), "HTTP_Response": rec.get("httpResponse"),
        "InitiatorCountry": t["geolocations"].get(rec.get("sourceCountry")) if rec.get("sourceCountry") else None,
        "ResponderCountry": t["geolocations"].get(rec.get("destinationCountry")) if rec.get("destinationCountry") else None,
        "FirewallPolicy": (t["acPolicies"].get((device, rev)) or rev) if not _unset(rev) else None,
        "IngressVRF": rec.get("ingressVrfName"), "EgressVRF": rec.get("egressVrfName"),
        "AMP_Cloud": t["ampClouds"].get(rec.get("cloudUuid")),
        "AgentUUID": rec.get("agentUuid"),
        "Device": t["devices"].get(device) if device else None,
        "DeviceID": device,
        "InstanceID": rec.get("connectionInstance") if device else None,
        "ConnectionID": rec.get("connectionCounter") if device else None,
        "SourceHost": fmc_host,
        "archive_ts": rec.get("archiveTimestamp"),
    }
    return _set(ev)


def vpn_fields(rec, names, fmc_host):
    """
    VPN login or logoff -> Splunk event dict. The client's public address is InitiatorIP and
    the address the VPN assigned is ResponderIP (and AssignedIP), so the Cisco Security Cloud
    app's aliases give CIM Network Sessions src_ip / dest_ip (and src / dest); bytes as
    InitiatorBytes (from the client) and ResponderBytes (to the client), as for connections.
    action = success for logins: AC_RuleAction (that app's action rule passes it through), and
    this add-on's lookup on EventType where only this add-on runs at search time.
    """
    t = names.t
    device = rec.get("deviceId")
    login = rec.get("recordType") == RECORD_VPN_LOGIN
    assigned = rec.get("ipv6Address") or rec.get("hostIpAddr")
    ev = {
        "time": rec.get("eventSecond") or rec.get("timestamp") or rec.get("archiveTimestamp"),
        "EventType": "VPNLoginEvent" if login else "VPNLogoffEvent",
        # The Cisco Security Cloud app's action rule passes AC_RuleAction through when it is not
        # Allow/Trust/Block: action = success for logins (CIM Authentication).
        "AC_RuleAction": "success" if login else None,
        "user": rec.get("userName") or (t["users"].get(rec.get("userId")) if rec.get("userId") else None),
        "user_id": rec.get("userId"),
        "user_domain": rec.get("domain"), "user_email": rec.get("email"),
        "InitiatorIP": rec.get("clientIpAddress"),     # -> src, src_ip: the client's public address
        "ResponderIP": assigned,                       # -> dest, dest_ip: the address the VPN assigned
        "AssignedIP": assigned,
        "InitiatorCountry": t["geolocations"].get(rec.get("clientCountry")) if rec.get("clientCountry") else None,
        "duration": None if login else rec.get("connectionDuration"),
        "InitiatorBytes": None if login else rec.get("bytesReceived"),     # from the client -> bytes_in
        "ResponderBytes": None if login else rec.get("bytesTransmitted"),  # to the client -> bytes_out
        "session_id": rec.get("sessionIndex"),
        "VPN_Type": VPN_TYPES.get(rec.get("vpnType"), rec.get("vpnType")),
        "GroupPolicy": rec.get("groupPolicy"),
        "ConnectionProfile": rec.get("connectionProfile"),
        "ClientOS": rec.get("clientOperatingSystem"),
        "ClientApplication": rec.get("clientApplication"),
        "reason": rec.get("description"),
        "Realm": t["realms"].get(rec.get("realmId")) if rec.get("realmId") else None,
        "AuthenticationType": AUTH_TYPES.get(rec.get("authType"), rec.get("authType")),
        "ReportedBy": rec.get("reportedBy"),
        "UserProtocol": USER_PROTOCOLS.get(rec.get("protocol"), rec.get("protocol")),
        "Device": t["devices"].get(device) if device else None,
        "DeviceID": device,
        "SourceHost": fmc_host,
        "archive_ts": rec.get("archiveTimestamp"),
    }
    out = _set(ev)
    if not login:                                   # a logoff of 0 bytes or 0 s still says so
        for key in ("duration", "InitiatorBytes", "ResponderBytes"):
            out.setdefault(key, ev[key] or 0)
    return out


def to_json(event):
    """Splunk event dict ("time" first) -> one compact JSON line."""
    return json.dumps(event, default=str, separators=(",", ":"))


# record type -> (decoder, Splunk fields, CEF builder name)
EVENT_TYPES = {
    RECORD_CORRELATION: (decode_correlation, correlation_fields, "correlation"),
    RECORD_MALWARE: (decode_malware, malware_fields, "malware"),
    RECORD_VPN_LOGIN: (decode_vpn, vpn_fields, "vpn"),
    RECORD_VPN_LOGOFF: (decode_vpn, vpn_fields, "vpn"),
}
