# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer_cef.py - CEF lines for the add-on's CEF output.

One line per event:
    CEF:0|Cisco|Firepower|6.0|<event class id>|<name>|<severity>|<extension>
The extension uses the standard CEF keys (src, dst, spt, act, cs1..cs6, ...), which
SIEMs map to their own columns. A syslog agent that reads the CEF files adds the
syslog header in front of each line.

Escaping follows the CEF specification: in the header, backslash and pipe; in
extension values, backslash, equals sign and line breaks.

The event class ids and names are the ones Cisco's earlier CEF exports used
(RNA:1003:1 CONNECTION STATISTICS, PV:112:<rule>:<policy> POLICY VIOLATION, ...),
so existing searches keep matching.
"""
import ipaddress
import re
import time

from fmc_estreamer_events import (CORRELATION_BLOCKED, DISPOSITIONS, FILE_ACTIONS, RECORD_VPN_LOGIN, VPN_TYPES,
                                  impact_from_flags)

VENDOR = "Cisco"
PRODUCT = "Firepower"
DEVICE_VERSION = "6.0"

# Time fields: rt, start, end and fileCreateTime in milliseconds since the epoch, as earlier
# exports wrote them (TIME_FORMAT "ms"). "date" gives the CEF date form "MMM dd yyyy
# HH:mm:ss" (UTC) for start, end and fileCreateTime instead.
TIME_FORMAT = "ms"

# Intrusion "blocked" codes -> action text, as earlier CEF exports wrote them.
BLOCKED_NAMES = ("Alerted", "Dropped", "Would Be Blocked", "Partially Dropped", "Blocked", "Would be Block",
                 "Partial Blocked", "Dropped", "Would be Dropped", "Rejected", "Would Rejected", "Rejected",
                 "Would be Rejected", "Rewritten", "Would be Rewritten")

# Severity from event priority (1 high .. 3 low) and impact (1 red .. 5 gray).
_SEVERITY = {1: {1: 10, 2: 9, 3: 7, 4: 8, 5: 9},
             2: {1: 7, 2: 6, 3: 4, 4: 5, 5: 6},
             3: {1: 3, 2: 2, 3: 0, 4: 1, 5: 2}}


def severity(priority, impact):
    return _SEVERITY.get(priority, {}).get(impact, 5)


def esc_header(value):
    """Header fields: backslash and pipe escaped; line breaks (not allowed in a header) become spaces."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    if "\n" in text or "\r" in text:
        text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return text


def esc_value(value):
    text = str(value)
    if "\\" in text:
        text = text.replace("\\", "\\\\")
    if "=" in text:
        text = text.replace("=", "\\=")
    if "\n" in text or "\r" in text:
        text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
    return text


def ms(seconds):
    """Seconds since the epoch -> milliseconds (None for 0 or missing)."""
    return int(seconds) * 1000 if seconds else None


def when(seconds):
    if not seconds:
        return None
    if TIME_FORMAT == "date":
        return time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
    return int(seconds) * 1000


def split_ip(text):
    """IP text -> (IPv4 text or None, IPv6 text or None); IPv4-mapped IPv6 counts as IPv4."""
    if not text:
        return None, None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None, None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.version == 4:
        return (str(addr), None) if int(addr) else (None, None)
    return (None, str(addr)) if int(addr) else (None, None)


_ZERO_TEXT = re.compile(r"^(?:0{8}-0{4}-0{4}-0{4}-0{12}|0\.0\.0\.0|::|0{16,})$")   # zero UUID, address, hash


def unset(value):
    """True for values that carry nothing: None, "", 0, and all-zero UUIDs, addresses and hashes."""
    if value is None or value == "":
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return bool(_ZERO_TEXT.match(value))
    return False


class Cef:
    """One CEF line, built key by key. Unset values (see unset()) are left out."""

    def __init__(self, class_id, name, sev):
        self.head = "|".join(("CEF:0", VENDOR, PRODUCT, DEVICE_VERSION, esc_header(class_id),
                              esc_header(name), esc_header(sev)))
        self.parts = []

    def add(self, key, value, keep_zero=False):
        if value is None or value == "" or (not keep_zero and unset(value)):
            return self
        self.parts.append(f"{key}={esc_value(value)}")
        return self

    def labelled(self, key, label, value):
        """A custom field (cs1, cn1, flexString1, ...) with its label, only when it has a value."""
        if unset(value):
            return self
        self.parts.append(f"{key}={esc_value(value)}")
        self.parts.append(f"{key}Label={esc_value(label)}")
        return self

    def addresses(self, src, dst):
        """src/dst for IPv4 (IPv4-mapped included), c6a2/c6a3 for IPv6, as earlier exports did."""
        s4, s6 = split_ip(src)
        d4, d6 = split_ip(dst)
        self.add("src", s4).add("dst", d4)
        if s6:
            self.labelled("c6a2", "sourceIPv6Address", s6)
        if d6:
            self.labelled("c6a3", "destinationIPv6Address", d6)
        return self

    def line(self):
        return self.head + "|" + " ".join(self.parts)


# ------------------------------------------------------------------ connection events (71)

def connection(record, fields, fmc_name, user_name=None):
    """
    Connection event -> CEF. record: the decoded record (raw values); fields: the
    output fields with names resolved (fmc_estreamer_protocol.connection_fields).
    """
    action = record.get("ruleAction") or 0
    c = Cef("RNA:1003:1", "CONNECTION STATISTICS", 3 if action < 4 else 7)
    first, last = record.get("firstPacketTimestamp"), record.get("lastPacketTimestamp")
    c.add("rt", ms(first)).add("start", when(first)).add("end", when(last))
    c.addresses(record.get("initiatorIpAddress"), record.get("responderIpAddress"))
    c.add("spt", record.get("initiatorPort")).add("dpt", record.get("responderPort"))
    c.add("proto", record.get("protocol"))                      # the number, as today
    c.add("act", fields.get("fw_rule_action")).add("reason", fields.get("fw_rule_reason"))
    c.add("app", fields.get("app_proto")).add("requestClientApplication", fields.get("client_app"))
    c.add("request", record.get("clientUrl"))
    c.add("dvchost", fields.get("sensor")).add("deviceExternalId", record.get("deviceId"))
    c.add("dvcpid", record.get("instanceId")).add("externalId", record.get("connectionCounter"))
    c.add("deviceInboundInterface", fields.get("iface_ingress"))
    c.add("deviceOutboundInterface", fields.get("iface_egress"))
    user = record.get("userId")
    c.add("suser", user_name or user).add("suid", user)
    c.add("in", record.get("responderTransmittedBytes"), keep_zero=True)
    c.add("out", record.get("initiatorTransmittedBytes"), keep_zero=True)
    c.add("destinationDnsDomain", record.get("dnsQuery"))
    nat_src, _ = split_ip(record.get("natInitiatorIp"))
    nat_dst, _ = split_ip(record.get("natResponderIp"))
    if nat_src:
        c.add("sourceTranslatedAddress", nat_src).add("sourceTranslatedPort", record.get("natInitiatorPort"))
    if nat_dst:
        c.add("destinationTranslatedAddress", nat_dst).add("destinationTranslatedPort", record.get("natResponderPort"))
    c.labelled("cs1", "fwPolicy", fields.get("fw_policy"))
    c.labelled("cs2", "fwRule", fields.get("fw_rule"))
    c.labelled("cs3", "ingressZone", fields.get("sec_zone_ingress"))
    c.labelled("cs4", "egressZone", fields.get("sec_zone_egress"))
    c.labelled("cs5", "secIntelCategory", fields.get("sec_intel_list1"))
    c.labelled("cs6", "fmcHost", fmc_name)
    c.labelled("flexString1", "destinationIpCountry", fields.get("dest_ip_country"))
    c.labelled("flexString2", "sourceIpCountry", fields.get("src_ip_country"))
    c.add("prefilterPolicy", fields.get("prefilter_policy")).add("tunnelRule", fields.get("tunnel_rule"))
    return c.line()


# ------------------------------------------------------------------ shared lookups

def _user(t, ident):
    """User name for a user id; the id itself when the name is not known; None for 0."""
    if not ident:
        return None
    return t["users"].get(ident) or ident


def _proto(t, number):
    if not number:
        return None
    return t["ipProtocols"].get(number) or number


def _country(t, code):
    """Country name for a country code; None for 0 (no country)."""
    return t["geolocations"].get(code) if code else None


def _device(t, device_id, fmc_name):
    """DeviceName: the firewall; the FMC's name for events no firewall generated (device 0)."""
    if device_id:
        return t["devices"].get(device_id) or device_id
    return fmc_name


def _policy(t, device_id, revision):
    if unset(revision):
        return None
    return t["acPolicies"].get((device_id, revision)) or revision


# ------------------------------------------------------------------ correlation events (112)

def correlation(rec, names, fmc_name):
    """Correlation (policy violation) event -> CEF."""
    t = names.t
    device = rec.get("eventDeviceId") or rec.get("deviceId")
    rev = rec.get("acPolicyRevision")
    c = Cef(f"PV:112:{rec.get('ruleId')}:{rec.get('policyId')}", "POLICY VIOLATION",
            severity(rec.get("priority"), impact_from_flags(rec.get("eventImpactFlags") or 0)))
    c.add("rt", ms(rec.get("eventSecond")))
    c.add("act", CORRELATION_BLOCKED.get(rec.get("blocked"), rec.get("blocked")), keep_zero=True)
    c.add("msg", rec.get("description"))
    c.addresses(rec.get("sourceIpAddress"), rec.get("destinationIpAddress"))
    c.add("spt", rec.get("sourcePort")).add("dpt", rec.get("destinationPort"))
    c.add("proto", rec.get("ipProtocol"))                       # the number, as today
    c.add("dvchost", _device(t, device, fmc_name)).add("deviceExternalId", device)
    c.add("externalId", rec.get("eventId"))
    c.add("deviceInboundInterface", t["interfaces"].get(rec.get("ingressInterface")))
    c.add("deviceOutboundInterface", t["interfaces"].get(rec.get("egressInterface")))
    src_user, dst_user = rec.get("sourceUserId"), rec.get("destinationUserId")
    c.add("suser", _user(t, src_user)).add("suid", src_user)
    c.add("duser", _user(t, dst_user)).add("duid", dst_user)
    c.add("request", rec.get("url"))
    c.add("requestClientApplication", t["clientApps"].get(rec.get("clientId")) if rec.get("clientId") else None)
    c.labelled("cs1", "policy", t["corrPolicies"].get(rec.get("policyId")) or rec.get("policyId"))
    c.labelled("cs2", "policyRule", t["corrRules"].get(rec.get("ruleId")) or rec.get("ruleId"))
    c.labelled("cs3", "ingressZone", t["securityZones"].get(rec.get("ingressZone")))
    c.labelled("cs4", "egressZone", t["securityZones"].get(rec.get("egressZone")))
    rule = rec.get("acRuleId")
    c.labelled("cs5", "fwRule", (t["acRules"].get((rev, rule)) or rule) if rule else None)
    c.labelled("cs6", "fmcHost", fmc_name)
    c.labelled("cn1", "vlan", rec.get("sourceVlanId"))
    c.labelled("flexString1", "destinationIpCountry", _country(t, rec.get("destinationCountry")))
    c.labelled("flexString2", "sourceIpCountry", _country(t, rec.get("sourceCountry")))
    return c.line()


# ------------------------------------------------------------------ malware events, AMP for Endpoints (125)

def malware(rec, names, fmc_name):
    """Malware (FireAMP) event -> CEF."""
    t = names.t
    device = rec.get("deviceId")
    c = Cef("FireAMP:125:1", "FireAMP Event", (rec.get("threatScore") or 0) / 10)   # as today: 0.0 .. 10.0
    c.add("rt", ms(rec.get("malwareEventTimestamp"))).add("start", when(rec.get("connectionEventTimestamp")))
    c.addresses(rec.get("sourceIpAddress"), rec.get("destinationIpAddress"))
    c.add("spt", rec.get("sourcePort")).add("dpt", rec.get("destinationPort"))
    c.add("proto", rec.get("protocol"))                         # the number, as for file events today
    c.add("dvchost", _device(t, device, fmc_name)).add("deviceExternalId", device)
    c.add("dvcpid", rec.get("connectionInstance") if device else None)
    c.add("outcome", t["malwareEventTypes"].get(rec.get("eventTypeId")) or rec.get("eventTypeId"))
    c.add("act", FILE_ACTIONS.get(rec.get("action")))
    direction = rec.get("direction")
    c.add("deviceDirection", {1: 0, 2: 1}.get(direction), keep_zero=True)
    c.add("app", t["appProtocols"].get(rec.get("applicationId")) if rec.get("applicationId") else None)
    c.add("requestClientApplication",
          t["clientApps"].get(rec.get("clientApplicationId")) if rec.get("clientApplicationId") else None)
    c.add("request", rec.get("uri"))
    c.add("duser", rec.get("user") or _user(t, rec.get("userId"))).add("duid", rec.get("userId"))
    c.add("fname", rec.get("fileName")).add("filePath", rec.get("filePath"))
    c.add("fileHash", rec.get("fileShaHash")).add("fsize", rec.get("fileSize"))
    c.add("fileType", t["ampFileTypes"].get(rec.get("fileType")) or rec.get("fileType"))
    c.add("fileCreateTime", when(rec.get("fileTimestamp")))
    c.add("sproc", rec.get("parentFileName"))
    c.labelled("cs1", "policy", _policy(t, device, rec.get("accessControlPolicyUuid")))
    c.labelled("cs2", "virusName", rec.get("detectionName"))
    c.labelled("cs3", "disposition", DISPOSITIONS.get(rec.get("disposition")))
    c.labelled("cs4", "retroDisposition", DISPOSITIONS.get(rec.get("retroDisposition")))
    c.labelled("cs5", "eventDescription", rec.get("eventDescription"))
    c.labelled("cs6", "fmcHost", fmc_name)
    c.labelled("flexString1", "destinationIpCountry", _country(t, rec.get("destinationCountry")))
    c.labelled("flexString2", "sourceIpCountry", _country(t, rec.get("sourceCountry")))
    return c.line()


# ------------------------------------------------------------------ VPN login / logoff (170, 171)

def vpn(rec, names, fmc_name):
    """VPN login or logoff -> CEF. src is the client's public address; the address the
    VPN assigned to it is sourceTranslatedAddress."""
    t = names.t
    device = rec.get("deviceId")
    login = rec.get("recordType") == RECORD_VPN_LOGIN
    c = Cef("USER:1004:8" if login else "USER:1004:2", "VPN Login" if login else "VPN", 3)
    event = rec.get("eventSecond") or rec.get("timestamp")
    duration = rec.get("connectionDuration") or 0
    c.add("rt", ms(event))
    c.add("start", when(event - duration if (not login and duration and event) else event))
    c.add("end", when(event))
    c.addresses(rec.get("clientIpAddress"), None)
    assigned, _ = split_ip(rec.get("ipv6Address") or rec.get("hostIpAddr"))
    c.add("sourceTranslatedAddress", assigned)
    c.add("dvchost", _device(t, device, fmc_name)).add("deviceExternalId", device)
    c.add("suser", rec.get("userName") or _user(t, rec.get("userId"))).add("suid", rec.get("userId"))
    c.add("sntdom", rec.get("domain"))
    c.add("externalId", rec.get("sessionIndex"))
    c.add("requestClientApplication", rec.get("clientApplication"))
    c.add("msg", rec.get("description"))
    if not login:
        c.add("in", rec.get("bytesTransmitted"), keep_zero=True)
        c.add("out", rec.get("bytesReceived"), keep_zero=True)
        c.labelled("cn1", "connectionDuration", duration)
    c.labelled("cs1", "groupPolicy", rec.get("groupPolicy"))
    c.labelled("cs2", "vpnType", VPN_TYPES.get(rec.get("vpnType"), rec.get("vpnType")))
    c.labelled("cs3", "clientOS", rec.get("clientOperatingSystem"))
    c.labelled("cs4", "clientApplication", rec.get("clientApplication"))
    c.labelled("cs5", "vpnProfile", rec.get("connectionProfile"))
    c.labelled("cs6", "fmcHost", fmc_name)
    c.labelled("flexString2", "sourceIpCountry", _country(t, rec.get("clientCountry")))
    return c.line()


# ------------------------------------------------------------------ FQE events (JSON from the FMC)

# Packet bytes in CEF, as hex characters: a whole 1,514-byte Ethernet frame (payload in cs1, frame in
# packetData) keeps the line under syslog's usual 8 KB message limit; longer packets are cut.
PACKET_HEX_MAX = 3100
_IMPACT_WORDS = (("currently not vulnerable", 3), ("potentially vulnerable", 2), ("unknown target", 4),
                 ("vulnerable", 1), ("unknown", 5))


def _g(obj, *keys):
    """First set value among keys (FQE leaves out fields that do not apply)."""
    for key in keys:
        value = obj.get(key)
        if value is not None and value != "":
            return value
    return None


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _proto_number(names, obj):
    number = _int(obj.get("ProtocolID"))
    if number:
        return number
    name = str(obj.get("Protocol") or "").upper()
    if not name:
        return None
    for num, text in names.t["ipProtocols"].items() if names else ():
        if str(text).upper() == name:
            return num
    return _int(name)


def _proto_text(names, obj):
    """Protocol name in capitals (as intrusion events have it today)."""
    number = _int(obj.get("ProtocolID"))
    if number and names and names.t["ipProtocols"].get(number):
        return str(names.t["ipProtocols"][number]).upper()
    text = obj.get("Protocol")
    return str(text).upper() if text else number


def _device_id(names, device):
    if not names or not device:
        return None
    return getattr(names, "device_ids", {}).get(device)


def _impact(value):
    number = _int(value)
    if number is not None:
        return number
    text = str(value or "").lower()
    for word, level in _IMPACT_WORDS:
        if word in text:
            return level
    return 0


def _user_fqe(obj, names):
    user = _g(obj, "UserName", "User")
    ident = _int(obj.get("UserID"))
    if not user and ident and names:
        user = names.t["users"].get(ident)
    return user or ident, ident


# File actions of file malware events (binary record 502); Detect and Block are plain file events (500).
MALWARE_FILE_ACTIONS = {"malware cloud lookup", "malware block", "malware allow list", "cloud lookup timeout",
                        "custom detection", "custom detection block", "archive block (depth exceeded)",
                        "archive block (encrypted)", "archive block (failed to inspect)"}


def file_event(obj, names, fmc_name):
    """
    FQE FileEvent -> CEF, as earlier exports wrote record 500 (file event) and 502 (file
    malware event). FQE sends both as EventType FileEvent; the file action tells them
    apart (a malware cloud lookup, malware block, ... is a file malware event).
    """
    action = str(obj.get("FileAction") or "").lower()
    malware = action in MALWARE_FILE_ACTIONS or bool(_g(obj, "ThreatName")) or \
        "alware" in str(obj.get("EventType") or "")
    score = _int(obj.get("ThreatScore")) or 0
    c = Cef("FileMalware:502:1" if malware else "File:500:1",
            "File Malware Event" if malware else "File Event", score / 10)
    c.add("rt", ms(_int(obj.get("EventSecond")))).add("start", when(_int(obj.get("FirstPacketSecond"))))
    c.addresses(obj.get("InitiatorIP"), obj.get("ResponderIP"))
    c.add("spt", _int(obj.get("InitiatorPort"))).add("dpt", _int(obj.get("ResponderPort")))
    c.add("proto", _proto_number(names, obj))
    c.add("act", obj.get("FileAction"))
    c.add("app", obj.get("Application")).add("requestClientApplication", obj.get("ClientApplication"))
    c.add("request", obj.get("URI"))
    direction = str(obj.get("FileDirection") or "").lower()
    c.add("deviceDirection", {"download": 0, "upload": 1}.get(direction), keep_zero=True)
    c.add("fname", obj.get("FileName")).add("fileHash", obj.get("FileSHA256"))
    c.add("fsize", _int(obj.get("FileSize"))).add("fileType", obj.get("FileType"))
    device = obj.get("Device")
    c.add("dvchost", device or fmc_name).add("deviceExternalId", _device_id(names, device))
    c.add("dvcpid", _int(obj.get("InstanceID")))
    user, ident = _user_fqe(obj, names)
    c.add("suser", user).add("suid", ident)
    c.labelled("cs1", "filePolicy", obj.get("FilePolicy"))
    c.labelled("cs2", "disposition", obj.get("SHA_Disposition"))
    c.labelled("cs3", "speroDisposition", obj.get("SperoDisposition"))
    c.labelled("cs4", "signature", obj.get("ThreatName"))
    c.labelled("cs6", "fmcHost", fmc_name)
    c.labelled("flexString1", "destinationIpCountry", obj.get("ResponderCountry"))
    c.labelled("flexString2", "sourceIpCountry", obj.get("InitiatorCountry"))
    return c.line()


def intrusion_event(obj, names, fmc_name):
    """FQE IntrusionEvent -> CEF, as earlier exports wrote record 400 (rule ID now in cn3, cs6 = FMC)."""
    gid, sid = _int(obj.get("GeneratorID")) or 1, _int(obj.get("SignatureID"))
    impact = _impact(obj.get("Impact"))
    c = Cef(f"INTRUSION:400:{gid}:{sid}", obj.get("IntrusionRuleMessage") or "Intrusion Event",
            severity(_int(obj.get("PriorityID")), impact))
    c.add("rt", ms(_int(obj.get("EventSecond")))).add("start", when(_int(obj.get("FirstPacketSecond"))))
    c.addresses(obj.get("InitiatorIP"), obj.get("ResponderIP"))
    c.add("spt", _int(obj.get("InitiatorPort"))).add("dpt", _int(obj.get("ResponderPort")))
    c.add("proto", _proto_text(names, obj))
    result = _int(obj.get("InlineResultID"))
    c.add("act", BLOCKED_NAMES[result] if result is not None and 0 <= result < len(BLOCKED_NAMES)
          else obj.get("InlineResult"), keep_zero=True)
    c.add("cat", obj.get("Classification"))
    c.add("app", obj.get("Application")).add("requestClientApplication", obj.get("ClientApplication"))
    c.add("deviceInboundInterface", obj.get("IngressInterface"))
    c.add("deviceOutboundInterface", obj.get("EgressInterface"))
    device = obj.get("Device")
    c.add("dvchost", device or fmc_name).add("deviceExternalId", _device_id(names, device))
    c.add("dvcpid", _int(obj.get("InstanceID"))).add("externalId", _int(obj.get("EventID")))
    user, ident = _user_fqe(obj, names)
    c.add("suser", user).add("suid", ident)
    c.labelled("cs1", "fwPolicy", obj.get("FirewallPolicy"))
    c.labelled("cs2", "fwRule", obj.get("FirewallRule"))
    c.labelled("cs3", "ingressZone", obj.get("IngressZone"))
    c.labelled("cs4", "egressZone", obj.get("EgressZone"))
    c.labelled("cs5", "ipsPolicy", obj.get("IntrusionPolicy"))
    c.labelled("cs6", "fmcHost", fmc_name)
    c.labelled("cn1", "vlan", _int(obj.get("VLAN_ID")))
    c.labelled("cn2", "impact", impact)
    c.labelled("cn3", "ruleId", sid)
    c.labelled("flexString1", "destinationIpCountry", obj.get("ResponderCountry"))
    c.labelled("flexString2", "sourceIpCountry", obj.get("InitiatorCountry"))
    return c.line()


def l7_payload(packet):
    """Bytes after the Ethernet (and VLAN), IPv4/IPv6 and TCP/UDP headers; the whole packet otherwise."""
    try:
        off = 12
        ethertype = int.from_bytes(packet[off:off + 2], "big")
        off += 2
        while ethertype in (0x8100, 0x88A8):
            ethertype = int.from_bytes(packet[off + 2:off + 4], "big")
            off += 4
        if ethertype == 0x0800:
            ihl = (packet[off] & 0x0F) * 4
            l4, off = packet[off + 9], off + ihl
        elif ethertype == 0x86DD:
            l4, off = packet[off + 6], off + 40
            while l4 in (0, 43, 60):                       # hop-by-hop, routing, destination options
                l4, off = packet[off], off + (packet[off + 1] + 1) * 8
            if l4 == 44:                                   # fragment header
                l4, off = packet[off], off + 8
        else:
            return packet
        if l4 == 6:
            off += (packet[off + 12] >> 4) * 4
        elif l4 == 17:
            off += 8
        return packet[off:] if off <= len(packet) else b""
    except IndexError:
        return packet


def intrusion_packet(obj, names, fmc_name):
    """FQE IntrusionPacket -> CEF PKT:2:1: cs1 = payload (hex), packetData = whole packet (hex), as today."""
    c = Cef("PKT:2:1", "Packet Data", 7)
    c.add("rt", ms(_int(obj.get("EventSecond")))).add("start", when(_int(obj.get("PacketSecond"))))
    device = obj.get("Device")
    c.add("dvchost", device or fmc_name).add("deviceExternalId", _device_id(names, device))
    c.add("externalId", _int(obj.get("EventID")))
    data = str(obj.get("PacketData") or "")
    try:
        packet = bytes.fromhex(data)
    except ValueError:
        packet = b""
    payload = l7_payload(packet).hex() if packet else ""
    c.labelled("cs1", "payload", payload[:PACKET_HEX_MAX])
    c.labelled("cs6", "fmcHost", fmc_name)
    c.add("packetData", data[:PACKET_HEX_MAX])
    return c.line()
