# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer_protocol.py - eStreamer client messages, connection events and metadata.

Written for this add-on from the eStreamer protocol as published in Cisco's
public "Secure Firewall Management Center eStreamer Integration Guide".
Python standard library only.

It covers what the add-on needs and nothing more:
  * the three messages a client sends: Event Stream Request, Streaming
    Request and the null acknowledgment;
  * connection event records (type 71) with every Connection Statistics data
    block version from 160 to 174 (later versions: the 174 fields are read and
    anything after them is ignored);
  * the metadata records that name the ids in connection events (rules,
    policies, zones, interfaces, devices, applications, URL categories,
    countries, DNS and SSL codes, ...), kept in a small JSON file;
  * one compact JSON line per event, with the field names of the
    cisco:sfw:estreamer sourcetype.
The other binary event types are in fmc_estreamer_events.py, the FQE (JSON)
session in fmc_estreamer_fqe.py and the CEF output in fmc_estreamer_cef.py.
"""
import json
import os
import socket
import struct

from fmc_estreamer_tables import (DEFAULT_NAMES, EVENT_DESCRIPTIONS, FIREWALL_RULE_REASONS,
                                  IP_PROTOCOLS, SSL_ACTIONS, SSL_CERT_STATUSES, SSL_FLOW_FLAGS,
                                  SSL_FLOW_MESSAGES, SSL_FLOW_STATUSES, TLS_CIPHER_SUITES)

# ------------------------------------------------------------------ messages

HEADER = struct.Struct(">HHL")              # version, message type, body length
VERSION = 1

MSG_NULL = 0
MSG_ERROR = 1
MSG_EVENT_STREAM_REQUEST = 2
MSG_EVENT_DATA = 4
MSG_STREAMING_REQUEST = 2049
MSG_STREAMING_INFO = 2051
MSG_BUNDLE = 4002
STREAMING_SERVICE_ID = 6667
START_NOW = 0xFFFFFFFF
MAX_MESSAGE = 128 << 20                    # larger messages are treated as a broken stream

# Request flags: packet data, impact alerts, intrusion, metadata, archive
# timestamps, event extra data, extended requests. Only connection events and
# their metadata are written; the other bits stay as the collector has always
# sent them, so the request is unchanged.
FLAG_PACKETS = 1 << 0
FLAG_IMPACT = 1 << 5
FLAG_INTRUSION = 1 << 6
FLAG_METADATA = 1 << 20
FLAG_ARCHIVE_TIMESTAMPS = 1 << 23
FLAG_EXTRA_DATA = 1 << 27
FLAG_EXTENDED = 1 << 30
REQUEST_FLAGS = (FLAG_PACKETS | FLAG_IMPACT | FLAG_INTRUSION | FLAG_METADATA |
                 FLAG_ARCHIVE_TIMESTAMPS | FLAG_EXTRA_DATA | FLAG_EXTENDED)       # 0x48900061

# Extended requests in the Streaming Request, (version, event code) in order:
# intrusion, metadata, correlation, discovery, connection, user, malware, file,
# impact, end of list.
EXTENDED_REQUESTS = ((11, 12), (4, 21), (9, 31), (11, 61), (17, 71),
                     (7, 91), (8, 101), (7, 111), (2, 131), (0, 0))

# The exact bytes earlier versions sent for "start now"; checked before connecting.
KNOWN_GOOD = {
    "event_stream_request": "0001000200000008ffffffff48900061",
    "streaming_request": "000108010000003800001a0b0000003848900061ffffffff000b000c000400150009001f"
                         "000b003d001100470007005b000800650007006f0002008300000000",
    "null": "0001000000000000",
}


def event_stream_request(start, flags=REQUEST_FLAGS):
    return HEADER.pack(VERSION, MSG_EVENT_STREAM_REQUEST, 8) + struct.pack(">LL", start, flags)


def streaming_request(start, flags=REQUEST_FLAGS):
    body = struct.pack(">LLLL", STREAMING_SERVICE_ID, 0, flags, start)
    body += b"".join(struct.pack(">HH", version, code) for version, code in EXTENDED_REQUESTS)
    length = len(body)
    body = body[:4] + struct.pack(">L", length) + body[8:]     # service length = whole body
    return HEADER.pack(VERSION, MSG_STREAMING_REQUEST, length) + body


def null_message():
    return HEADER.pack(VERSION, MSG_NULL, 0)


def check_requests():
    """Raise if a request would differ by one byte from what the FMC has always received."""
    built = {"event_stream_request": event_stream_request(START_NOW).hex(),
             "streaming_request": streaming_request(START_NOW).hex(),
             "null": null_message().hex()}
    bad = [name for name, value in built.items() if value != KNOWN_GOOD[name]]
    if bad:
        raise RuntimeError(f"request self-check failed for {', '.join(bad)}")


def offers_streaming(data):
    """Streaming Information message: does the FMC offer the streaming service?"""
    offset = 0
    while offset + 8 <= len(data):
        service, length = struct.unpack_from(">LL", data, offset)
        if service == STREAMING_SERVICE_ID:
            return True
        offset += 8 + length
    return False


def bundle_records(data):
    """
    Records in a message bundle (connection id, sequence, then type-4 items):
    (records, number of items of another type, which are skipped).
    """
    offset, out, unknown = 8, [], 0
    while offset + 8 <= len(data):
        itype, ilen = struct.unpack_from(">LL", data, offset)
        if itype == MSG_EVENT_DATA:
            out.append(data[offset + 8: offset + 8 + ilen])
        else:
            unknown += 1
        offset += 8 + ilen
    return out, unknown


def error_text(data):
    code, length = struct.unpack_from(">lH", data, 0)
    return code, data[6:6 + length].decode("utf-8", "replace").replace("\x00", "")


# ------------------------------------------------------------------ records

class DecodeError(Exception):
    pass


RECORD_CONNECTION = 71

# Metadata record types used to name connection-event values.
MD_CLIENT_APP = 55
MD_APP_PROTOCOL = 63
MD_WEB_APP = 109
MD_ZONE = 115
MD_INTERFACE = 116
MD_AC_RULE = 119
MD_RULE_ACTION = 120
MD_URL_CATEGORY = 121
MD_URL_REPUTATION = 122
MD_DEVICE = 123
MD_RULE_REASON = 124
MD_AC_POLICY = 145
MD_PREFILTER_POLICY = 146
MD_TUNNEL_RULE = 147
MD_IOC = 161
MD_SI_CATEGORY = 280
MD_SI_SRC_DST = 281
MD_DNS_RECORD = 320
MD_DNS_RESPONSE = 321
MD_SINKHOLE = 322
MD_GEOLOCATION = 520
MD_SSL_CIPHER = 602
MD_SSL_VERSION = 604
MD_SSL_CERT_STATUS = 605
MD_SSL_ACTUAL_ACTION = 606
MD_SSL_EXPECTED_ACTION = 607
MD_SSL_FLOW_STATUS = 608
MD_SSL_URL_CATEGORY = 613

# Metadata for the other event types (2.2.0): correlation (policy violation),
# VPN, malware and file events.
MD_CORR_POLICY = 69
MD_CORR_RULE = 70
MD_USER = 98
MD_AMP_CLOUD = 127
MD_MALWARE_EVENT_TYPE = 128
MD_MALWARE_EVENT_SUBTYPE = 129
MD_AMP_DETECTOR = 130
MD_AMP_FILE_TYPE = 131
MD_ICMP_TYPE = 260
MD_ICMP_CODE = 270
MD_REALM = 300
MD_FILE_TYPE = 510
MD_FILE_STORAGE = 515
MD_FILE_SANDBOX = 516
MD_FILE_SPERO = 517
MD_FILE_ARCHIVE = 518
MD_FILE_STATIC = 519
MD_FILE_POLICY = 530

# "id, length, name" records -> name table
ID_NAME_TABLES = {
    MD_CLIENT_APP: "clientApps", MD_APP_PROTOCOL: "appProtocols", MD_WEB_APP: "payloads",
    MD_RULE_ACTION: "ruleActions", MD_URL_CATEGORY: "urlCategories",
    MD_URL_REPUTATION: "urlReputations", MD_DEVICE: "devices", MD_SI_SRC_DST: "siSrcDests",
    MD_SSL_CIPHER: "sslCipherSuites", MD_SSL_VERSION: "sslVersions",
    MD_SSL_CERT_STATUS: "sslCertStatuses", MD_SSL_ACTUAL_ACTION: "sslActions",
    MD_SSL_EXPECTED_ACTION: "sslExpectedActions", MD_SSL_FLOW_STATUS: "sslFlowStatuses",
    MD_SSL_URL_CATEGORY: "sslUrlCategories",
    MD_MALWARE_EVENT_TYPE: "malwareEventTypes", MD_MALWARE_EVENT_SUBTYPE: "malwareEventSubtypes",
    MD_AMP_DETECTOR: "ampDetectors", MD_AMP_FILE_TYPE: "ampFileTypes", MD_REALM: "realms",
    MD_FILE_TYPE: "fileTypes", MD_FILE_STORAGE: "fileStorages", MD_FILE_SANDBOX: "fileSandboxes",
    MD_FILE_SPERO: "fileSperos", MD_FILE_ARCHIVE: "fileArchives", MD_FILE_STATIC: "fileStatics",
}
# "uuid, name" records -> name table
UUID_NAME_TABLES = {MD_ZONE: "securityZones", MD_INTERFACE: "interfaces", MD_SINKHOLE: "sinkholes",
                    MD_AMP_CLOUD: "ampClouds", MD_FILE_POLICY: "filePolicies"}
# "uuid, device, name" policy records -> name table
POLICY_TABLES = {MD_AC_POLICY: "acPolicies", MD_PREFILTER_POLICY: "prefilterPolicies",
                 MD_TUNNEL_RULE: "tunnelRules"}

METADATA_TYPES = frozenset(set(ID_NAME_TABLES) | set(UUID_NAME_TABLES) | set(POLICY_TABLES) | {
    MD_AC_RULE, MD_RULE_REASON, MD_IOC, MD_SI_CATEGORY, MD_DNS_RECORD, MD_DNS_RESPONSE,
    MD_GEOLOCATION, MD_CORR_POLICY, MD_CORR_RULE, MD_USER, MD_ICMP_TYPE, MD_ICMP_CODE})

ZERO_UUID = "00000000-0000-0000-0000-000000000000"
_LL = struct.Struct(">LL")
_L = struct.Struct(">L")
_DISCOVERY = struct.Struct(">LL6sBBLLLLLL")      # 40-byte discovery event header
_inet_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6


def ip_text(packed):
    """IPv6 address text; IPv4-mapped addresses as plain IPv4."""
    text = _inet_ntop(_AF_INET6, packed)
    return text[7:] if text.startswith("::ffff:") else text


def uuid_text(packed):
    h = packed.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def hex_text(packed):
    return packed.hex()


def string_value(raw):
    """String block contents: UTF-8 without NULs, or hex when it is not text."""
    try:
        return raw.decode("utf-8").replace("\x00", "")
    except UnicodeDecodeError:
        return raw.hex()


def record_header(data):
    """(record type, archive timestamp, checksum, body offset)."""
    if len(data) < 8:
        raise DecodeError("record shorter than its header")
    rtype, rlen = _LL.unpack_from(data, 0)
    if len(data) == 16 + rlen:
        ats, checksum = _LL.unpack_from(data, 8)
        return rtype, rlen, ats, checksum, 16
    if len(data) == 8 + rlen:
        return rtype, rlen, 0, 0, 8
    raise DecodeError(f"record length {rlen} does not match {len(data)} bytes")


# ---- connection statistics data blocks
#
# Field order and types per block version, from the Integration Guide's
# "Connection Statistics Data Block" tables. Types: B/H/L/Q = 8/16/32/64-bit
# unsigned, uuid = 16-byte UUID, ip = 16-byte IPv6 (IPv4-mapped for IPv4),
# h16/h20/h32 = raw bytes shown as hex, str = string block.

_BLOCK_174 = """
blockType:L blockLength:L deviceId:L ingressZone:uuid egressZone:uuid ingressInterface:uuid
egressInterface:uuid initiatorIpAddress:ip responderIpAddress:ip originalClientIpAddress:ip
policyRevision:uuid ruleId:L tunnelRuleId:L ruleAction:H ruleReason:L initiatorPort:H
responderPort:H tcpFlag:H protocol:B netflowSource:uuid instanceId:H connectionCounter:H
firstPacketTimestamp:L lastPacketTimestamp:L initiatorTransmittedPackets:Q
responderTransmittedPackets:Q initiatorTransmittedBytes:Q responderTransmittedBytes:Q
initiatorPacketsDropped:Q responderPacketsDropped:Q initiatorBytesDropped:Q responderBytesDropped:Q
qosAppliedInterface:uuid qosRuleId:L userId:L applicationId:L urlCategory:L urlReputation:L
clientApplicationId:L webApplicationId:L clientUrl:str netbios:str clientApplicationVersion:str
monitorRule1:L monitorRule2:L monitorRule3:L monitorRule4:L monitorRule5:L monitorRule6:L
monitorRule7:L monitorRule8:L securityIntelligenceSourceDestination:B securityIntelligenceLayer:B
fileEventCount:H intrusionEventCount:H initiatorCountry:H responderCountry:H
originalClientCountry:H iocNumber:H sourceAutonomousSystem:L destinationAutonomousSystem:L
snmpIn:H snmpOut:H sourceTos:B destinationTos:B sourceMask:B destinationMask:B
securityContext:uuid vlanId:H referencedHost:str userAgent:str httpReferrer:str
sslCertificateFingerprint:h20 sslPolicyId:uuid sslRuleId:L sslCipherSuite:H sslVersion:B
sslServerCertificateStatus:L sslActualAction:H sslExpectedAction:H sslFlowStatus:H sslFlowError:L
sslFlowMessages:L sslFlowFlags:Q sslServerName:str sslUrlCategory:L sslSessionId:h32
sslSessionIdLength:B sslTicketId:h20 sslTicketIdLength:B networkAnalysisPolicyRevision:uuid
endpointProfileId:L securityGroupId:L sourceSecurityGroupTag:H sourceSecurityGroupTagType:B
destinationSecurityGroupTag:H destinationSecurityGroupTagType:B locationIpv6:ip httpResponse:L
dnsQuery:str dnsRecordType:H dnsResponseType:H dnsTtl:L sinkholeUuid:uuid
securityIntelligenceList1:L securityIntelligenceList2:L threatIntelligenceCategory:L
eveProcess:str eveProcessConfidencePercentage:B eveThreatConfidencePercentage:B
eveThreatConfidenceIndex:B clientAppDectectorId:B natInitiatorPort:H natResponderPort:H
natInitiatorIp:ip natResponderIp:ip ingressVRFName:str egressVRFName:str
sourceIpDynamicAttributes:str destIpDynamicAttributes:str
"""

_EVE_NAT = ("eveProcess eveProcessConfidencePercentage eveThreatConfidencePercentage "
            "eveThreatConfidenceIndex clientAppDectectorId natInitiatorPort natResponderPort "
            "natInitiatorIp natResponderIp").split()
_DYNAMIC = ["sourceIpDynamicAttributes", "destIpDynamicAttributes"]
_SGT_TYPES = ["sourceSecurityGroupTagType", "destinationSecurityGroupTagType"]
_SGT = ["sourceSecurityGroupTag", "destinationSecurityGroupTag"]
_VRF = ["ingressVRFName", "egressVRFName"]
_SINCE_161 = ("originalClientIpAddress tunnelRuleId initiatorPacketsDropped responderPacketsDropped "
              "initiatorBytesDropped responderBytesDropped qosAppliedInterface qosRuleId "
              "originalClientCountry").split()


def _fields(spec):
    return [tuple(item.split(":")) for item in spec.split()]


def _without(fields, names):
    names = set(names)
    return [f for f in fields if f[0] not in names]


def _block_versions():
    v174 = _fields(_BLOCK_174)
    v171 = _without(v174, _EVE_NAT + _DYNAMIC)
    v173 = [("fileCount", t) if n == "fileEventCount" else (n, t)
            for n, t in _without(v174, _EVE_NAT)]
    v170 = _without(v171, _SGT_TYPES + _VRF)
    v169 = _without(v170, _SGT)
    v168 = _without(v169, ["threatIntelligenceCategory"]) + [("securityIntelligenceList3", "L")]
    v161 = _without(v168, ["securityIntelligenceList3"])
    v160 = [(n, "h16") if n in ("securityContext", "sslPolicyId") else (n, t)
            for n, t in _without(v161, _SINCE_161)]
    # block type on the wire -> field list (163 is the 6.x layout following 160)
    return {160: v160, 163: v161, 168: v168, 169: v169, 170: v170, 171: v171, 173: v173, 174: v174}


_STRUCT_CODES = {"B": "B", "H": "H", "L": "L", "Q": "Q", "uuid": "16s", "ip": "16s",
                 "h16": "16s", "h20": "20s", "h32": "32s"}
_CONVERTERS = {"uuid": uuid_text, "ip": ip_text, "h16": hex_text, "h20": hex_text, "h32": hex_text}


class Layout:
    """A block version compiled into fixed-size runs (one struct each) and string blocks."""

    def __init__(self, block_type, fields):
        self.block_type = block_type
        self.fields = fields
        self.steps = []
        run = []
        for name, kind in fields + [(None, "str")]:
            if kind == "str":
                if run:
                    fmt = ">" + "".join(_STRUCT_CODES[k] for _, k in run)
                    names = tuple(n for n, _ in run)
                    conv = tuple((i, n, _CONVERTERS[k]) for i, (n, k) in enumerate(run)
                                 if k in _CONVERTERS)
                    sizes = [struct.calcsize(">" + _STRUCT_CODES[k]) for _, k in run]
                    self.steps.append(("fixed", struct.Struct(fmt), names, conv, run, sizes))
                    run = []
                if name:
                    self.steps.append(("str", name))
            else:
                run.append((name, kind))

    def decode(self, data, offset, record):
        """Fill record from data[offset:]; returns the offset after the block."""
        end = len(data)
        for step in self.steps:
            if offset == end:                       # short block: later fields are absent
                break
            if step[0] == "str":
                if offset + 8 > end:
                    raise DecodeError(f"{step[1]}: string block header past end of record")
                _, length = _LL.unpack_from(data, offset)
                if length < 8 or offset + length > end:
                    raise DecodeError(f"{step[1]}: string block length {length} invalid")
                record[step[1]] = string_value(data[offset + 8: offset + length]) if length > 8 else ""
                offset += length
                continue
            _, st, names, conv, run, sizes = step
            if offset + st.size <= end:
                values = st.unpack_from(data, offset)
                record.update(zip(names, values))
                for i, name, fn in conv:
                    record[name] = fn(values[i])
                offset += st.size
            else:                                   # record ends inside this run
                offset = self._decode_partial(data, offset, run, sizes, record)
        return offset

    @staticmethod
    def _decode_partial(data, offset, run, sizes, record):
        end = len(data)
        for (name, kind), size in zip(run, sizes):
            if offset == end:
                return offset
            if offset + size > end:
                raise DecodeError(f"{name}: field past end of record")
            value = struct.unpack_from(">" + _STRUCT_CODES[kind], data, offset)[0]
            fn = _CONVERTERS.get(kind)
            record[name] = fn(value) if fn else value
            offset += size
        return offset


LAYOUTS = {bt: Layout(bt, fields) for bt, fields in _block_versions().items()}
NEWEST_BLOCK = max(LAYOUTS)


def connection_layout(block_type):
    """Layout for a block type; an unknown one is read with the closest older known version."""
    layout = LAYOUTS.get(block_type)
    if layout is None:
        older = [bt for bt in LAYOUTS if bt < block_type]
        layout = LAYOUTS[max(older)] if older else LAYOUTS[min(LAYOUTS)]
    return layout


def decode_connection(data):
    """Connection event record (type 71) -> dict of its fields (Integration Guide names)."""
    rtype, rlen, ats, checksum, offset = record_header(data)
    if rtype != RECORD_CONNECTION:
        raise DecodeError(f"record type {rtype} is not a connection event")
    if offset + 40 > len(data):
        raise DecodeError("connection record shorter than the discovery header")
    (device, legacy_ip, mac, has_ipv6, _pad, event_sec, event_usec, event_type, event_subtype,
     _x1, _x2) = _DISCOVERY.unpack_from(data, offset)
    offset += 40
    if has_ipv6 == 1:
        host_ip = ip_text(data[offset:offset + 16])
        offset += 16
    else:
        host_ip = socket.inet_ntoa(struct.pack(">L", legacy_ip))
    if offset + 4 > len(data):
        raise DecodeError("connection record has no data block")
    block_type = _L.unpack_from(data, offset)[0]
    record = {
        "recordType": rtype, "recordLength": rlen, "blockType": block_type,
        "archiveTimestamp": ats, "checksum": checksum, "deviceId": device,
        "hostIpAddr": host_ip, "macAddress": ":".join(format(b, "02x") for b in mac),
        "eventSecond": event_sec, "eventMicrosecond": event_usec,
        "eventType": event_type, "eventSubtype": event_subtype,
    }
    layout = connection_layout(block_type)
    end = layout.decode(data, offset, record)
    if end > len(data):
        raise DecodeError("connection record overrun")
    return record, layout.block_type


# ------------------------------------------------------------------ names

class Names:
    """
    Value -> name tables, filled from the FMC's metadata records and saved as
    JSON (one file per decoder process) so names are known straight away
    after a restart. Fixed tables (IP protocols, cipher suites, SSL codes,
    rule reasons) are built in; names from the FMC take precedence.
    """
    TABLES = ("devices", "securityZones", "interfaces", "appProtocols", "clientApps", "payloads",
              "geolocations", "urlReputations", "urlCategories", "siSrcDests", "ipProtocols",
              "ruleActions", "ruleReasons", "acRules", "acPolicies", "prefilterPolicies",
              "tunnelRules", "ioc", "siLists", "dnsRecords", "dnsResponses", "sinkholes",
              "sslCipherSuites", "sslVersions", "sslCertStatuses", "sslActions",
              "sslExpectedActions", "sslFlowStatuses", "sslFlowFlags", "sslFlowMessages", "sslUrlCategories",
              "users", "corrPolicies", "corrRules", "ampClouds", "malwareEventTypes", "malwareEventSubtypes",
              "ampDetectors", "ampFileTypes", "realms", "fileTypes", "fileStorages", "fileSandboxes",
              "fileSperos", "fileArchives", "fileStatics", "filePolicies", "icmpTypes", "icmpCodes")
    FIXED = {"ipProtocols": IP_PROTOCOLS, "ruleReasons": FIREWALL_RULE_REASONS,
             "sslCipherSuites": TLS_CIPHER_SUITES, "sslCertStatuses": SSL_CERT_STATUSES,
             "sslActions": SSL_ACTIONS, "sslFlowStatuses": SSL_FLOW_STATUSES,
             "sslFlowFlags": SSL_FLOW_FLAGS, "sslFlowMessages": SSL_FLOW_MESSAGES}
    FILE_VERSION = 1

    def __init__(self, path=None):
        self.path = path
        self.t = {name: {} for name in self.TABLES}
        for name, values in list(DEFAULT_NAMES.items()) + list(self.FIXED.items()):
            self.t[name].update(values)
        self.learned = {name: {} for name in self.TABLES}
        self.changed = False
        self.ignored = 0                    # metadata records without the fields that carry a name

    # ---- persistence
    def load(self):
        if not self.path or not os.path.exists(self.path):
            return False
        try:
            with open(self.path, encoding="utf-8") as fh:
                saved = json.load(fh)
            if saved.get("version") != self.FILE_VERSION:
                return False
            for name, entries in saved.get("tables", {}).items():
                if name not in self.t:
                    continue
                for key, value in entries:
                    self._set(name, tuple(key) if isinstance(key, list) else key, value)
        except (OSError, ValueError, TypeError, AttributeError):
            return False
        self.changed = False
        return True

    def save(self):
        if not self.path or not self.changed:
            return
        tables = {name: [[list(k) if isinstance(k, tuple) else k, v] for k, v in entries.items()]
                  for name, entries in self.learned.items() if entries}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"version": self.FILE_VERSION, "tables": tables}, fh, separators=(",", ":"))
        os.replace(tmp, self.path)
        self.changed = False

    def _set(self, table, key, value):
        self.t[table][key] = value
        self.learned[table][key] = value
        self.changed = True

    def get(self, table, key):
        return self.t[table].get(key)

    # ---- metadata records
    def store(self, data):
        """Learn names from a metadata record. Returns False for other record types."""
        rtype, _rlen, _ats, _cs, off = record_header(data)
        if rtype not in METADATA_TYPES:
            return False
        try:
            self._store(rtype, data, off)
        except (struct.error, DecodeError):
            # Too short for its fields: the FMC sends some empty ones (e.g. a type-119
            # record that is only a block header). There is no name to learn.
            self.ignored += 1
        return True

    def _store(self, rtype, data, off):
        if rtype == MD_USER:                                # user: id, protocol, name
            self._store_user(data, off)
            return
        if rtype in (MD_CORR_POLICY, MD_CORR_RULE):          # id, then names with 16-bit lengths
            ident = _L.unpack_from(data, off)[0]
            (length,) = struct.unpack_from(">H", data, off + 4)
            if off + 6 + length > len(data):
                raise DecodeError(f"record {rtype}: name past end of record")
            self._set("corrPolicies" if rtype == MD_CORR_POLICY else "corrRules", ident,
                      string_value(data[off + 6: off + 6 + length]))
            return
        if rtype in ID_NAME_TABLES:                         # id, length, name
            ident, length = _LL.unpack_from(data, off)
            if off + 8 + length > len(data):
                raise DecodeError(f"record {rtype}: name past end of record")
            self._set(ID_NAME_TABLES[rtype], ident,
                      string_value(data[off + 8: off + 8 + length]) if length else "")
            return
        off += 8                                            # series 2 block type + length
        if rtype in UUID_NAME_TABLES:
            uid = uuid_text(data[off:off + 16])
            name, _ = self._string(data, off + 16)
            self._set(UUID_NAME_TABLES[rtype], uid, name)
        elif rtype in POLICY_TABLES:
            uid = uuid_text(data[off:off + 16])
            ident = _L.unpack_from(data, off + 16)[0]
            name, _ = self._string(data, off + 20)
            if rtype == MD_TUNNEL_RULE:                     # rule id is in the device field
                self._set("tunnelRules", ident, name)
            else:
                self._set(POLICY_TABLES[rtype], (ident, uid), name)
        elif rtype == MD_AC_RULE:
            uid = uuid_text(data[off:off + 16])
            ident = _L.unpack_from(data, off + 16)[0]
            name, _ = self._string(data, off + 20)
            self._set("acRules", (uid, ident), name)
        elif rtype == MD_RULE_REASON:
            ident = _L.unpack_from(data, off)[0]
            self._set("ruleReasons", ident, self._string(data, off + 4)[0])
        elif rtype == MD_IOC:
            ident = _L.unpack_from(data, off)[0]
            category, _ = self._string(data, off + 4)
            self._set("ioc", ident, category)
        elif rtype == MD_SI_CATEGORY:
            ident = _L.unpack_from(data, off)[0]
            policy = uuid_text(data[off + 4:off + 20])
            self._set("siLists", (ident, policy), self._string(data, off + 20)[0])
        elif rtype in (MD_DNS_RECORD, MD_DNS_RESPONSE):
            ident = _L.unpack_from(data, off)[0]
            name, nxt = self._string(data, off + 4)
            desc, _ = self._string(data, nxt)
            self._set("dnsRecords" if rtype == MD_DNS_RECORD else "dnsResponses", ident, [name, desc])
        elif rtype == MD_GEOLOCATION:
            code = struct.unpack_from(">H", data, off)[0]
            self._set("geolocations", code, self._string(data, off + 2)[0])
        elif rtype == MD_ICMP_TYPE:                         # type, protocol, name
            icmp_type, ip_proto = struct.unpack_from(">HH", data, off)
            self._set("icmpTypes", (ip_proto, icmp_type), self._string(data, off + 4)[0])
        elif rtype == MD_ICMP_CODE:                         # code, type, protocol, name
            code, icmp_type, ip_proto = struct.unpack_from(">HHH", data, off)
            self._set("icmpCodes", (ip_proto, icmp_type, code), self._string(data, off + 6)[0])

    def _store_user(self, data, off):
        """User record: a user information block (type 57), or the plain id, protocol, length, name form."""
        if off + 8 <= len(data):
            btype, blen = _LL.unpack_from(data, off)
            if btype == 57 and off + blen == len(data):
                ident = _L.unpack_from(data, off + 8)[0]
                self._set("users", ident, self._string(data, off + 16)[0])
                return
        ident, _protocol, length = struct.unpack_from(">LLL", data, off)
        if off + 12 + length > len(data):
            raise DecodeError("user record: name past end of record")
        self._set("users", ident, string_value(data[off + 12: off + 12 + length]))

    @staticmethod
    def _string(data, off):
        if off + 8 > len(data):
            raise DecodeError("string block past end of record")
        _, length = _LL.unpack_from(data, off)
        if length < 8 or off + length > len(data):
            raise DecodeError(f"string block length {length} invalid")
        return (string_value(data[off + 8: off + length]) if length > 8 else ""), off + length


# ------------------------------------------------------------------ events

# Record field -> output field, in output order. Field names stay as earlier
# versions wrote them; to_sfw() then renames the ones the cisco:sfw:estreamer
# sourcetype knows (InitiatorIP, FirewallRule, ...).
RECORD_FIELDS = (
    ("applicationId", "app_proto"), ("blockType", "blockType"),
    ("clientApplicationId", "client_app"), ("clientApplicationVersion", "client_version"),
    ("clientUrl", "url"), ("connectionCounter", "connection_id"),
    ("destinationAutonomousSystem", "dest_autonomous_system"),
    ("destIpDynamicAttributes", "dest_ip_dynamic_attributes"), ("destinationMask", "dest_mask"),
    ("destinationSecurityGroupTag", "destination_security_group_tag"),
    ("destinationSecurityGroupTagType", "destination_security_group_tag_type"),
    ("destinationTos", "dest_tos"), ("dnsQuery", "dns_query"), ("dnsRecordType", "dns_rec_id"),
    ("dnsResponseType", "dns_resp_id"), ("dnsTtl", "dns_ttl"), ("egressInterface", "iface_egress"),
    ("egressVRFName", "egress_vrf_name"), ("egressZone", "sec_zone_egress"),
    ("fileEventCount", "file_count"), ("firstPacketTimestamp", "first_pkt_sec"),
    ("httpReferrer", "http_referrer"), ("httpResponse", "http_response"),
    ("ingressInterface", "iface_ingress"), ("ingressZone", "sec_zone_ingress"),
    ("initiatorBytesDropped", "src_bytes_dropped"), ("initiatorCountry", "src_ip_country"),
    ("initiatorIpAddress", "src_ip"), ("initiatorPacketsDropped", "src_packets_dropped"),
    ("initiatorPort", "src_port"), ("initiatorTransmittedBytes", "src_bytes"),
    ("initiatorTransmittedPackets", "src_pkts"), ("ingressVRFName", "ingress_vrf_name"),
    ("instanceId", "instance_id"), ("intrusionEventCount", "ips_count"), ("iocNumber", "num_ioc"),
    ("hostIpAddr", "src_host"), ("lastPacketTimestamp", "last_pkt_sec"),
    ("monitorRule1", "monitor_rule_1"), ("monitorRule2", "monitor_rule_2"),
    ("monitorRule3", "monitor_rule_3"), ("monitorRule4", "monitor_rule_4"),
    ("monitorRule5", "monitor_rule_5"), ("monitorRule6", "monitor_rule_6"),
    ("monitorRule7", "monitor_rule_7"), ("monitorRule8", "monitor_rule_8"),
    ("netbios", "netbios_domain"), ("netflowSource", "netflow_src"),
    ("networkAnalysisPolicyRevision", "network_analysis_policy_revision"),
    ("originalClientCountry", "original_src_country"),
    ("policyRevision", "fw_policy"), ("protocol", "ip_proto"),
    ("qosAppliedInterface", "qoa_applied_interface"), ("qosRuleId", "qoa_rule_id"),
    ("referencedHost", "referenced_host"),
    ("responderBytesDropped", "dest_bytes_dropped"), ("responderCountry", "dest_ip_country"),
    ("responderIpAddress", "dest_ip"), ("responderPacketsDropped", "dest_packets_dropped"),
    ("responderPort", "dest_port"), ("responderTransmittedBytes", "dest_bytes"),
    ("responderTransmittedPackets", "dest_pkts"), ("ruleAction", "fw_rule_action"),
    ("ruleId", "fw_rule"), ("ruleReason", "fw_rule_reason"),
    ("securityContext", "security_context"), ("securityIntelligenceLayer", "ip_layer"),
    ("securityIntelligenceList1", "sec_intel_list1"),
    ("securityIntelligenceList2", "sec_intel_list2"),
    ("securityIntelligenceSourceDestination", "sec_intel_ip"), ("sinkholeUuid", "sinkhole_uuid"),
    ("snmpIn", "snmp_in"), ("snmpOut", "snmp_out"),
    ("sourceAutonomousSystem", "src_autonomous_system"), ("sourceMask", "src_mask"),
    ("sourceIpDynamicAttributes", "source_ip_dynamic_attributes"),
    ("sourceSecurityGroupTag", "source_security_group_tag"),
    ("sourceSecurityGroupTagType", "source_security_group_tag_type"), ("sourceTos", "src_tos"),
    ("sslActualAction", "ssl_actual_action"),
    ("sslCertificateFingerprint", "ssl_cert_fingerprint"), ("sslCipherSuite", "ssl_cipher_suite"),
    ("sslExpectedAction", "ssl_expected_action"), ("sslFlowError", "ssl_flow_error"),
    ("sslFlowFlags", "ssl_flow_flags"), ("sslFlowMessages", "ssl_flow_messages"),
    ("sslFlowStatus", "ssl_flow_status"), ("sslPolicyId", "ssl_policy_id"),
    ("sslRuleId", "ssl_rule_id"), ("sslServerCertificateStatus", "ssl_server_cert_status"),
    ("sslServerName", "ssl_server_name"), ("sslSessionId", "ssl_session_id"),
    ("sslTicketId", "ssl_ticket_id"), ("sslUrlCategory", "ssl_url_category"),
    ("sslVersion", "ssl_version"), ("tcpFlag", "tcp_flags"),
    ("threatIntelligenceCategory", "threat_intelligence_category"),
    ("urlCategory", "url_category"), ("urlReputation", "url_reputation"),
    ("userAgent", "user_agent"), ("userId", "user_id"), ("vlanId", "vlan_id"),
    ("webApplicationId", "web_app"), ("eventMicrosecond", "event_usec"),
    ("eventSecond", "event_sec"), ("eventSubtype", "event_subtype"), ("eventType", "event_type"),
    ("macAddress", "mac_address"),
)
# Record fields never written (lengths, ids already shown by name, unused).
DROPPED_FIELDS = {"blockLength", "deviceId", "endpointProfileId", "locationIpv6", "securityGroupId",
                  "sslSessionIdLength", "sslTicketIdLength", "tunnelRuleId"}
HEADER_FIELDS = {"recordType", "recordLength", "blockType", "blockLength", "checksum",
                 "archiveTimestamp"}
_MAPPED = {key for key, _ in RECORD_FIELDS} | DROPPED_FIELDS | HEADER_FIELDS

# Unset fields are dropped (None, empty, 0, all-zero addresses/UUIDs/hashes), except these.
KEEP_ZERO = {"rec_type", "src_port", "dest_port", "ip_proto", "fw_rule_action", "fw_rule_reason"}

# Output names -> the names the Cisco Security Cloud app uses for
# cisco:sfw:estreamer, so that sourcetype's field aliases and CIM mappings apply.
SFW_NAMES = {
    "src_ip": "InitiatorIP", "dest_ip": "ResponderIP",
    "src_port": "InitiatorPort", "dest_port": "ResponderPort",
    "ip_proto": "Protocol", "app_proto": "Application",
    "client_app": "ClientApplication", "client_version": "ClientApplicationVersion",
    "iface_ingress": "IngressInterface", "iface_egress": "EgressInterface",
    "sec_zone_ingress": "IngressZone", "sec_zone_egress": "EgressZone",
    "ingress_vrf_name": "IngressVRF", "egress_vrf_name": "EgressVRF",
    "fw_policy": "FirewallPolicy", "fw_rule": "FirewallRule", "fw_rule_action": "AC_RuleAction",
    "prefilter_policy": "PrefilterPolicy", "tunnel_rule": "TunnelRule",
    "src_pkts": "InitiatorPackets", "dest_pkts": "ResponderPackets",
    "src_bytes": "InitiatorBytes", "dest_bytes": "ResponderBytes",
    "first_pkt_sec": "FirstPacketSecond", "last_pkt_sec": "LastPacketSecond",
    "connection_id": "ConnectionID", "instance_id": "InstanceID", "sensor": "Device",
    "url": "URL", "src_ip_country": "InitiatorCountry", "dest_ip_country": "ResponderCountry",
    "ssl_version": "SSL_Version", "ssl_cipher_suite": "SSL_CipherSuite",
    "ssl_cert_fingerprint": "SSL_CertFingerprint", "ssl_session_id": "SSL_SessionID",
    "eveProcess": "EVE_Process",
    "eveProcessConfidencePercentage": "EVE_ProcessConfidencePct",
    "eveThreatConfidencePercentage": "EVE_ThreatConfidencePct",
    "eveThreatConfidenceIndex": "EVE_ThreatConfidenceIndex",
}


def _named(out, key, value):
    if value:
        out[key] = value


def connection_fields(record, names):
    """Record -> output fields (before trimming), with names from the metadata tables."""
    out = {}
    for key, name in RECORD_FIELDS:
        if key in record:
            out[name] = record[key]
    t = names.t
    rev = record.get("policyRevision")
    device = record.get("deviceId")
    sisd = record.get("securityIntelligenceSourceDestination")

    out["rec_type_category"] = "RNA"
    out["rec_type_desc"] = "Connection Statistics"
    _named(out, "ip_proto", t["ipProtocols"].get(record.get("protocol")))
    _named(out, "web_app", t["payloads"].get(record.get("webApplicationId")))
    _named(out, "client_app", t["clientApps"].get(record.get("clientApplicationId")))
    _named(out, "app_proto", t["appProtocols"].get(record.get("applicationId")))
    _named(out, "sec_intel_ip", t["siSrcDests"].get(sisd))
    out["sec_intel_event"] = "No" if sisd == 0 else "Yes"
    _named(out, "sec_intel_list1", t["siLists"].get((record.get("securityIntelligenceList1"), rev)))
    _named(out, "sec_intel_list2", t["siLists"].get((record.get("securityIntelligenceList2"), rev)))
    _named(out, "url_category", t["urlCategories"].get(record.get("urlCategory")))
    _named(out, "url_reputation", t["urlReputations"].get(record.get("urlReputation")))
    _named(out, "fw_rule", t["acRules"].get((rev, record.get("ruleId"))))
    _named(out, "fw_rule_action", t["ruleActions"].get(record.get("ruleAction")))
    _named(out, "fw_rule_reason", t["ruleReasons"].get(record.get("ruleReason")))
    _named(out, "fw_policy", t["acPolicies"].get((device, rev)))
    _named(out, "prefilter_policy", t["prefilterPolicies"].get((device, rev)))
    tunnel = record.get("tunnelRuleId")
    if tunnel:
        _named(out, "tunnel_rule", t["tunnelRules"].get(tunnel))
    _named(out, "iface_ingress", t["interfaces"].get(record.get("ingressInterface")))
    _named(out, "iface_egress", t["interfaces"].get(record.get("egressInterface")))
    _named(out, "sec_zone_ingress", t["securityZones"].get(record.get("ingressZone")))
    _named(out, "sec_zone_egress", t["securityZones"].get(record.get("egressZone")))
    _named(out, "src_ip_country", t["geolocations"].get(record.get("initiatorCountry")))
    _named(out, "dest_ip_country", t["geolocations"].get(record.get("responderCountry")))
    dns = t["dnsRecords"].get(record.get("dnsRecordType"))
    if dns:
        _named(out, "dns_record_name", dns[0])
        _named(out, "dns_record_desc", dns[1])
    dns = t["dnsResponses"].get(record.get("dnsResponseType"))
    if dns:
        _named(out, "dns_response_name", dns[0])
        _named(out, "dns_response_desc", dns[1])
    _named(out, "sinkhole", t["sinkholes"].get(record.get("sinkholeUuid")))
    _named(out, "ioc_category", t["ioc"].get(record.get("iocNumber")))
    _named(out, "ssl_actual_action", t["sslActions"].get(record.get("sslActualAction")))
    expected = record.get("sslExpectedAction")            # 607 names, else the 606/fixed ones
    _named(out, "ssl_expected_action", t["sslExpectedActions"].get(expected) or t["sslActions"].get(expected))
    _named(out, "ssl_flow_flag", t["sslFlowFlags"].get(record.get("sslFlowFlags")))
    _named(out, "ssl_flow_message", t["sslFlowMessages"].get(record.get("sslFlowMessages")))
    _named(out, "ssl_flow_status", t["sslFlowStatuses"].get(record.get("sslFlowStatus")))
    _named(out, "ssl_server_cert_status",
           t["sslCertStatuses"].get(record.get("sslServerCertificateStatus")))
    _named(out, "ssl_cipher_suite", t["sslCipherSuites"].get(record.get("sslCipherSuite")))
    _named(out, "ssl_version", t["sslVersions"].get(record.get("sslVersion")))
    _named(out, "ssl_url_category", t["sslUrlCategories"].get(record.get("sslUrlCategory")))
    rules = t["acRules"]
    for n in range(1, 8):                                   # monitor rules 1-7 by name
        value = record.get(f"monitorRule{n}")
        if value == 0:
            out[f"monitor_rule_{n}"] = "N/A"
        _named(out, f"monitor_rule_{n}", rules.get((rev, value)))
    out["sensor"] = t["devices"].get(device)
    desc = EVENT_DESCRIPTIONS.get(record.get("eventType"), {}).get(record.get("eventSubtype"))
    if desc:
        out["event_desc"] = desc
    event_sec = record.get("eventSecond") or 0
    event_usec = record.get("eventMicrosecond") or 0
    if event_sec == 0:
        event_sec = record.get("archiveTimestamp", 0)
    if event_sec > 0:
        out["event_sec"] = event_sec
    if event_usec > 0:
        out["event_usec"] = event_usec
    out["rec_type"] = RECORD_CONNECTION
    for key, value in record.items():                       # newer fields, under their own names
        if key not in _MAPPED and key not in out:
            out[key] = value
    return out


def trim(fields):
    """Drop unset fields (None, zero placeholders, numeric 0) to keep events small."""
    out = {}
    for key, value in fields.items():
        if key in KEEP_ZERO:
            out[key] = value
            continue
        if value is None:
            continue
        kind = type(value)
        if kind is str:
            if not value.strip("0:.-") or (value[-1:] == "\n" and not value[:-1].strip("0:.-")):
                continue
        elif (kind is int or kind is float) and value == 0:
            continue
        out[key] = value
    return out


def to_sfw(fields, event_time, fmc_host):
    """Rename to the Security Cloud app's names; add duration and the FMC address."""
    out = {"time": event_time, "EventType": "ConnectionEvent"}
    for key, value in fields.items():
        out[SFW_NAMES.get(key, key)] = value
    if isinstance(out.get("Protocol"), str):
        out["Protocol"] = out["Protocol"].lower()
    first, last = out.get("FirstPacketSecond"), out.get("LastPacketSecond")
    if isinstance(first, int) and isinstance(last, int) and last >= first:
        out["ConnectionDuration"] = last - first
    out["SourceHost"] = fmc_host
    return out


def format_connection(record, names, fmc_host, keep_empty=False):
    """Decoded connection record -> one JSON line (sourcetype cisco:sfw:estreamer)."""
    return format_connection_fields(record, connection_fields(record, names), fmc_host, keep_empty)


def format_connection_fields(record, fields, fmc_host, keep_empty=False):
    """As format_connection, from fields already built by connection_fields()."""
    event_time = fields.get("last_pkt_sec") or fields.get("event_sec") or record.get("archiveTimestamp")
    out = to_sfw(fields if keep_empty else trim(fields), event_time, fmc_host)
    out["archive_ts"] = record.get("archiveTimestamp")
    return json.dumps(out, default=str, separators=(",", ":"))
