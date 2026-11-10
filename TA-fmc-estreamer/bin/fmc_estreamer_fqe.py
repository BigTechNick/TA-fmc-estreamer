# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer_fqe.py - the FQE (fully-qualified events, JSON) session.

File, intrusion and intrusion packet events come over a second eStreamer
connection in the FMC's own JSON form ("Fully-Qualified Events", Cisco's public
"Secure Firewall eStreamer Fully-Qualified Events Guide" for 7.4):

  * Request: the documented Event Stream Request with only bit 23 (archive
    timestamps) set, followed by the JSON configuration block. The configuration
    asks for the same field sets, in the same order and the same JSON text, as the
    Cisco Security Cloud app's eStreamer input, so the FMC gets the very bytes it
    already serves (checked against KNOWN_GOOD before connecting).
  * Replies: message bundles (4002) of event records whose data is one JSON
    object; one null acknowledgment after each bundle or event message.
  * Splunk: the FMC's JSON as is, plus "time" (first, for the timestamp),
    SourceHost (the FMC address, as the Cisco app adds it) and archive_ts.
  * CEF: fmc_estreamer_cef.file_event / intrusion_event / intrusion_packet.

The session runs as a thread of the input's collector process, with its own
bookmark (bookmark-fqe.json) and its own event files (writer number 99).
"""
import hashlib
import json
import logging
import os
import socket
import struct
import threading
import time

import fmc_estreamer_cef as cef
import fmc_estreamer_protocol as proto

LOG = logging.getLogger("fmc_estreamer")

FQE_FLAGS = 1 << 23                       # archive timestamps; the only flag FQE allows

# Field sets and fields per event type, in the order the Cisco app's input lists them.
FIELDS = {
    "FileEvent": ["HeaderFieldSet", "ConnectionKeySet", "DetailFieldSet", "Device", "DeviceIP",
                  "DeviceSerialNumber", "DeviceUUID"],
    "IntrusionEvent": [
        "HeaderFieldSet", "ConnectionKeySet", "DetailFieldSet", "Impact", "ApplicationID",
        "ApplicationProductivityIndex", "ApplicationRiskIndex", "AuthenticationSource", "Classification",
        "ClientApplicationID", "ClientApplicationProductivityIndex", "ClientApplicationRiskIndex", "Context",
        "CVE_ID", "Device", "DeviceIP", "DeviceSerialNumber", "Domain", "EgressInterfaceUUID", "EgressZoneUUID",
        "EventID", "EventPriority", "FirewallPolicyUUID", "FirewallRuleID", "Hostname", "ICMP_Code", "ICMP_Type",
        "ImpactFlag", "IngressInterfaceUUID", "IngressZoneUUID", "InitiatorContinent", "InitiatorContinentCode",
        "InitiatorCountry", "InitiatorCountryCode", "InitiatorCountryID", "InitiatorHostCriticality",
        "InitiatorIP", "InitiatorOS_Name", "InitiatorOS_Version", "InlineResultID", "InlineResultReason",
        "InlineResultReasonID", "IntrusionPolicyRevUUID", "IntrusionPolicyUUID", "IntrusionRuleMessage",
        "ManagerName", "ManagerUUID", "MatchedRule", "MPLS_Label", "NAP_PolicyUUID", "NetmapID", "Priority",
        "PriorityID", "ProtocolID", "RealmID", "RealmName", "ResponderContinent", "ResponderContinentCode",
        "ResponderCountry", "ResponderCountryCode", "ResponderCountryID", "ResponderHostCriticality",
        "ResponderIP", "ResponderOS_Name", "ResponderOS_Version", "ReviewedBy", "SensorID", "SignatureID",
        "SMTP_Attachments", "SMTP_From", "SMTP_Headers", "SMTP_To", "SnortVersionID", "SSL_ActualAction",
        "SSL_ActualActionID", "SSL_Cert", "SSL_CertFingerprint", "SSL_FlowStatusID", "UserID", "UserProtocol",
        "VLAN_ID", "WebApplicationHTTP", "WebApplicationID", "WebApplicationProductivityIndex", "IOC_Count"],
    "IntrusionPacket": ["HeaderFieldSet", "DetailFieldSet", "Device", "DeviceIP", "DeviceSerialNumber",
                        "DeviceUUID", "SensorID"],
}
ORDER = ("FileEvent", "IntrusionEvent", "IntrusionPacket")
OUTPUT_FORMAT = {"Transform": "Text", "TransformConfig": "JSON"}

# SHA-256 of the request for start time 0, per set of event types; the same bytes
# the Cisco Security Cloud app's input sends for the same selection.
KNOWN_GOOD = {
    ("FileEvent",): "f7c4bbaf321de5ceacbcfd63899d3bcdb05b9338b429f409d98f668975631f65",
    ("IntrusionEvent",): "c195324cf2d4493e025caf3b662356d4965fed1a53852f4efbec6e8b315a4a33",
    ("IntrusionPacket",): "f77d258eb6f8944f33a2fa63a033b698e1dec17bdb53b842a0398ab3a50c79e6",
    ("FileEvent", "IntrusionEvent"): "83576399ed98ad5f0f007a03cb7e020d0ace0e8e01fe4ec774ad7fe82261ba54",
    ("FileEvent", "IntrusionPacket"): "c0c2c347c693b528f18bcf8d7eb580bac12510a4ca4c658b413012a03988e651",
    ("IntrusionEvent", "IntrusionPacket"): "56bb6a94c46c3990ace93c33f491f26899cf5b6beb8fee79a89e4df930ea6c9c",
    ("FileEvent", "IntrusionEvent", "IntrusionPacket"):
        "4e760d2158c767e6cef98f843e5577df4dc49b22ebf1dde5e0715c3cef5eaf5d",
}


def selection(kinds):
    """Event types in request order (unknown names dropped)."""
    return tuple(k for k in ORDER if k in kinds)


def request_config(kinds):
    events = {}
    for kind in selection(kinds):
        events[kind] = {"FieldSetDef": {"OutputFieldSet": list(FIELDS[kind])}, "Fields": ["OutputFieldSet"]}
    return {"Events": events, "OutputFormat": dict(OUTPUT_FORMAT)}


def request(start, kinds):
    """Event Stream Request + JSON configuration block (FQE guide, "Requesting Fully-qualified Events")."""
    body = json.dumps(request_config(kinds)).encode("utf-8")
    return proto.HEADER.pack(proto.VERSION, proto.MSG_EVENT_STREAM_REQUEST, 8 + len(body)) + \
        struct.pack(">LL", start, FQE_FLAGS) + body


def check_request(kinds):
    """Raise unless the request for this selection is byte for byte the known-good one."""
    key = selection(kinds)
    if not key:
        raise RuntimeError("FQE session without event types")
    if hashlib.sha256(request(0, key)).hexdigest() != KNOWN_GOOD.get(key):
        raise RuntimeError(f"FQE request self-check failed for {', '.join(key)}")


_REC = struct.Struct(">LLLL")      # record type, record length, archive timestamp, reserved (bit 23 set)


def parse_record(data):
    """
    FQE event record -> (record type, archive timestamp, JSON object). The request
    always sets bit 23, so the header is 16 bytes; the data is the record length
    after it (anything after that, such as padding, is ignored).
    """
    if len(data) < 16:
        raise ValueError("FQE record shorter than its header")
    rtype, rlen, ats, _reserved = _REC.unpack_from(data, 0)
    text = data[16:16 + rlen].rstrip(b"\x00")
    obj = json.loads(text.decode("utf-8", "replace"))
    if not isinstance(obj, dict):
        raise ValueError("FQE record data is not a JSON object")
    return rtype, ats, obj


def event_time(obj, ats):
    for key in ("EventSecond", "PacketSecond", "FirstPacketSecond"):
        value = obj.get(key)
        try:
            if value:
                return int(value)
        except (TypeError, ValueError):
            continue
    return ats


def splunk_line(obj, ats, fmc_host):
    """The FMC's JSON with "time" first, SourceHost (the FMC address) and archive_ts."""
    out = {"time": event_time(obj, ats)}
    for key, value in obj.items():
        if key != "time":
            out[key] = value
    out["SourceHost"] = fmc_host
    out["archive_ts"] = ats
    return json.dumps(out, separators=(",", ":"), default=str)


CEF_BUILDERS = {"FileEvent": cef.file_event, "IntrusionEvent": cef.intrusion_event,
                "IntrusionPacket": cef.intrusion_packet}


def cef_line(obj, names, fmc_name):
    """CEF for an FQE event (FileEvent, IntrusionEvent, IntrusionPacket)."""
    kind = str(obj.get("EventType") or "")
    if kind.startswith("File"):
        return cef.file_event(obj, names, fmc_name)
    builder = CEF_BUILDERS.get(kind)
    return builder(obj, names, fmc_name) if builder else None


class SharedNames:
    """
    Read-only copy of the decoder processes' name tables (devices, protocols, ...),
    reloaded from their names-N.json files every few minutes. The FQE events carry
    names already; these give the numbers CEF also has today (device ID).
    """

    RELOAD = 300                   # seconds between reloads
    RELOAD_EMPTY = 30              # ... while no device names are known yet (first start)

    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.names = proto.Names()
        self.names.device_ids = {}
        self.loaded = 0
        self.device_ids = {}

    def get(self):
        now = time.time()
        if now - self.loaded >= (self.RELOAD if self.device_ids else self.RELOAD_EMPTY):
            self.loaded = now
            fresh = proto.Names()
            try:
                files = sorted(f for f in os.listdir(self.state_dir) if f.startswith("names-") and f.endswith(".json"))
            except OSError:
                files = []
            for fname in files:
                part = proto.Names(os.path.join(self.state_dir, fname))
                if part.load():
                    for table, entries in part.learned.items():
                        fresh.t[table].update(entries)
            self.names = fresh
            self.device_ids = {name: ident for ident, name in fresh.t["devices"].items() if name}
            self.names.device_ids = self.device_ids
        return self.names


class NotWritten(Exception):
    """Events received but not written (the collector is stopping): no ack, bookmark unchanged."""


class FqeSession(threading.Thread):
    """
    The FQE connection of one input. host: the collector (connect(), stopping, buffer,
    args); writers: {"json": EventWriter or None, "cef": EventWriter or None}.
    """

    def __init__(self, host, kinds, writers, fmc_host, fmc_name, state_dir, start_now):
        super().__init__(name="fqe-session", daemon=True)
        self.host = host
        self.kinds = selection(kinds)
        check_request(self.kinds)
        self.writers = writers
        self.fmc_host, self.fmc_name = fmc_host, fmc_name
        self.bookmark_path = os.path.join(state_dir, "bookmark-fqe.json")
        self.committed = 0 if start_now else self._load_bookmark()
        self.saved = self.committed
        self.names = SharedNames(state_dir)
        # every key exists from the start: the main thread copies this dict for its stats line
        self.stats = {"written": 0, "records": 0, "errors": 0, "bundles": 0, "sessions": 0, "unknown_logged": 0}
        self.errors_logged = 0
        self.last_rx = 0
        self.connected = False

    # ---- bookmark
    def _load_bookmark(self):
        try:
            with open(self.bookmark_path) as fh:
                return int(json.load(fh)["timestamp"])
        except (OSError, ValueError, KeyError, TypeError):
            return 0

    def save_bookmark(self, force=False):
        if self.committed and (force or self.committed != self.saved):
            tmp = self.bookmark_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({"timestamp": self.committed,
                           "saved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, fh)
            os.replace(tmp, self.bookmark_path)
            self.saved = self.committed

    # ---- events
    def handle_records(self, records):
        """Write the events of one bundle. False when they could not all be written (stopping
        while the disk is full or unwritable): then nothing is acknowledged and the bookmark
        stays, so the FMC sends them again next time."""
        out = {"json": [], "cef": []}
        newest = 0
        names = self.names.get() if self.writers.get("cef") else None
        for data in records:
            self.stats["records"] += 1
            try:
                _rtype, ats, obj = parse_record(data)
                newest = max(newest, ats)
                if self.writers.get("json"):
                    out["json"].append(splunk_line(obj, ats, self.fmc_host))
                if self.writers.get("cef"):
                    line = cef_line(obj, names, self.fmc_name)
                    if line:
                        out["cef"].append(line)
                self.stats["written"] += 1
            except Exception as exc:                            # bad record: log, keep going
                self.stats["errors"] += 1
                if self.errors_logged < 20:
                    self.errors_logged += 1
                    LOG.warning("fqe: event not read (%s: %s), %d bytes", type(exc).__name__, exc, len(data))
        for kind, lines in out.items():
            writer = self.writers.get(kind)
            while lines and writer is not None:
                try:
                    writer.write(lines)
                    break
                except OSError as exc:                           # disk full / unwritable: wait, never drop
                    LOG.error("fqe: cannot write events (%s) - retrying in 10 s", exc)
                    writer.close()
                    for _ in range(10):
                        if self.host.stopping:
                            return False
                        time.sleep(1)
        if newest > self.committed:                              # written: the bookmark may move on
            self.committed = newest
        return True

    def handle(self, sock, mtype, data):
        if mtype == proto.MSG_BUNDLE:
            records, unknown = proto.bundle_records(data)
            if not self.handle_records(records):
                raise NotWritten("stopping before the events could be written")
            self.stats["bundles"] += 1
            if unknown and not self.stats.get("unknown_logged"):
                self.stats["unknown_logged"] = 1
                LOG.warning("fqe: bundle with %d item(s) of an unexpected type - skipped", unknown)
            return True
        if mtype == proto.MSG_EVENT_DATA:
            if not self.handle_records([data]):
                raise NotWritten("stopping before the event could be written")
            return True
        if mtype == proto.MSG_ERROR:
            code, text = proto.error_text(data)
            LOG.error("fqe: FMC error %s: %s", code, " ".join(text.split()))
        elif mtype != proto.MSG_NULL:
            LOG.warning("fqe: unexpected message type %s (%d bytes)", mtype, len(data))
        return False

    # ---- connection
    def session(self):
        start = self.committed or int(time.time())
        if not self.committed:              # first request: later ones (reconnects, restarts) start here
            self.committed = start
            self.save_bookmark()
        sock = self.host.connect()
        self.connected = True
        self.stats["sessions"] += 1
        ack = proto.null_message()
        try:
            LOG.info("fqe: connected to %s:%s, requesting %s from %s", self.host.args.host, self.host.args.port,
                     ", ".join(self.kinds), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start)))
            sock.sendall(request(start, self.kinds))
            buf = bytearray()
            self.last_rx = time.time()
            last_save = time.time()
            while not self.host.stopping:
                if self.host.buffer is not None and self.host.buffer.full:
                    LOG.info("fqe: disconnecting while the buffer is full")
                    return
                try:
                    chunk = sock.recv(262144)
                    if not chunk:
                        raise ConnectionError("FMC closed the FQE connection")
                    buf += chunk
                    self.last_rx = time.time()
                except socket.timeout:
                    pass
                while len(buf) >= 8:
                    version, mtype, length = proto.HEADER.unpack_from(buf, 0)
                    if version != 1:
                        raise ConnectionError(f"header version {version}")
                    if length > proto.MAX_MESSAGE:
                        raise ConnectionError(f"message of {length} bytes (more than {proto.MAX_MESSAGE})")
                    if len(buf) < 8 + length:
                        break
                    data = bytes(buf[8:8 + length])
                    del buf[:8 + length]
                    if self.handle(sock, mtype, data):
                        sock.sendall(ack)                       # one acknowledgment per bundle / event
                now = time.time()
                if now - last_save >= 10:
                    self.save_bookmark()
                    last_save = now
                if now - self.last_rx > self.host.args.idle_timeout:
                    raise TimeoutError(f"no data from FMC on the FQE connection for {self.host.args.idle_timeout}s")
        finally:
            self.connected = False
            self.save_bookmark()
            sock.close()

    def run(self):
        backoff = 5
        while not self.host.stopping:
            if self.host.buffer is not None and self.host.buffer.full:
                time.sleep(1)
                continue
            began = time.time()
            try:
                self.session()
            except Exception as exc:
                LOG.warning("fqe: session ended: %s: %s", type(exc).__name__, " ".join(str(exc).split()))
            if self.host.stopping:
                break
            if time.time() - began > 120:
                backoff = 5
            LOG.info("fqe: reconnecting in %ss", backoff)
            for _ in range(backoff):
                if self.host.stopping:
                    break
                time.sleep(1)
            backoff = min(backoff * 2, 60)
        self.save_bookmark(force=True)
        for writer in self.writers.values():
            if writer is not None:
                writer.close()
