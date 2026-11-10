#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer.py - FMC eStreamer event collector for Splunk and CEF.

Runs two ways:
  * Splunk modular input "fmc_estreamer" (normal use). One input per FMC,
    managed from the app's Inputs page or Settings > Data inputs. Splunk
    starts one process per enabled input and restarts it 60 s after it exits.
    The client certificate comes from Splunk's credential store; the input
    keeps its own file monitor in step (index, sourcetype, host = FMC name).
  * Command line, for tests and raw captures (see --help).

Network side, one or two connections per FMC:
  * Binary: connection, policy violation (correlation), VPN login/logoff and
    FireAMP events, and the metadata that names their values. The standard Event
    Stream Request and Streaming Request (always the same bytes, checked against
    known-good copies before connecting), one acknowledgment after every message.
  * FQE (only when file, intrusion or packet events are chosen): the documented
    Event Stream Request with the JSON field list the Cisco Security Cloud app's
    input sends (the same bytes, checked before connecting), one acknowledgment
    after every bundle (fmc_estreamer_fqe.py).
  * Nothing else is ever sent to the FMC. TLS with the eStreamer client
    certificate the FMC issued; full-length reads, reconnect with backoff, and a
    bookmark per connection that only advances once every event before it is on disk.

Decoding: this app's own eStreamer decoder (fmc_estreamer_protocol.py, _events.py).
Worker processes decode in parallel; metadata records (names) go to every
worker so each worker's name tables stay complete.

Output, per input folder (<out-dir>/<input>_<fmc>_<date>_<HHMMSS>_w<n>.<kind>, UTC
start time, one file per writer, a new file every hour or at --rotate-mb):
  * .log: compact JSON for Splunk's file monitor, sourcetype cisco:sfw:estreamer
    (connection events with the Security Cloud app's field names, FQE events as
    the FMC sends them, other types with CIM field names), unset fields dropped;
  * .cef: CEF lines (fmc_estreamer_cef.py) for a syslog agent to read and delete.

Disk: a .log file is deleted --delete-after-min after Splunk's file monitor has
read all of it. The folder (both kinds) never grows past --max-buffer-gb: when
full, the collector either pauses (stops reading from the FMC and resumes from its
bookmarks once there is room) or deletes the oldest files even if they have not
been read (--when-full delete_oldest).

Record types: what the FMC sends is counted per record type (collector log and
<state-dir>/record_types.json); a raw sample can be switched on with
<state-dir>/raw_sample.request (see "record types" below).

Runs on Splunk's bundled Python, standard library only.
Only one collector per state dir can run; a second one exits.

Command-line test run (writes to the given dirs, stops after N seconds):
  $SPLUNK_HOME/bin/splunk cmd python3 fmc_estreamer.py --host 192.0.2.10 \\
      --cert client.cert --key client.key --types connection,vpn --cef \\
      --out-dir /tmp/es-test/out --state-dir /tmp/es-test/state \\
      --start now --test-seconds 120
"""
import argparse
import base64
import collections
import fcntl
import json
import logging
import logging.handlers
import multiprocessing
import os
import queue
import re
import shutil
import signal
import socket
import ssl
import struct
import sys
import time
import xml.etree.ElementTree as ElementTree
from xml.sax.saxutils import escape as xml_escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fmc_estreamer_cef as cef  # noqa: E402
import fmc_estreamer_events as events  # noqa: E402
import fmc_estreamer_fqe as fqe  # noqa: E402
import fmc_estreamer_protocol as proto  # noqa: E402
import fmc_estreamer_store as store  # noqa: E402

LOG = logging.getLogger("fmc_estreamer")


# ------------------------------------------------------------------- output

class EventWriter:
    """
    One decoder process's events of one kind: <folder>/<prefix>_<date>_<HHMMSS>_w<n>.<kind>
    (UTC start time; kind log = JSON for Splunk, cef = CEF lines). A new file starts
    every hour and when max_bytes is reached. Files are never renamed or reopened, so
    each is read once and deleted afterwards. A name is never used twice, so a reader
    that remembers files by name (Splunk, a syslog agent) never mistakes a new file
    for an old, deleted one: a writer that needs a second new file within the same
    second waits for the next second (at most one file a second, never named ahead
    of the clock), and its first file also starts after its newest file in the folder.
    """

    def __init__(self, folder, prefix, worker, max_bytes, kind="log"):
        self.folder, self.prefix, self.worker, self.max_bytes = folder, prefix, worker, max_bytes
        self.kind = kind
        self.fh, self.path, self.size, self.hour = None, None, 0, None
        self.last_start = None                          # start time in this writer's newest file name

    def _newest_start(self):
        """Start time of this writer's newest file of this kind already in the folder (0: none)."""
        newest = 0
        for f in store.list_event_files(self.folder):
            m = store.EVENT_RE.match(os.path.basename(f["path"]))
            if m and m.group("prefix") == self.prefix and f["worker"] == self.worker and f["kind"] == self.kind:
                newest = max(newest, f["start"])
        return newest

    def _open(self, now):
        last = self.last_start if self.last_start is not None else self._newest_start()
        start = int(now)
        if start <= last:
            if self.last_start is not None and last - start < 2:
                time.sleep(max(0.0, last + 1 - now))    # a second file within one second: wait for the next
                now = time.time()
            start = max(int(now), last + 1)             # (after a restart: a file named ahead, or a clock step)
        while True:
            path = os.path.join(self.folder, store.event_file_name(self.prefix, start, self.worker, self.kind))
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o640)
                break
            except FileExistsError:
                start += 1
        self.fh = os.fdopen(fd, "ab")
        self.path, self.size, self.hour, self.last_start = path, 0, int(now // 3600), start

    def write(self, lines):
        data = ("\n".join(lines) + "\n").encode("utf-8")
        now = time.time()
        if self.fh is None or int(now // 3600) != self.hour or \
                (self.size and self.size + len(data) > self.max_bytes) or self._deleted():
            self.close()
            self._open(now)
        self.fh.write(data)
        self.fh.flush()
        self.size += len(data)

    def _deleted(self):
        """The current file was deleted (e.g. by whatever reads the CEF files): start a new one."""
        try:
            return os.fstat(self.fh.fileno()).st_nlink == 0
        except (OSError, ValueError):
            return True

    def close(self):
        fh, self.fh = self.fh, None
        if fh is not None:
            try:
                fh.close()                  # may fail again after a failed write (disk full)
            except OSError:
                pass


DISK_RESERVE = 1 << 30            # disk nearly full: less than 1 GB free where the event folder is
DISK_RESUME = 2 << 30             # ... and back to normal at 2 GB free


class EventBuffer:
    """
    The input's event folder (parent process): deletes files Splunk has read,
    keeps the folder under the size cap and the disk from filling up, and says
    when to pause. Buffer full and disk nearly full are handled the same way,
    by the input's when_full setting (delete the oldest files, or pause).
    """

    def __init__(self, args, splunkd=None):
        self.folder = args.out_dir
        self.cap = int(args.max_buffer_gb * (1 << 30))
        self.resume_at = int(self.cap * 0.9)
        self.when_full = args.when_full
        self.delete_after = args.delete_after_min * 60
        self.splunkd = splunkd
        self.run_start = int(time.time())
        self.full = False
        self.total = self.files = 0
        self.warned = set()

    def _warn_once(self, key, msg, *args):
        if key not in self.warned:
            self.warned.add(key)
            LOG.warning(msg, *args)

    def _open_files(self, files):
        """Newest file of each writer and kind started by this run (may still be written)."""
        newest = {}
        for f in files:
            if f["start"] >= self.run_start - 1:
                newest[(f["worker"], f["kind"])] = f["path"]
        return set(newest.values())

    def _splunk_read(self):
        if not self.splunkd:
            return None
        try:
            status = store.splunk_file_status(self.splunkd, self.folder)
            self.warned.discard("status")
            return status
        except Exception as exc:
            self._warn_once("status", "cannot read Splunk's file status (%s); files are deleted only "
                            "when the buffer is full%s", exc,
                            " (pause mode: the input stays paused until the status is readable)"
                            if self.when_full == "pause" else "")
            return None

    @staticmethod
    def _remove(f):
        try:
            os.remove(f["path"])
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            LOG.warning("could not delete %s: %s", f["path"], exc)
            return False

    def _free(self):
        try:
            return shutil.disk_usage(self.folder).free
        except OSError:
            return None

    def check(self, ask_splunk=True):
        """ask_splunk=False: only the size cap and free disk (cheap, every few seconds)."""
        files = store.list_event_files(self.folder)
        busy = self._open_files(files)
        read = self._splunk_read() if ask_splunk else None
        now = time.time()
        free = self._free()
        disk_low = free is not None and free < DISK_RESERVE
        # Over the cap, disk nearly full or paused: files Splunk has read go at once, without the delay.
        delay = 0 if self.full or disk_low or sum(f["size"] for f in files) >= self.cap else self.delete_after
        done, done_bytes, unseen = [], 0, 0
        for f in files:
            # CEF files are read by a syslog agent, which deletes them; here they only count
            # towards the buffer (and go first-in-first-out when it is full).
            if f["kind"] != "log" or f["path"] in busy or read is None or now - f["mtime"] < delay:
                continue
            seen = read.get(os.path.realpath(f["path"]))
            if seen and seen[1] == f["size"] and seen[0] >= f["size"]:
                if self._remove(f):
                    done.append(f)
                    done_bytes += f["size"]
            elif not seen:
                unseen += 1
        if done:
            LOG.info("deleted %d event files Splunk has read (%.2f GB)", len(done), done_bytes / (1 << 30))
        if unseen and read is not None and not read:
            self._warn_once("unseen", "Splunk is not reading %s (no file monitor?); files are deleted only "
                            "when the buffer is full", self.folder)
        gone = {f["path"] for f in done}
        left = [f for f in files if f["path"] not in gone]
        total = sum(f["size"] for f in left)
        if done:
            free = self._free()
            disk_low = free is not None and free < DISK_RESERVE
        over = total >= self.cap
        gb = 1 << 30

        if (over or disk_low) and self.when_full == "delete_oldest":
            dropped, dropped_bytes, free_before = 0, 0, free
            for f in left:
                if total < self.resume_at and (free is None or free >= DISK_RESUME):
                    break
                if f["path"] in busy or f["path"] in gone:
                    continue
                if self._remove(f):
                    total -= f["size"]
                    dropped += 1
                    dropped_bytes += f["size"]
                    gone.add(f["path"])
                    free = self._free()
            if dropped:
                why = (f"buffer full (max {self.cap / gb:.0f} GB)" if over else
                       f"disk nearly full ({free_before / gb:.1f} GB free)")
                LOG.warning("%s: deleted %d files not read yet (%.2f GB) - those events are lost",
                            why, dropped, dropped_bytes / gb)
            if free is not None and free < DISK_RESERVE:
                self._warn_once("disk", "disk nearly full: %.1f GB free for %s and no more event files to "
                                "delete; other files are filling the disk", free / gb, self.folder)
            else:
                self.warned.discard("disk")
        elif (over or disk_low) and not self.full:
            self.full = True
            if over:
                LOG.warning("buffer full: %.2f GB in %s (max %.0f GB) - pausing; resumes from the bookmark "
                            "once enough files have been read and deleted", total / gb, self.folder, self.cap / gb)
            else:
                LOG.warning("disk nearly full: %.1f GB free for %s - pausing; resumes from the bookmark when "
                            "%.0f GB are free", free / gb, self.folder, DISK_RESUME / gb)
        elif self.full and total < self.resume_at and (free is None or free >= DISK_RESUME):
            self.full = False
            LOG.info("buffer down to %.2f GB, %s free - resuming", total / gb,
                     "?" if free is None else f"{free / gb:.1f} GB")
        self.total = total
        self.files = len([f for f in left if f["path"] not in gone])
        return self.full


class BufferFull(Exception):
    pass


class OldFolders:
    """
    Event folders this input wrote to before its Event folder was changed
    (recorded by the Inputs page): files Splunk has read there are deleted, and
    once a folder is empty its file monitor is removed.
    """

    def __init__(self, args, splunkd=None):
        self.name = args.input_name
        self.current = os.path.realpath(args.out_dir)
        self.splunkd = splunkd
        self.cef_waiting = set()

    def check(self):
        if not self.name or not self.splunkd:
            return
        folders = store.read_old_folders(self.name)
        keep = []
        for folder in folders:
            if os.path.realpath(folder) == self.current:
                continue
            logs = [f for f in store.list_event_files(folder) if f["kind"] == "log"]
            if logs:
                try:
                    read = store.splunk_file_status(self.splunkd, folder)
                except Exception:
                    keep.append(folder)
                    continue
                for f in logs:
                    seen = read.get(os.path.realpath(f["path"]))
                    if seen and seen[1] == f["size"] and seen[0] >= f["size"]:
                        EventBuffer._remove(f)
                if any(f["kind"] == "log" for f in store.list_event_files(folder)):
                    keep.append(folder)
                    continue
            try:
                store.remove_monitor(self.splunkd, folder)
            except Exception as exc:
                LOG.warning("previous event folder %s: could not remove its file monitor (%s)", folder, exc)
                keep.append(folder)
                continue
            if store.list_event_files(folder):
                # Splunk is done here; CEF files are left for the syslog agent, which deletes them
                # once read. The folder is checked again until they are gone.
                if folder not in self.cef_waiting:
                    self.cef_waiting.add(folder)
                    LOG.info("previous event folder %s: Splunk has read it (file monitor removed); "
                             "CEF files are left for the syslog agent", folder)
                keep.append(folder)
                continue
            try:
                os.rmdir(folder)
            except OSError:
                pass
            self.cef_waiting.discard(folder)
            LOG.info("previous event folder %s has been read and emptied; its file monitor is removed", folder)
        if keep != folders:
            store.write_old_folders(self.name, keep)


LOG_MAX_BYTES = 10 << 20          # collector and console logs: 10 MB, 3 old copies kept
LOG_KEEP = 3


def shift_old_logs(path, keep=LOG_KEEP):
    """path.2 -> path.3, path.1 -> path.2 (the oldest beyond keep is replaced)."""
    for i in range(keep - 1, 0, -1):
        if os.path.exists(f"{path}.{i}"):
            os.replace(f"{path}.{i}", f"{path}.{i + 1}")


def rotate_console(path, max_bytes=LOG_MAX_BYTES):
    """
    The console file is every process's stdout/stderr (opened with O_APPEND), so
    it is copied to path.1 and truncated in place rather than renamed.
    """
    try:
        if not path or os.path.getsize(path) < max_bytes:
            return
        shift_old_logs(path)
        shutil.copyfile(path, path + ".1")
        os.truncate(path, 0)
    except OSError:
        pass


# ------------------------------------------------------------- event types

# Event types an input can collect: name -> binary record types, or the FQE event type.
EVENT_TYPES = ("connection", "policy_violation", "vpn", "fireamp", "file", "intrusion", "packets")
BINARY_TYPES = {"connection": (proto.RECORD_CONNECTION,), "policy_violation": (events.RECORD_CORRELATION,),
                "vpn": (events.RECORD_VPN_LOGIN, events.RECORD_VPN_LOGOFF), "fireamp": (events.RECORD_MALWARE,)}
FQE_TYPES = {"file": "FileEvent", "intrusion": "IntrusionEvent", "packets": "IntrusionPacket"}


def binary_record_types(types):
    return {rtype for name in types for rtype in BINARY_TYPES.get(name, ())}


def fqe_event_kinds(types):
    return fqe.selection([FQE_TYPES[name] for name in types if name in FQE_TYPES])


def open_writers(workers, splunk, cef, fqe_session):
    """Files open at once (never deleted while written): per decoder process and output kind, plus
    the FQE connection's. Max buffer must hold two of each, or a full buffer never drains."""
    kinds = int(bool(splunk)) + int(bool(cef))
    return (workers + (1 if fqe_session else 0)) * kinds


def parse_types(text):
    names = [t.strip() for t in (text or "").split(",") if t.strip()]
    bad = [t for t in names if t not in EVENT_TYPES]
    if bad:
        raise ValueError(f"unknown event type(s): {', '.join(bad)} (choose from {', '.join(EVENT_TYPES)})")
    return [t for t in EVENT_TYPES if t in names]


# ------------------------------------------------------------------ workers

def worker_main(idx, cfg, inq, doneq):
    """
    Decode raw eStreamer records, add names from the metadata tables, write JSON lines
    (Splunk) and/or CEF lines. Metadata records only update the name tables.
    """
    logging.basicConfig(level=cfg["log_level"],
                        format=f"%(asctime)s worker-{idx} %(levelname)s %(message)s")
    log = logging.getLogger(f"worker-{idx}")
    signal.signal(signal.SIGINT, signal.SIG_IGN)      # parent handles shutdown
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    parent = os.getppid()

    names = proto.Names(os.path.join(cfg["state_dir"], f"names-{idx}.json"))
    names.load()
    writers = []
    if cfg["splunk"]:
        writers.append(("json", EventWriter(cfg["out_dir"], cfg["file_prefix"], idx, cfg["rotate_bytes"], "log")))
    if cfg["cef"]:
        writers.append(("cef", EventWriter(cfg["out_dir"], cfg["file_prefix"], idx, cfg["rotate_bytes"], "cef")))
    want_json, want_cef = cfg["splunk"], cfg["cef"]
    fmc_host, fmc_name = cfg["host"], cfg["fmc_name"]
    wanted = set(cfg["types"])
    errors_logged = 0
    newer_blocks = set()
    last_save = time.time()

    while True:
        try:
            item = inq.get(timeout=5)
        except queue.Empty:
            if os.getppid() != parent:                  # collector was killed
                log.error("collector process is gone - exiting")
                break
            continue
        if item is None:
            break
        batch_id, records = item
        out = {"json": [], "cef": []}
        written, errors = 0, 0
        for data in records:
            rtype = None
            try:
                rtype = struct.unpack_from(">L", data, 0)[0]
                if rtype == proto.RECORD_CONNECTION:
                    if rtype not in wanted:
                        continue
                    record, layout = proto.decode_connection(data)
                    if layout != record["blockType"] and record["blockType"] not in newer_blocks:
                        newer_blocks.add(record["blockType"])
                        log.warning("connection block type %s is not one this version knows; reading it as "
                                    "block %s (fields added after that one are not written)",
                                    record["blockType"], layout)
                    fields = proto.connection_fields(record, names)
                    if want_json:
                        out["json"].append(proto.format_connection_fields(record, fields, fmc_host))
                    if want_cef:
                        out["cef"].append(cef.connection(record, fields, fmc_name,
                                                         names.t["users"].get(record.get("userId"))))
                    written += 1
                elif rtype in events.EVENT_TYPES:
                    if rtype not in wanted:
                        continue
                    decode, to_fields, cef_name = events.EVENT_TYPES[rtype]
                    rec = decode(data)
                    if want_json:
                        out["json"].append(events.to_json(to_fields(rec, names, fmc_host)))
                    if want_cef:
                        out["cef"].append(getattr(cef, cef_name)(rec, names, fmc_name))
                    written += 1
                else:
                    names.store(data)
            except Exception as exc:                    # bad record: log, keep going
                errors += 1
                if errors_logged < 20:
                    errors_logged += 1
                    log.warning("decode failed (%s: %s), record type %s, %d bytes", type(exc).__name__,
                                exc, rtype if rtype is not None else "?", len(data))
                    log.debug("record=%s", base64.b64encode(data[:512]).decode())
        for kind, writer in writers:
            lines = out[kind]
            while lines:                                # disk full / unwritable: wait, never drop
                try:
                    writer.write(lines)
                    break
                except OSError as exc:
                    log.error("cannot write events to %s (%s) - retrying in 10 s", cfg["out_dir"], exc)
                    writer.close()
                    time.sleep(10)
                    if os.getppid() != parent:
                        return
        doneq.put((batch_id, written, errors))
        if time.time() - last_save > 300:
            save_names(names, log)
            last_save = time.time()

    save_names(names, log)
    for _kind, writer in writers:
        writer.close()


def save_names(names, log):
    try:
        names.save()
    except OSError as exc:
        log.warning("could not save the name tables to %s: %s", names.path, exc)


# ------------------------------------------------------------- record types

# What the FMC sends, per record type (added in 2.1.4). Always on and read-only
# towards the FMC:
#   * the first record of each type, and each new data block version of a type,
#     are logged once (type, size and block numbers only, no event contents);
#   * every hour one line counts the records of each type;
#   * <state-dir>/record_types.json, rewritten every minute, holds the same counts.
# Raw sample, off by default: while <state-dir>/raw_sample.request exists (checked
# at start and every minute; it may hold the number of records to keep per type,
# default 500), the first records of each type are saved exactly as received to
# <state-dir>/raw_sample/records.bin (4-byte big-endian length, then the record),
# with a summary in sample.json, 256 MB at most. Deleting the request file stops it;
# the sample then continues where it left off when the request file comes back.
# Deleting records.bin (also while it runs) starts a new sample. The sample holds
# event contents (addresses, user names, packet payloads); it is never indexed.

RECORD_TYPES_FILE = "record_types.json"
SAMPLE_REQUEST = "raw_sample.request"
SAMPLE_DIR = "raw_sample"
SAMPLE_DEFAULT = 500
SAMPLE_MAX_PER_TYPE = 100000
SAMPLE_MAX_BYTES = 256 << 20
SAMPLE_MAX_RECORD = 1 << 24             # larger records are not saved (and end a scan of the file)
MAX_TYPES = 512                         # record types tracked one by one; any more are counted as "other"
MAX_BLOCKS = 32                         # distinct data blocks tracked per record type
OTHER = "other"
RECORD_NAMES = {2: "intrusion packet", 71: "connection statistics", 110: "intrusion extra data",
                112: "correlation", 125: "malware", 170: "VPN login", 171: "VPN logoff",
                400: "intrusion", 500: "file", 502: "file malware"}
_PAIR = struct.Struct(">LL")
_LEN = struct.Struct(">L")


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _type_name(rtype):
    if rtype == OTHER:
        return "more record types than tracked one by one"
    return RECORD_NAMES.get(rtype) or ("metadata" if rtype in proto.METADATA_TYPES else "")


def record_body(rec):
    """Offset of a raw record's body: 16 with an archive timestamp, else 8."""
    return 16 if len(rec) >= 8 and len(rec) == 16 + _PAIR.unpack_from(rec, 0)[1] else 8


def record_block(rec):
    """
    Data block type of a raw record, or None. Tried in order: a block that starts
    the body, then one after a 40-byte discovery header (plus 16 bytes of IPv6
    address when its IPv6 flag is set); either counts when its length field (which
    includes the 8-byte block header) matches the rest of the record.
    """
    size = len(rec)
    if size < 16:
        return None
    off = record_body(rec)
    if size - off >= 8:
        btype, blen = _PAIR.unpack_from(rec, off)
        if blen == size - off:
            return btype
    if size - off >= 48:
        start = off + 40 + (16 if rec[off + 14] == 1 else 0)
        if size - start >= 8:
            btype, blen = _PAIR.unpack_from(rec, start)
            if blen == size - start:
                return btype
    return None


class RecordTypes:
    """Counts the records the FMC sends, per type and data block (parent process); optional raw sample."""

    def __init__(self, state_dir):
        self.path = os.path.join(state_dir, RECORD_TYPES_FILE)
        self.request = os.path.join(state_dir, SAMPLE_REQUEST)
        self.sample_dir = os.path.join(state_dir, SAMPLE_DIR)
        self.sample_path = os.path.join(self.sample_dir, "records.bin")
        self.started = time.time()
        self.types = {}                 # record type (or OTHER) -> entry
        self.hour_counts = {}           # counts at the last hourly line
        self.last_hour = self.started
        self.sample_fh = None           # open while the raw sample is on
        self.sample_limit = 0
        self.saved = {}                 # record type -> records in records.bin
        self.sample_bytes = 0
        self.sample_full = False
        self.sample_failed = None       # request file (identity) a sample failed with: not retried until it changes
        self._step("raw sample", self._sample_switch)   # requested before the start: sample from the first record

    @staticmethod
    def _step(what, fn, *args):
        """Run one housekeeping step; a failure is logged and never reaches the collector."""
        try:
            fn(*args)
        except Exception as exc:
            LOG.warning("%s: %s: %s", what, type(exc).__name__, exc)

    # ---- every record

    def see(self, rtype, rec):
        block = record_block(rec)
        size = len(rec)
        entry = self.types.get(rtype)
        if entry is None:
            if len(self.types) >= MAX_TYPES:
                rtype = OTHER
                entry = self.types.get(OTHER)
            if entry is None:
                entry = self.types[rtype] = {"count": 0, "blocks": {}, "first_seen": time.time(),
                                             "min": size, "max": size,
                                             "starts": rec[record_body(rec):record_body(rec) + 24].hex()}
                LOG.info("record type %s (%s) first seen: %d bytes, data block %s", rtype,
                         _type_name(rtype) or "?", size, "?" if block is None else block)
        entry["count"] += 1
        blocks = entry["blocks"]
        if block in blocks:
            blocks[block] += 1
        else:
            if len(blocks) >= MAX_BLOCKS:               # not a block field after all: count the rest together
                block = OTHER
            elif blocks and len(blocks) <= 5:
                LOG.info("record type %s: new data block %s (already seen: %s)%s", rtype,
                         "?" if block is None else block, ", ".join("?" if b is None else str(b) for b in blocks),
                         "; further new blocks are only counted in " + RECORD_TYPES_FILE if len(blocks) == 5 else "")
            blocks[block] = blocks.get(block, 0) + 1
        if size > entry["max"]:
            entry["max"] = size
        elif size < entry["min"]:
            entry["min"] = size
        if self.sample_fh is not None and rtype != OTHER:
            self._save(rtype, rec)

    def _save(self, rtype, rec):
        n = self.saved.get(rtype, 0)
        if n >= self.sample_limit or len(rec) > SAMPLE_MAX_RECORD:
            return
        size = 4 + len(rec)
        if self.sample_bytes + size > SAMPLE_MAX_BYTES:
            if not self.sample_full:
                self.sample_full = True
                LOG.warning("raw sample has reached %d MB: no more records are saved", SAMPLE_MAX_BYTES >> 20)
            return
        try:
            self.sample_fh.write(_LEN.pack(len(rec)) + rec)
        except OSError as exc:
            LOG.warning("raw sample: cannot write to %s (%s) - stopped; it is tried again when %s changes",
                        self.sample_path, exc, self.request)
            self._stop_sample(failed=True)
            self.sample_failed = self._request_id()
            return
        self.saved[rtype] = n + 1
        self.sample_bytes += size

    # ---- every minute (housekeeping)

    def tick(self, now=None):
        now = now or time.time()
        self._step("raw sample", self._sample_switch)
        if self.sample_fh is not None:
            self._step("raw sample", self._flush_sample)
        self._step("record types", self._write_types, now)
        if now - self.last_hour >= 3600:
            self._step("record types", self._log_hour, now)

    def close(self):
        self._step("record types", self._write_types, time.time())
        if self.sample_fh is not None:
            self._step("raw sample", self._stop_sample)

    def _log_hour(self, now):
        parts = []
        for rtype in sorted(self.types, key=lambda t: (t == OTHER, t if t != OTHER else 0)):
            entry = self.types[rtype]
            n = entry["count"] - self.hour_counts.get(rtype, 0)
            if n:
                blocks = "/".join("?" if b is None else str(b) for b in entry["blocks"])
                parts.append(f"{rtype}={n}" + (f" (block {blocks})" if blocks != "?" else ""))
        self.hour_counts = {t: e["count"] for t, e in self.types.items()}
        minutes, self.last_hour = (now - self.last_hour) / 60, now
        LOG.info("records per type in the last %.0f min: %s", minutes, ", ".join(parts) or "none")

    def _write_types(self, now):
        doc = {"updated": _iso(now), "since": _iso(self.started),
               "raw_sample": (f"on, up to {self.sample_limit} per type" if self.sample_fh is not None else "off"),
               "types": {}}
        for rtype in sorted(self.types, key=lambda t: (t == OTHER, t if t != OTHER else 0)):
            e = self.types[rtype]
            doc["types"][str(rtype)] = {
                "name": _type_name(rtype), "count": e["count"], "first_seen": _iso(e["first_seen"]),
                "bytes": [e["min"], e["max"]],
                "blocks": {("?" if b is None else str(b)): n for b, n in e["blocks"].items()},
                "body_starts": e["starts"]}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        os.replace(tmp, self.path)

    # ---- raw sample

    def _request_id(self):
        """Identity of the request file (inode, mtime, size), or None when it is absent."""
        try:
            st = os.stat(self.request)
        except OSError:
            return None
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def _requested(self):
        """None when the request file is absent, else the records to keep per type."""
        try:
            with open(self.request, encoding="utf-8", errors="replace") as fh:
                text = fh.read(100).strip()
        except FileNotFoundError:
            return None
        if re.fullmatch(r"\d+", text or ""):
            return max(1, min(int(text), SAMPLE_MAX_PER_TYPE))
        return SAMPLE_DEFAULT

    def _sample_switch(self):
        limit = self._requested()
        if limit is None:
            self.sample_failed = None
            if self.sample_fh is not None:
                self._stop_sample()
            return
        if self.sample_fh is not None:
            if os.fstat(self.sample_fh.fileno()).st_nlink == 0:
                LOG.info("raw sample: %s was deleted - starting a new sample", self.sample_path)
                self._stop_sample(failed=True)
            elif limit != self.sample_limit:
                self.sample_limit = limit
                LOG.info("raw sample: now up to %d records of each record type", limit)
                return
            else:
                return
        request = self._request_id()
        if self.sample_failed is not None and self.sample_failed == request:
            return                                      # failed with this request: wait until it changes
        try:
            self._start_sample(limit)
            self.sample_failed = None
        except OSError as exc:
            self.sample_failed = request
            LOG.warning("raw sample: cannot start (%s); it is tried again when %s changes", exc, self.request)

    def _start_sample(self, limit):
        os.makedirs(self.sample_dir, mode=0o750, exist_ok=True)
        self.saved, good = self._scan_sample()
        fd = os.open(self.sample_path, os.O_WRONLY | os.O_CREAT, 0o640)
        try:
            os.ftruncate(fd, good)                          # drop a record cut short by a crash
            os.lseek(fd, good, os.SEEK_SET)
            self.sample_fh = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        self.sample_bytes = good
        self.sample_limit = limit
        self.sample_full = good + 8 > SAMPLE_MAX_BYTES
        LOG.info("raw sample on: saving up to %d records of each record type to %s (%d MB at most; "
                 "delete %s to stop)%s", limit, self.sample_path, SAMPLE_MAX_BYTES >> 20, self.request,
                 f", continuing a sample of {sum(self.saved.values())} records" if self.saved else "")

    def _scan_sample(self):
        """Records per type already in records.bin, and the size up to its last complete record."""
        saved, good = {}, 0
        try:
            with open(self.sample_path, "rb") as fh:
                while True:
                    head = fh.read(4)
                    if len(head) < 4:
                        break
                    size = _LEN.unpack(head)[0]
                    if size < 8 or size > SAMPLE_MAX_RECORD:    # not a record length: stop here
                        break
                    rec = fh.read(size)
                    if len(rec) < size:
                        break
                    rtype = _LEN.unpack_from(rec, 0)[0]
                    saved[rtype] = saved.get(rtype, 0) + 1
                    good += 4 + size
        except FileNotFoundError:
            pass
        return saved, good

    def _flush_sample(self):
        try:
            self.sample_fh.flush()
        except OSError as exc:
            LOG.warning("raw sample: cannot write to %s (%s) - stopped; it is tried again when %s changes",
                        self.sample_path, exc, self.request)
            self._stop_sample(failed=True)
            self.sample_failed = self._request_id()
            return
        self._write_sample_summary()

    def _stop_sample(self, failed=False):
        fh, self.sample_fh = self.sample_fh, None
        try:
            fh.close()
        except OSError:
            pass
        if not failed:
            self._write_sample_summary()
            LOG.info("raw sample off: %d records of %d record types in %s", sum(self.saved.values()),
                     len(self.saved), self.sample_path)

    def _write_sample_summary(self):
        doc = {"updated": _iso(time.time()), "file": self.sample_path, "bytes": self.sample_bytes,
               "limit_per_type": self.sample_limit, "full": self.sample_full,
               "format": "per record: 4-byte big-endian length, then the record as received",
               "types": {str(t): {"saved": n, "name": _type_name(t)} for t, n in sorted(self.saved.items())}}
        path = os.path.join(self.sample_dir, "sample.json")
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        os.replace(path + ".tmp", path)


# ----------------------------------------------------------------- receiver

class ProtocolError(Exception):
    pass


class WorkerDied(Exception):
    pass


class Collector:
    def __init__(self, args, splunkd=None):
        self.args = args
        self.stopping = False
        self.fatal = False
        self.buffer = EventBuffer(args, splunkd)
        self.old_folders = OldFolders(args, splunkd)
        self.last_buffer = self.last_buffer_size = 0
        proto.check_requests()                # the FMC only ever gets the standard request bytes
        self.meta_types = proto.METADATA_TYPES
        self.binary_types = binary_record_types(args.types)  # event records the workers write
        self.fqe_kinds = fqe_event_kinds(args.types)       # events asked for on the FQE connection
        if self.fqe_kinds:
            fqe.check_request(self.fqe_kinds)
        self.fqe = None
        self.types = RecordTypes(args.state_dir)    # what the FMC sends, per record type

        self.bookmark_path = os.path.join(args.state_dir, "bookmark.json")
        self.committed = self._load_bookmark()
        self.hw_ts = self.committed           # newest archive timestamp received
        self.batch_id = 0
        self.cur_batch = []
        self.next_worker = 0
        self.inflight = collections.deque()   # [batch_id, hw_ts, done]
        self.by_id = {}
        self.stats = collections.Counter()
        self.last_flush = self.last_meta_flush = self.last_save = time.time()
        self.last_stats = time.time()
        self.stats_mark = collections.Counter()
        self.saved_bookmark = self.committed
        for old in os.listdir(args.state_dir):          # name caches of 2.0.x (replaced by names-N.json)
            if old.startswith("cache-") and old.endswith(".dat"):
                try:
                    os.remove(os.path.join(args.state_dir, old))
                except OSError:
                    pass

    # ---- bookmark

    def _load_bookmark(self):
        try:
            with open(self.bookmark_path) as fh:
                return int(json.load(fh)["timestamp"])
        except (OSError, ValueError, KeyError):
            return 0

    def _save_bookmark(self, force=False):
        if self.committed and (force or self.committed != self.saved_bookmark):
            tmp = self.bookmark_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({"timestamp": self.committed,
                           "saved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, fh)
            os.replace(tmp, self.bookmark_path)
            self.saved_bookmark = self.committed

    # ---- workers

    def start_workers(self):
        ctx = multiprocessing.get_context("spawn")
        self.doneq = ctx.Queue()
        self.queues, self.procs = [], []
        cfg = {
            "state_dir": self.args.state_dir, "out_dir": self.args.out_dir,
            "rotate_bytes": self.args.rotate_mb * 1024 * 1024, "file_prefix": self.args.file_prefix,
            "host": self.args.host, "log_level": self.args.log_level,
            "fmc_name": self.args.fmc_name, "splunk": self.args.splunk, "cef": self.args.cef,
            "types": sorted(self.binary_types),
        }
        for idx in range(self.args.workers):
            q = ctx.Queue(maxsize=8)
            p = ctx.Process(target=worker_main, args=(idx, cfg, q, self.doneq),
                            name=f"estreamer-worker-{idx}", daemon=True)
            p.start()
            self.queues.append(q)
            self.procs.append(p)
        self.meta_backlog = [[] for _ in self.queues]

    def stop_workers(self):
        for q, proc in zip(self.queues, self.procs):
            if proc.is_alive():
                try:
                    q.put(None, timeout=5)
                except queue.Full:
                    pass
        for proc in self.procs:
            proc.join(timeout=60)
            if proc.is_alive():
                proc.terminate()

    def _send_batch(self, worker, records):
        self.batch_id += 1
        entry = [self.batch_id, self.hw_ts, False]
        self.inflight.append(entry)
        self.by_id[self.batch_id] = entry
        while True:                                          # waits while the worker is busy
            try:
                self.queues[worker].put((self.batch_id, records), timeout=1)
                return
            except queue.Full:
                self.check_workers()

    def check_workers(self):
        for idx, proc in enumerate(self.procs):
            if not proc.is_alive():
                raise WorkerDied(f"worker {idx} exited with code {proc.exitcode}")

    def flush(self):
        """Send the current event batch (plus that worker's pending metadata) to the next worker."""
        if self.cur_batch:
            w = self.next_worker
            self.next_worker = (w + 1) % len(self.queues)
            records = self.meta_backlog[w] + self.cur_batch
            self.meta_backlog[w] = []
            self.cur_batch = []
            self._send_batch(w, records)
        self.last_flush = time.time()

    def flush_meta(self):
        """Push pending metadata to idle workers so their caches stay current."""
        for w, backlog in enumerate(self.meta_backlog):
            if backlog:
                self.meta_backlog[w] = []
                self._send_batch(w, backlog)
        self.last_meta_flush = time.time()

    def dispatch(self, rec):
        if len(rec) < 8:
            return
        rtype, rlen = struct.unpack_from(">LL", rec, 0)
        if len(rec) == 16 + rlen:
            ats = struct.unpack_from(">L", rec, 8)[0]
            if ats > self.hw_ts:
                self.hw_ts = ats
        self.stats["records"] += 1
        self.types.see(rtype, rec)
        if rtype in self.meta_types:
            self.stats["metadata"] += 1
            for backlog in self.meta_backlog:
                backlog.append(rec)
        elif rtype in self.binary_types:
            self.cur_batch.append(rec)
            if len(self.cur_batch) >= self.args.batch:
                self.flush()
        else:
            self.stats["skipped"] += 1

    def drain_done(self):
        while True:
            try:
                batch_id, written, errors = self.doneq.get_nowait()
            except Exception:
                break
            self.stats["written"] += written
            self.stats["errors"] += errors
            entry = self.by_id.pop(batch_id, None)
            if entry:
                entry[2] = True
        while self.inflight and self.inflight[0][2]:
            self.committed = max(self.committed, self.inflight.popleft()[1])
        if not self.inflight and not self.cur_batch and not any(self.meta_backlog):
            self.committed = max(self.committed, self.hw_ts)

    def housekeeping(self, final=False):
        now = time.time()
        if not final:
            self.check_workers()
        if final or now - self.last_flush >= 1:
            self.flush()
        if final or now - self.last_meta_flush >= 5:
            self.flush_meta()
        self.drain_done()
        if final or now - self.last_save >= 10:
            self._save_bookmark()
            self.last_save = now
        if now - self.last_stats >= 60:
            self.log_stats(now - self.last_stats)
            self.last_stats = now
            rotate_console(self.args.stderr_file)
            self.types.tick(now)
        if self.buffer and not final:
            self.buffer_tick(now)
            if self.buffer.full:
                raise BufferFull()

    def buffer_tick(self, now):
        """Size cap every 5 s, Splunk's read status (and old folders) every minute."""
        if now - self.last_buffer_size >= 5:
            ask = now - self.last_buffer >= 60
            self.buffer.check(ask_splunk=ask)
            self.last_buffer_size = now
            if ask:
                self.last_buffer = now
                self.old_folders.check()

    def idle_tick(self):
        """While the binary connection is down (reconnect wait): the FQE connection may still be
        writing, so keep the buffer checks and the stats line going."""
        now = time.time()
        if self.buffer:
            self.buffer_tick(now)
        if now - self.last_stats >= 60:
            self.log_stats(now - self.last_stats)
            self.last_stats = now
            rotate_console(self.args.stderr_file)

    def log_stats(self, secs):
        d = self.stats - self.stats_mark
        self.stats_mark = collections.Counter(self.stats)
        lag = (time.time() - self.committed) / 60 if self.committed else -1
        buf = ""
        if self.buffer:
            buf = ", buffer %.2f GB%s" % (self.buffer.total / (1 << 30), " PAUSED" if self.buffer.full else "")
        LOG.info("written %.0f/s, records %.0f/s, metadata %d, skipped %d, errors %d, "
                 "inflight %d, bookmark %s, behind %.1f min%s",
                 d["written"] / secs, d["records"] / secs, d["metadata"], d["skipped"],
                 d["errors"], len(self.inflight),
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.committed)), lag, buf)
        if self.fqe is not None:
            f = self.fqe.stats
            mark = getattr(self, "fqe_mark", {})
            self.fqe_mark = dict(f)
            fqe_ts = self.fqe.committed
            LOG.info("fqe: written %.1f/s, errors %d, %s, bookmark %s, behind %.1f min",
                     (f["written"] - mark.get("written", 0)) / secs, f["errors"] - mark.get("errors", 0),
                     "connected" if self.fqe.connected else "not connected",
                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(fqe_ts)) if fqe_ts else "none",
                     (time.time() - fqe_ts) / 60 if fqe_ts else -1)

    def wait_for_buffer(self, deadline):
        """Buffer full (pause mode): stay disconnected until Splunk has read enough."""
        while self.buffer.full and not self.stopping and not (deadline and time.time() >= deadline):
            for _ in range(self.args.pause_check_sec):
                if self.stopping:
                    return
                time.sleep(1)
            self.buffer.check()
            now = time.time()
            if now - self.last_stats >= 60:
                self.log_stats(now - self.last_stats)
                self.last_stats = now
                rotate_console(self.args.stderr_file)
        self.last_buffer = self.last_buffer_size = time.time()

    # ---- network

    def connect(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if hasattr(ctx, "minimum_version"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        if self.args.ca:
            ctx.load_verify_locations(cafile=self.args.ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
            if hasattr(ssl, "VERIFY_X509_STRICT"):
                ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        else:
            ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(certfile=self.args.cert, keyfile=self.args.key)
        raw = socket.create_connection((self.args.host, self.args.port), timeout=10)
        try:
            sock = ctx.wrap_socket(raw, server_hostname=self.args.host)
        except BaseException:
            raw.close()
            raise
        sock.settimeout(1.0)
        return sock

    def handle(self, sock, mtype, data, start_ts):
        if mtype == proto.MSG_BUNDLE:
            records, unknown = proto.bundle_records(data)
            for rec in records:
                self.dispatch(rec)
            self.stats["bundles"] += 1
            if unknown:
                self.stats["skipped"] += unknown
                if not self.stats["unknown_items_logged"]:
                    self.stats["unknown_items_logged"] = 1
                    LOG.warning("bundle with %d item(s) of an unexpected type - skipped", unknown)
        elif mtype == proto.MSG_EVENT_DATA:
            self.dispatch(data)
        elif mtype == proto.MSG_NULL:
            pass
        elif mtype == proto.MSG_STREAMING_INFO:
            if not proto.offers_streaming(data):
                raise ProtocolError("FMC did not offer the streaming service")
            sock.sendall(proto.streaming_request(start_ts))
            LOG.info("streaming request sent")
        elif mtype == proto.MSG_ERROR:
            code, text = proto.error_text(data)
            LOG.error("FMC error %s: %s", code, " ".join(text.split()))
            self.stats["fmc_errors"] += 1
        else:
            LOG.warning("unexpected message type %s (%d bytes)", mtype, len(data))

    def session(self, start_ts, deadline):
        ack = proto.null_message()
        sock = self.connect()
        try:
            LOG.info("connected to %s:%s, requesting from %s", self.args.host, self.args.port,
                     "now" if start_ts == proto.START_NOW else
                     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts)))
            sock.sendall(proto.event_stream_request(start_ts))
            buf = bytearray()
            last_rx = time.time()
            while not self.stopping:
                try:
                    chunk = sock.recv(262144)
                    if not chunk:
                        raise ConnectionError("FMC closed the connection")
                    buf += chunk
                    last_rx = time.time()
                except socket.timeout:
                    pass
                while len(buf) >= 8:
                    version, mtype, length = proto.HEADER.unpack_from(buf, 0)
                    if version != 1:
                        raise ProtocolError(f"header version {version}")
                    if length > proto.MAX_MESSAGE:
                        raise ProtocolError(f"message of {length} bytes (more than {proto.MAX_MESSAGE})")
                    if len(buf) < 8 + length:
                        break
                    data = bytes(buf[8:8 + length])
                    del buf[:8 + length]
                    self.handle(sock, mtype, data, start_ts)
                    sock.sendall(ack)                   # one acknowledgment per message
                self.housekeeping()
                if time.time() - last_rx > self.args.idle_timeout:
                    raise TimeoutError(f"no data from FMC for {self.args.idle_timeout}s")
                if deadline and time.time() >= deadline:
                    return
        finally:
            sock.close()

    def wait_for_workers(self, timeout):
        end = time.time() + timeout
        try:
            self.housekeeping(final=True)
        except WorkerDied as exc:
            LOG.error("%s - stopping (see the console output for the worker's error)", exc)
            self.fatal = self.stopping = True
        while self.inflight and time.time() < end and not self.fatal:
            time.sleep(0.2)
            self.drain_done()
        self._save_bookmark()

    def resolve_start(self):
        if self.args.since_min:
            return int(time.time()) - self.args.since_min * 60
        if self.args.start == "bookmark" and self.committed:
            return self.committed
        if self.args.start == "bookmark":
            LOG.info("no bookmark yet, starting from now")
        return proto.START_NOW

    def start_fqe(self):
        """The FQE connection (file, intrusion, packet events), when any of them is chosen."""
        if not self.fqe_kinds:
            return
        writers = {
            "json": EventWriter(self.args.out_dir, self.args.file_prefix, store.FQE_WRITER,
                                self.args.rotate_mb * 1024 * 1024, "log") if self.args.splunk else None,
            "cef": EventWriter(self.args.out_dir, self.args.file_prefix, store.FQE_WRITER,
                               self.args.rotate_mb * 1024 * 1024, "cef") if self.args.cef else None,
        }
        self.fqe = fqe.FqeSession(self, self.fqe_kinds, writers, self.args.host, self.args.fmc_name,
                                  self.args.state_dir, self.args.start == "now" and not self.args.since_min)
        if self.args.since_min:
            self.fqe.committed = int(time.time()) - self.args.since_min * 60
        self.fqe.start()

    def stop_fqe(self):
        if self.fqe is not None:
            self.fqe.join(timeout=30)

    def run(self):
        self.start_workers()
        start_ts = self.resolve_start()
        deadline = time.time() + self.args.test_seconds if self.args.test_seconds else 0
        t0, backoff = time.time(), 5
        if self.buffer:
            self.buffer.check()
            self.old_folders.check()
            self.last_buffer = self.last_buffer_size = time.time()
        self.start_fqe()                      # after the first buffer check: no connection while full
        while not self.stopping:
            if self.buffer and self.buffer.full:
                self.wait_for_buffer(deadline)
                if self.stopping or (deadline and time.time() >= deadline):
                    break
            began = time.time()
            try:
                self.session(start_ts, deadline)
                if deadline and time.time() >= deadline:
                    break
            except BufferFull:
                LOG.info("disconnected from the FMC while the buffer is full")
                self.wait_for_workers(30)
                if self.committed:
                    start_ts = self.committed
                backoff = 5
                continue
            except WorkerDied as exc:
                LOG.error("%s - stopping (see the console output for the worker's error)", exc)
                self.fatal = True
                break
            except ssl.SSLCertVerificationError as exc:
                LOG.error("session ended: the FMC's certificate could not be verified with the CA stored "
                          "with the client certificate (%s). If the FMC uses another CA, set the input's "
                          "'Verify FMC certificate' to off.", exc.verify_message or exc)
            except Exception as exc:
                LOG.warning("session ended: %s: %s", type(exc).__name__, " ".join(str(exc).split()))
            if self.stopping or (deadline and time.time() >= deadline):
                break
            self.wait_for_workers(30)
            if self.fatal:
                break
            if self.committed:
                start_ts = self.committed
            if time.time() - began > 120:
                backoff = 5
            LOG.info("reconnecting in %ss", backoff)
            for _ in range(backoff):
                if self.stopping:
                    break
                time.sleep(1)
                self.idle_tick()
            backoff = min(backoff * 2, 60)

        if not self.fatal:
            self.wait_for_workers(60)
        self.stopping = True                  # the FQE thread stops with the binary session
        self.stop_fqe()
        self.stop_workers()
        self.types.close()
        self._save_bookmark(force=True)
        if self.args.test_seconds:
            secs = time.time() - t0
            lag = (time.time() - self.committed) / 60 if self.committed else -1
            print(f"\nran {secs:.0f}s: bundles {self.stats['bundles']}, records {self.stats['records']}, "
                  f"metadata {self.stats['metadata']}, skipped {self.stats['skipped']}, "
                  f"written {self.stats['written']} ({self.stats['written'] / secs:.0f}/s), "
                  f"errors {self.stats['errors']}, fmc_errors {self.stats['fmc_errors']}, "
                  f"behind {lag:.1f} min")


# --------------------------------------------------------------- start-up

def build_parser():
    p = argparse.ArgumentParser(description="FMC eStreamer event collector for Splunk and CEF")
    p.add_argument("--host", required=True)
    p.add_argument("--fmc-name", help="FMC name in CEF (cs6, and DeviceName when no firewall sent the "
                                      "event); default the host")
    p.add_argument("--types", default="connection",
                   help="event types, comma-separated: " + ", ".join(EVENT_TYPES) + " (default connection)")
    p.add_argument("--no-splunk", action="store_true", help="do not write JSON event files for Splunk")
    p.add_argument("--cef", action="store_true", help="also write CEF event files (<name>_..._w<n>.cef)")
    p.add_argument("--port", type=int, default=8302)
    p.add_argument("--cert", help="client cert PEM (default <state-dir>/client.cert)")
    p.add_argument("--key", help="client key PEM (default <state-dir>/client.key)")
    p.add_argument("--ca", help="FMC CA PEM; without it the FMC certificate is not verified")
    p.add_argument("--input-name", help=argparse.SUPPRESS)          # modular input: its name
    p.add_argument("--out-dir", help="default $SPLUNK_HOME/var/log/fmc_estreamer/<host>")
    p.add_argument("--state-dir", help="default $SPLUNK_HOME/var/lib/splunk/modinputs/fmc_estreamer/<host>")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--batch", type=int, default=500)
    p.add_argument("--start", choices=["bookmark", "now"], default="bookmark")
    p.add_argument("--since-min", type=int, default=0, help="start N minutes back (overrides --start)")
    p.add_argument("--rotate-mb", type=int, default=1024,
                   help="start a new event file at this size (and every hour)")
    p.add_argument("--file-prefix", help="event file name prefix (default the FMC host)")
    p.add_argument("--max-buffer-gb", type=float, default=200,
                   help="most disk the event files may use (default 200)")
    p.add_argument("--when-full", choices=["pause", "delete_oldest"], default="delete_oldest",
                   help="buffer full: delete the oldest files, unread too (default), or pause reading "
                        "from the FMC")
    p.add_argument("--pause-check-sec", type=int, default=30, help=argparse.SUPPRESS)
    p.add_argument("--delete-after-min", type=int, default=15,
                   help="delete a file this long after Splunk has read all of it (0 = right away); "
                        "needs Splunk's file status, so modular input runs only")
    p.add_argument("--idle-timeout", type=int, default=600)
    p.add_argument("--test-seconds", type=int, default=0, help="stop after N seconds and print a summary")
    p.add_argument("--log-level", default="INFO")
    p.add_argument("--log-file", help="collector log, rotated at 10 MB (default <state-dir>/collector.log)")
    p.add_argument("--stderr-file", help="send stdout/stderr (incl. worker errors) here; the previous "
                                         "file is kept as <file>.1 (default <state-dir>/console.log "
                                         "when not run from a terminal)")
    return p


def resolve_args(p, args):
    if not HOST_RE.fullmatch(args.host):
        p.error("--host must be an IP address or host name")
    args.fmc_name = args.fmc_name or args.host
    try:
        args.types = parse_types(args.types)
    except ValueError as exc:
        p.error(str(exc))
    if not args.types:
        p.error("--types: choose at least one event type")
    args.splunk = not args.no_splunk
    if not args.splunk and not args.cef:
        p.error("nothing to write: --no-splunk without --cef")
    writers = open_writers(args.workers, args.splunk, args.cef, bool(fqe_event_kinds(args.types)))
    if args.max_buffer_gb * 1024 < 2 * writers * args.rotate_mb:
        p.error(f"--max-buffer-gb must be at least 2 x {writers} open files x rotate size")
    args.file_prefix = args.file_prefix or store.file_prefix(args.host, args.host)
    args.out_dir = args.out_dir or os.path.join(store.default_output_root(), args.host)
    args.state_dir = args.state_dir or os.path.join(store.state_root(), args.host)
    args.cert = args.cert or os.path.join(args.state_dir, "client.cert")
    args.key = args.key or os.path.join(args.state_dir, "client.key")
    args.log_file = args.log_file or os.path.join(args.state_dir, "collector.log")
    if not args.stderr_file and not sys.stderr.isatty():
        args.stderr_file = os.path.join(args.state_dir, "console.log")
    for name in ("cert", "key", "ca", "out_dir", "state_dir", "stderr_file", "log_file"):
        if getattr(args, name):
            setattr(args, name, os.path.abspath(getattr(args, name)))
    return args


def run(args, prepare=None, splunkd=None):
    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(args.state_dir, exist_ok=True)

    # One collector per FMC: a second copy (manual run, or Splunk restarting it
    # while an old one still runs) exits without touching anything.
    lock_fh = open(os.path.join(args.state_dir, "collector.lock"), "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        if sys.stderr.isatty():
            print(f"a collector for {args.host} is already running - exiting", file=sys.stderr)
        return

    if args.stderr_file:
        if os.path.exists(args.stderr_file):                 # previous run's output -> .1
            shift_old_logs(args.stderr_file)
            os.replace(args.stderr_file, args.stderr_file + ".1")
        fd = os.open(args.stderr_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.close(fd)

    handlers = [logging.handlers.RotatingFileHandler(args.log_file, maxBytes=LOG_MAX_BYTES, backupCount=LOG_KEEP)]
    if sys.stderr.isatty() or not args.stderr_file:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(level=args.log_level, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s")
    if prepare:
        prepare(args)
    missing = [path for path in (args.cert, args.key, args.ca) if path and not os.path.isfile(path)]
    if missing:
        LOG.error("missing or unreadable: %s - exiting", ", ".join(missing))
        sys.exit(1)
    if not args.ca:
        LOG.info("the FMC's certificate is not verified (%s)", getattr(args, "no_ca_reason", "no --ca given"))

    # Workers start in this directory; it must be one the service user can enter.
    os.chdir(args.state_dir)
    collector = Collector(args, splunkd)

    def stop(_sig, _frame):
        collector.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    collector.run()
    LOG.info("collector stopped, bookmark %s",
             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(collector.committed)) if collector.committed else "none")
    if collector.fatal:
        sys.exit(1)


def main(argv=None):
    p = build_parser()
    run(resolve_args(p, p.parse_args(argv)))


# ---------------------------------------------------------- modular input

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:\-]*")

# name, title, description, data_type, required_on_create
ARGS = [
    ("fmc_host", "FMC host", "IP address or host name of the FMC.", "string", True),
    ("fmc_port", "FMC port", "eStreamer port on the FMC. Default 8302.", "number", False),
    ("fmc_name", "FMC name (host)",
     "Stored as the events' host field. Default: the input name. The FMC's IP address stays in every "
     "event as SourceHost.", "string", False),
    ("certificate", "Client certificate",
     "Name of the eStreamer client certificate uploaded on the app's Inputs page.", "string", True),
    ("start_from", "Start from",
     "bookmark (default): resume where it stopped ('now' when there is no bookmark yet). now: start at the "
     "current time at every start, including restarts; events while it was stopped are skipped.",
     "string", False),
    ("verify_fmc", "Verify FMC certificate",
     "off (default): the FMC's certificate is not checked. on: check it against the FMC's CA, which must be "
     "in the uploaded client certificate (PKCS12 from the FMC, or PEM with the CA after the client "
     "certificate).", "string", False),
    ("workers", "Decoder processes", "Parallel decoder processes. Default 4.", "number", False),
    ("output_dir", "Event folder",
     "Where events wait until Splunk has read them, one subfolder per input. The splunk user must be "
     "able to write there; at high rates this can use a lot of disk (up to Max buffer). "
     "Default $SPLUNK_HOME/var/log/fmc_estreamer.", "string", False),
    ("buffer_max_gb", "Max buffer (GB)", "Most disk this input's event files may use. Default 200.",
     "number", False),
    ("when_full", "When the buffer or disk is full",
     "Applies when the event files reach Max buffer, and when less than 1 GB is free on the event "
     "folder's disk. delete_oldest (default): keep collecting and delete the oldest files even if Splunk "
     "has not read them. pause: stop reading from the FMC until Splunk catches up and space is free again; "
     "nothing unread is deleted, but the FMC must still hold the events (it keeps a fixed number, so "
     "minutes to hours on busy FMCs).", "string", False),
    ("delete_after_min", "Delete read files after (minutes)",
     "A file is deleted this long after Splunk has read all of it (0 = right away). Default 15.",
     "number", False),
    ("rotate_mb", "New file at (MB)", "Size at which a new event file starts (also every hour). Default 1024.",
     "number", False),
    ("log_level", "Log level", "DEBUG, INFO, WARNING or ERROR. Default INFO.", "string", False),
    # Outputs and event types (2.2.0). Defaults: connection events for Splunk only, as before.
    ("index_in_splunk", "Index in Splunk",
     "Write JSON event files for this input's file monitor (sourcetype cisco:sfw:estreamer). Default 1.",
     "boolean", False),
    ("write_cef", "Write CEF",
     "Also write CEF event files (<name>_..._w<n>.cef) in the same folder, for a syslog agent to read. "
     "They count towards Max buffer. Default 0.", "boolean", False),
    ("connection_events", "Connection events", "Default 1.", "boolean", False),
    ("policy_violation_events", "Policy violation (correlation) events", "Default 0.", "boolean", False),
    ("vpn_events", "VPN login and logoff events", "Default 0.", "boolean", False),
    ("fireamp_events", "FireAMP (AMP for Endpoints) malware events", "Default 0.", "boolean", False),
    ("file_events", "File and file malware events (FQE connection)", "Default 0.", "boolean", False),
    ("intrusion_events", "Intrusion events (FQE connection)", "Default 0.", "boolean", False),
    ("intrusion_packets", "Intrusion packets (FQE connection)", "Default 0.", "boolean", False),
    # Settings of 2.0.x, not used since 2.1.0 but still in README/inputs.conf.spec so old inputs stay
    # valid. Declared here as optional: splunkd treats a spec key the scheme leaves out as required.
    ("event_types", "Event types (not used)", "Not used since version 2.1.0 (see the event type settings). "
     "Leave empty.", "string", False),
    ("decoder", "Decoder (not used)", "Not used since version 2.1.0. Leave empty.", "string", False),
    ("encore_path", "eNcore path (not used)", "Not used since version 2.1.0. Leave empty.", "string", False),
]


def modinput_scheme():
    rows = []
    for name, title, desc, kind, required in ARGS:
        rows.append(
            f'      <arg name="{name}">\n'
            f"        <title>{xml_escape(title)}</title>\n"
            f"        <description>{xml_escape(desc)}</description>\n"
            f"        <data_type>{kind}</data_type>\n"
            f"        <required_on_create>{str(required).lower()}</required_on_create>\n"
            f"        <required_on_edit>false</required_on_edit>\n"
            f"      </arg>")
    print(f"""<scheme>
  <title>FMC eStreamer events</title>
  <description>Events from a Secure Firewall Management Center (FMC) over eStreamer, for Splunk and as CEF.</description>
  <use_external_validation>true</use_external_validation>
  <use_single_instance>false</use_single_instance>
  <streaming_mode>simple</streaming_mode>
  <endpoint>
    <args>
{chr(10).join(rows)}
    </args>
  </endpoint>
</scheme>""")


def read_config(text):
    """splunkd's XML (run or validate) -> dict with session info and [(name, params)]."""
    root = ElementTree.fromstring(text)
    cfg = {k: (root.findtext(k) or "") for k in ("server_host", "server_uri", "session_key", "checkpoint_dir")}
    stanzas = []
    for node in root.iter():
        if node.tag in ("stanza", "item"):
            name = node.get("name", "")
            if name.startswith(store.SCHEME + "://"):
                name = name[len(store.SCHEME) + 3:]
            params = {p.get("name"): (p.text or "").strip() for p in node.findall("param")}
            stanzas.append((name, params))
    cfg["stanzas"] = stanzas
    return cfg


# input setting -> event type name; (setting, default)
TYPE_SETTINGS = (("connection_events", "connection", True), ("policy_violation_events", "policy_violation", False),
                 ("vpn_events", "vpn", False), ("fireamp_events", "fireamp", False),
                 ("file_events", "file", False), ("intrusion_events", "intrusion", False),
                 ("intrusion_packets", "packets", False))
TRUE, FALSE = ("1", "true", "yes", "on", "t", "y"), ("0", "false", "no", "off", "f", "n")


def flag(params, key, default):
    """A boolean input setting; None when it is not a boolean."""
    value = str(params.get(key) or "").strip().lower()
    if not value:
        return default
    if value in TRUE:
        return True
    if value in FALSE:
        return False
    return None


def chosen_types(params):
    return [name for key, name, default in TYPE_SETTINGS if flag(params, key, default)]


def check_params(name, params):
    """Returns an error message, or None when the input is valid."""
    def number(key, low, high, default):
        value = params.get(key) or str(default)
        if not re.fullmatch(r"\d+", value) or not low <= int(value) <= high:
            return f"{key} must be a whole number from {low} to {high}"
        return None

    if not store.NAME_RE.match(name or ""):
        return "Input name: letters, digits, '.', '_' or '-' (max 64), starting with a letter or digit"
    if not HOST_RE.fullmatch(params.get("fmc_host") or ""):
        return "fmc_host must be an IP address or host name"
    if params.get("fmc_name") and not store.NAME_RE.match(params["fmc_name"]):
        return "fmc_name: letters, digits, '.', '_' or '-' (max 64), starting with a letter or digit"
    if not store.NAME_RE.match(params.get("certificate") or ""):
        return "certificate: enter the name of an uploaded client certificate"
    for check in (number("fmc_port", 1, 65535, 8302), number("workers", 1, 32, 4),
                  number("rotate_mb", 10, 102400, 1024), number("buffer_max_gb", 1, 100000, 200),
                  number("delete_after_min", 0, 1440, 15)):
        if check:
            return check
    for key, default in [("index_in_splunk", True), ("write_cef", False)] + \
            [(k, d) for k, _n, d in TYPE_SETTINGS]:
        if flag(params, key, default) is None:
            return f"{key} must be 1 or 0"
    splunk, cef_out = flag(params, "index_in_splunk", True), flag(params, "write_cef", False)
    if not splunk and not cef_out:
        return "Choose at least one output: Index in Splunk and/or Write CEF"
    types = chosen_types(params)
    if not types:
        return "Choose at least one event type"
    workers, rotate_mb = int(params.get("workers") or 4), int(params.get("rotate_mb") or 1024)
    writers = open_writers(workers, splunk, cef_out, bool(fqe_event_kinds(types)))
    if int(params.get("buffer_max_gb") or 200) * 1024 < 2 * writers * rotate_mb:
        return (f"buffer_max_gb must be at least 2 x {writers} open files (decoder processes x outputs, plus "
                f"the FQE connection's) x new-file size ({-(-2 * writers * rotate_mb // 1024)} GB with these "
                f"settings)")
    if (params.get("when_full") or "delete_oldest") not in ("pause", "delete_oldest"):
        return "when_full must be pause or delete_oldest"
    if (params.get("start_from") or "bookmark") not in ("bookmark", "now"):
        return "start_from must be bookmark or now"
    if (params.get("verify_fmc") or "off") not in ("off", "on"):
        return "verify_fmc must be off or on"
    if (params.get("log_level") or "INFO").upper() not in LOG_LEVELS:
        return "log_level must be one of " + ", ".join(LOG_LEVELS)

    index = params.get("index") or "default"
    if not re.fullmatch(r"[a-z0-9][a-z0-9_\-]{0,79}", index):
        return "index: lowercase letters, digits, '_' or '-', starting with a letter or digit"
    out = params.get("output_dir")
    if out:
        return store.check_output_root(out)
    return None


def read_conf_stanzas(path):
    """Splunk .conf file -> {stanza: {key: value}} (comments, continuation lines)."""
    out, stanza, pending = {}, None, None
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for line in lines:
        if pending is not None:                         # continuation of the previous value
            key, value = pending
            value += "\n" + line.rstrip("\\")
            pending = (key, value) if line.endswith("\\") else None
            out[stanza][key] = value
            continue
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("[") and text.endswith("]"):
            stanza = text[1:-1]
            out.setdefault(stanza, {})
            continue
        if stanza is not None and "=" in text:
            key, value = (part.strip() for part in text.split("=", 1))
            out[stanza][key] = value.rstrip("\\").rstrip()
            if value.endswith("\\"):
                pending = (key, out[stanza][key])
    return out


def saved_settings(name):
    """
    The input's saved settings, read from the .conf files (default stanza of
    this app, then the input's own stanza in any local/inputs.conf). Not via
    splunkd: during validation splunkd is busy with the very request being
    validated, and a call to its inputs endpoint waits until that times out.
    """
    keep = {arg[0] for arg in ARGS} | {"index"}
    app_default = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "default", "inputs.conf")
    merged = dict(read_conf_stanzas(app_default).get(store.SCHEME, {}))
    home = store.splunk_home()
    locals_ = [os.path.join(home, "etc", "system", "local", "inputs.conf")]
    apps = os.path.join(home, "etc", "apps")
    try:
        locals_ += [os.path.join(apps, app, "local", "inputs.conf") for app in sorted(os.listdir(apps))]
    except OSError:
        pass
    for path in locals_:
        stanzas = read_conf_stanzas(path)
        merged.update(stanzas.get(store.SCHEME, {}))
        merged.update(stanzas.get(f"{store.SCHEME}://{name}", {}))
    return {k: v for k, v in merged.items() if k in keep}


def modinput_validate():
    cfg = read_config(sys.stdin.read())
    error = None
    for name, params in cfg["stanzas"]:
        # On an edit splunkd passes only the settings being changed (others missing
        # or empty): check them together with the input's saved ones.
        params = {**saved_settings(name), **{k: v for k, v in params.items() if v}}
        error = check_params(name, params) or store.check_output_folder(store.output_dir(params, name))
        if not error and cfg["session_key"]:
            try:
                store.Certificates(store.Splunkd(cfg["session_key"])).get(params["certificate"])
            except store.StoreError as exc:
                if exc.status == 404:
                    error = f"{exc} - upload it on the app's Inputs page first"
            except Exception:                           # store unreachable: don't block the edit
                pass
        if error:
            break
    if error:
        print(f"<error><message>{xml_escape(error)}</message></error>")
        sys.exit(1)


def modinput_run():
    cfg = read_config(sys.stdin.read())
    if not cfg["stanzas"]:
        return
    name, params = cfg["stanzas"][0]
    error = check_params(name, params)
    if error:
        sys.stderr.write(f"fmc_estreamer://{name}: {error}\n")      # lands in splunkd.log
        sys.exit(1)
    logs = os.path.join(store.splunk_home(), "var", "log", "splunk")
    state_dir = os.path.join(cfg["checkpoint_dir"] or store.state_root(), name)
    fmc_name = params.get("fmc_name") or name                    # the events' host field, cs6 in CEF
    argv = [
        "--host", params["fmc_host"],
        "--fmc-name", fmc_name,
        "--types", ",".join(chosen_types(params)),
        "--port", params.get("fmc_port") or "8302",
        "--out-dir", store.output_dir(params, name),
        "--state-dir", state_dir,
        "--workers", params.get("workers") or "4",
        "--start", params.get("start_from") or "bookmark",
        "--rotate-mb", params.get("rotate_mb") or "1024",
        "--file-prefix", store.file_prefix(name, params["fmc_host"]),
        "--max-buffer-gb", params.get("buffer_max_gb") or "200",
        "--when-full", params.get("when_full") or "delete_oldest",
        "--delete-after-min", params.get("delete_after_min") or "15",
        "--log-level", (params.get("log_level") or "INFO").upper(),
        "--log-file", os.path.join(logs, f"fmc_estreamer_{name}.log"),
        "--input-name", name,
        "--stderr-file", os.path.join(logs, f"fmc_estreamer_{name}_console.log"),
    ]
    if not flag(params, "index_in_splunk", True):
        argv.append("--no-splunk")
    if flag(params, "write_cef", False):
        argv.append("--cef")
    p = build_parser()
    args = resolve_args(p, p.parse_args(argv))
    splunkd = store.Splunkd(cfg["session_key"])

    def prepare(args):
        """After the lock: client certificate from the credential store, file monitor."""
        LOG.info("starting input %s (FMC %s %s:%s, certificate %s, event types %s, output %s, events %s, "
                 "max buffer %s GB, when full %s)",
                 name, fmc_name, args.host, args.port, params["certificate"], ",".join(args.types),
                 "+".join(k for k, on in (("splunk", args.splunk), ("cef", args.cef)) if on),
                 args.out_dir, args.max_buffer_gb, args.when_full)
        try:
            doc = store.Certificates(splunkd).get(params["certificate"])
            store.write_pair(args.state_dir, doc["cert"], doc["key"], doc.get("ca") or "")
            if (params.get("verify_fmc") or "off") != "on":
                args.no_ca_reason = "Verify FMC certificate is off"
            elif doc.get("ca"):
                args.ca = os.path.join(args.state_dir, "fmc-ca.pem")
                LOG.info("the FMC's certificate is checked against the CA stored with %s", params["certificate"])
            else:
                LOG.error("Verify FMC certificate is on, but certificate %s has no FMC CA (upload the FMC's "
                          "PKCS12 file, or PEM with the CA after the client certificate) - exiting",
                          params["certificate"])
                sys.exit(1)
        except Exception as exc:
            LOG.error("client certificate %s: %s - exiting", params["certificate"], exc)
            sys.exit(1)
        try:
            result = store.ensure_monitor(splunkd, args.out_dir, params, fmc_name)
            LOG.info("file monitor for %s: %s", args.out_dir, result)
        except Exception as exc:
            LOG.error("file monitor for %s could not be set (%s); events are written but not indexed",
                      args.out_dir, exc)

    run(args, prepare, splunkd)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--scheme":
        modinput_scheme()
    elif len(sys.argv) > 1 and sys.argv[1] == "--validate-arguments":
        modinput_validate()
    elif len(sys.argv) == 1:
        modinput_run()
    else:
        main()
