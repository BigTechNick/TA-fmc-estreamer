# Nikhil Chawla Add-on for Cisco Secure Firewall eStreamer (FMC)

Version 2.2.1. App ID (folder name): `TA-fmc-estreamer`.

Collects events from a Secure Firewall Management Center (FMC) over eStreamer:

* **connection**, **policy violation** (correlation), **VPN login/logoff** and
  **FireAMP** (AMP for Endpoints) malware events over the binary eStreamer
  connection;
* **file** (and file malware), **intrusion** and **intrusion packet** events over
  a second, FQE (fully-qualified events, JSON) connection to the same FMC.

Per input, events go to Splunk as sourcetype `cisco:sfw:estreamer`, as CEF
files for a syslog agent, or both. In Splunk, connection events have the field
names the Cisco Security Cloud app uses for that sourcetype (InitiatorIP,
ResponderIP, FirewallRule, AC_RuleAction, ...), and file, intrusion and packet
events are the FMC's own JSON, as that app indexes them; so its field aliases,
CIM mappings and dashboards work on these events. **CIM mapping needs the Cisco
Security Cloud app on the search heads** (see Requirements); collecting does
not. One input keeps up with several thousand events per second.

> Independent project, not affiliated with or endorsed by Cisco. Cisco, Cisco
> Secure Firewall, Firepower and FMC are trademarks of Cisco Systems, Inc. See
> NOTICE.

Everything is managed in Splunk Web:

* **Inputs** page: one input per FMC (many per heavy forwarder): add, edit,
  enable/disable, restart, delete. Upload the eStreamer client certificate:
  the PKCS12 file from the FMC (with its password) or a PEM certificate + key.
  Certificates are stored encrypted in Splunk's credential store.
* **Status** dashboard (classic Simple XML): per-input throughput, minutes
  behind the FMC, connects/disconnects, errors, indexed volume and index delay
  per FMC, and Splunk's own messages about the inputs. It carries its own
  searches, so it also works pasted onto a search head without the add-on.

With file, intrusion or packet events chosen, an input makes the same FQE
request the Cisco Security Cloud app's eStreamer input makes, so that input can
be switched off once this one is verified.

## Requirements

* Splunk Enterprise 9.x or 10.x heavy forwarder (Linux or macOS). Runs on
  Splunk's bundled Python (3.13 where available, else 3.9) with the standard
  library only: no third-party packages and no compiled modules. PKCS12
  uploads, and the certificate details shown on the Inputs page, are read with
  the `cryptography` package or the `openssl` that ship with Splunk.
* Search heads: the **Cisco Security Cloud** app (Splunkbase 7404) for CIM
  mapping. Its field aliases, event types, tags and lookups on
  `cisco:sfw:estreamer` map these events to the CIM data models (src, dest,
  action, signature, ...), as they do for the events its own input collects.
  Without it the events are still indexed and searchable, with the FMC's field
  names, but not CIM-mapped. Collecting does not need it on the forwarder.
* Network: the forwarder connects to TCP 8302 on each FMC. The add-on opens no
  listening ports.
* FMC: System > Integration > eStreamer: enable the event types to collect
  (connection, correlation, user activity for VPN, malware, file, intrusion and
  intrusion packet data), create a client for the forwarder's IP address,
  download the PKCS12 file and note its password.
* Sessions: an input uses one eStreamer session per FMC, or two when file,
  intrusion or packet events are chosen, both with the same client
  certificate. The FMC limits how many sessions one client can hold at once
  (two worked in tests; a third was refused), so stop other collectors that use
  the same client (another input or eStreamer client, the Security Cloud app's
  input) first.
* Reads the Connection Statistics data block versions 160, 163, 168, 169,
  170, 171, 173 and 174 (FMC 6.x and 7.x). Another version is read with the
  closest older layout and logged once. Policy violation events: correlation
  block 156; VPN: user login block 167 with VPN session block 166; FireAMP:
  malware event block 80 (checked against FMC 7.6.6). FQE: FMC 7.4 or later.

## Install

1. Install the add-on on the heavy forwarder (Apps > Manage Apps > Install app
   from file, or untar into `$SPLUNK_HOME/etc/apps`) and restart Splunk.
2. Search heads: install the Cisco Security Cloud app for CIM mapping
   (Requirements). Optionally install this add-on there too, with no inputs. It
   adds the field extractions for the collector logs and, for the policy
   violation, VPN and FireAMP events, signature and signature_id (policy
   violations), the VPN login action and the CIM event types and tags (the
   Cisco Security Cloud app provides the other CIM field aliases).
3. Status dashboard: see below. On a forwarder that does not index locally it
   has nothing to search; use it on a search head. The Inputs page still shows
   each input's state from its log file.

## Set up an FMC

1. Open the add-on (**Nikhil Chawla Add-on for Cisco Secure Firewall eStreamer (FMC)**) and go to **Inputs**.
2. **Upload certificate**: give it a name, choose the PKCS12 file and type its
   password (or choose PEM and pick or paste the certificate and key).
3. **Add input**:
   * name, FMC host (IP or name) and port (8302);
   * FMC name: the events' `host` field (default: the input name);
   * certificate;
   * output: *Index in Splunk* (and the index) and/or *Write CEF*;
   * event types: connection, policy violation, VPN login/logoff, FireAMP,
     file, intrusion, intrusion packets;
   * event folder, max buffer, and what to do when the buffer is full.
4. Save: the input starts within a minute.
5. Watch **Status**: the input shows *OK*, and "behind" stays under a minute
   once it has caught up.

## Status dashboard

A classic (Simple XML) dashboard, with no automatic refresh: panels load when
it opens and when a field changes.

* **Time range**, **Event index** (the index the inputs write to; `*`, the
  default, searches every index and is slower) and **Input**.
* Collector logs are read from index `_internal`, where Splunk puts the
  add-on's own logs; the forwarder must forward its `_internal` data (the
  default). Events are read from the index entered, as sourcetype
  `cisco:sfw:estreamer` from this add-on's event files.
* It needs neither this add-on nor its settings where it runs. To use it on a
  search head without the add-on: create a new classic dashboard there
  (Dashboards > Create New Dashboard > Classic Dashboards), open **Source**, and
  paste `default/data/ui/views/fmc_status.xml` from the add-on over it.

## Events

* sourcetype `cisco:sfw:estreamer`. Files are read as `fmc:estreamer:events`
  and renamed at index time.
* The sourcetype and the field names are chosen on purpose: they are the ones
  the Cisco Security Cloud app uses for eStreamer events, so that app's field
  aliases, CIM mappings and dashboards work on these events too, and searches
  written for it keep working. This add-on is not part of that app and does
  not change the events that app collects.
* host = the input's **FMC name**; `SourceHost` = the FMC's address, in every
  event. `EventType` tells the types apart.
* **Connection** (`ConnectionEvent`): `_time` = the connection's last packet.
  Names come from the FMC's metadata. These fields carry the names: rules,
  access control policy (`FirewallPolicy`), prefilter policy
  (`PrefilterPolicy`), tunnel/prefilter rule (`TunnelRule`), zones,
  interfaces, device, applications, URL categories, countries, and DNS/SSL
  codes. Unset fields (zero, empty) are left out to keep events small.
* **File, intrusion, packets** (`FileEvent...`, `IntrusionEvent`,
  `IntrusionPacket`): the FMC's JSON with the field names it sends (the same
  request as the Security Cloud app's input), plus `time`, `SourceHost` and
  `archive_ts`.
* **Policy violation, VPN, FireAMP:** fields that the Cisco Security Cloud app
  aliases on `cisco:sfw:estreamer` use its source names (`InitiatorIP`,
  `ResponderIP`, `InitiatorPort`, `Protocol`, `URL`, `FileName`, `FileSHA256`,
  `ThreatName`, `FileAction`, `InitiatorBytes`, ...), so that app's aliases give
  the CIM fields (src, dest, src_port, transport, url, file_name, file_hash,
  signature, action, bytes_in, ...), as for connection events. Its aliases
  replace a field of the same name, so these events do not carry CIM-named
  copies of their own. So that signature and action are set where only that
  app runs at search time, policy violations also carry the rule name as
  `IntrusionRuleMessage`, FireAMP events the detection name as
  `IntrusionRuleMessage`, and VPN logins `AC_RuleAction` = success. This
  add-on's search-time settings (when it is installed on the search heads)
  add signature (from `CorrelationRule`) and signature_id for policy
  violations, the VPN login action, and the CIM event types and tags.
  * **Policy violation** (`CorrelationEvent`, CIM Alerts): `CorrelationRule`
    (signature), `CorrelationPolicy`, description, user, `URL`, zones,
    interfaces, `FirewallRule`, Device.
  * **VPN** (`VPNLoginEvent`, `VPNLogoffEvent`, CIM Network Sessions and, for
    logins, Authentication): user, `InitiatorIP` = the client's public address
    (src, src_ip), `ResponderIP` / `AssignedIP` = the address the VPN assigned
    (dest_ip), `GroupPolicy`, `ConnectionProfile`, `VPN_Type`, `ClientOS`,
    `ClientApplication`, `InitiatorCountry`, session_id; on logoff also
    duration, `InitiatorBytes` (from the client), `ResponderBytes` (to the
    client) and reason.
  * **FireAMP** (`MalwareEvent`, CIM Malware): `ThreatName` (signature),
    `MalwareEventType`, `FileName`/file_path/`FileSHA256`, disposition,
    `FileAction` (action), `ThreatScore`, `InitiatorIP`/`ResponderIP`, user,
    `AMP_Cloud`.

## CEF output

With *Write CEF* on, every chosen event is also written as one CEF line
(`CEF:0|Cisco|Firepower|6.0|<class>|<name>|<severity>|<extension>`) to `.cef`
files in the input's event folder. A syslog agent reads them (for example
rsyslog `imfile` on `<event folder>/<input>/*.cef`) and adds the syslog header;
the add-on does not index or delete them, the agent's side deletes them once
read. They count towards *Max buffer*. Delete a `.cef` file only when it has
been read to the end and not written for a few minutes (each writer starts a new
file every hour, at the size limit, or when its current file is deleted; lines
written between the agent's last read and the delete would be lost).

* Event class IDs and names are the ones earlier CEF exports of eStreamer
  events used (`RNA:1003:1` CONNECTION STATISTICS, `PV:112:<rule>:<policy>`,
  `USER:1004:8` VPN Login, `USER:1004:2`, `FireAMP:125:1`, `File:500:1`,
  `FileMalware:502:1`, `INTRUSION:400:<gid>:<sid>`, `PKT:2:1`), so existing
  searches keep matching.
* Standard CEF keys (src, dst, spt, dpt, act, suser, suid, in, out, request,
  dvchost, deviceExternalId, ...) and labelled custom fields (cs1-cs6, cn1-cn3,
  flexString1-2); cs6 = the input's FMC name on every event; dvchost = the
  firewall (the FMC name for events no firewall sent).

## Event files and disk

Events wait on disk until they have been read:

    <event folder>/<input>/<input>_<fmc>_<YYYY-MM-DD>_<HHMMSS>_w<n>.log   (JSON, for Splunk)
    <event folder>/<input>/<input>_<fmc>_<YYYY-MM-DD>_<HHMMSS>_w<n>.cef   (CEF)

The time in the name is the file's UTC start time. Each decoder process writes
its own files (w99: the FQE connection), and a new file starts every hour or
at 1 GB (at most one new file a second per writer, so a name is never used
twice). Each input keeps a file monitor on its folder; it reads only the `.log`
files.

* **Event folder** (default `$SPLUNK_HOME/var/log/fmc_estreamer`):
  * The user Splunk runs as must be able to write there. This is checked when
    the input is saved.
  * A busy FMC writes 20-30 GB an hour.
  * A separate disk mounted at the event folder keeps a full buffer away from
    Splunk's own `var`.
* **Delete read files after** (default 15 min): a `.log` file is deleted once
  Splunk's file monitor has read all of it (according to Splunk's file
  status, `admin/inputstatus/TailingProcessor:FileStatus`) and it has not been
  written for that long. Normally the folder holds roughly 15-30 minutes of
  events.
* **Max buffer** (default 200 GB per input) caps the folder (both kinds of
  file) if Splunk or the syslog agent falls behind or stops reading. **When the
  buffer or disk is full** (the files reach Max buffer, or less than 1 GB is
  free on the folder's disk):
  * *Delete oldest* (default): keep collecting, and delete the oldest files
    even if they have not been read.
  * *Pause*: stop reading from the FMC (both connections), and resume from the
    bookmarks once there is room again. Nothing unread is deleted, but the FMC must still
    hold the events by then.
    * The FMC keeps a fixed number of connection events (System >
      Configuration > Database). At thousands of events per second, that is
      minutes to hours.
    * Use Pause only for FMCs that hold days of events.

The Inputs page shows each input's folder, how much it uses and the free
space.

If an input's Event folder is changed, the files left in the old folder are
still read; the input deletes them once Splunk has read them and then removes
the old folder's file monitor. Deleting an input on the Inputs page removes
its file monitor and the event files still on disk. Deleting it in Settings >
Data inputs instead leaves both behind.

## How it runs

* Modular input `fmc_estreamer`, one process per enabled input:
  * Splunk starts it, and restarts it 60 s after it exits.
  * Disabling an input stops it.
  * Editing an input restarts it, and it resumes from its bookmark.
* Network:
  * TLS 1.2 or later with the client certificate.
  * The FMC's certificate is not checked by default. With *Verify FMC
    certificate* = on, it is checked against the FMC CA stored with the
    client certificate: the PKCS12 file from the FMC includes the CA; for a
    PEM upload, paste the CA after the client certificate.
  * Binary connection: the standard eStreamer Event Stream Request and
    Streaming Request, then one acknowledgment per message.
  * FQE connection (file, intrusion or packet events): the documented Event
    Stream Request with the archive-timestamp flag and the JSON field list the
    Security Cloud app's input sends, byte for byte; then one acknowledgment per
    bundle.
  * Nothing else is sent to the FMC. Both requests are checked against
    known-good copies when the input starts.
  * Reconnects with backoff (5-60 s).
* Each connection has its own bookmark (archive timestamp; `bookmark.json`,
  `bookmark-fqe.json`), which only advances when every earlier event has been
  written. With *Start from* = bookmark (the default), a restart never skips
  events (a few may repeat). With *Start from* = now, every start begins at the
  current time.
* Inputs and their file monitors are saved in this add-on's
  `local/inputs.conf`. A deployment server that pushes the add-on would replace
  them, so manage the add-on on each forwarder directly.
* Decoding runs in `workers` processes (default 4), with the add-on's own
  eStreamer decoder (`bin/fmc_estreamer_protocol.py`, `_events.py`). It is
  written from the protocol as published in Cisco's eStreamer Integration Guide
  and FQE Guide. The FQE connection runs in the input's main process.

## Files

| Path | What |
|---|---|
| `bin/fmc_estreamer.py` | the collector (modular input and command line) |
| `bin/fmc_estreamer_protocol.py` | eStreamer messages, connection-event decoding, names |
| `bin/fmc_estreamer_events.py` | policy violation, VPN and FireAMP decoding and Splunk fields |
| `bin/fmc_estreamer_fqe.py` | the FQE connection (file, intrusion, packet events) |
| `bin/fmc_estreamer_cef.py` | CEF lines |
| `bin/fmc_estreamer_tables.py` | fixed name tables (IP protocols, TLS cipher suites, SSL codes) |
| `bin/fmc_estreamer_rest.py` | REST API for the Inputs page |
| `bin/fmc_estreamer_store.py` | credential store, certificates, file monitor |
| `$SPLUNK_HOME/var/lib/splunk/modinputs/fmc_estreamer/<input>/` | state, rewritten in place, does not grow: bookmark.json, bookmark-fqe.json, names-N.json, record_types.json, client.cert/.key and fmc-ca.pem (mode 600), collector.lock |
| `$SPLUNK_HOME/var/log/splunk/fmc_estreamer_<input>.log` | collector log: stats every minute, connections, deletions (index _internal); 10 MB, 3 old copies |
| `$SPLUNK_HOME/var/log/splunk/fmc_estreamer_<input>_console.log` | decoder warnings and tracebacks (index _internal); 10 MB, 3 old copies |
| `$SPLUNK_HOME/var/log/splunk/fmc_estreamer-webapi.log` | changes made on the Inputs page (index _internal); 5 MB, 2 old copies |

The collector writes a stats line every minute:

`written 2040/s, records 2058/s, metadata 32, skipped 718, errors 0, inflight 1, bookmark 2026-10-16T01:53:04Z, behind 0.0 min, buffer 3.12 GB`

* *skipped*: record types the input does not use.
* *errors*: records that could not be decoded.
* *buffer*: event files on disk, with `PAUSED` added when full in Pause mode.

With an FQE connection, a second line follows:

`fqe: written 52.3/s, errors 0, connected, bookmark 2026-10-21T17:14:30Z, behind 0.1 min`

## Command line

The same script runs by hand for tests. It writes to the given folders and
stops after N seconds. Stop the input for that FMC first, because only one
session per certificate can be connected:

    $SPLUNK_HOME/bin/splunk cmd python3 $SPLUNK_HOME/etc/apps/TA-fmc-estreamer/bin/fmc_estreamer.py \
        --host <fmc> --cert client.cert --key client.key \
        --state-dir /tmp/fmc-test/state --out-dir /tmp/fmc-test/out --start now --test-seconds 120

`--help` lists every option.

## Troubleshooting

* Status shows *NO RECENT LOG*: the input is not running. Check the panel
  "Splunk messages about the inputs" and `fmc_estreamer_<input>_console.log`.
* *client certificate ... not uploaded*: upload it, or fix the input's
  certificate name.
* *session ended: ... Connection refused / timed out*: a network or FMC
  eStreamer service problem. The input keeps retrying.
* *FMC error*: the FMC rejected the request (client not allowed for this IP,
  or certificate revoked).
* *the FMC's certificate could not be verified*: the FMC presents a
  certificate that the stored CA did not issue. Upload the PKCS12 file from
  this FMC again, or set *Verify FMC certificate* to off.
* *disk nearly full*: less than 1 GB free on the event folder's disk. The
  input deletes the oldest files or pauses (*When full*); if other files fill
  the disk, it says so. Free space or move the Event folder.
* *buffer full ... deleted N files not read yet*: Splunk (or the syslog agent
  for `.cef` files) is not keeping up, or not reading the folder. Check the
  input's file monitor, the forwarder's output queue, and that the agent
  deletes the `.cef` files it has read.
* *fqe: session ended ...* while the binary connection runs: the FMC refused
  the second session (session limit, FQE not enabled for this client) or
  closed it. The FQE connection keeps retrying on its own.
* *Splunk is not reading <folder>*: the file monitor is missing or disabled.
  Saving the input again recreates it.
* *cannot write to <folder>*: give the splunk user write access, or choose
  another event folder.
* *connection block type N is not one this version knows*: the FMC sends a
  newer layout. Events are still written with the known fields; check for an
  add-on update.

### Record types and raw sample

To see what an FMC sends (for example after an FMC upgrade, or to report a
problem):

* **Record types**, always on: the binary connection's records are counted per
  record type and data block, in `record_types.json` in the input's state
  folder (`$SPLUNK_HOME/var/lib/splunk/modinputs/fmc_estreamer/<input>/`), and
  in a log line every hour: types, data block versions, sizes and counts, and
  the first 24 bytes of each type's first record body (in hex, to identify
  its layout).
* **Raw sample**, off by default: create the file `raw_sample.request` in the
  input's state folder, as the user Splunk runs as. It may hold a number: the
  records to keep per type (default 500, at most 100000). Within a minute the
  input saves the first records of each type of the binary connection, exactly
  as the FMC sent them, to `raw_sample/records.bin` (a 4-byte big-endian
  length before each record), with a summary in `raw_sample/sample.json`;
  256 MB at most. Delete `raw_sample.request` to stop it, and delete the
  `raw_sample` folder when you no longer need it.
* The raw sample holds event contents (addresses, user names, packet data).
  It stays in the state folder: it is never indexed or sent anywhere.

## Upgrading from 2.0.x

Install over the old version and restart. Inputs, certificates and bookmarks
are kept, and inputs resume where they stopped.

* The name tables are rebuilt from the FMC's metadata, which the FMC sends with
  the events of every session. The old `cache-N.dat` files are removed.
* The settings `event_types`, `decoder` and `encore_path` are no longer used
  and are ignored.

## Upgrading to 2.2.1

Install over 2.2.0 and restart; inputs continue from their bookmarks. The
Status dashboard is now a classic dashboard with an *Event index* field, and
the search macros `fmc_estreamer_logs` and `fmc_estreamer_events` are no longer
used: a `local/macros.conf` made for them can be deleted.

## Upgrading to 2.2.0

Install over the old version and restart. Inputs keep collecting connection
events for Splunk only, as before, until other event types or *Write CEF* are
chosen on the Inputs page. The new event types start from the binary
connection's bookmark; the FQE connection starts at the current time (or from
`bookmark-fqe.json` in the input's state folder, if one is placed there).

## Changes

* 2.2.1
  * Event file names are never used twice. A writer that needs a second new
    file within one second now waits for the next second. Before, it named files
    ahead of the clock (only with small *New file at* sizes and high rates) and
    could reuse the name of a file already deleted; a reader that remembers files
    by name (Splunk, a syslog agent) could then skip the new file.
  * The Inputs page's status no longer depends on a search macro.
  * Status dashboard: classic (Simple XML) instead of Dashboard Studio; no
    automatic refresh; an *Event index* field used by every event search; its
    own field extractions, so it works on a search head without the add-on;
    FQE connection state and rate per input.
  * The search macros are removed (the dashboard no longer uses them).
  * README: the Cisco Security Cloud app is required on the search heads for CIM
    mapping; record types and the raw sample; the Status dashboard.
* 2.2.0
  * All event types: policy violation (correlation), VPN login/logoff and
    FireAMP over the binary connection; file, intrusion and intrusion packet
    events over a second (FQE) connection, with the same request as the
    Cisco Security Cloud app's input.
  * CEF output (*Write CEF*), in the same event folder, under the same Max
    buffer.
  * Inputs page: *Index in Splunk*, *Write CEF* and one checkbox per event type.
  * CIM event types and tags for policy violation (Alerts), VPN (Network
    Sessions, Authentication) and FireAMP (Malware) events.
  * Record types and data blocks the FMC sends are counted (from 2.1.4), with an
    optional raw sample (`raw_sample.request`).
* 2.1.3
  * Renamed to "Nikhil Chawla Add-on for Cisco Secure Firewall eStreamer (FMC)", following the Splunkbase naming conventions.
    The app ID stays `TA-fmc-estreamer`, so upgrades, inputs, certificates and
    bookmarks are not affected.
  * The certificate details on the Inputs page (subject, issuer, validity,
    serial) are read with the `cryptography` package that ships with Splunk,
    or with Splunk's `openssl`, instead of an internal Python function that a
    later Python version could remove. They are shown the same way as before.
  * README: why the add-on uses the `cisco:sfw:estreamer` sourcetype.
* 2.1.2: Creating an input on the Inputs page (or through its REST API)
  failed with "required arguments are missing: decoder, encore_path,
  event_types". Those old settings are declared again as optional, unused
  settings, so Splunk no longer requires them. Running inputs were not
  affected.
* 2.1.1: Metadata records too short to carry a name (the FMC sends some
  empty ones) are ignored instead of counted as decode errors.
* 2.1.0
  * The add-on's own eStreamer decoder replaces the bundled third-party
    library. The add-on is now Python standard library only and connection
    events only.
  * Events are field-for-field the same as 2.0.x, except:
    * `FirewallPolicy` shows the access control policy name (it was the
      policy revision UUID).
    * New field `PrefilterPolicy`.
    * New field `TunnelRule`.
    * Sinkhole, SSL URL category and SSL expected action names are filled in
      when the FMC sends them.
    * Connection block 168 is read (it failed before).
    * Legacy user records no longer count as decode errors.
  * Optional check of the FMC's certificate against the CA in the uploaded
    PKCS12 (new setting *Verify FMC certificate*, default off).
  * A changed Event folder is drained and its monitor removed; deleting an
    input removes its monitor and event files.
  * Messages over 128 MB and unknown bundle items no longer stall a session.
  * *When full* now also covers the disk: under 1 GB free, the input
    deletes the oldest files or pauses, as set.
  * Credential store entries are readable by admins only.
  * The app is now labelled "eStreamer Collector for FMC". The Status
    dashboard is a Dashboard Studio dashboard.
  * `python.required` is set for the REST handlers.
  * Licensed under Apache-2.0.
* 2.0.2: Input validation reads the input's saved settings from the .conf
  files instead of asking splunkd. In 2.0.1, that call waited on the request
  being validated, so creating or editing an input timed out after 30 s.
* 2.0.1: Editing an input now needs only the changed settings. Splunk passes
  only those to validation; they are checked together with the saved ones.
* 2.0.0: First release:
  * modular input per FMC;
  * Inputs page with certificate upload;
  * Status dashboard;
  * dated .log event files, deleted after Splunk reads them;
  * size cap (delete oldest or pause);
  * host = FMC name.

## License and support

Apache License 2.0 (see LICENSE and NOTICE). Copyright 2026 Nikhil Chawla.
Community-supported, best effort, through the add-on's Splunkbase page; no
warranty.
