[fmc_estreamer://<name>]
* One input per FMC. <name>: letters, digits, '.', '_' or '-' (max 64),
  starting with a letter or digit.
* Created and edited in Splunk Web: app "eStreamer Add-on for Cisco Secure Firewall (FMC/Firepower)" > Inputs (or Settings > Data inputs > FMC
  eStreamer events).
  Delete inputs on the Inputs page: it also removes the input's file monitor
  and event files.
* Collects the chosen event types from the FMC, for Splunk (JSON files read by
  the input's file monitor) and/or as CEF files for a syslog agent:
  connection, policy violation (correlation), VPN login/logoff and FireAMP
  events over the binary eStreamer connection, with the metadata that names
  their values; file, intrusion and intrusion packet events over a second
  (FQE, JSON) connection to the same FMC.

fmc_host = <string>
* Required. IP address or host name of the FMC.

fmc_port = <integer>
* eStreamer port on the FMC.
* Default: 8302

fmc_name = <string>
* Stored as the host field of this input's events (letters, digits, '.',
  '_' or '-', max 64). The FMC's IP address stays in every event as the
  SourceHost field. In CEF: cs6 (fmcHost) of every event, and the device name
  of events no firewall generated (FireAMP).
* Default: empty (the input name)

index_in_splunk = <boolean>
* Write JSON event files (<name>_..._w<n>.log) for this input's file monitor,
  sourcetype cisco:sfw:estreamer.
* Default: 1

write_cef = <boolean>
* Also write CEF event files (<name>_..._w<n>.cef) in the same folder, one CEF
  line per event, for a syslog agent (for example rsyslog imfile) to read. The
  add-on does not index them and does not delete them once read: the agent's
  side does. They count towards buffer_max_gb and when_full like the JSON files.
* At least one of index_in_splunk and write_cef must be 1.
* Default: 0

connection_events = <boolean>
* Connection events (binary connection). Default: 1

policy_violation_events = <boolean>
* Policy violation (correlation) events (binary connection). Default: 0

vpn_events = <boolean>
* VPN login and logoff events (binary connection). Default: 0

fireamp_events = <boolean>
* Malware events from AMP for Endpoints / FireAMP (binary connection). Default: 0

file_events = <boolean>
* File and file malware events (FQE connection). Default: 0

intrusion_events = <boolean>
* Intrusion events (FQE connection). Default: 0

intrusion_packets = <boolean>
* Intrusion event packets (FQE connection). Default: 0
* When any of file_events, intrusion_events and intrusion_packets is 1, the
  input opens a second connection to the FMC (FQE) with the same client
  certificate. It asks for the same fields as the Cisco Security Cloud app's
  eStreamer input, has its own bookmark and writes with the field names the
  FMC sends. The FMC must allow two connections for this client.

certificate = <string>
* Required. Name of the eStreamer client certificate uploaded on the Inputs
  page. Stored encrypted in the credential store (storage/passwords, realm
  fmc_estreamer_certificate).

start_from = bookmark|now
* bookmark: resume from the last saved bookmark ("now" when there is none).
* now: start at the current time at every start of the input, including
  restarts and edits; events the FMC sent while it was stopped are skipped.
* Default: bookmark

verify_fmc = off|on
* off: the FMC's TLS certificate is not checked.
* on: check it against the FMC CA stored with the client certificate (the
  PKCS12 file from the FMC includes it; for PEM, paste the CA after the
  client certificate). The input does not start if no CA is stored.
* Default: off

workers = <integer>
* Parallel decoder processes (1-32).
* Default: 4

output_dir = <string>
* Absolute folder where events wait until they are read; each input
  writes to <output_dir>/<name>/<name>_<fmc>_<YYYY-MM-DD>_<HHMMSS>_w<n>.log
  (and .cef) (UTC start time, one file per decoder process; w99 = the FQE
  connection).
* The user Splunk runs as must be able to write there. At high event rates
  this can use a lot of disk, up to buffer_max_gb.
* Not inside $SPLUNK_HOME/etc, var/lib, var/log/splunk, var/spool or var/run.
* When it is changed, files left in the old folder are still read; the input
  deletes them once Splunk has read them and then removes that folder's
  file monitor.
* Default: empty ($SPLUNK_HOME/var/log/fmc_estreamer)

buffer_max_gb = <integer>
* Most disk this input's event files (JSON and CEF together) may use, in GB
  (1-100000).
* Must be at least 2 x (open files) x rotate_mb, where open files = (workers,
  plus 1 with an FQE connection) x (number of outputs: JSON, CEF).
* Default: 200

when_full = pause|delete_oldest
* What happens when the event files reach buffer_max_gb, or when less than
  1 GB is free on the event folder's disk.
* delete_oldest: keep collecting; delete the oldest files (JSON or CEF) even
  if they have not been read yet (until the buffer is under 90% of buffer_max_gb and 2 GB
  are free).
* pause: stop reading from the FMC; resume from the bookmark once Splunk has
  read (and the input has deleted) enough files and 2 GB are free. Nothing
  unread is deleted, but events the FMC no longer holds by then are lost.
  The FMC keeps a fixed number of connection events (System > Configuration
  > Database), so at thousands of events per second that is minutes to hours.
* Default: delete_oldest

delete_after_min = <integer>
* A JSON file is deleted once Splunk's file monitor has read all of it and it has
  not been written for this many minutes (0-1440; 0 = as soon as it is
  read). Uses Splunk's file status
  (admin/inputstatus/TailingProcessor:FileStatus).
* Default: 15

rotate_mb = <integer>
* Size in MB at which a new event file starts (10-102400). A new file also
  starts every hour.
* Default: 1024

log_level = DEBUG|INFO|WARNING|ERROR
* Default: INFO

event_types = <string>
decoder = <string>
encore_path = <string>
* Not used since version 2.1.0 (built-in decoder; since 2.2.0 the event types
  are the *_events settings above). Ignored when an input created by an older
  version still has them.
