# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer_store.py - shared helpers for TA-fmc-estreamer.

  * Splunkd: small REST client for splunkd (Splunk's own splunk.rest when
    running inside Splunk; tests can pass their own transport).
  * Client certificates: PKCS12 or PEM in, validated PEM cert + key out,
    stored encrypted in Splunk's credential store (storage/passwords).
  * The file monitor that indexes a collector's output, and the event files
    themselves (names, disk use, what Splunk has read).

Standard library only; runs on Splunk's bundled Python 3.9 and 3.13.
"""
import base64
import calendar
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.parse

APP = "TA-fmc-estreamer"
SCHEME = "fmc_estreamer"
REALM = "fmc_estreamer_certificate"
CHUNK = 255                         # credential store values are stored in parts of this size
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
# Event files, one folder per input: <input>_<fmc>_<UTC start date>_<HHMMSS>_w<n>.<kind>
# n: the decoder process (0-31) or FQE_WRITER for the FQE session's own writer.
# kind: log = JSON for Splunk (the file monitor reads only these), cef = CEF lines
# for a syslog agent (never indexed by this add-on; the agent's side deletes them
# once read, and the input's max buffer covers both kinds).
EVENT_RE = re.compile(r"^(?P<prefix>.+)_(?P<start>\d{4}-\d{2}-\d{2}_\d{6})_w(?P<worker>\d+)\.(?P<kind>log|cef)$")
OUTPUT_WHITELIST = r"_\d{4}-\d{2}-\d{2}_\d{6}_w\d+\.log$"
FQE_WRITER = 99
# Read as this sourcetype (props.conf: line breaking, timestamp), then renamed to
# cisco:sfw:estreamer at index time (transforms.conf), so the path does not matter.
EVENTS_SOURCETYPE = "fmc:estreamer:events"


class StoreError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def splunk_home():
    return os.environ.get("SPLUNK_HOME") or os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", ".."))


def default_output_root():
    return os.path.join(splunk_home(), "var", "log", "fmc_estreamer")


def state_root():
    return os.path.join(splunk_home(), "var", "lib", "splunk", "modinputs", SCHEME)


def file_prefix(name, host):
    """Event file name prefix: input name and FMC (once, when they are the same)."""
    parts = [name] if not host or name == host else [name, host]
    return "_".join(re.sub(r"[^A-Za-z0-9.\-]", "-", p) for p in parts if p)


def event_file_name(prefix, start, worker, kind="log"):
    return f"{prefix}_{time.strftime('%Y-%m-%d_%H%M%S', time.gmtime(start))}_w{worker}.{kind}"


def list_event_files(folder):
    """Event files in folder, oldest first: [{path, start, worker, kind, size, mtime}]."""
    out = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for fname in names:
        m = EVENT_RE.match(fname)
        if not m:
            continue
        path = os.path.join(folder, fname)
        try:
            st = os.stat(path)
        except OSError:
            continue
        start = calendar.timegm(time.strptime(m.group("start"), "%Y-%m-%d_%H%M%S"))
        out.append({"path": path, "start": start, "worker": int(m.group("worker")), "kind": m.group("kind"),
                    "size": st.st_size, "mtime": st.st_mtime})
    out.sort(key=lambda f: (f["start"], f["worker"], f["kind"]))
    return out


def folder_usage(folder):
    """{bytes, files, cef_bytes, free_bytes} for an input's event folder (free space of its file system)."""
    files = list_event_files(folder)
    probe = folder
    while probe and not os.path.exists(probe):
        probe = os.path.dirname(probe)
    try:
        free = shutil.disk_usage(probe or "/").free
    except OSError:
        free = None
    return {"bytes": sum(f["size"] for f in files), "files": len(files),
            "cef_bytes": sum(f["size"] for f in files if f["kind"] == "cef"), "free_bytes": free}


def check_output_folder(folder):
    """Error text if this process (the splunk user) cannot create and write files in folder."""
    try:
        os.makedirs(folder, exist_ok=True)
        fd, probe = tempfile.mkstemp(prefix=".write_test_", dir=folder)
        os.close(fd)
        os.remove(probe)
    except OSError as exc:
        try:
            import pwd
            user = pwd.getpwuid(os.geteuid()).pw_name
        except Exception:
            user = str(os.geteuid())
        return (f"Splunk (user {user}) cannot write to {folder}: {exc.strerror or exc}. "
                f"Use a folder the {user} user can write, e.g. {default_output_root()}")
    return None


def splunk_file_status(splunkd, folder):
    """
    What Splunk's file monitor has read in folder: {path: (position, size)}, from
    /services/admin/inputstatus/TailingProcessor:FileStatus. None if unavailable.
    """
    status, body = splunkd.call("GET", "/services/admin/inputstatus/TailingProcessor:FileStatus")
    if status != 200 or not isinstance(body, dict):
        raise StoreError(error_text(body) or f"HTTP {status}", status)
    roots = {os.path.join(folder, ""), os.path.join(os.path.realpath(folder), "")}
    out = {}

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, dict) and "file position" in value:
                    if any(key.startswith(r) for r in roots):
                        try:
                            out[os.path.realpath(key)] = (int(float(value.get("file position", 0))),
                                                          int(float(value.get("file size", -1))))
                        except (TypeError, ValueError):
                            pass
                else:
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(body)
    return out


# ------------------------------------------------------------------ splunkd

class Splunkd:
    """
    Calls splunkd REST as the given session (user token or the modular input's
    system token). Returns (status, parsed JSON or text).
    """

    def __init__(self, token, transport=None):
        self.token = token
        self.transport = transport or _splunk_rest

    def call(self, method, path, args=None):
        if not path.startswith("/"):
            path = f"/servicesNS/nobody/{APP}/{path}"
        args = dict(args or {})
        args["output_mode"] = "json"
        status, body = self.transport(method, path, args, self.token)
        try:
            body = json.loads(body) if isinstance(body, (str, bytes)) and body else body
        except ValueError:
            pass
        return status, body

    def ok(self, method, path, args=None, allow=(200, 201)):
        status, body = self.call(method, path, args)
        if status not in allow:
            raise StoreError(error_text(body) or f"splunkd returned {status} for {path}", status)
        return body


def _splunk_rest(method, path, args, token):
    import splunk.rest               # Splunk's own Python library (present inside Splunk)
    getargs = args if method in ("GET", "DELETE") else {"output_mode": args.get("output_mode", "json")}
    postargs = None if method in ("GET", "DELETE") else {k: v for k, v in args.items() if k != "output_mode"}
    try:
        response, content = splunk.rest.simpleRequest(
            path, sessionKey=token, method=method, getargs=getargs, postargs=postargs,
            raiseAllErrors=False)
        return int(response.status), content
    except Exception as exc:                 # splunk.RESTException and subclasses (404, 403, ...)
        status = getattr(exc, "statusCode", None)
        if not status:
            raise
        return int(status), json.dumps(
            {"messages": [{"type": "ERROR", "text": getattr(exc, "msg", None) or str(exc)}]})


def error_text(body):
    if isinstance(body, dict):
        msgs = body.get("messages") or []
        text = "; ".join(m.get("text", "") for m in msgs if isinstance(m, dict))
        return text or body.get("error", "")
    if isinstance(body, (bytes, str)):
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        found = re.findall(r"<msg[^>]*>([^<]*)</msg>", text)
        return "; ".join(found) or text[:300]
    return ""


def entries(body):
    return body.get("entry", []) if isinstance(body, dict) else []


def quote(name):
    return urllib.parse.quote(name, safe="")


# ------------------------------------------------------------- certificates

PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----\s.*?-----END \1-----\s*", re.S)


def pem_blocks(text, kind):
    return [m.group(0).strip() + "\n" for m in PEM_BLOCK.finditer(text) if m.group(1) == kind]


def parse_pem(cert_text, key_text):
    certs = pem_blocks(cert_text, "CERTIFICATE")
    keys = [b for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
            for b in pem_blocks(key_text, kind)]
    if pem_blocks(key_text, "ENCRYPTED PRIVATE KEY") or "Proc-Type: 4,ENCRYPTED" in key_text:
        raise StoreError("the private key is encrypted; upload the PKCS12 file with its password instead")
    if not certs:
        raise StoreError("no PEM certificate found (expected -----BEGIN CERTIFICATE-----)")
    if not keys:
        raise StoreError("no PEM private key found (expected -----BEGIN PRIVATE KEY-----)")
    return certs[0], keys[0], certs[1:]


def parse_pkcs12(data, password):
    """PKCS12 (the file the FMC gives out) -> (cert PEM, key PEM, CA PEMs)."""
    pw = password.encode("utf-8") if password else None
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, pkcs12)
        key, cert, extra = pkcs12.load_key_and_certificates(data, pw)
    except Exception as exc:          # not installed, wrong password, or a legacy cipher it can't read
        try:
            return _pkcs12_openssl(data, password)
        except StoreError as fallback:
            first = "" if isinstance(exc, ImportError) else f"{exc}; "
            raise StoreError(f"could not open the PKCS12 file (wrong password?): {first}{fallback}")
    if key is None or cert is None:
        raise StoreError("the PKCS12 file has no client certificate and key")
    return (cert.public_bytes(Encoding.PEM).decode(),
            key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(),
            [c.public_bytes(Encoding.PEM).decode() for c in (extra or [])])


def _openssl_cmd():
    home = splunk_home()
    splunk = os.path.join(home, "bin", "splunk")
    if os.path.isfile(splunk):
        return [splunk, "cmd", "openssl"]
    found = shutil.which("openssl")
    if not found:
        raise StoreError("cannot read PKCS12: neither Python 'cryptography' nor openssl is available", 500)
    return [found]


def _pkcs12_openssl(data, password):
    tmp = tempfile.mkdtemp(prefix="fmc_p12_")
    try:
        path = os.path.join(tmp, "upload.p12")
        with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as fh:
            fh.write(data)
        env = dict(os.environ, FMC_P12_PASS=password or "")
        out, last_error = {}, ""
        for part, extra in (("cert", ["-clcerts", "-nokeys"]), ("key", ["-nocerts", "-nodes"]),
                            ("ca", ["-cacerts", "-nokeys"])):
            for legacy in ([], ["-legacy"]):          # -legacy: RC2/3DES files on OpenSSL 3
                cmd = _openssl_cmd() + ["pkcs12", "-in", path, "-passin", "env:FMC_P12_PASS"] + extra + legacy
                res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    out[part] = res.stdout
                    break
                lines = [ln for ln in res.stderr.strip().splitlines() if ln.strip()]
                last_error = lines[0] if lines else f"openssl exit {res.returncode}"
            if part != "ca" and part not in out:
                raise StoreError(f"openssl could not open it: {last_error}")
        cert, key, _ = parse_pem(out["cert"], out["key"])
        return cert, key, pem_blocks(out.get("ca", ""), "CERTIFICATE")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def inspect_pair(cert_pem, key_pem):
    """Checks the key belongs to the certificate; returns subject/issuer/validity."""
    tmp = tempfile.mkdtemp(prefix="fmc_cert_")
    try:
        cert_path, key_path = write_pair(tmp, cert_pem, key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            ctx.load_cert_chain(cert_path, key_path, password=lambda: b"")
        except ssl.SSLError as exc:
            raise StoreError(f"the private key does not match the certificate ({exc.reason or exc})")
        try:
            return cert_details(cert_path)
        except Exception:                                        # informational only
            return {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# Certificate name attributes (cryptography's NameOID constants), shown by their long names as
# OpenSSL prints them. Attributes not listed, or not known to the installed cryptography
# version, are shown by their numeric OID.
NAME_ATTRS = (
    ("COMMON_NAME", "commonName"), ("SURNAME", "surname"), ("SERIAL_NUMBER", "serialNumber"),
    ("COUNTRY_NAME", "countryName"), ("LOCALITY_NAME", "localityName"),
    ("STATE_OR_PROVINCE_NAME", "stateOrProvinceName"), ("STREET_ADDRESS", "streetAddress"),
    ("ORGANIZATION_NAME", "organizationName"), ("ORGANIZATIONAL_UNIT_NAME", "organizationalUnitName"),
    ("TITLE", "title"), ("POSTAL_CODE", "postalCode"), ("GIVEN_NAME", "givenName"), ("INITIALS", "initials"),
    ("GENERATION_QUALIFIER", "generationQualifier"), ("DN_QUALIFIER", "dnQualifier"),
    ("PSEUDONYM", "pseudonym"), ("ORGANIZATION_IDENTIFIER", "organizationIdentifier"),
    ("EMAIL_ADDRESS", "emailAddress"), ("USER_ID", "userId"), ("DOMAIN_COMPONENT", "domainComponent"),
)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def cert_details(cert_path):
    """
    Subject, issuer, validity and serial of a PEM certificate, for the Inputs page:
    {subject, issuer, not_before, not_after, serial, expires_epoch}. Names read
    "commonName=..., organizationalUnitName=...", dates "Sep 17 05:26:09 2026 GMT"
    and the serial as uppercase hex, as OpenSSL prints them. Uses the cryptography
    package that ships with Splunk, else Splunk's openssl.
    """
    try:
        return _details_cryptography(cert_path)
    except Exception:                                   # not installed, or a certificate it can't read
        return _details_openssl(cert_path)


def _details_cryptography(cert_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    long_names = {getattr(NameOID, attr): label for attr, label in NAME_ATTRS if hasattr(NameOID, attr)}

    def name(value):
        return ", ".join(f"{long_names.get(a.oid, a.oid.dotted_string)}="
                         f"{a.value if isinstance(a.value, str) else bytes(a.value).hex()}"
                         for rdn in value.rdns for a in rdn)

    def when(attr):                                     # *_utc since cryptography 42; naive UTC before
        moment = getattr(cert, attr + "_utc", None) or getattr(cert, attr)
        return (f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment.hour:02d}:{moment.minute:02d}:"
                f"{moment.second:02d} {moment.year} GMT"), calendar.timegm(moment.utctimetuple())

    serial = format(cert.serial_number, "X")
    not_before, _ = when("not_valid_before")
    not_after, expires = when("not_valid_after")
    return {"subject": name(cert.subject), "issuer": name(cert.issuer), "not_before": not_before,
            "not_after": not_after, "serial": serial if len(serial) % 2 == 0 else "0" + serial,
            "expires_epoch": int(expires)}


def _details_openssl(cert_path):
    cmd = _openssl_cmd() + ["x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-startdate",
                            "-enddate", "-serial", "-nameopt", "lname,sep_comma_plus_space,utf8"]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if res.returncode:
        raise StoreError(f"openssl could not read the certificate: {res.stderr.strip()[:200]}")
    found = {}
    for line in res.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            found[key.strip()] = value.strip()
    info = {"subject": found.get("subject", ""), "issuer": found.get("issuer", ""),
            "not_before": found.get("notBefore", ""), "not_after": found.get("notAfter", ""),
            "serial": found.get("serial", "")}
    if info["not_after"]:
        info["expires_epoch"] = int(ssl.cert_time_to_seconds(info["not_after"]))
    return info


def write_pair(folder, cert_pem, key_pem, ca_pem=None):
    """client.cert / client.key (mode 600), plus fmc-ca.pem when the upload carried the FMC's CA."""
    cert_path = os.path.join(folder, "client.cert")
    key_path = os.path.join(folder, "client.key")
    ca_path = os.path.join(folder, "fmc-ca.pem")
    files = [(cert_path, cert_pem), (key_path, key_pem)]
    if ca_pem:
        files.append((ca_path, ca_pem))
    elif ca_pem is not None and os.path.exists(ca_path):
        os.remove(ca_path)
    for path, text in files:
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    return cert_path, key_path


class Certificates:
    """Client certificates in storage/passwords, split into CHUNK-sized parts."""

    def __init__(self, splunkd):
        self.splunkd = splunkd

    def _parts(self):
        body = self.splunkd.ok("GET", "storage/passwords", {"count": 0, "search": f"realm={REALM}"})
        parts = {}
        for entry in entries(body):
            content = entry.get("content", {})
            if content.get("realm") != REALM:
                continue
            user = content.get("username", "")
            m = re.match(r"^(.*)\.(\d{3})$", user)
            if m:
                parts.setdefault(m.group(1), {})[int(m.group(2))] = (
                    content.get("clear_password", ""), entry.get("name", ""))
        return parts

    def _assemble(self, chunks):
        text, i = "", 0
        while i in chunks:
            text += chunks[i][0]
            i += 1
        return json.loads(text)

    def list(self):
        out = []
        for name, chunks in sorted(self._parts().items()):
            try:
                doc = self._assemble(chunks)
            except ValueError:
                out.append({"name": name, "error": "stored certificate is incomplete; upload it again"})
                continue
            out.append({"name": name, **{k: v for k, v in doc.items() if k not in ("cert", "key", "ca")},
                        "has_ca": bool(doc.get("ca"))})
        return out

    def get(self, name):
        chunks = self._parts().get(name)
        if not chunks:
            raise StoreError(f"client certificate '{name}' is not uploaded", 404)
        try:
            return self._assemble(chunks)
        except ValueError:
            raise StoreError(f"client certificate '{name}' is incomplete; upload it again", 500)

    def save(self, name, cert_pem, key_pem, ca_pems, source, user):
        if not NAME_RE.match(name or ""):
            raise StoreError("certificate name: letters, digits, '.', '_' or '-' (max 64)")
        info = inspect_pair(cert_pem, key_pem)
        doc = dict(info, cert=cert_pem, key=key_pem, ca="".join(ca_pems or []), source=source,
                   uploaded=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), uploaded_by=user or "")
        text = json.dumps(doc, separators=(",", ":"))
        self.delete(name, missing_ok=True)
        for i in range(0, len(text), CHUNK):
            self.splunkd.ok("POST", "storage/passwords",
                            {"name": f"{name}.{i // CHUNK:03d}", "realm": REALM,
                             "password": text[i:i + CHUNK]})
        return {"name": name, **{k: v for k, v in doc.items() if k not in ("cert", "key", "ca")}}

    def delete(self, name, missing_ok=False):
        chunks = self._parts().get(name)
        if not chunks:
            if missing_ok:
                return
            raise StoreError(f"client certificate '{name}' not found", 404)
        for _, entry_name in chunks.values():
            self.splunkd.ok("DELETE", f"storage/passwords/{quote(entry_name)}", allow=(200, 404))


def upload(certs, form, user):
    """Form from the Inputs page -> stored certificate (PKCS12 or PEM)."""
    name = (form.get("name") or "").strip()
    kind = form.get("format", "pkcs12")
    if kind == "pkcs12":
        raw = form.get("pkcs12", "")
        if not raw:
            raise StoreError("choose the PKCS12 file the FMC created for this client")
        try:
            data = base64.b64decode(raw, validate=True)
        except ValueError:
            raise StoreError("the PKCS12 upload is not valid base64")
        cert, key, ca = parse_pkcs12(data, form.get("password", ""))
    elif kind == "pem":
        cert, key, ca = parse_pem(form.get("cert", ""), form.get("key", ""))
    else:
        raise StoreError("format must be pkcs12 or pem")
    return certs.save(name, cert, key, ca, kind, user)


# ------------------------------------------------------------------ monitor

def output_dir(params, name):
    return os.path.join(os.path.normpath(params.get("output_dir") or default_output_root()), name)


def check_output_root(folder):
    """Error text if the event folder is somewhere Splunk itself uses (config, its own logs, indexes)."""
    if not os.path.isabs(folder):
        return "output_dir must be an absolute path"
    real = os.path.realpath(folder)
    home = os.path.realpath(splunk_home())
    for sub in (("etc",), ("var", "log", "splunk"), ("var", "spool"), ("var", "run"), ("var", "lib")):
        reserved = os.path.join(home, *sub)
        if real == reserved or real.startswith(reserved + os.sep):
            return (f"output_dir must not be inside {reserved} (Splunk uses it); "
                    f"e.g. {default_output_root()}")
    return None


# Event folders an input used before its Event folder was changed: the input keeps
# deleting the files Splunk has read there, then removes that folder's file monitor.
OLD_FOLDERS = "old_folders.json"


def read_old_folders(name):
    try:
        with open(os.path.join(state_root(), name, OLD_FOLDERS), encoding="utf-8") as fh:
            return [f for f in json.load(fh) if isinstance(f, str)]
    except (OSError, ValueError, TypeError):
        return []


def write_old_folders(name, folders):
    folder = os.path.join(state_root(), name)
    path = os.path.join(folder, OLD_FOLDERS)
    if not folders:
        if os.path.exists(path):
            os.remove(path)
        return
    os.makedirs(folder, exist_ok=True)
    with open(path + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(sorted(set(folders)), fh)
    os.replace(path + ".tmp", path)


def delete_event_files(folder):
    """Remove this add-on's event files (only names it writes) and the folder if it is then empty."""
    removed = 0
    for f in list_event_files(folder):
        try:
            os.remove(f["path"])
            removed += 1
        except OSError:
            pass
    try:
        os.rmdir(folder)
    except OSError:
        pass
    return removed


def ensure_monitor(splunkd, path, params, host):
    """Create or update the file monitor that indexes this collector's output (host = FMC name)."""
    # crc-salt <SOURCE>: files are never renamed, so the path is part of each file's identity
    # (two files whose first bytes look alike are still read as two files).
    wanted = {"whitelist": OUTPUT_WHITELIST, "sourcetype": EVENTS_SOURCETYPE,
              "host": host, "index": params.get("index") or "default", "crc-salt": "<SOURCE>"}
    entity = f"data/inputs/monitor/{quote(path)}"
    status, body = splunkd.call("GET", entity)
    if status == 200 and entries(body):
        have = entries(body)[0].get("content", {})
        have = dict(have, **{"crc-salt": have.get("crcSalt", have.get("crc-salt", ""))})
        changed = {k: v for k, v in wanted.items() if str(have.get(k, "")) != str(v)}
        result = "unchanged"
        if changed:
            splunkd.ok("POST", entity, changed)
            result = "updated"
        if have.get("disabled") in (True, "1", 1, "true"):      # create/edit take no 'disabled' argument
            splunkd.ok("POST", f"{entity}/enable")
            result += ", enabled"
        return result
    splunkd.ok("POST", "data/inputs/monitor", dict(wanted, name=path))
    return "created"


def remove_monitor(splunkd, path):
    status, _ = splunkd.call("DELETE", f"data/inputs/monitor/{quote(path)}")
    return status in (200, 404)


# ------------------------------------------------------------------ status

STATS_RE = re.compile(r"written (?P<eps>\d+)/s, records \d+/s, .*?errors (?P<errors>\d+), "
                      r"inflight \d+, bookmark \S+, behind (?P<behind>-?[\d.]+) min"
                      r"(?:, buffer (?P<buffer>[\d.]+) GB(?P<paused> PAUSED)?)?")
LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} (?P<level>[A-Z]+) (?P<msg>.*)$")


def log_path(name):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return os.path.join(splunk_home(), "var", "log", "splunk", f"fmc_estreamer_{safe}.log")


def read_status(name, window=900):
    """Latest stats from the input's own log file on this instance (works without local indexing)."""
    try:
        with open(log_path(name), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 65536))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return {}
    out = {}
    newest = None
    for line in reversed(lines):
        m = LINE_RE.match(line)
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            continue
        if newest is None:
            newest = ts
            out["last_seen"] = ts
        if newest - ts > window:
            break
        stats = STATS_RE.search(m.group("msg"))
        if stats and "behind" not in out:
            out.update(behind=stats.group("behind"), eps=stats.group("eps"),
                       paused=bool(stats.group("paused")))
        if m.group("level") in ("ERROR", "CRITICAL") and "last_error" not in out \
                and "behind" not in out:              # an error newer than the last stats line
            out["last_error"] = m.group("msg")
    return out
