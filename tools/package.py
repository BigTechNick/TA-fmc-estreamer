#!/usr/bin/env python3
"""
package.py - build the installable add-on package and run local checks.

  python3 package.py <app dir> <out dir> [--forbid words.txt] [--vendor cisco]

Checks (the AppInspect basics that can be tested offline): no local/,
local.meta, hidden files or compiled Python; .conf files parse; every modular
input has a spec and its scheme matches the spec; Python parses as 3.9 and
imports only the standard library, the add-on's own modules and Splunk's;
Simple XML views are version 1.1; icons have the right sizes; app.conf and
app.manifest agree (id, version, label = title, Splunkbase name rules);
LICENSE, NOTICE and README.md are present; no vendor copyright notices outside
NOTICE/README, no private or IP-like addresses outside documentation ranges,
and none of the words in --forbid (one per line, case-insensitive), e.g. site
names that must not be published.
"""
import ast
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET

PROBLEMS = []


def problem(msg):
    PROBLEMS.append(msg)
    print("FAIL ", msg)


def read_conf(path):
    """Splunk .conf -> {stanza: {key: value}} (continuation lines, comments)."""
    out, stanza, cont = {}, "default", None
    if not os.path.exists(path):                     # optional .conf files
        return out
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            if cont is not None:
                out[stanza][cont] += "\n" + raw.rstrip("\\")
                if not raw.endswith("\\"):
                    cont = None
                continue
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("[") and s.endswith("]"):
                stanza = s[1:-1]
                if stanza in out:
                    problem(f"{path}:{n} duplicate stanza [{stanza}]")
                out.setdefault(stanza, {})
            elif "=" in s:
                key, value = s.split("=", 1)
                key = key.strip()
                if key in out.setdefault(stanza, {}):
                    problem(f"{path}:{n} duplicate key {key} in [{stanza}]")
                out[stanza][key] = value.strip().rstrip("\\")
                if s.endswith("\\"):
                    cont = key
            else:
                problem(f"{path}:{n} not a stanza or key = value: {s[:60]}")
    return out


def check_scheme(app, stanza, spec):
    """Every spec key must be a scheme arg (splunkd requires the others on create), and the reverse."""
    script = os.path.join(app, "bin", stanza + ".py")
    try:
        out = subprocess.run([sys.executable, "-I", "-B", script, "--scheme"], capture_output=True, text=True,
                             timeout=30, check=True).stdout
        args = {a.get("name") for a in ET.fromstring(out).iter("arg")}
    except (subprocess.SubprocessError, OSError, ET.ParseError) as exc:
        problem(f"bin/{stanza}.py --scheme failed: {exc}")
        return
    m = re.search(rf"^\[{re.escape(stanza)}://<name>\]\n(.*?)(?=^\[|\Z)", spec, re.M | re.S)
    keys = set(re.findall(r"^([A-Za-z_][A-Za-z0-9_.]*) = ", m.group(1) if m else "", re.M))
    for key in sorted(keys - args):
        problem(f"inputs.conf.spec [{stanza}] key {key} is not in the scheme")
    for key in sorted(args - keys):
        problem(f"{stanza} scheme arg {key} is not in inputs.conf.spec")


def check(app):
    name = os.path.basename(app)
    for root, dirs, files in os.walk(app):
        rel_root = os.path.relpath(root, app)
        for d in dirs:
            if d in ("local", "__pycache__") or d.startswith("."):
                problem(f"forbidden directory {os.path.join(rel_root, d)}")
        for f in files:
            rel = os.path.normpath(os.path.join(rel_root, f))
            full = os.path.join(root, f)
            if f.startswith(".") or f.endswith((".pyc", ".pyo")) or f == "local.meta":
                problem(f"forbidden file {rel}")
            mode = os.stat(full).st_mode
            if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) and not rel.startswith("bin" + os.sep):
                problem(f"executable outside bin/: {rel}")
            if f.endswith(".py"):
                try:
                    ast.parse(open(full, encoding="utf-8").read(), filename=rel, feature_version=(3, 9))
                except SyntaxError as exc:
                    problem(f"{rel} does not parse as Python 3.9: {exc}")
            if f.endswith(".conf") or f.endswith(".meta"):
                read_conf(full)
            if f.endswith(".xml"):
                try:
                    ET.parse(full)
                except ET.ParseError as exc:
                    problem(f"{rel}: XML does not parse: {exc}")

    app_conf = read_conf(os.path.join(app, "default", "app.conf"))
    version = app_conf.get("launcher", {}).get("version")
    label = app_conf.get("ui", {}).get("label", "")
    if app_conf.get("package", {}).get("id") != name or app_conf.get("id", {}).get("name") != name:
        problem("app.conf [package] id / [id] name must equal the folder name")
    if app_conf.get("id", {}).get("version") != version:
        problem("app.conf [id] version differs from [launcher] version")
    manifest = json.load(open(os.path.join(app, "app.manifest")))
    if manifest["info"]["id"]["name"] != name or manifest["info"]["id"]["version"] != version:
        problem("app.manifest id/version differ from app.conf")
    if manifest["info"]["title"] != label:
        problem("app.manifest title differs from app.conf [ui] label")
    if not re.fullmatch(r"[A-Za-z0-9 +\-.!\\/()]{5,80}", label):
        problem(f"label {label!r}: Splunkbase names allow letters, digits, spaces and + - . ! \\ / ( ), 5-80 chars")

    inputs = read_conf(os.path.join(app, "default", "inputs.conf"))
    spec_path = os.path.join(app, "README", "inputs.conf.spec")
    spec = open(spec_path).read() if os.path.exists(spec_path) else ""
    standard = {"python.version", "python.required", "interval", "index", "sourcetype", "host", "disabled",
                "start_by_shell"}
    for stanza, keys in inputs.items():
        if "://" in stanza or stanza == "default":
            if keys.get("disabled") not in ("1", "true"):
                problem(f"default/inputs.conf [{stanza}] must be disabled by default")
            continue
        if not os.path.exists(os.path.join(app, "bin", stanza + ".py")):
            problem(f"modular input {stanza} has no bin/{stanza}.py")
        if f"[{stanza}://<name>]" not in spec:
            problem(f"README/inputs.conf.spec has no [{stanza}://<name>] stanza")
        for key in keys:
            if key not in standard and not re.search(rf"^{re.escape(key)} = ", spec, re.M):
                problem(f"inputs.conf [{stanza}] {key} is not in inputs.conf.spec")
        if keys.get("python.version") != "python3":
            problem(f"inputs.conf [{stanza}] needs python.version = python3")
        check_scheme(app, stanza, spec)

    restmap = read_conf(os.path.join(app, "default", "restmap.conf"))
    matches = {v.get("match", "").strip("/") for v in restmap.values()}
    for stanza, keys in restmap.items():
        if stanza.startswith("script:"):
            if keys.get("python.version") != "python3" or not keys.get("python.required"):
                problem(f"restmap [{stanza}] needs python.version = python3 and python.required")
            if not os.path.exists(os.path.join(app, "bin", keys.get("script", ""))):
                problem(f"restmap [{stanza}] script not found")
    for stanza, keys in read_conf(os.path.join(app, "default", "web.conf")).items():
        if stanza.startswith("expose:") and keys.get("pattern") not in matches:
            problem(f"web.conf [{stanza}] pattern has no restmap match")

    tags = read_conf(os.path.join(app, "default", "tags.conf"))
    eventtypes = read_conf(os.path.join(app, "default", "eventtypes.conf"))
    for stanza in tags:
        if stanza.startswith("eventtype=") and stanza.split("=", 1)[1] not in eventtypes:
            problem(f"tags.conf [{stanza}] has no event type")
    transforms = read_conf(os.path.join(app, "default", "transforms.conf"))
    for stanza, keys in read_conf(os.path.join(app, "default", "props.conf")).items():
        for key, value in keys.items():
            if key.startswith("REPORT-") or key.startswith("TRANSFORMS-"):
                for t in value.split(","):
                    if t.strip() not in transforms:
                        problem(f"props.conf [{stanza}] {key}: transform {t.strip()} not defined")
            if key.startswith("EVAL-") and value.count("(") != value.count(")"):
                problem(f"props.conf [{stanza}] {key}: unbalanced parentheses")
            if key.startswith("EVAL-") and value.replace('\\"', "").count('"') % 2:
                problem(f"props.conf [{stanza}] {key}: unbalanced quotes")
    for stanza, keys in transforms.items():
        if keys.get("filename") and not os.path.exists(os.path.join(app, "lookups", keys["filename"])):
            problem(f"transforms.conf [{stanza}] lookup file {keys['filename']} missing")

    views = os.path.join(app, "default", "data", "ui", "views")
    for f in (os.listdir(views) if os.path.isdir(views) else []):
        root = ET.parse(os.path.join(views, f)).getroot()
        if root.tag in ("dashboard", "form") and root.get("version") != "1.1":
            problem(f"view {f} must be version=\"1.1\" (Simple XML)")
        for attr in ("script", "stylesheet"):
            for item in (root.get(attr) or "").split(","):
                if item and not os.path.exists(os.path.join(app, "appserver", "static", item.strip())):
                    problem(f"view {f} {attr} {item} not found")
    nav_file = os.path.join(app, "default", "data", "ui", "nav", "default.xml")
    nav = ET.parse(nav_file).getroot() if os.path.exists(nav_file) else ET.Element("nav")
    for view in nav.iter("view"):
        if view.get("name") != "search" and not os.path.exists(os.path.join(views, view.get("name") + ".xml")):
            problem(f"nav view {view.get('name')} not found")

    try:
        from PIL import Image
        for f, size in (("appIcon.png", 36), ("appIcon_2x.png", 72), ("appIconAlt.png", 36),
                        ("appIconAlt_2x.png", 72)):
            p = os.path.join(app, "static", f)
            if not os.path.exists(p) or Image.open(p).size != (size, size):
                problem(f"static/{f} must be {size}x{size}")
    except ImportError:
        pass
    js = os.path.join(app, "appserver", "static")
    for f in (os.listdir(js) if os.path.isdir(js) else []):
        if f.endswith(".js"):
            text = open(os.path.join(js, f)).read()
            for bad in ("eval(", "innerHTML", "document.write", "http://", "https://"):
                if bad in text:
                    problem(f"{f} contains {bad}")
    for f in ("LICENSE", "NOTICE", "README.md"):
        if not os.path.isfile(os.path.join(app, f)):
            problem(f"{f} missing")
    return version


# splunk: Splunk's own modules; certifi, cryptography: ship with Splunk's Python (optional)
STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"splunk", "certifi", "cryptography"}
PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")
IPV4_LIKE = re.compile(r"(?=(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d))")
IP_OK = ("192.0.2.", "198.51.100.", "203.0.113.", "127.", "0.0.0.0")


def ip_like(text):
    for m in IPV4_LIKE.finditer(text):
        ip = m.group(1)
        if all(int(octet) <= 255 for octet in ip.split(".")) and not ip.startswith(IP_OK):
            yield ip


def provenance(app, forbid, vendor):
    bindir = os.path.join(app, "bin")
    own = {f[:-3] for f in os.listdir(bindir) if f.endswith(".py")} if os.path.isdir(bindir) else set()
    for root, dirs, files in os.walk(app):
        if os.path.relpath(root, app).split(os.sep)[:2] in (["bin", "lib"],):
            problem("bin/lib exists (bundled third-party code)")
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, app)
            if f.endswith(".png"):
                continue
            text = open(full, encoding="utf-8", errors="replace").read()
            low = text.lower()
            if rel not in ("NOTICE", "README.md", "LICENSE") and re.search(
                    rf"copyright[^\n]{{0,40}}{vendor}|{vendor} systems, inc|all rights reserved", low):
                problem(f"{rel}: vendor copyright notice")
            for word in forbid:
                if word in low:
                    problem(f"{rel}: contains forbidden word '{word}'")
            private = set(PRIVATE_IP.findall(text))
            for ip in sorted(private):
                problem(f"{rel}: private IP address {ip}")
            if rel != "LICENSE":
                for ip in sorted(set(ip_like(text)) - private):
                    problem(f"{rel}: {ip} looks like an IP address (AppInspect reports it as a public IP)")
            if f.endswith(".py"):
                for node in ast.walk(ast.parse(text)):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.level == 0:
                        names = [node.module or ""]
                    for n in names:
                        top = n.split(".")[0]
                        if top not in STDLIB and top not in own:
                            problem(f"{rel}: imports {n} (not standard library, Splunk or the add-on)")


def main():
    app, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    forbid = []
    if "--forbid" in sys.argv:
        with open(sys.argv[sys.argv.index("--forbid") + 1], encoding="utf-8") as fh:
            forbid = [w.strip().lower() for w in fh if w.strip() and not w.startswith("#")]
    vendor = sys.argv[sys.argv.index("--vendor") + 1].lower() if "--vendor" in sys.argv else "cisco"
    name = os.path.basename(app)
    build = tempfile.mkdtemp(prefix="pkg_")
    dest = os.path.join(build, name)
    shutil.copytree(app, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".*", "local", "local.meta"))
    os.chmod(dest, 0o755)                         # top folder too (files on a 077-umask mount start private)
    for root, dirs, files in os.walk(dest):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    version = check(dest)
    provenance(dest, forbid, re.escape(vendor))
    os.makedirs(out, exist_ok=True)
    target = os.path.join(out, f"{name}-{version}.tgz")

    def clean(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info
    with tarfile.open(target, "w:gz") as tar:
        tar.add(dest, arcname=name, filter=clean)
    shutil.rmtree(build)
    n = len(tarfile.open(target).getnames())
    print(f"{target}  ({os.path.getsize(target) // 1024} KB, {n} entries)")
    print("RESULT:", "OK" if not PROBLEMS else f"{len(PROBLEMS)} problem(s)")
    sys.exit(1 if PROBLEMS else 0)


if __name__ == "__main__":
    main()
