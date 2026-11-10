# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nikhil Chawla
"""
fmc_estreamer_rest.py - REST API behind the app's Inputs page.

  /services/fmc_estreamer/inputs
      GET                           inputs, uploaded certificate names, indexes
      POST action=create|edit       name + input settings
      POST action=enable|disable|restart|delete   name
  /services/fmc_estreamer/certificates
      GET                           uploaded client certificates (never the key)
      POST action=upload            name + format=pkcs12 (pkcs12=base64, password)
                                         or format=pem (cert, key as PEM text)
      POST action=delete            name

Every change is made with the signed-in user's own session, so Splunk's
normal permissions apply (admin rights to change inputs and the credential
store). Certificates are stored encrypted in Splunk's credential store.
"""
import json
import logging
import logging.handlers
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fmc_estreamer_store as store  # noqa: E402
from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

INPUT_FIELDS = ("fmc_host", "fmc_port", "fmc_name", "certificate", "start_from", "verify_fmc", "workers",
                "output_dir", "buffer_max_gb", "when_full", "delete_after_min", "rotate_mb",
                "log_level", "index", "index_in_splunk", "write_cef", "connection_events",
                "policy_violation_events", "vpn_events", "fireamp_events", "file_events", "intrusion_events",
                "intrusion_packets")
INPUTS = f"data/inputs/{store.SCHEME}"


def get_logger():
    log = logging.getLogger("fmc_estreamer_rest")
    if not log.handlers:
        path = os.path.join(store.splunk_home(), "var", "log", "splunk", "fmc_estreamer-webapi.log")
        try:
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=5 << 20, backupCount=2)
        except OSError:
            handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


def form_of(req):
    form = {}
    for key in ("query", "form"):
        for pair in req.get(key) or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                form[pair[0]] = pair[1]
    payload = req.get("payload")
    if not req.get("form") and isinstance(payload, str) and payload:
        try:
            form.update(json.loads(payload))
        except ValueError:
            form.update({k: v[-1] for k, v in urllib.parse.parse_qs(payload, keep_blank_values=True).items()})
    return form


def reply(payload, status=200):
    return {"payload": payload, "status": status}


class Api:
    def __init__(self, splunkd, user, log):
        self.splunkd, self.user, self.log = splunkd, user, log
        self.certs = store.Certificates(splunkd)

    # ---- inputs
    def inputs(self):
        body = self.splunkd.ok("GET", INPUTS, {"count": 0}, allow=(200,))
        out = []
        for entry in store.entries(body):
            content = entry.get("content", {})
            item = {k: content.get(k, "") for k in INPUT_FIELDS}
            item["name"] = entry.get("name")
            item["disabled"] = content.get("disabled") in (True, "1", 1, "true")
            item["output_path"] = store.output_dir(content, item["name"])
            item["status"] = store.read_status(item["name"])
            item["buffer"] = store.folder_usage(item["output_path"])
            out.append(item)
        return out

    def get_inputs(self):
        indexes = []
        status, body = self.splunkd.call("GET", "/services/data/indexes", {"count": 0, "datatype": "event"})
        if status == 200:
            indexes = sorted(e.get("name") for e in store.entries(body)
                             if not e.get("content", {}).get("disabled"))
        names = []
        try:
            names = [c["name"] for c in self.certs.list()]
        except store.StoreError as exc:
            self.log.warning("listing certificates failed: %s", exc)
        return {"inputs": self.inputs(), "certificates": names, "indexes": indexes}

    def post_inputs(self, form):
        action = form.get("action", "")
        name = (form.get("name") or "").strip()
        if not store.NAME_RE.match(name):
            raise store.StoreError("Input name: letters, digits, '.', '_' or '-' (max 64)")
        path = f"{INPUTS}/{store.quote(name)}"
        if action in ("create", "edit"):
            args = {k: form[k] for k in INPUT_FIELDS if k in form}
            if action == "create":
                self.splunkd.ok("POST", INPUTS, dict(args, name=name))
            else:
                current = self.find(name)
                self.splunkd.ok("POST", path, args)
                new_path = self.find(name)["output_path"]
                if new_path != current["output_path"]:
                    self.folder_changed(name, current["output_path"], new_path)
                if not current["disabled"]:                 # make sure it restarts with the new settings
                    self.restart(path)
        elif action in ("enable", "disable"):
            self.splunkd.ok("POST", f"{path}/{action}")
        elif action == "restart":
            self.restart(path)
        elif action == "delete":
            current = self.find(name)
            self.splunkd.ok("DELETE", path)
            removed = 0
            for folder in [current["output_path"]] + store.read_old_folders(name):
                store.remove_monitor(self.splunkd, folder)
                removed += store.delete_event_files(folder)
            store.write_old_folders(name, [])
            for leftover in ("client.cert", "client.key", "fmc-ca.pem"):
                try:
                    os.remove(os.path.join(store.state_root(), name, leftover))
                except OSError:
                    pass
            if removed:
                self.log.info("user=%s input=%s deleted %d event files not yet removed", self.user, name, removed)
        else:
            raise store.StoreError("action must be create, edit, enable, disable, restart or delete")
        self.log.info("user=%s input=%s action=%s", self.user, name, action)
        inputs = self.inputs()
        result = {"ok": True, "inputs": inputs}
        if action in ("create", "edit"):
            item = next((i for i in inputs if i["name"] == name), None)
            free = item and item["buffer"].get("free_bytes")
            cap = float((item or {}).get("buffer_max_gb") or 200)
            if free is not None and free < cap * (1 << 30):
                result["warning"] = (f"{item['output_path']} has {free / (1 << 30):.1f} GB free, less than this "
                                     f"input's max buffer ({cap:g} GB). Lower Max buffer or choose another folder.")
        return result

    def folder_changed(self, name, old, new):
        """
        Event folder changed: files still in the old folder stay monitored; the input
        deletes them once Splunk has read them, then removes the old folder's monitor.
        """
        folders = [f for f in store.read_old_folders(name) if f != new]
        if store.list_event_files(old):
            folders.append(old)
        else:
            store.remove_monitor(self.splunkd, old)
        store.write_old_folders(name, folders)

    def restart(self, path):
        self.splunkd.ok("POST", f"{path}/disable")
        self.splunkd.ok("POST", f"{path}/enable")

    def find(self, name):
        for item in self.inputs():
            if item["name"] == name:
                return item
        raise store.StoreError(f"input '{name}' not found", 404)

    # ---- certificates
    def get_certificates(self):
        certs = self.certs.list()
        try:
            used = {}
            for item in self.inputs():
                used.setdefault(item["certificate"], []).append(item["name"])
            for cert in certs:
                cert["used_by"] = used.get(cert["name"], [])
        except store.StoreError:
            pass
        return {"certificates": certs}

    def post_certificates(self, form):
        action = form.get("action", "")
        name = (form.get("name") or "").strip()
        if action == "upload":
            saved = store.upload(self.certs, form, self.user)
            self.log.info("user=%s certificate=%s action=upload format=%s subject=%s",
                          self.user, name, form.get("format"), saved.get("subject"))
            return {"ok": True, "certificate": saved}
        if action == "delete":
            users = [i["name"] for i in self.inputs() if i["certificate"] == name]
            if users:
                raise store.StoreError(f"'{name}' is used by input(s) {', '.join(users)}; "
                                       "change or delete them first")
            self.certs.delete(name)
            self.log.info("user=%s certificate=%s action=delete", self.user, name)
            return {"ok": True}
        raise store.StoreError("action must be upload or delete")


class Handler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        PersistentServerConnectionApplication.__init__(self)
        self.log = get_logger()

    def handle(self, in_string):
        try:
            req = json.loads(in_string)
            session = req.get("session") or {}
            api = Api(store.Splunkd(session.get("authtoken")), session.get("user", ""), self.log)
            method = (req.get("method") or "GET").upper()
            path = (req.get("rest_path") or "").rstrip("/")
            form = form_of(req)
            if method == "DELETE":
                method, form["action"] = "POST", "delete"
            if path.endswith("/inputs"):
                return reply(api.get_inputs() if method == "GET" else api.post_inputs(form))
            if path.endswith("/certificates"):
                return reply(api.get_certificates() if method == "GET" else api.post_certificates(form))
            return reply({"error": f"unknown path {path}"}, 404)
        except store.StoreError as exc:
            return reply({"error": str(exc)}, exc.status if 400 <= exc.status < 600 else 400)
        except Exception as exc:                                    # keep the handler alive
            self.log.exception("request failed")
            return reply({"error": f"{type(exc).__name__}: {exc}"}, 500)
