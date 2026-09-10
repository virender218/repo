"""
Check Point Management API client.

Extracted so the web UI and any command-line tooling share one implementation.
Every method takes an optional `log` callable so long-running operations can
stream progress back to whatever is watching.
"""

import time

import requests
from requests.packages.urllib3 import disable_warnings

disable_warnings()

MANAGED_MARKER = "[ldap-sync]"
TASK_POLL_INTERVAL = 5
TASK_TIMEOUT = 900


class CheckPointError(Exception):
    pass


def _noop(_msg, _level="info"):
    pass


class CheckPointAPI:
    def __init__(self, host, verify=False, timeout=60, log=None):
        host = (host or "").strip().rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        if not host.endswith("/web_api"):
            host += "/web_api"
        self.url = host
        self.verify = verify
        self.timeout = timeout
        self.sid = None
        self.log = log or _noop
        self.session = requests.Session()

    # ---------------- transport ----------------
    def call(self, command, payload=None, timeout=None):
        """POST a command. Returns (http_status, body_or_None, raw_text)."""
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        try:
            r = self.session.post(
                f"{self.url}/{command}",
                json=payload or {},
                headers=headers,
                verify=self.verify,
                timeout=timeout or self.timeout,
            )
        except requests.RequestException as exc:
            raise CheckPointError(f"{command}: {exc}") from exc

        try:
            body = r.json() if r.text.strip() else {}
        except ValueError:
            body = None
        return r.status_code, body, r.text

    # ---------------- session ----------------
    def login(self, user, password, domain=None, session_timeout=3600):
        payload = {"user": user, "password": password,
                   "session-timeout": session_timeout}
        if domain:
            payload["domain"] = domain

        status, body, raw = self.call("login", payload)
        if status != 200 or not body or "sid" not in body:
            msg = (body or {}).get("message") or raw or f"HTTP {status}"
            raise CheckPointError(f"Login failed: {msg}")

        self.sid = body["sid"]
        self.log(f"Signed in to {self.url} "
                 f"(API {body.get('api-server-version', '?')})")
        return self.sid

    def logout(self):
        if self.sid:
            self.call("logout", {})
            self.sid = None
            self.log("Signed out of the management server.")

    def discard(self):
        if self.sid:
            self.call("discard", {})

    # ---------------- tasks ----------------
    def wait_for_task(self, task_id, label="Task"):
        deadline = time.time() + TASK_TIMEOUT
        last = -1
        while time.time() < deadline:
            status, body, raw = self.call(
                "show-task", {"task-id": task_id, "details-level": "full"})
            if status != 200 or not body or "tasks" not in body:
                self.log(f"{label}: could not read task status: {raw}", "error")
                return False

            task = body["tasks"][0]
            state = str(task.get("status", "")).lower()
            progress = task.get("progress-percentage", 0)

            if progress != last:
                self.log(f"{label}: {progress}% ({state})")
                last = progress

            if "progress" not in state:
                if state == "succeeded":
                    self.log(f"{label}: succeeded", "ok")
                    return True
                self.log(f"{label}: finished as '{state}'", "error")
                for line in self.task_errors(task):
                    self.log(f"  {line}", "error")
                return False

            time.sleep(TASK_POLL_INTERVAL)

        self.log(f"{label}: timed out after {TASK_TIMEOUT}s", "error")
        return False

    @staticmethod
    def task_errors(task):
        """Pull the human-readable failure text out of a task object."""
        out = []
        for detail in task.get("task-details", []):
            for key in ("statusDescription", "fault-message"):
                if detail.get(key):
                    out.append(str(detail[key]))
            for stage in detail.get("stagesInfo") or []:
                for msg in stage.get("messages", []):
                    if msg.get("message"):
                        out.append(f"[{stage.get('stage', '?')}] {msg['message']}")
        return out

    def run_async(self, command, payload, label):
        """POST a command that returns a task-id, then wait on it."""
        status, body, raw = self.call(command, payload)

        if status != 200:
            message = (body or {}).get("message") or raw
            self.log(f"{label} rejected: {message}", "error")
            for err in (body or {}).get("errors", []):
                self.log(f"  {err.get('message', err)}", "error")
            for warn in (body or {}).get("warnings", []):
                self.log(f"  {warn.get('message', warn)}", "warn")
            return False

        task_id = (body or {}).get("task-id")
        if task_id:
            return self.wait_for_task(task_id, label)

        # MDS can return several task ids
        ids = (body or {}).get("tasks") or (body or {}).get("task-ids")
        if ids:
            ok = True
            for tid in ids:
                tid = tid["task-id"] if isinstance(tid, dict) else tid
                ok = self.wait_for_task(tid, label) and ok
            return ok

        self.log(f"{label}: completed immediately.", "ok")
        return True

    # ---------------- users ----------------
    def show_users(self):
        """
        Return (managed, unmanaged) sets of usernames.

        managed   -- carries MANAGED_MARKER in comments, i.e. we created it
        unmanaged -- made by hand in SmartConsole; never deleted by the sync
        """
        managed, unmanaged = set(), set()
        offset, limit = 0, 500

        while True:
            status, body, raw = self.call(
                "show-users",
                {"offset": offset, "limit": limit, "details-level": "full"})
            if status != 200 or body is None:
                raise CheckPointError(
                    f"show-users failed: {(body or {}).get('message', raw)}")

            for obj in body.get("objects", []):
                name = obj.get("name")
                if not name:
                    continue
                if MANAGED_MARKER in (obj.get("comments") or ""):
                    managed.add(name)
                else:
                    unmanaged.add(name)

            total = body.get("total", 0)
            offset = body.get("to", offset + limit)
            if offset >= total:
                break

        return managed, unmanaged

    def add_user(self, name, radius_server, expiration=None):
        payload = {
            "name": name,
            "authentication-method": "radius",
            "radius-server": radius_server,
            "comments": f"{MANAGED_MARKER} synced "
                        f"{time.strftime('%Y-%m-%d %H:%M')}",
        }
        if expiration:
            payload["expiration-date"] = expiration

        status, body, raw = self.call("add-user", payload)
        if status == 200:
            return "created"

        msg = str((body or {}).get("message", raw)).lower()
        if "already exists" in msg or "more than one" in msg:
            return "exists"
        self.log(f"add-user {name}: {(body or {}).get('message', raw)}", "error")
        return "failed"

    def delete_user(self, name):
        status, body, raw = self.call("delete-user", {"name": name})
        if status == 200:
            return "deleted"
        self.log(f"delete-user {name}: {(body or {}).get('message', raw)}",
                 "error")
        return "failed"

    # ---------------- session commands ----------------
    def publish(self):
        return self.run_async("publish", {}, "Publish")

    def verify_policy(self, package):
        return self.run_async("verify-policy", {"policy-package": package},
                              f"Verify '{package}'")

    def install_policy(self, package, targets=None, access=True,
                       threat_prevention=False, all_members_or_fail=True):
        payload = {
            "policy-package": package,
            "access": access,
            "threat-prevention": threat_prevention,
            "install-on-all-cluster-members-or-fail": all_members_or_fail,
        }
        if targets:
            payload["targets"] = targets
        where = ", ".join(targets) if targets else "the package's own targets"
        return self.run_async("install-policy", payload,
                              f"Install '{package}' on {where}")


# --------------------------------------------------------------------------
def plan_changes(ldap_uids, managed, unmanaged, allow_delete=True):
    """
    Work out what needs to happen. Pure function, so it is easy to test and
    easy to show the operator before anything is written.
    """
    return {
        "add": sorted(set(ldap_uids) - managed - unmanaged),
        "delete": sorted(managed - set(ldap_uids)) if allow_delete else [],
        "collisions": sorted(set(ldap_uids) & unmanaged),
        "in_sync": sorted(set(ldap_uids) & managed),
    }
