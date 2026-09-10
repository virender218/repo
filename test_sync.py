"""
Tests the Check Point sync path against a fake web_api, so the diff logic,
the managed-marker safety rule, publish/verify/install ordering and the
background job plumbing are all exercised without a real SMS.

    python3 test_sync.py
"""
import os
import sys
import time

os.environ["FLASK_SECRET_KEY"] = "test-only"
os.environ["LDAPUI_SYNC_CONFIG"] = "/tmp/ldapui-sync-test.json"

import checkpoint
from checkpoint import CheckPointAPI, plan_changes, MANAGED_MARKER

failures = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" +
          (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(label)


# ---------------------------------------------------------------- fake SMS
class FakeSMS:
    """Stands in for a Security Management Server."""

    def __init__(self, existing=None):
        # name -> comments
        self.users = dict(existing or {})
        self.published = False
        self.verified = False
        self.installed = None
        self.calls = []
        self.pending = []
        self.fail_publish = False
        self.fail_install = False

    def post(self, url, json=None, headers=None, **kw):
        cmd = url.rsplit("/", 1)[-1]
        payload = json or {}
        self.calls.append(cmd)
        return FakeResp(*self._handle(cmd, payload))

    def _handle(self, cmd, p):
        if cmd == "login":
            if p.get("password") != "correct":
                return 400, {"code": "err_login_failed",
                             "message": "Authentication to server failed."}
            return 200, {"sid": "fake-sid", "api-server-version": "1.9"}
        if cmd == "logout":
            return 200, {"message": "OK"}
        if cmd == "show-users":
            objs = [{"name": n, "comments": c} for n, c in
                    sorted(self.users.items())]
            return 200, {"objects": objs, "total": len(objs), "to": len(objs)}
        if cmd == "add-user":
            if p["name"] in self.users:
                return 400, {"code": "err", "message": "Object already exists"}
            if not p.get("radius-server"):
                return 400, {"code": "err", "message": "radius-server missing"}
            self.pending.append(("add", p["name"], p.get("comments", "")))
            return 200, {"uid": "u", "name": p["name"]}
        if cmd == "delete-user":
            if p["name"] not in self.users:
                return 400, {"code": "err", "message": "not found"}
            self.pending.append(("del", p["name"], ""))
            return 200, {"message": "OK"}
        if cmd == "publish":
            if self.fail_publish:
                return 400, {"message": "Publish rejected"}
            for op, name, comments in self.pending:
                if op == "add":
                    self.users[name] = comments
                else:
                    self.users.pop(name, None)
            self.pending = []
            self.published = True
            return 200, {"task-id": "task-publish"}
        if cmd == "verify-policy":
            self.verified = True
            return 200, {"task-id": "task-verify"}
        if cmd == "install-policy":
            if self.fail_install:
                return 200, {"task-id": "task-install-fail"}
            self.installed = (p.get("policy-package"), tuple(p.get("targets", [])))
            return 200, {"task-id": "task-install"}
        if cmd == "show-task":
            tid = p["task-id"]
            if tid == "task-install-fail":
                return 200, {"tasks": [{"status": "failed",
                                        "progress-percentage": 100,
                                        "task-details": [{"stagesInfo": [
                                            {"stage": "Verification",
                                             "messages": [{"message":
                                                           "Rule 3 is broken"}]}
                                        ]}]}]}
            return 200, {"tasks": [{"status": "succeeded",
                                    "progress-percentage": 100}]}
        return 404, {"message": f"unknown command {cmd}"}


class FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


checkpoint.TASK_POLL_INTERVAL = 0


def api_for(sms, log=None):
    api = CheckPointAPI("10.0.0.1", log=log)
    api.session = sms
    return api


M = f"{MANAGED_MARKER} synced 2026-01-01"

# ---------------------------------------------------------------- planning
print("\nPlanning")
plan = plan_changes({"a", "b", "c"}, managed={"a", "z"}, unmanaged={"b"})
check("adds only what is missing", plan["add"] == ["c"], str(plan["add"]))
check("deletes only managed strays", plan["delete"] == ["z"], str(plan["delete"]))
check("flags hand-made collisions", plan["collisions"] == ["b"], str(plan))
check("reports already in sync", plan["in_sync"] == ["a"], str(plan))

plan = plan_changes({"a"}, managed={"z"}, unmanaged=set(), allow_delete=False)
check("delete can be disabled", plan["delete"] == [], str(plan))

# ---------------------------------------------------------------- API layer
print("\nManagement API")
sms = FakeSMS()
api = api_for(sms)
try:
    api.login("admin", "wrong")
    check("bad password rejected", False, "no exception raised")
except checkpoint.CheckPointError as exc:
    check("bad password rejected", "Authentication" in str(exc), str(exc))

api = api_for(sms)
api.login("admin", "correct")
check("good password accepted", api.sid == "fake-sid")

sms.users = {"alis": M, "manual_admin": "made in SmartConsole"}
managed, unmanaged = api.show_users()
check("managed users identified by marker", managed == {"alis"}, str(managed))
check("hand-made users identified", unmanaged == {"manual_admin"},
      str(unmanaged))

check("add-user stamps the marker",
      api.add_user("bkumar", "Radius_Test") == "created")
check("duplicate add reported as existing",
      api.add_user("alis", "Radius_Test") == "exists")
api.publish()
check("marker present on new object", MANAGED_MARKER in sms.users["bkumar"],
      sms.users.get("bkumar"))

# ---------------------------------------------------------------- full sync
print("\nEnd-to-end sync")
os.environ["LDAPUI_SYNC_CONFIG"] = "/tmp/ldapui-sync-test.json"
import app as ldapui

settings = {
    "mgmt_host": "10.0.0.1", "mgmt_user": "admin", "domain": "",
    "radius_server": "Radius_Test", "expiration": "never",
    "policy_package": "Standard", "targets": "Dwarpal",
    "verify_first": True, "install_policy": True,
    "allow_delete": True, "verify_ssl": False,
}

sms = FakeSMS({"alis": M, "gone": M, "manual_admin": "hand made"})
_orig_api = ldapui.CheckPointAPI


def patched(host, verify=False, timeout=60, log=None):
    return api_for(sms, log=log)


ldapui.CheckPointAPI = patched

job = ldapui._new_job("apply")
ldapui._run_sync(job, settings, "correct", ["alis", "bkumar"], True)
result = ldapui._jobs[job]

check("job completed", result["state"] == "done", result["summary"])
check("new user created", "bkumar" in sms.users, str(sms.users))
check("stale managed user deleted", "gone" not in sms.users, str(sms.users))
check("hand-made user survived", "manual_admin" in sms.users, str(sms.users))
check("session was published", sms.published)
check("policy verified before install", sms.verified)
check("policy installed on the right target",
      sms.installed == ("Standard", ("Dwarpal",)), str(sms.installed))
check("verify ran before install",
      sms.calls.index("verify-policy") < sms.calls.index("install-policy"))
check("publish ran before install",
      sms.calls.index("publish") < sms.calls.index("install-policy"))

print("\nPreview mode")
sms2 = FakeSMS({"alis": M})
ldapui.CheckPointAPI = lambda *a, **kw: api_for(sms2, log=kw.get("log"))
job = ldapui._new_job("preview")
ldapui._run_sync(job, settings, "correct", ["alis", "newguy"], False)
result = ldapui._jobs[job]
check("preview writes nothing", "newguy" not in sms2.users, str(sms2.users))
check("preview does not publish", not sms2.published)
check("preview still reports the plan", result["plan"]["add"] == ["newguy"],
      str(result["plan"]))

print("\nSafety")
sms3 = FakeSMS({"alis": M, "bkumar": M})
ldapui.CheckPointAPI = lambda *a, **kw: api_for(sms3, log=kw.get("log"))
job = ldapui._new_job("apply")
ldapui._run_sync(job, settings, "correct", [], True)
result = ldapui._jobs[job]
check("empty directory does not wipe the server",
      sms3.users == {"alis": M, "bkumar": M}, str(sms3.users))
check("empty directory is reported as an error",
      result["state"] == "error" and "no users" in result["summary"].lower(),
      result["summary"])

sms4 = FakeSMS({"alis": M})
sms4.fail_publish = True
ldapui.CheckPointAPI = lambda *a, **kw: api_for(sms4, log=kw.get("log"))
job = ldapui._new_job("apply")
ldapui._run_sync(job, settings, "correct", ["alis", "newguy"], True)
result = ldapui._jobs[job]
check("failed publish stops before policy install", sms4.installed is None)
check("failed publish is reported",
      result["state"] == "error" and "publish" in result["summary"].lower(),
      result["summary"])

sms5 = FakeSMS({"alis": M})
sms5.fail_install = True
ldapui.CheckPointAPI = lambda *a, **kw: api_for(sms5, log=kw.get("log"))
job = ldapui._new_job("apply")
ldapui._run_sync(job, settings, "correct", ["alis", "newguy"], True)
result = ldapui._jobs[job]
check("users still published when install fails", "newguy" in sms5.users)
check("install failure surfaces the stage message",
      any("Rule 3 is broken" in l["msg"] for l in result["log"]),
      str(result["log"][-3:]))

print("\nSettings persistence")
ldapui.CheckPointAPI = _orig_api


class FakeForm(dict):
    def get(self, k, d=""):
        return dict.get(self, k, d)


saved = ldapui.save_sync_settings(FakeForm({
    "mgmt_host": "20.44.59.96", "mgmt_user": "admin",
    "radius_server": "Radius_Test", "policy_package": "Standard",
    "targets": "Dwarpal, GW2", "password": "supersecret",
    "install_policy": "on", "verify_first": "on", "allow_delete": "on",
}))
on_disk = open(ldapui.SYNC_CONFIG).read()
check("settings written to disk", "20.44.59.96" in on_disk)
check("password never written to disk", "supersecret" not in on_disk, on_disk)
check("targets parsed into a list",
      ldapui.target_list(saved) == ["Dwarpal", "GW2"],
      str(ldapui.target_list(saved)))

reloaded = ldapui.load_sync_settings()
check("settings reload intact", reloaded["policy_package"] == "Standard",
      str(reloaded))

os.remove(ldapui.SYNC_CONFIG)

print()
if failures:
    print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("All checks passed.")
