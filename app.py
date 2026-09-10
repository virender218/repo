#!/usr/bin/env python3
"""
LDAP Directory Console
======================
A small web UI for managing users and groups in the local OpenLDAP server.

Runs on the same host as slapd and talks to it over ldapi:/// or
ldap://127.0.0.1, so directory traffic never leaves the machine.

There is no separate account database. You log in with an LDAP DN and
password, and the app binds as you for every operation -- so slapd's own
ACLs decide what you are allowed to do. If your bind account is read-only,
the write buttons will fail with a permissions error, which is correct.

    export FLASK_SECRET_KEY="$(openssl rand -hex 32)"
    python3 app.py

Requires: pip install flask ldap3
"""

import csv
import io
import json
import os
import re
import secrets
import threading
import time
import uuid
from functools import wraps

from flask import (Flask, Response, flash, g, jsonify, redirect,
                   render_template, request, session, url_for)

import checkpoint
from checkpoint import CheckPointAPI, CheckPointError, plan_changes

from ldap3 import Server, Connection, SUBTREE, BASE, ALL, MODIFY_REPLACE, \
    MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.utils.conv import escape_filter_chars


# ========================== CONFIG =========================================
LDAP_URI = os.environ.get("LDAP_URI", "ldap://127.0.0.1:389")
BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=cplab,dc=local")
PEOPLE_OU = os.environ.get("LDAP_PEOPLE_OU", f"ou=people,{BASE_DN}")
GROUPS_OU = os.environ.get("LDAP_GROUPS_OU", f"ou=groups,{BASE_DN}")

USER_CLASSES = ["top", "person", "organizationalPerson", "inetOrgPerson",
                "posixAccount", "shadowAccount"]
USER_ATTRS = ["uid", "cn", "sn", "givenName", "mail", "uidNumber",
              "gidNumber", "homeDirectory", "loginShell", "description"]
GROUP_ATTRS = ["cn", "gidNumber", "description", "memberUid", "member",
               "uniqueMember", "objectClass"]

UID_MIN = 10000          # first uidNumber handed out
GID_MIN = 10000          # first gidNumber handed out
DEFAULT_SHELL = "/bin/bash"
HOME_ROOT = "/home"

SESSION_IDLE_SECONDS = 1800
LISTEN_HOST = os.environ.get("LDAPUI_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LDAPUI_PORT", "8080"))

# Where the Check Point connection settings are kept. The password is
# deliberately NOT among them -- see save_sync_settings().
SYNC_CONFIG = os.environ.get("LDAPUI_SYNC_CONFIG", "/var/lib/ldapui/sync.json")

SYNC_DEFAULTS = {
    "mgmt_host": "",
    "mgmt_user": "admin",
    "domain": "",
    "radius_server": "",
    "expiration": "never",
    "policy_package": "",
    "targets": "",
    "verify_first": True,
    "install_policy": True,
    "allow_delete": True,
    "verify_ssl": False,
}

# Object names we are willing to put into a DN. Deliberately strict.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# ===========================================================================


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("LDAPUI_HTTPS")),
)

# Credentials are held server-side, keyed by an opaque token in the cookie,
# so the bind password never travels to the browser.
# NOTE: this is in-process state. Run with a single worker.
_creds = {}
_creds_lock = threading.Lock()


# --------------------------------------------------------------------------
# Session plumbing
# --------------------------------------------------------------------------
def _store_creds(bind_dn, password):
    token = secrets.token_urlsafe(32)
    with _creds_lock:
        _creds[token] = {"dn": bind_dn, "pw": password, "seen": time.time()}
    return token


def _get_creds(token):
    with _creds_lock:
        entry = _creds.get(token)
        if not entry:
            return None
        if time.time() - entry["seen"] > SESSION_IDLE_SECONDS:
            _creds.pop(token, None)
            return None
        entry["seen"] = time.time()
        return dict(entry)


def _drop_creds(token):
    with _creds_lock:
        _creds.pop(token, None)


def ldap_conn():
    """Bind as the logged-in operator. One connection per request."""
    if "conn" in g:
        return g.conn
    creds = _get_creds(session.get("tok", ""))
    if not creds:
        raise LDAPBindError("session expired")
    server = Server(LDAP_URI, get_info=ALL, connect_timeout=5)
    g.conn = Connection(server, user=creds["dn"], password=creds["pw"],
                        auto_bind=True, raise_exceptions=True)
    return g.conn


@app.teardown_appcontext
def _close_conn(_exc):
    conn = g.pop("conn", None)
    if conn is not None:
        try:
            conn.unbind()
        except Exception:
            pass


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not _get_creds(session.get("tok", "")):
            session.clear()
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def _check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            flash("Your session expired. Sign in again and retry.", "error")
            return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def safe(name):
    """Validate anything destined for a DN. Blocks DN/filter injection."""
    name = (name or "").strip()
    if not SAFE_NAME.match(name):
        raise ValueError(
            f"'{name}' is not a usable name. Use letters, digits, dot, "
            f"underscore or hyphen, starting with a letter or digit.")
    return name


def user_dn(uid):
    return f"uid={safe(uid)},{PEOPLE_OU}"


def group_dn(cn):
    return f"cn={safe(cn)},{GROUPS_OU}"


def one(value, default=""):
    """ldap3 returns lists for most attributes; take the first."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value if value not in (None, "") else default


def search(base, flt, attrs, scope=SUBTREE):
    conn = ldap_conn()
    conn.search(base, flt, search_scope=scope, attributes=attrs)
    return [dict(e.entry_attributes_as_dict, dn=e.entry_dn) for e in conn.entries]


def next_number(base, attr, floor):
    """Smallest free value at or above the floor."""
    try:
        rows = search(base, f"({attr}=*)", [attr])
    except LDAPException:
        return floor
    used = set()
    for r in rows:
        try:
            used.add(int(one(r.get(attr), 0)))
        except (TypeError, ValueError):
            continue
    n = floor
    while n in used:
        n += 1
    return n


def group_member_attr(entry):
    """
    Groups come in two flavours. posixGroup lists bare usernames in
    memberUid; groupOfNames lists full DNs in member. Detect which.
    """
    classes = [c.lower() for c in entry.get("objectClass", [])]
    if "posixgroup" in classes:
        return "memberUid", False
    if "groupofuniquenames" in classes:
        return "uniqueMember", True
    return "member", True


def group_members(entry):
    """Return member usernames regardless of group flavour."""
    attr, is_dn = group_member_attr(entry)
    values = entry.get(attr) or []
    if not is_dn:
        return sorted(str(v) for v in values)
    out = []
    for dn in values:
        m = re.match(r"^uid=([^,]+),", str(dn), re.IGNORECASE)
        out.append(m.group(1) if m else str(dn))
    return sorted(out)


def load_groups():
    rows = search(GROUPS_OU, "(|(objectClass=posixGroup)(objectClass=groupOfNames)"
                             "(objectClass=groupOfUniqueNames))", GROUP_ATTRS)
    groups = []
    for r in rows:
        groups.append({
            "cn": one(r.get("cn")),
            "dn": r["dn"],
            "gidNumber": one(r.get("gidNumber")),
            "description": one(r.get("description")),
            "members": group_members(r),
            "kind": "posixGroup" if "memberUid" == group_member_attr(r)[0]
                    else "groupOfNames",
        })
    return sorted(groups, key=lambda x: x["cn"].lower())


def load_users():
    rows = search(PEOPLE_OU, "(objectClass=inetOrgPerson)", USER_ATTRS)
    users = []
    for r in rows:
        users.append({a: one(r.get(a)) for a in USER_ATTRS} | {"dn": r["dn"]})
    return sorted(users, key=lambda x: x["uid"].lower())


def groups_for(uid, groups):
    return [gr["cn"] for gr in groups if uid in gr["members"]]


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        bind_dn = request.form.get("bind_dn", "").strip()
        password = request.form.get("password", "")
        if not bind_dn or not password:
            flash("Enter both a bind DN and a password.", "error")
            return render_template("login.html", base_dn=BASE_DN,
                                   server=LDAP_URI, bind_dn=bind_dn)
        try:
            server = Server(LDAP_URI, get_info=ALL, connect_timeout=5)
            conn = Connection(server, user=bind_dn, password=password,
                              auto_bind=True, raise_exceptions=True)
            conn.unbind()
        except LDAPException as exc:
            flash(f"Bind failed: {exc}", "error")
            return render_template("login.html", base_dn=BASE_DN,
                                   server=LDAP_URI, bind_dn=bind_dn)

        session.clear()
        session["tok"] = _store_creds(bind_dn, password)
        session["dn"] = bind_dn
        csrf_token()
        return redirect(request.args.get("next") or url_for("users"))

    return render_template("login.html", base_dn=BASE_DN, server=LDAP_URI,
                           bind_dn="")


@app.route("/logout", methods=["POST"])
def logout():
    _drop_creds(session.get("tok", ""))
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
@app.route("/users")
@login_required
def users():
    selected = request.args.get("uid", "")
    try:
        all_groups = load_groups()
        all_users = load_users()
    except LDAPException as exc:
        flash(str(exc), "error")
        all_groups, all_users = [], []

    current = next((u for u in all_users if u["uid"] == selected), None)
    for u in all_users:
        u["groups"] = groups_for(u["uid"], all_groups)

    return render_template(
        "users.html",
        users=all_users,
        groups=all_groups,
        current=current,
        current_groups=groups_for(selected, all_groups) if current else [],
        suggested_uid_number=next_number(PEOPLE_OU, "uidNumber", UID_MIN),
        default_shell=DEFAULT_SHELL,
        home_root=HOME_ROOT,
        people_ou=PEOPLE_OU,
        bound_as=session.get("dn", ""),
    )


# --------------------------------------------------------------------------
# Check Point sync: settings, jobs
# --------------------------------------------------------------------------
def load_sync_settings():
    settings = dict(SYNC_DEFAULTS)
    try:
        with open(SYNC_CONFIG, "r", encoding="utf-8") as f:
            saved = json.load(f)
        settings.update({k: v for k, v in saved.items() if k in SYNC_DEFAULTS})
    except (OSError, ValueError):
        pass
    return settings


def save_sync_settings(form):
    """
    Persist connection settings. The management password is never written --
    it lives in server-side session memory for as long as you are signed in
    and is discarded at sign-out.
    """
    settings = {
        "mgmt_host": form.get("mgmt_host", "").strip(),
        "mgmt_user": form.get("mgmt_user", "").strip() or "admin",
        "domain": form.get("domain", "").strip(),
        "radius_server": form.get("radius_server", "").strip(),
        "expiration": form.get("expiration", "").strip(),
        "policy_package": form.get("policy_package", "").strip(),
        "targets": form.get("targets", "").strip(),
        "verify_first": form.get("verify_first") == "on",
        "install_policy": form.get("install_policy") == "on",
        "allow_delete": form.get("allow_delete") == "on",
        "verify_ssl": form.get("verify_ssl") == "on",
    }
    os.makedirs(os.path.dirname(SYNC_CONFIG), exist_ok=True)
    tmp = f"{SYNC_CONFIG}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    os.replace(tmp, SYNC_CONFIG)
    return settings


def target_list(settings):
    return [t.strip() for t in settings.get("targets", "").split(",") if t.strip()]


def _set_cp_password(password):
    with _creds_lock:
        entry = _creds.get(session.get("tok", ""))
        if entry is not None:
            entry["cp_pw"] = password


def _get_cp_password():
    creds = _get_creds(session.get("tok", ""))
    return (creds or {}).get("cp_pw", "")


# Background jobs. Policy installation takes minutes; running it inside the
# request would hit the gunicorn timeout and leave a session open on the
# management server. So the work happens on a thread and the page polls.
_jobs = {}
_jobs_lock = threading.Lock()
JOB_RETENTION = 3600


def _new_job(kind):
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        # drop anything old enough that nobody is watching it
        cutoff = time.time() - JOB_RETENTION
        for jid in [j for j, v in _jobs.items() if v["started"] < cutoff]:
            _jobs.pop(jid, None)
        _jobs[job_id] = {"kind": kind, "state": "running", "log": [],
                         "plan": None, "started": time.time(),
                         "summary": ""}
    return job_id


def _job_log(job_id, message, level="info"):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job["log"].append({"t": time.strftime("%H:%M:%S"),
                               "level": level, "msg": message})


def _job_finish(job_id, state, summary="", plan=None):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job["state"] = state
            job["summary"] = summary
            if plan is not None:
                job["plan"] = plan


def _run_sync(job_id, settings, password, ldap_uids, apply_changes):
    """Runs on a worker thread. Takes plain data -- no request context."""
    log = lambda m, lvl="info": _job_log(job_id, m, lvl)
    api = CheckPointAPI(settings["mgmt_host"],
                        verify=settings.get("verify_ssl", False), log=log)
    try:
        if not ldap_uids:
            raise CheckPointError(
                "The directory returned no users. Refusing to continue, "
                "because acting on an empty list would delete every synced "
                "user on the management server.")

        api.login(settings["mgmt_user"], password,
                  settings.get("domain") or None)

        log("Reading existing users from the management server...")
        managed, unmanaged = api.show_users()
        log(f"Found {len(managed)} previously synced and "
            f"{len(unmanaged)} manually created users.")

        plan = plan_changes(ldap_uids, managed, unmanaged,
                            settings.get("allow_delete", True))

        if plan["collisions"]:
            log(f"{len(plan['collisions'])} directory user(s) already exist as "
                f"manually created objects and will be left alone: "
                f"{', '.join(plan['collisions'][:10])}", "warn")

        log(f"Plan: {len(plan['add'])} to add, {len(plan['delete'])} to delete, "
            f"{len(plan['in_sync'])} already in sync.")

        if not apply_changes:
            _job_finish(job_id, "done", "Preview only. Nothing was changed.",
                        plan)
            return

        if not plan["add"] and not plan["delete"]:
            _job_finish(job_id, "done", "Already in sync. Nothing to do.", plan)
            return

        counts = {"created": 0, "exists": 0, "deleted": 0, "failed": 0}
        for name in plan["add"]:
            counts[api.add_user(name, settings["radius_server"],
                                settings.get("expiration") or None)] += 1
        for name in plan["delete"]:
            counts[api.delete_user(name)] += 1

        log(f"{counts['created']} created, {counts['exists']} already present, "
            f"{counts['deleted']} deleted, {counts['failed']} failed.")

        if not api.publish():
            raise CheckPointError(
                "Publish failed, so nothing was saved. The session was "
                "discarded.")

        summary = (f"{counts['created']} user(s) created, "
                   f"{counts['deleted']} deleted, and published.")

        if settings.get("install_policy") and settings.get("policy_package"):
            if settings.get("verify_first"):
                if not api.verify_policy(settings["policy_package"]):
                    _job_finish(job_id, "error",
                                summary + " Policy verification failed, so "
                                          "the policy was not installed.", plan)
                    return
            if api.install_policy(settings["policy_package"],
                                  target_list(settings)):
                summary += " Policy installed."
            else:
                _job_finish(job_id, "error",
                            summary + " Policy installation failed.", plan)
                return
        elif settings.get("install_policy"):
            log("No policy package configured, so nothing was installed.",
                "warn")

        _job_finish(job_id, "done", summary, plan)

    except (CheckPointError, Exception) as exc:
        _job_log(job_id, str(exc), "error")
        try:
            api.discard()
        except Exception:
            pass
        _job_finish(job_id, "error", str(exc))
    finally:
        try:
            api.logout()
        except Exception:
            pass


@app.route("/sync")
@login_required
def sync():
    settings = load_sync_settings()
    job_id = request.args.get("job", "")
    with _jobs_lock:
        job = dict(_jobs[job_id]) if job_id in _jobs else None
    try:
        user_count = len(load_users())
    except LDAPException:
        user_count = 0
    return render_template("sync.html", settings=settings, job=job,
                           job_id=job_id, user_count=user_count,
                           have_password=bool(_get_cp_password()),
                           bound_as=session.get("dn", ""))


@app.route("/sync/settings", methods=["POST"])
@login_required
def sync_settings():
    try:
        save_sync_settings(request.form)
        flash("Connection settings saved.", "ok")
    except OSError as exc:
        flash(f"Could not save settings: {exc}", "error")
    if request.form.get("password"):
        _set_cp_password(request.form["password"])
    return redirect(url_for("sync"))


@app.route("/sync/run", methods=["POST"])
@login_required
def sync_run():
    apply_changes = request.form.get("mode") == "apply"

    try:
        settings = save_sync_settings(request.form)
    except OSError:
        settings = load_sync_settings()

    password = request.form.get("password") or _get_cp_password()
    if request.form.get("password"):
        _set_cp_password(request.form["password"])

    if not settings["mgmt_host"]:
        flash("Enter the management server address first.", "error")
        return redirect(url_for("sync"))
    if not password:
        flash("Enter the management password.", "error")
        return redirect(url_for("sync"))
    if apply_changes and not settings["radius_server"]:
        flash("Set the RADIUS server object name before syncing. It must "
              "match the name in SmartConsole exactly.", "error")
        return redirect(url_for("sync"))

    try:
        ldap_uids = sorted(u["uid"] for u in load_users())
    except LDAPException as exc:
        flash(f"Could not read the directory: {exc}", "error")
        return redirect(url_for("sync"))

    job_id = _new_job("apply" if apply_changes else "preview")
    _job_log(job_id, f"{len(ldap_uids)} user(s) in the directory.")
    threading.Thread(
        target=_run_sync,
        args=(job_id, settings, password, ldap_uids, apply_changes),
        daemon=True,
    ).start()

    return redirect(url_for("sync", job=job_id))


@app.route("/sync/status/<job_id>")
@login_required
def sync_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
        payload = dict(job) if job else None
    if payload is None:
        return jsonify({"state": "missing"}), 404
    return jsonify(payload)


@app.route("/users/export")
@login_required
def export_users():
    """
    Download the current user list.

    csv   -- full attributes plus group membership, for reporting
    uid   -- one username per line, the input format the Check Point sync
             and older scripts expect
    ldif  -- complete entries, restorable with ldapadd
    """
    fmt = request.args.get("format", "csv")
    stamp = time.strftime("%Y%m%d-%H%M")

    try:
        all_users = load_users()
        all_groups = load_groups()
    except LDAPException as exc:
        flash(f"Could not read the directory: {exc}", "error")
        return redirect(url_for("users"))

    if fmt == "uid":
        body = "".join(f"{u['uid']}\n" for u in all_users)
        return _download(body, f"users-{stamp}.txt", "text/plain")

    if fmt == "ldif":
        lines = []
        for u in all_users:
            lines.append(f"dn: {u['dn']}")
            for oc in USER_CLASSES:
                lines.append(f"objectClass: {oc}")
            for attr in USER_ATTRS:
                if u.get(attr):
                    lines.append(f"{attr}: {u[attr]}")
            lines.append("")
        for gr in all_groups:
            lines.append(f"dn: {gr['dn']}")
            if gr["kind"] == "posixGroup":
                lines.append("objectClass: top")
                lines.append("objectClass: posixGroup")
                lines.append(f"cn: {gr['cn']}")
                if gr["gidNumber"]:
                    lines.append(f"gidNumber: {gr['gidNumber']}")
                for m in gr["members"]:
                    lines.append(f"memberUid: {m}")
            else:
                lines.append("objectClass: top")
                lines.append("objectClass: groupOfNames")
                lines.append(f"cn: {gr['cn']}")
                for m in gr["members"]:
                    lines.append(f"member: uid={m},{PEOPLE_OU}")
            if gr["description"]:
                lines.append(f"description: {gr['description']}")
            lines.append("")
        header = (f"# Exported {time.strftime('%Y-%m-%d %H:%M:%S')} from "
                  f"{LDAP_URI}\n# Passwords are not included.\n\n")
        return _download(header + "\n".join(lines),
                         f"directory-{stamp}.ldif", "text/plain")

    # default: csv
    buf = io.StringIO()
    cols = ["uid", "cn", "sn", "givenName", "mail", "uidNumber", "gidNumber",
            "homeDirectory", "loginShell", "groups", "dn"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for u in all_users:
        row = {c: u.get(c, "") for c in cols}
        row["groups"] = ";".join(groups_for(u["uid"], all_groups))
        w.writerow(row)
    return _download(buf.getvalue(), f"users-{stamp}.csv", "text/csv")


def _download(body, filename, mimetype):
    return Response(
        body,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/users/create", methods=["POST"])
@login_required
def create_user():
    f = request.form
    try:
        uid = safe(f.get("uid"))
        dn = user_dn(uid)
        given = f.get("givenName", "").strip()
        sn = f.get("sn", "").strip() or uid
        cn = f.get("cn", "").strip() or f"{given} {sn}".strip() or uid

        attrs = {
            "uid": uid,
            "cn": cn,
            "sn": sn,
            "uidNumber": str(f.get("uidNumber") or
                             next_number(PEOPLE_OU, "uidNumber", UID_MIN)),
            "gidNumber": str(f.get("gidNumber") or GID_MIN),
            "homeDirectory": f.get("homeDirectory", "").strip()
                             or f"{HOME_ROOT}/{uid}",
            "loginShell": f.get("loginShell", "").strip() or DEFAULT_SHELL,
        }
        if given:
            attrs["givenName"] = given
        if f.get("mail", "").strip():
            attrs["mail"] = f["mail"].strip()

        conn = ldap_conn()
        conn.add(dn, USER_CLASSES, attrs)

        password = f.get("password", "")
        if password:
            conn.extend.standard.modify_password(dn, new_password=password)

        joined = [g_ for g_ in f.getlist("groups") if g_]
        for cn_ in joined:
            _membership_change(cn_, uid, "add")

        msg = f"Created {uid}."
        if joined:
            msg += f" Added to {', '.join(joined)}."
        flash(msg, "ok")
        return redirect(url_for("users", uid=uid))

    except (LDAPException, ValueError) as exc:
        flash(f"Could not create the user: {exc}", "error")
        return redirect(url_for("users"))


@app.route("/users/<uid>/update", methods=["POST"])
@login_required
def update_user(uid):
    f = request.form
    try:
        dn = user_dn(uid)
        changes = {}
        for attr, form_key in (("cn", "cn"), ("sn", "sn"),
                               ("givenName", "givenName"), ("mail", "mail"),
                               ("loginShell", "loginShell"),
                               ("homeDirectory", "homeDirectory"),
                               ("gidNumber", "gidNumber")):
            value = f.get(form_key, "").strip()
            if value:
                changes[attr] = [(MODIFY_REPLACE, [value])]
            else:
                changes[attr] = [(MODIFY_REPLACE, [])]

        # cn and sn are mandatory on inetOrgPerson; never clear them.
        for required in ("cn", "sn"):
            if not f.get(required, "").strip():
                changes.pop(required, None)

        conn = ldap_conn()
        conn.modify(dn, changes)

        if f.get("password"):
            conn.extend.standard.modify_password(dn, new_password=f["password"])
            flash(f"Updated {uid} and set a new password.", "ok")
        else:
            flash(f"Updated {uid}.", "ok")

    except (LDAPException, ValueError) as exc:
        flash(f"Could not update {uid}: {exc}", "error")

    return redirect(url_for("users", uid=uid))


@app.route("/users/<uid>/delete", methods=["POST"])
@login_required
def delete_user(uid):
    try:
        uid = safe(uid)
        # Strip the user out of every group first, or posixGroup entries
        # are left holding a memberUid that points at nothing.
        for gr in load_groups():
            if uid in gr["members"]:
                _membership_change(gr["cn"], uid, "remove")
        ldap_conn().delete(user_dn(uid))
        flash(f"Deleted {uid} and removed it from all groups.", "ok")
    except (LDAPException, ValueError) as exc:
        flash(f"Could not delete {uid}: {exc}", "error")
    return redirect(url_for("users"))


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------
@app.route("/groups")
@login_required
def groups():
    selected = request.args.get("cn", "")
    try:
        all_groups = load_groups()
        all_users = load_users()
    except LDAPException as exc:
        flash(str(exc), "error")
        all_groups, all_users = [], []

    current = next((gr for gr in all_groups if gr["cn"] == selected), None)
    return render_template(
        "groups.html",
        groups=all_groups,
        users=all_users,
        current=current,
        suggested_gid_number=next_number(GROUPS_OU, "gidNumber", GID_MIN),
        groups_ou=GROUPS_OU,
        bound_as=session.get("dn", ""),
    )


@app.route("/groups/create", methods=["POST"])
@login_required
def create_group():
    f = request.form
    try:
        cn = safe(f.get("cn"))
        dn = group_dn(cn)
        kind = f.get("kind", "posixGroup")
        members = [m for m in f.getlist("members") if m]
        conn = ldap_conn()

        if kind == "groupOfNames":
            # groupOfNames is invalid with no members, so require one.
            if not members:
                raise ValueError(
                    "A groupOfNames must have at least one member. Pick a "
                    "member, or create a posixGroup instead -- those can "
                    "start empty.")
            conn.add(dn, ["top", "groupOfNames"],
                     {"cn": cn,
                      "member": [user_dn(m) for m in members],
                      **({"description": f["description"].strip()}
                         if f.get("description", "").strip() else {})})
        else:
            attrs = {
                "cn": cn,
                "gidNumber": str(f.get("gidNumber") or
                                 next_number(GROUPS_OU, "gidNumber", GID_MIN)),
            }
            if f.get("description", "").strip():
                attrs["description"] = f["description"].strip()
            if members:
                attrs["memberUid"] = members
            conn.add(dn, ["top", "posixGroup"], attrs)

        flash(f"Created group {cn}.", "ok")
        return redirect(url_for("groups", cn=cn))

    except (LDAPException, ValueError) as exc:
        flash(f"Could not create the group: {exc}", "error")
        return redirect(url_for("groups"))


@app.route("/groups/<cn>/update", methods=["POST"])
@login_required
def update_group(cn):
    try:
        cn = safe(cn)
        description = request.form.get("description", "").strip()
        ldap_conn().modify(
            group_dn(cn),
            {"description": [(MODIFY_REPLACE, [description] if description
                              else [])]})
        flash(f"Updated {cn}.", "ok")
    except (LDAPException, ValueError) as exc:
        flash(f"Could not update {cn}: {exc}", "error")
    return redirect(url_for("groups", cn=cn))


@app.route("/groups/<cn>/delete", methods=["POST"])
@login_required
def delete_group(cn):
    try:
        cn = safe(cn)
        ldap_conn().delete(group_dn(cn))
        flash(f"Deleted group {cn}. Its members were not touched.", "ok")
    except (LDAPException, ValueError) as exc:
        flash(f"Could not delete {cn}: {exc}", "error")
    return redirect(url_for("groups"))


# --------------------------------------------------------------------------
# Membership
# --------------------------------------------------------------------------
def _membership_change(cn, uid, action):
    """Add or remove one user from one group, whatever the group flavour."""
    cn, uid = safe(cn), safe(uid)
    conn = ldap_conn()
    conn.search(group_dn(cn), "(objectClass=*)", search_scope=BASE,
                attributes=GROUP_ATTRS)
    if not conn.entries:
        raise ValueError(f"Group {cn} not found.")

    entry = dict(conn.entries[0].entry_attributes_as_dict)
    attr, is_dn = group_member_attr(entry)
    value = user_dn(uid) if is_dn else uid
    existing = [str(v) for v in (entry.get(attr) or [])]

    if action == "add":
        if value in existing:
            return
        op = MODIFY_ADD
    else:
        if value not in existing:
            return
        if is_dn and len(existing) == 1:
            raise ValueError(
                f"{uid} is the only member of {cn}. A groupOfNames cannot be "
                f"empty -- add another member first, or delete the group.")
        op = MODIFY_DELETE

    conn.modify(group_dn(cn), {attr: [(op, [value])]})


@app.route("/membership", methods=["POST"])
@login_required
def membership():
    f = request.form
    uid = f.get("uid", "")
    cn = f.get("cn", "")
    action = f.get("action", "add")
    back = f.get("back", "users")

    try:
        _membership_change(cn, uid, action)
        verb = "Added" if action == "add" else "Removed"
        prep = "to" if action == "add" else "from"
        flash(f"{verb} {uid} {prep} {cn}.", "ok")
    except (LDAPException, ValueError) as exc:
        flash(str(exc), "error")

    if back == "groups":
        return redirect(url_for("groups", cn=cn))
    return redirect(url_for("users", uid=uid))


# --------------------------------------------------------------------------
@app.errorhandler(LDAPBindError)
def _rebind(_exc):
    session.clear()
    flash("Your session expired. Sign in again.", "error")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
