"""
End-to-end smoke test: drives the real Flask views against ldap3's in-memory
mock LDAP server. Verifies create/modify/delete of users and groups, and
membership changes across both posixGroup and groupOfNames.

    python3 test_smoke.py
"""
import os
import re
import sys

os.environ["FLASK_SECRET_KEY"] = "test-only"

from ldap3 import Server, Connection, MOCK_SYNC, OFFLINE_SLAPD_2_4

import app as ldapui

BASE = "dc=cplab,dc=local"
PEOPLE = f"ou=people,{BASE}"
GROUPS = f"ou=groups,{BASE}"
ADMIN = f"cn=admin,{BASE}"

_server = Server("mock", get_info=OFFLINE_SLAPD_2_4)


def _seed(conn):
    conn.strategy.add_entry(ADMIN, {"userPassword": "secret", "objectClass": ["simpleSecurityObject", "organizationalRole"], "cn": "admin"})
    conn.strategy.add_entry(BASE, {"objectClass": ["top", "dcObject", "organization"], "dc": "cplab", "o": "cplab"})
    conn.strategy.add_entry(PEOPLE, {"objectClass": ["top", "organizationalUnit"], "ou": "people"})
    conn.strategy.add_entry(GROUPS, {"objectClass": ["top", "organizationalUnit"], "ou": "groups"})


_shared = Connection(_server, user=ADMIN, password="secret",
                     client_strategy=MOCK_SYNC, raise_exceptions=True)
_seed(_shared)
_shared.bind()


def fake_conn():
    """All requests share one mock connection so state persists."""
    return _shared


# Patch the app's connection factory and password op (mock has no extop).
ldapui.ldap_conn = fake_conn
ldapui._close_conn = lambda exc=None: None
_shared.extend.standard.modify_password = lambda *a, **kw: True

failures = []


def check(label, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {label}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(label)


def entry(dn):
    try:
        _shared.search(dn, "(objectClass=*)", search_scope="BASE",
                       attributes=["*"])
    except Exception:
        return None
    return dict(_shared.entries[0].entry_attributes_as_dict) if _shared.entries else None


ldapui.app.config["TESTING"] = True
client = ldapui.app.test_client()

# Establish a logged-in session without hitting the real bind path.
with client.session_transaction() as s:
    s["tok"] = ldapui._store_creds(ADMIN, "secret")
    s["dn"] = ADMIN
    s["csrf"] = "test-csrf"

CSRF = {"csrf": "test-csrf"}


def post(path, data):
    return client.post(path, data={**CSRF, **data}, follow_redirects=True)


print("\nUsers")
r = post("/users/create", {"uid": "alis", "givenName": "Alis", "sn": "Alis",
                           "mail": "alis@cplab.local", "uidNumber": "10011",
                           "loginShell": "/bin/bash", "password": "pw"})
u = entry(f"uid=alis,{PEOPLE}")
check("create user", u is not None)
check("uid set", u and u.get("uid") == ["alis"], str(u))
check("uidNumber set", u and u.get("uidNumber") == [10011] or u.get("uidNumber") == ["10011"], str(u.get("uidNumber")))
check("homeDirectory defaulted", u and u.get("homeDirectory") == ["/home/alis"], str(u.get("homeDirectory")))

post("/users/create", {"uid": "bkumar", "givenName": "B", "sn": "Kumar",
                       "uidNumber": "10012"})
check("second user", entry(f"uid=bkumar,{PEOPLE}") is not None)

post("/users/alis/update", {"cn": "Alis Verma", "sn": "Verma",
                            "givenName": "Alis", "mail": "a.verma@cplab.local",
                            "loginShell": "/bin/sh", "homeDirectory": "/home/alis",
                            "gidNumber": "10000"})
u = entry(f"uid=alis,{PEOPLE}")
check("modify user cn", u and u.get("cn") == ["Alis Verma"], str(u.get("cn")))
check("modify user shell", u and u.get("loginShell") == ["/bin/sh"], str(u.get("loginShell")))

print("\nGroups (posixGroup)")
post("/groups/create", {"cn": "vpnusers", "kind": "posixGroup",
                        "gidNumber": "10050", "description": "Remote Access VPN"})
gr = entry(f"cn=vpnusers,{GROUPS}")
check("create empty posixGroup", gr is not None)
check("description set", gr and gr.get("description") == ["Remote Access VPN"], str(gr))

post("/groups/vpnusers/update", {"description": "VPN users"})
gr = entry(f"cn=vpnusers,{GROUPS}")
check("modify group description", gr and gr.get("description") == ["VPN users"], str(gr.get("description")))

print("\nMembership (memberUid)")
post("/membership", {"uid": "alis", "cn": "vpnusers", "action": "add"})
gr = entry(f"cn=vpnusers,{GROUPS}")
check("add member", gr and "alis" in (gr.get("memberUid") or []), str(gr.get("memberUid")))

post("/membership", {"uid": "alis", "cn": "vpnusers", "action": "add"})
gr = entry(f"cn=vpnusers,{GROUPS}")
check("add is idempotent", gr and (gr.get("memberUid") or []).count("alis") == 1,
      str(gr.get("memberUid")))

post("/membership", {"uid": "bkumar", "cn": "vpnusers", "action": "add"})
post("/membership", {"uid": "bkumar", "cn": "vpnusers", "action": "remove"})
gr = entry(f"cn=vpnusers,{GROUPS}")
check("remove member", gr and "bkumar" not in (gr.get("memberUid") or []),
      str(gr.get("memberUid")))

print("\nGroups (groupOfNames)")
r = post("/groups/create", {"cn": "empties", "kind": "groupOfNames"})
check("groupOfNames with no members is refused",
      entry(f"cn=empties,{GROUPS}") is None)
check("refusal explains why", b"at least one member" in r.data)

post("/groups/create", {"cn": "admins", "kind": "groupOfNames", "members": "alis"})
gr = entry(f"cn=admins,{GROUPS}")
check("create groupOfNames with member", gr is not None)
check("member stored as DN",
      gr and f"uid=alis,{PEOPLE}" in [str(m) for m in (gr.get("member") or [])],
      str(gr.get("member")))

r = post("/membership", {"uid": "alis", "cn": "admins", "action": "remove"})
gr = entry(f"cn=admins,{GROUPS}")
check("last member of groupOfNames cannot be removed",
      gr and len(gr.get("member") or []) == 1)
check("refusal explains why", b"cannot be empty" in r.data)

print("\nUser list reflects membership")
r = client.get("/users")
check("users page renders", r.status_code == 200)
check("group chip shown on user row", b"vpnusers" in r.data)

print("\nExport")
r = client.get("/users/export?format=uid")
check("uid export downloads", r.status_code == 200)
check("uid export is one name per line",
      r.data.decode().splitlines() == ["alis", "bkumar"], r.data.decode())
check("uid export sets a filename",
      "attachment" in r.headers.get("Content-Disposition", ""))

r = client.get("/users/export?format=csv")
rows = r.data.decode().splitlines()
check("csv has a header row", rows[0].startswith("uid,cn,sn"), rows[0])
check("csv includes group membership",
      any("vpnusers" in line for line in rows[1:]), "\n".join(rows))

r = client.get("/users/export?format=ldif")
text = r.data.decode()
check("ldif includes user entries", f"dn: uid=alis,{PEOPLE}" in text)
check("ldif includes group entries", f"dn: cn=vpnusers,{GROUPS}" in text)
check("ldif carries memberUid", "memberUid: alis" in text)
check("ldif omits passwords", "userPassword" not in text)

print("\nInput validation")
r = post("/users/create", {"uid": "bad,uid=evil", "sn": "X"})
check("DN injection rejected", entry(f"uid=bad,{PEOPLE}") is None)
check("rejection is explained", b"not a usable name" in r.data)

r = client.post("/users/create", data={"uid": "nocsrf", "sn": "X"},
                follow_redirects=True)
check("missing CSRF token rejected", entry(f"uid=nocsrf,{PEOPLE}") is None)

print("\nDeletion")
r = post("/users/alis/delete", {})
check("sole member of a groupOfNames is not silently deleted",
      entry(f"uid=alis,{PEOPLE}") is not None)
check("blocking group is named in the message", b"admins" in r.data,
      r.data.decode()[:400])

post("/groups/admins/delete", {})
post("/users/alis/delete", {})
check("user deleted once unblocked", entry(f"uid=alis,{PEOPLE}") is None)
gr = entry(f"cn=vpnusers,{GROUPS}")
check("deleted user stripped from group",
      gr and "alis" not in (gr.get("memberUid") or []), str(gr.get("memberUid")))

post("/groups/vpnusers/delete", {})
check("group deleted", entry(f"cn=vpnusers,{GROUPS}") is None)
check("group members survive", entry(f"uid=bkumar,{PEOPLE}") is not None)

print()
if failures:
    print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
    sys.exit(1)
print("All checks passed.")
