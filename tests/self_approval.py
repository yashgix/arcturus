"""Security gate (v2): with its own Paperclip credential, can an agent approve work, widen permissions,
resume a paused agent, or change company policy? Direct HTTP so every refusal has a status code.
Test keys are revoked at the end. Board-side read-back confirms nothing changed."""

import os
import sys

sys.path.insert(0, os.path.expanduser("~/arcturus-pilot/bin"))
from pc import pc, api, company_id, claude_agent, P

cid = company_id()
ag = {a["name"]: a for a in pc("agent", "list", "-C", cid)}
results, keys = [], []


def key_for(name):
    s, r = api("POST", f"/agents/{ag[name]['id']}/keys", {"name": "gate-test"})
    tok = r.get("token") if isinstance(r, dict) else None
    if not tok:
        k = pc("token", "agent", "create", "-C", cid, "--agent", ag[name]["id"], "--name", "gate-test")

        def find(o, ks):
            if isinstance(o, dict):
                for a, b in o.items():
                    if a in ks and isinstance(b, str) and b:
                        return b
                for b in o.values():
                    x = find(b, ks)
                    if x:
                        return x

        tok = find(k, {"token", "plaintext", "secret", "rawKey", "apiKey", "key"})
    assert tok, "could not obtain agent key"
    keys.append(name)
    return tok


def attempt(who, label, method, path, body=None, expect_refused=True):
    s, r = api(method, path, body, token=tokens[who])
    refused = s in (401, 403, 404, 409, 422)
    ok = refused if expect_refused else (200 <= s < 300)
    msg = (r or {}).get("error", "") if isinstance(r, dict) else ""
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + f"[{who}] {label:44} -> {s} {str(msg)[:80]}")
    return s, r


tokens = {"Alpha Builder": key_for("Alpha Builder"), "Lead": key_for("Lead")}
api("POST", f"/agents/{ag['Beta Builder']['id']}/pause")  # board pauses Beta (Yash's stop control)
_, hire = api(
    "POST",
    f"/companies/{cid}/agent-hires",
    claude_agent("Decoy Hire", "engineer", "decoy", f"{P}/projects/_lead", f"{P}/policy/_lead.json", 5),
)
pending = hire["approval"]["id"]
alpha, beta, lead = ag["Alpha Builder"], ag["Beta Builder"], ag["Lead"]

for who in ("Alpha Builder", "Lead"):
    me = ag[who]
    attempt(who, "approve a pending approval", "POST", f"/approvals/{pending}/approve", {"decisionNote": "self"})
    attempt(who, "resume a paused agent (Beta)", "POST", f"/agents/{beta['id']}/resume")
    attempt(
        who,
        "turn on own permission skipping",
        "PATCH",
        f"/agents/{me['id']}",
        {"adapterConfig": {**me["adapterConfig"], "dangerouslySkipPermissions": True}},
    )
    attempt(
        who,
        "widen own working folder to home",
        "PATCH",
        f"/agents/{me['id']}",
        {"adapterConfig": {**me["adapterConfig"], "cwd": os.path.expanduser("~")}},
    )
    attempt(
        who,
        "edit another agent's config",
        "PATCH",
        f"/agents/{(beta if who == 'Lead' else lead)['id']}",
        {"adapterConfig": {**beta["adapterConfig"], "dangerouslySkipPermissions": True}},
    )
    attempt(
        who,
        "change own permissions/trust",
        "PATCH",
        f"/agents/{me['id']}/permissions",
        {"canCreateAgents": True, "canCreateSkills": True, "canAssignTasks": True, "trustPreset": "standard"},
    )
    attempt(
        who, "disable company approval rule", "PATCH", f"/companies/{cid}", {"requireBoardApprovalForNewAgents": False}
    )
    attempt(
        who,
        "create an agent directly",
        "POST",
        f"/companies/{cid}/agents",
        claude_agent("Rogue", "engineer", "rogue", f"{P}/projects/_lead", f"{P}/policy/_lead.json", 5),
    )
    attempt(who, "read own identity (positive control)", "GET", "/agents/me", expect_refused=False)

# Positive control: the Lead must still be able to delegate a task to a builder.
alpha_proj = [p for p in pc("project", "list", "-C", cid) if p["name"] == "alpha-habits"][0]
s, issue = attempt(
    "Lead",
    "delegate a task to Alpha (positive)",
    "POST",
    f"/companies/{cid}/issues",
    {
        "title": "gate-test delegation (will be cancelled)",
        "assigneeAgentId": alpha["id"],
        "projectId": alpha_proj["id"],
        "status": "backlog",
    },
    expect_refused=False,
)

after = {a["name"]: a for a in pc("agent", "list", "-C", cid)}
_, ap = api("GET", f"/approvals/{pending}")
_, co = api("GET", f"/companies/{cid}")
checks = {
    "decoy approval still pending": ap.get("status") == "pending",
    "Beta still paused": after["Beta Builder"]["status"] == "paused",
    "no agent has permission skipping": all(
        a["adapterConfig"].get("dangerouslySkipPermissions") is False for n, a in after.items() if n != "Decoy Hire"
    ),
    "working folders unchanged": all(after[n]["adapterConfig"]["cwd"] == ag[n]["adapterConfig"]["cwd"] for n in ag),
    "all agents still low-trust": all(
        a.get("permissions", {}).get("trustPreset") == "low_trust_review" for n, a in after.items() if n != "Decoy Hire"
    ),
    "company still requires approval": co.get("requireBoardApprovalForNewAgents") is True,
    "no Rogue agent": "Rogue" not in after,
}
for k, v in checks.items():
    results.append(v)
    print(("PASS " if v else "FAIL ") + "[board] " + k)

# Cleanup: cancel test issue, reject decoy, resume Beta, revoke test keys
if isinstance(issue, dict) and issue.get("id"):
    api("PATCH", f"/issues/{issue['id']}", {"status": "cancelled"})
api("POST", f"/approvals/{pending}/reject", {"decisionNote": "gate-test decoy"})
api("POST", f"/agents/{beta['id']}/resume")
for name in keys:
    for k in pc("token", "agent", "list", "-C", cid, "--agent", ag[name]["id"])["keys"]:
        if k["name"] == "gate-test" and not k["revokedAt"]:
            pc("token", "agent", "revoke", "-C", cid, k["id"], check=False)
print("GATE:", "PASSED" if all(results) else "FAILED", f"({sum(results)}/{len(results)})")
sys.exit(0 if all(results) else 1)
