#!/usr/bin/env python3
"""Refresh the azure-tiering Tier-0 snapshots in test/data and report what changed.

The snapshots are what test/fixture.test.js checks kb.js against: every Tier-0
Graph permission and Entra role must be in the KB, with the same GUID, rated no
lower than azure-tiering. This script never edits kb.js. A KB change is a security
review: read the azure-tiering entry, then edit kb.js by hand and bump KB_VERSION.

Usage (Windows: "py"; macOS/Linux: "python3"):
  py scripts/sync_azure_tiering.py                   # download from GitHub
  py scripts/sync_azure_tiering.py --graph-file X.json --entra-file Y.json   # offline
Then: node test/fixture.test.js
"""
import datetime, json, pathlib, sys, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "test" / "data"
BASE = "https://raw.githubusercontent.com/emiliensocchi/azure-tiering/main/"
SOURCES = {
    "graph": ("Microsoft%20Graph%20application%20permissions/tiered-msgraph-app-permissions.json",
              "azure-tiering-graph-tier0.json"),
    "entra": ("Entra%20roles/tiered-entra-roles.json", "azure-tiering-entra-tier0.json"),
}


def arg(name):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else None


def load(kind):
    local = arg(f"--{kind}-file")
    if local:
        return json.loads(pathlib.Path(local).read_text(encoding="utf-8")), f"file:{local}"
    url = BASE + SOURCES[kind][0]
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read().decode("utf-8")), url.replace(
            "https://raw.githubusercontent.com/emiliensocchi/azure-tiering/main/",
            "https://github.com/emiliensocchi/azure-tiering/blob/main/")


def tier0(rows):
    out = []
    for e in rows:
        if str(e.get("tier")) != "0":
            continue
        if not e.get("assetName") or not e.get("id"):
            sys.exit(f"unexpected entry shape, refusing to write a partial snapshot: {e}")
        out.append({"assetName": e["assetName"], "id": e["id"].lower(), "pathType": e.get("pathType") or "n/a",
                    # kept for review: what a KB entry's escalationNote should be written from
                    "shortestPath": e.get("shortestPath") or e.get("knownShortestPath") or "",
                    "example": e.get("example") or ""})
    if len(out) < 10:
        sys.exit(f"only {len(out)} Tier-0 entries found; the upstream format probably changed. Not writing.")
    return sorted(out, key=lambda x: x["assetName"].lower())


changes = 0
for kind, (_, fname) in SOURCES.items():
    rows, source = load(kind)
    new = tier0(rows)
    path = DATA / fname
    old = json.loads(path.read_text(encoding="utf-8"))["tier0"] if path.exists() else []
    o, n = {e["assetName"]: e for e in old}, {e["assetName"]: e for e in new}
    print(f"\n== {kind}: {len(new)} Tier-0 entries ({source})")
    for name in sorted(n.keys() - o.keys()):
        print(f"  + added      {name}  [{n[name]['pathType']}]  {n[name]['id']}"); changes += 1
    for name in sorted(o.keys() - n.keys()):
        print(f"  - removed    {name}  (was {o[name]['pathType']})"); changes += 1
    for name in sorted(n.keys() & o.keys()):
        if (n[name]["pathType"], n[name]["id"]) != (o[name]["pathType"], o[name]["id"]):
            print(f"  ~ changed    {name}  {o[name]['pathType']} -> {n[name]['pathType']}"
                  + (f"  id {o[name]['id']} -> {n[name]['id']}" if n[name]["id"] != o[name]["id"] else "")); changes += 1
    DATA.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps({
        "source": source,
        "snapshot": datetime.date.today().isoformat(),
        "note": "Tier-0 entries only (assetName, id, pathType, plus the published attack path for review). Refresh with scripts/sync_azure_tiering.py; review every change before editing kb.js.",
        "tier0": new,
    }, indent=2) + "\n").encode("utf-8"))

print(f"\n{changes} change(s). Next: node test/fixture.test.js, then review and edit kb.js by hand for anything it flags."
      if changes else "\nNo changes since the last snapshot.")
