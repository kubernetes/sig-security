#!/usr/bin/env python3
"""Build the combined Kubernetes CVE VEX feed from the per-issue OpenVEX
documents in ../files/.

The per-issue files under files/ are the source of truth (one document per
GitHub issue, preserving provenance). This script merges them into a single
consumer-facing feed with one statement per (product, CVE):

  - statements are grouped by (product @id, CVE);
  - status and justification must agree across all issues that report a CVE
    (the build fails loudly if they conflict, rather than guessing);
  - subcomponents are unioned (version variants of one package collapse to the
    unversioned base);
  - for a CVE reported by more than one issue, the merged note/remediation come
    from merge-overrides.json (curated, since prose can't be merged mechanically);
    single-source CVEs keep their per-issue note verbatim.

Ordering matches a newest-issue-first walk (first occurrence wins), so the feed
lists the most recently reported CVEs first.

Usage:  python3 hack/build-feed.py [--check]
  (default) writes ../kubernetes-vex-feed-draft.openvex.json
  --check   exits non-zero if the on-disk feed is stale (for CI); writes nothing
"""
import json, glob, os, re, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
FILES_GLOB = os.path.join(BASE, "files", "issue-*.openvex.json")
FEED = os.path.join(BASE, "kubernetes-vex-feed-draft.openvex.json")
OVERRIDES = os.path.join(HERE, "merge-overrides.json")

# Preserved feed identity (edit here if the feed is renamed/re-homed).
CONTEXT = "https://openvex.dev/ns/v0.2.0"
FEED_ID = "https://raw.githubusercontent.com/kubernetes/sig-security/main/sig-security-tooling/vex-feed/kubernetes-vex-feed-draft.openvex.json"
AUTHOR = "kubernetes maintainers"


def issue_num(path):
    return int(re.search(r"issue-(\d+)", os.path.basename(path)).group(1))


def collapse_subcomponents(ids):
    ids = sorted(ids)
    if len(ids) <= 1:
        return ids
    bases = {i.split("@", 1)[0] for i in ids}
    return [next(iter(bases))] if len(bases) == 1 else ids


def build():
    overrides = {k: v for k, v in json.load(open(OVERRIDES)).items() if not k.startswith("_")}
    # newest issue first; first occurrence of a CVE fixes its position
    files = sorted(glob.glob(FILES_GLOB), key=issue_num, reverse=True)
    if not files:
        sys.exit(f"no per-issue files found at {FILES_GLOB}")

    order, groups = [], {}
    for path in files:
        n = issue_num(path)
        for st in json.load(open(path))["statements"]:
            cve = st["vulnerability"]["name"]
            prod = st["products"][0]["@id"]
            key = (prod, cve)
            subs = [sc["@id"] for sc in st["products"][0].get("subcomponents", [])]
            if key not in groups:
                groups[key] = {"status": [], "just": [], "subs": set(), "sources": [],
                               "first": st, "cve": cve, "prod": prod}
                order.append(key)
            g = groups[key]
            g["status"].append(st["status"])
            g["just"].append(st.get("justification"))
            g["subs"].update(subs)
            g["sources"].append(n)

    conflicts, statements = [], []
    for key in order:
        g = groups[key]
        cve, prod = g["cve"], g["prod"]
        if len(set(g["status"])) > 1:
            conflicts.append(f"{cve}: conflicting status {sorted(set(g['status']))}")
            continue
        if len(set(g["just"])) > 1:
            conflicts.append(f"{cve}: conflicting justification {sorted(map(str, set(g['just'])))}")
            continue
        product = {"@id": prod}
        subs = collapse_subcomponents(g["subs"])
        if subs:
            product["subcomponents"] = [{"@id": s} for s in subs]
        stmt = {"vulnerability": {"name": cve}, "products": [product], "status": g["status"][0]}
        if g["just"][0] is not None:
            stmt["justification"] = g["just"][0]
        multi = len(set(g["sources"])) > 1
        if cve in overrides:
            src = overrides[cve]
        elif multi:
            conflicts.append(f"{cve}: reported by {sorted(set(g['sources']))} but no merge-overrides.json entry")
            continue
        else:
            src = g["first"]
        if src.get("status_notes"):
            stmt["status_notes"] = src["status_notes"]
        if src.get("action_statement"):
            stmt["action_statement"] = src["action_statement"]
        statements.append(stmt)

    if conflicts:
        sys.exit("build failed — resolve these before regenerating:\n  - " + "\n  - ".join(conflicts))
    return statements


def main():
    check = "--check" in sys.argv[1:]
    statements = build()
    existing = json.load(open(FEED)) if os.path.exists(FEED) else None

    statements_changed = existing is None or existing.get("statements") != statements
    metadata_changed = existing is None or any(
        existing.get(k) != v for k, v in (("@context", CONTEXT), ("@id", FEED_ID), ("author", AUTHOR)))

    if check:
        if statements_changed or metadata_changed:
            sys.exit("feed is STALE — run: python3 hack/build-feed.py")
        print(f"feed up to date ({len(statements)} statements)")
        return

    if not statements_changed and not metadata_changed:
        print(f"no change ({len(statements)} statements); feed left as-is")
        return

    if statements_changed:
        # content changed: new revision + timestamp
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ver = (existing["version"] + 1) if existing else 1
    else:
        # metadata-only change (e.g. @id): keep the existing revision + timestamp
        ts, ver = existing["timestamp"], existing["version"]

    feed = {"@context": CONTEXT, "@id": FEED_ID, "author": AUTHOR,
            "timestamp": ts, "version": ver, "statements": statements}
    with open(FEED, "w") as f:
        json.dump(feed, f, indent=2)
        f.write("\n")
    cves = len({s["vulnerability"]["name"] for s in statements})
    what = "statements + metadata" if statements_changed else "metadata only"
    print(f"wrote {FEED} ({what})\n  {len(statements)} statements / {cves} CVEs, version {ver}")


if __name__ == "__main__":
    main()
