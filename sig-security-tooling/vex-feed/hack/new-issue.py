#!/usr/bin/env python3
"""Scaffold a per-issue OpenVEX document from a kubernetes/kubernetes issue.

Fetches the issue with `gh`, pulls the CVE IDs it mentions, and writes a
skeleton ../files/issue-<n>.openvex.json with one statement per CVE for a
human to complete.

The VEX determination — status (fixed / not_affected / under_investigation),
justification, and the explanatory notes — is a judgment call made by reading
the issue discussion, so it is intentionally left as a TODO. This script only
removes the boilerplate: it sets the document @id to the issue URL, fills in
the author/context, and stubs one statement per CVE as under_investigation.

Usage:  python3 hack/new-issue.py <issue-number>

Then edit status / justification / status_notes (and add a subcomponent PURL if
the CVE is in a dependency), add a merge-overrides.json entry if the CVE is also
reported by other issues, and run: python3 hack/build-feed.py
"""
import json, os, re, subprocess, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(os.path.dirname(HERE), "files")
REPO = "kubernetes/kubernetes"
CONTEXT = "https://openvex.dev/ns/v0.2.0"
AUTHOR = "kubernetes maintainers"
PRODUCT = "pkg:golang/k8s.io/kubernetes"
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def gh_issue(n):
    r = subprocess.run(
        ["gh", "issue", "view", str(n), "--repo", REPO,
         "--json", "number,title,body,url,comments"],
        capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"gh failed for issue #{n}: {r.stderr.strip()}")
    return json.loads(r.stdout)


def main():
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        sys.exit("usage: python3 hack/new-issue.py <issue-number>")
    n = sys.argv[1]
    out_path = os.path.join(FILES, f"issue-{n}.openvex.json")
    if os.path.exists(out_path):
        sys.exit(f"refusing to overwrite existing {out_path}")

    iss = gh_issue(n)
    blob = " ".join([iss.get("title", ""), iss.get("body", "") or ""]
                    + [c.get("body", "") or "" for c in iss.get("comments", [])])
    cves = sorted({m.group(0).upper() for m in CVE_RE.finditer(blob)})
    if not cves:
        print(f"warning: no CVE IDs found in issue #{n}; stubbing one TODO statement")
        cves = ["CVE-XXXX-XXXX"]

    url = iss.get("url") or f"https://github.com/{REPO}/issues/{n}"
    title = (iss.get("title") or "").replace("\n", " ").strip()
    statements = [{
        "vulnerability": {"name": cve},
        "products": [{"@id": PRODUCT}],
        "status": "under_investigation",
        "status_notes": (f"TODO: determine status and justification for {cve}. "
                         f"Source issue: \"{title}\". [ref: {url}]"),
    } for cve in cves]

    doc = {
        "@context": CONTEXT,
        "@id": url,
        "author": AUTHOR,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "statements": statements,
    }
    os.makedirs(FILES, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

    print(f"wrote {out_path}")
    print(f"  {len(cves)} statement(s): {', '.join(cves)}")
    print("Next: fill in status / justification / status_notes (add a subcomponent")
    print("PURL if the CVE is in a dependency), add a merge-overrides.json entry if")
    print("the CVE spans multiple issues, then run: python3 hack/build-feed.py")


if __name__ == "__main__":
    main()
