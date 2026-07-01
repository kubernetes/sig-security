# Kubernetes CVE VEX feed — Draft

## Scope & method

Source query (kubernetes/kubernetes): `is:issue state:closed CVE -label:official-cve-feed no:assignee -label:wg/security-audit no:milestone` (131 issues total). Included below are the 10 issues where **the issue creator (reporter) identified a CVE and asked maintainers to fix it**. 

> **Note on values.** VEX subject = upstream Kubernetes. `status_justification` is populated only on `not affected` rows (VEX/CSAF spec). The `.openvex.json` files use OpenVEX canonical enums (`not_affected`, `under_investigation`); the table below uses the human-readable form. The `status_notes` column maps to the OpenVEX `status_notes` field, and `status_justification` to `justification`.

## VEX table

| Issue | CVE(s) | Component / subject | status | status_justification | status_notes |
|---|---|---|---|---|---|
| #140092 | CVE-2026-39821 | k8s.io/kubernetes — golang.org/x/net@v0.49.0 | under investigation | `—` | kubectl 1.36.2 ships golang.org/x/net v0.49.0 (<v0.55.0), flagged for CVE-2026-39821. The reporter explicitly did NOT confirm that kubectl reaches the vulnerable x/net/idna code path, and maintainers made no reachability ruling in-issue (directed to the security guide). Reachability of the vulnerable code in kubectl is undetermined. See [#140092](https://github.com/kubernetes/kubernetes/issues/140092). |
| #140091 | CVE-2025-68121, CVE-2026-33811, CVE-2026-33814, CVE-2026-39836 | k8s.io/kubernetes — stdlib | fixed | `—` | Go stdlib CVEs flagged against the kubectl go.mod (go 1.26.0). Overlaps #137195/#139510. Remediated by scheduled Go toolchain bumps already merged/in progress across supported branches; a maintainer pointed to the project security guide (Go CVEs are tracked and fixed on the standard schedule). See [#140091](https://github.com/kubernetes/kubernetes/issues/140091). |
| #139510 | CVE-2026-33811, CVE-2026-33814, CVE-2026-39820, CVE-2026-39836, CVE-2026-42499, CVE-2026-42501 | k8s.io/kubernetes — stdlib | fixed | `—` | Go stdlib CVEs in kubectl binaries for 1.33/1.34/1.35. Go 1.26.4 merged to master (#139479) and release-1.36 (#138871). Supported-branch backports were requested; maintainer pointed to the security/patch process rather than confirming per-branch backport in-issue. Fixed on master/1.36; supported-branch Go bumps handled via monthly patch cadence. See [#139510](https://github.com/kubernetes/kubernetes/issues/139510). |
| #139221 | CVE-2026-33186 | k8s.io/kubernetes — google.golang.org/grpc | not affected | `vulnerable_code_not_present` | A maintainer determined Kubernetes has no in-tree gRPC servers using path-based authorization interceptors (google.golang.org/grpc/authz RBAC or custom interceptors relying on info.FullMethod / grpc.Method(ctx)) with 'deny' rules plus a default 'allow' fallback — the two conditions GHSA-p77j-4mvh-x3m3 requires. The vulnerable code path is not present. Reporter provided only a scanner hit. See [#139221](https://github.com/kubernetes/kubernetes/issues/139221). |
| #138329 | CVE-2026-39883 | k8s.io/kubernetes — go.opentelemetry.io/otel/sdk@v1.40.0 | not affected | `vulnerable_code_not_present` | The vulnerable code (go.opentelemetry.io/otel/sdk/resource host_id_bsd.go, which runs 'kenv' without an absolute path) is gated behind DragonFly/FreeBSD/NetBSD/OpenBSD/Solaris build tags. Kubernetes ships only linux/windows/darwin binaries, so the vulnerable BSD-specific code is not compiled into shipped artifacts. A maintainer confirmed Kubernetes does not ship binaries or images for any of the affected platforms, so it is not affected. See [#138329](https://github.com/kubernetes/kubernetes/issues/138329). |
| #138040 | CVE-2026-25679 | k8s.io/kubernetes — stdlib@v1.25.7 | fixed | `—` | Duplicate of #137853. Go stdlib CVE-2026-25679 in kubectl v1.35.3 (built with Go 1.25.7); fixed in Go 1.25.8 / 1.26.1. Reporter mistyped the ID as 'CVE-2026-2567'. Linked to #137853 as the tracking issue. Remediated via Go bump. See [#138040](https://github.com/kubernetes/kubernetes/issues/138040). |
| #137853 | CVE-2026-25679 | k8s.io/kubernetes — stdlib@v1.25.7 | fixed | `—` | Go stdlib CVE-2026-25679 flagged in kubectl (Go 1.25.7). A maintainer confirmed Go was already updated across all currently supported Kubernetes branches, with patch releases in progress; fix merged, release pending at close. See [#137853](https://github.com/kubernetes/kubernetes/issues/137853). |
| #137228 | CVE-2025-68121 | k8s.io/kubernetes — stdlib@v1.25.6 | fixed | `—` | Duplicate of #137195. Go stdlib crypto/tls CVE-2025-68121 in kubectl (Go 1.25.6); fixed in Go 1.24.13 / 1.25.7 / 1.26.0-rc.3. The reporter's own Trivy output lists Status='fixed'. Linked to #137195 as the tracking issue. See [#137228](https://github.com/kubernetes/kubernetes/issues/137228). |
| #137195 | CVE-2025-68121 | k8s.io/kubernetes — stdlib | fixed | `—` | Go stdlib crypto/tls CVE-2025-68121 in kubectl v1.35.1. A maintainer confirmed the fix was already merged in supported branches, pending the next release. Root issue for the #137228 duplicate. See [#137195](https://github.com/kubernetes/kubernetes/issues/137195). |
| #135083 | CVE-2025-47912, CVE-2025-58183, CVE-2025-58185, CVE-2025-58186, CVE-2025-58187, CVE-2025-58188, CVE-2025-58189, CVE-2025-61723, CVE-2025-61724, CVE-2025-61725 | k8s.io/kubernetes — stdlib | fixed | `—` | Go stdlib CVEs in kubectl v1.33.5. A maintainer confirmed Go was already updated to 1.24.9 on release-1.33 but not yet released; fix merged, release pending at close. See [#135083](https://github.com/kubernetes/kubernetes/issues/135083). |


## Files

- `kubernetes-vex-feed-draft.openvex.json` — combined OpenVEX feed, deduped to **one statement per CVE** (21 statements). CVEs reported in more than one issue cite all source issues in the notes.
- `files/issue-<num>.openvex.json` — per-issue OpenVEX documents, the source of truth, kept for provenance (the same CVE may appear across more than one issue file).

## Validation

These documents follow the [OpenVEX](https://github.com/openvex/spec) v0.2.0
specification. Validate them with [`vexctl`](https://github.com/openvex/vexctl)
— to install it yourself, see the
[vexctl installation instructions](https://github.com/openvex/vexctl#installing).

```console
# validate the combined feed (non-zero exit on a parse error)
$ vexctl merge kubernetes-vex-feed-draft.openvex.json > /dev/null

# validate every per-issue document
$ vexctl merge files/issue-*.openvex.json > /dev/null
```
