# vex-feed generator

`build-feed` assembles the combined feed
(`../kubernetes-vex-feed-draft.openvex.json`) from the per-issue OpenVEX
documents in `../files/`. All commands below are Go and are run from the
`vex-feed/` directory (one level up from here).

## Model

- **`../files/issue-<N>.openvex.json` are the source of truth.** Each is one
  OpenVEX document for a single kubernetes/kubernetes issue and lists that
  issue's determination(s). A CVE may legitimately appear in more than one
  file — that is the provenance trail, and it is intentional.
- **The combined feed is generated, not hand-edited.** It is deduped to one
  statement per `(product, CVE)` for consumers (scanners want a single answer
  per CVE).

## What the build does

1. Reads every `../files/issue-*.openvex.json` (newest issue first).
2. Groups statements by `(product @id, CVE)`.
3. Requires `status` and `justification` to agree across all issues that report
   a CVE — it **fails loudly** on a conflict instead of guessing.
4. Unions `subcomponents` (version variants of one package collapse to the
   unversioned base).
5. For a CVE reported by **more than one** issue, takes the merged
   `status_notes` from `merge-overrides.json` (prose can't be merged
   mechanically). Single-source CVEs keep their per-issue note.
6. Bumps `version` and refreshes `timestamp` only when the statements actually
   change.

## Usage

```console
$ go run ./hack/build-feed          # regenerate the feed
$ go run ./hack/build-feed --check  # CI: non-zero exit if the feed is stale
```

## Typical workflow

1. Add a per-issue document under `files/` — either by hand, or scaffold one
   with `go run ./hack/new-issue <issue-number>` (fetches the issue, extracts
   its CVE IDs, and writes a stub with status `under_investigation` and TODO
   notes for you to complete).
2. If the new/changed CVE is reported by more than one issue, add or update its
   entry in `merge-overrides.json`.
3. Run `go run ./hack/build-feed`.
4. Commit the changed `files/…`, `merge-overrides.json`, and the regenerated
   `kubernetes-vex-feed-draft.openvex.json` together.

## Files

- `openvex/` — shared library: the OpenVEX `Document`/`Statement` Go types
  and JSON load/save helpers used by both tools below.
- `build-feed/` — the generator (builds the combined feed from `files/`).
- `new-issue/` — scaffolds a `files/issue-<n>.openvex.json` stub from a GitHub
  issue (fetches it via `gh`, extracts CVE IDs); status/justification/notes are
  left as TODO for a human to complete. Refuses to overwrite an existing file.
- `merge-overrides.json` — curated merged notes for CVEs reported by multiple
  issues; `status` / `justification` / `product` are still derived from
  `files/` and are not overridable here.

## Development

Run from `vex-feed/`:

```console
$ go build ./...
$ go test ./...
```
