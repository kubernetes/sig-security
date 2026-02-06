# srctl

`srctl` is a small CLI tool used by Kubernetes Security Response Committee (SRC) members to publish official CVE announcements.

It was created to standardize and simplify the CVE publication workflow, while enabling the generation of structured vulnerability metadata that can be consumed by downstream security tooling.

---

## Background

As Kubernetes security processes evolved, publishing CVEs required more structure and consistency. In particular, there was a need to:

- Reduce manual steps during CVE publication
- Generate reproducible and machine-readable vulnerability data
- Support OSV-formatted metadata for integration with the official CVE feed

`srctl` was introduced to address these needs with a simple, focused command-line tool.

Related context can be found in:

- tooling: add new CLI for CVE publication by SRC members (#171)
- tooling: official CVE feed: add OSV schema JSON feed (#169)

---

## What This Tool Does

At a high level, `srctl` helps SRC members:

- Create CVE announcement content
- Generate OSV-compliant JSON vulnerability data
- Ensure CVE metadata follows agreed conventions

The generated outputs are typically embedded into GitHub issues and later consumed by tooling that builds the official Kubernetes CVE feed.

---

## Intended Users

This tool is primarily intended for:

- Kubernetes Security Response Committee (SRC) members
- Contributors involved in CVE publication and coordination

It is not designed as a general-purpose vulnerability scanning or analysis tool.

---

## Usage Overview

`srctl` is a CLI-based tool. Its commands are used as part of the CVE publication workflow to generate and validate CVE-related artifacts.

For concrete examples of its usage, refer to CVE issues created using `srctl` and the initial implementation in PR #171.

---

## Contributing

Documentation improvements and tooling enhancements are welcome. Contributions should follow Kubernetes community guidelines and SIG Security processes.
