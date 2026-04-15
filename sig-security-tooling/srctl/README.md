# srctl: CVE Report Generation CLI-Tool for the Security Response Committee (SRC)

## What `srctl` provides.

The `srctl` tool encodes the standard SRC workflow for vulnerability disclosure and announcement across multiple communication channels into one tool that can handle consistently export to multiple formats (github issue, email, slack). Having this tool also makes adding additional potential channels and formats in the future more approachable. 

Repetitive error prone work of the copy and paste variety is handled by the tool. SRC members are able to automatically generate a structured json output of their report in OSV format improving machine readability of vulnerability disclosure.

For more details about the SRC who this is for and the workflow behind this see:
- [Kubernetes Security Release Process and Security Committee documentation.](https://github.com/kubernetes/committee-security-response/tree/main)
- [A Bug’s-Eye View: Kubernetes SIG Security Explains It... Ian C, Tabitha S, Rory M, Iain S & Mahé T](https://youtu.be/ujnqeWQZ17w?t=710) from link start time stamp 11:50-21:15
- [SRC Fix Disclosure Process](https://github.com/kubernetes/committee-security-response/blob/main/security-release-process.md#fix-disclosure-process)

Example Usage:
- https://github.com/kubernetes/kubernetes/issues/136680

### Templates & OSV Schema

- Github Issue: [issue.tmpl src](https://github.com/kubernetes/sig-security/blob/main/sig-security-tooling/srctl/state/issue.tmpl)
- Email: [email.tmpl src](https://github.com/kubernetes/sig-security/blob/main/sig-security-tooling/srctl/state/email.tmpl)
- Slack: [slack.tmpl src](https://github.com/kubernetes/sig-security/blob/main/sig-security-tooling/srctl/state/slack.tmpl)
- JSON OSV ([OSV schema](https://ossf.github.io/osv-schema/)) is automatically built for the GitHub Issue

## Installation

```
git clone https://github.com/kubernetes/sig-security.git
cd sig-security/sig-security-tooling/srctl
go build
```

`go install` is not used because it won't work. There is a mismatch of the repository the package lives in on GitHub and the import path recognized from the package name in the `go.mod` file.

## CLI Usage

### `srctl`

Execute the command with no arguments.
The tool will generate placeholder template in stdout.

```
usage: srctl CVE-YYYY-NNNNN
No CVE arg provided, printing placeholder issue template:

TITLE: PLACEHOLDER ISSUE

---

/triage accepted
/lifecycle frozen
/area security
/kind bug
/committee security-response
```

### `srctl "CVE-{YEAR}-{ID#}"`

Execute the command followed by a valid file name.
Provide a prompt for choice of work to do.

```
CVE-2026-12354
(0) Summary:
(1) CVSS:
(2) Description:
(3) Am I vulnerable?:
(4) Affected Versions:
(5) How to upgrade?:
(6) How to mitigate?:
(7) Detection:
(8) Additional Details:
(9) Acknowledgements:
(a) GitHub Issue:
(b) Fix Lead:

Status: could not find file for CVE-2026-12354, starting from fresh state
Enter or (0-9,a-b) to edit, (s)ave, e(x)port, (q)uit:
```

You can provide an existing saved json file from the tool to act on or the name of a new file to create.
