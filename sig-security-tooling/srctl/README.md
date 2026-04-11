# srctl: CVE Report Generation CLI-Tool for the Security Response Committee (SRC)

## Introduction: What this provides.

The `srctl` tool encodes the standard SRC workflow for vulnerability disclosure and announcement across multiple communication channels. Repetitive work of the copy paste and boiler plate variety is handled by the tool. SRC members are able to automatically generate a structured json output of the report in OSV format enabling non-human ingestion and tracking of vulnerability disclosure.

## Who this tool is for: The SRC

The Security Response Committee (SRC) is responsible for triaging and handling the security issues for Kubernetes. A committee has the license to do work in private, the SRC is the confidential side of sig-security. The primary goal of this group and their process is to reduce the total time users are vulnerable to publicly known exploits.

As part of the above responsibility, the SRC is also responsible for organizing the entire project security response including internal communication and external disclosure but will need help from relevant developers and release managers to successfully run this process.

So the key responsibilities include (with a bit of overlap)
1. security incident response for k8s project infrastructure
2. the identification, triage, disclosure, and fixing of vulnerabilities
3. communication and coordination with relevant parties at the appropriate times

For more details see:
- [Kubernetes Security Release Process and Security Committee documentation.](https://github.com/kubernetes/committee-security-response/tree/main)
- [A Bug’s-Eye View: Kubernetes SIG Security Explains It... Ian C, Tabitha S, Rory M, Iain S & Mahé T](https://youtu.be/ujnqeWQZ17w?t=710) from link start time stamp 11:50-21:15
## Why this tool exists: SRC Vulnerability Disclosure Workflow

### Understanding the workflow.

**Step 1:** The [Private Distributors List](https://github.com/kubernetes/committee-security-response/blob/main/security-release-process.md#private-distributors-list) will be given advance notification of any vulnerability that is assigned a CVE, at least 7 days before the planned public disclosure date.

**Step 2:** Releasing the fix.

**Step 3:** Public Disclosure

The announcement will contain the following information:
- The new releases, the CVE number, severity, and impact, and the location of the binaries to get wide distribution and user action.
- As much as possible this announcement should be actionable, and include any mitigating steps users can take prior to upgrading to a fixed version. 

The announcement will be sent via the following channels:
- General announcement email ([template](https://github.com/kubernetes/committee-security-response/blob/main/comms-templates/vulnerability-announcement-email.md)) to multiple Kubernetes lists
- OSS-Security announcement email ([template](https://github.com/kubernetes/committee-security-response/blob/main/comms-templates/vulnerability-announcement-email.md)) to `oss-security@lists.openwall.com`
- `#announcements` slack channel ([template](https://github.com/kubernetes/committee-security-response/blob/main/comms-templates/vulnerability-announcement-slack.md))
- [discuss.kubernetes.io](https://discuss.kubernetes.io/c/announcements) forum (this should be posted automatically using the general announcement email template)
- Tracking issue opened in [https://github.com/kubernetes/kubernetes/issues](https://github.com/kubernetes/kubernetes/issues) ([template](https://github.com/kubernetes/committee-security-response/blob/main/comms-templates/vulnerability-announcement-issue.md)) and prefixed with the associated CVE ID (if applicable). Add `/label official-cve-feed` so it will be part of [https://kubernetes.io/docs/reference/issues-security/official-cve-feed/](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/). Close the issue after the announcement is made.
    - Once all communications are sent, fixes are released, and the CVE data has been populated, close out the public tracking issue.
- Medium and Low severity vulnerability fixes that will be released as part of the next Kubernetes [patch release](https://github.com/kubernetes/website/blob/main/content/en/releases/patch-releases.md) will have the fix details included in the patch release notes. Any public announcement sent for these fixes will link to the release notes.
- For Kubernetes core components that are part of a Kubernetes release, provide the CVE feed yaml to the release team, [https://github.com/kubernetes/sig-release/blob/master/release-engineering/role-handbooks/branch-manager.md#announcing-security-fixes](https://github.com/kubernetes/sig-release/blob/master/release-engineering/role-handbooks/branch-manager.md#announcing-security-fixes)
- After public disclosure, [populate CVE details as soon as possible](https://github.com/kubernetes/committee-security-response/blob/main/cna-handbook.md#populate-cve-details-after-public-disclosure)

For more details see:
- https://github.com/kubernetes/committee-security-response/blob/main/security-release-process.md#fix-disclosure-process

### What the problem was.

Vulnerability disclosure needed to be consistently reproduced (no copy paste errors) many times across many communication channels (so reproduce according to many different templates). Additionally, there was need for a more machine friendly OSV feed and SRC is busy enough as can be seen.

Reducing the report creation workflow to a single writeup process paired with easy automated export processes for the relevant target formats was best to save SRC work, reduce error, and improve usability for the security ecosystem (stable machine-readability). This also makes additional potential channels and formats in the future more approachable.

## Command Usage

### CLI Options

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

Notes regarding the file name provided as an argument:
- must match the following regex expression: `^CVE-\d{4}-\d{4,}$`
- is valid with or without the ext which is trimmed off
- if a file with the given valid name
	- does exist in the current directory and the content is fine: the tool will act on the given file
	- does not exist or can't be read by the tool: the tool will create a file with that name and act on that file

Notes on potential problems
- incorrect file name error msg: `invalid CVE name`
- invalid file provided: `error: failed to restore state from file {file name given}: {parsing error}`
- unable to find editor provided at env-var `$EDITOR` in `$PATH`: `failed to read from editor: failed to run the editor: {execution error}`
- unable to run editor provided in PATH at `$EDITOR`

### Additional Usage Explanation

Purpose: For editing particular sections of the report.
Usage Step: Input from the cli process launched with the tool: `0-9` or letters `a-b`

Purpose: For saving changed to the report.
Usage Step: Input from the cli process launched with the tool: `s`
Note:
- The tool generates a tmp file which the user operates on in place of the target file during editing so exiting the cli process without telling the tool to save even if saving was done in text editor is not enough. The reasoning here is editing is done back and forth between editor and tool here to work on different sections in isolation easily.

Purpose: For exporting to any supported format.
Supported Formats:
- github issue: [issue.tmpl src](https://github.com/kubernetes/sig-security/blob/main/sig-security-tooling/srctl/state/issue.tmpl)
- email: [email.tmpl src](https://github.com/kubernetes/sig-security/blob/main/sig-security-tooling/srctl/state/email.tmpl)
- slack: [slack.tmpl src](https://github.com/kubernetes/sig-security/blob/main/sig-security-tooling/srctl/state/slack.tmpl)
Usage Steps:
1. Input from the cli process launched with the tool: `e`
2. Input from the cli process launched with the tool: one of `i` issue `m` mail `s` slack `a` all
Note:
- Saving to a JSON file for session state persistence is possible but not a proper disclosure export.
- The json OSV ([OSV schema](https://ossf.github.io/osv-schema/)) is automatically built for the GitHub Issue.

### Usage Example

The first example of `srctl` in action was this CVE on which Tabitha used the new tool: https://github.com/kubernetes/kubernetes/issues/136680.

## Implementation

[tooling: add new CLI for CVE publication by SRC members #171](https://github.com/kubernetes/sig-security/pull/171)
[`srctl` source directory](https://github.com/kubernetes/sig-security/tree/main/sig-security-tooling/srctl)
