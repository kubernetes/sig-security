_Use this email template for publicly disclosing security vulnerabilities._

_The email should be **concise** and **actionable**. Assume the audience are not
Kubernetes developers. Non-actionable information (e.g. technical discussion of
the vulnerability) should be deferred to the [vulnerability
issue](vulnerability-announcement-issue.md)._

TO: `kubernetes-announce@googlegroups.com, dev@kubernetes.io, kubernetes-security-announce@googlegroups.com, kubernetes-security-discuss@googlegroups.com, distributors-announce@kubernetes.io`

SUBJECT: `[Security Advisory] $CVE: $SUMMARY`

_A separate email should be sent for `oss-security@lists.openwall.com`, with `[kubernetes]` in the subject:_

TO: `oss-security@lists.openwall.com`

SUBJECT: `[kubernetes] $CVE: $SUMMARY`

_A separate email should be sent to the forum from the `security@kubernetes.io` Google group and cc `kubernetes+announcements@discoursemail.com`:_

TO: `security@kubernetes.io`
cc: `kubernetes+announcements@discoursemail.com`

SUBJECT: `[Security Advisory] $CVE: $SUMMARY`

_See [Fix disclosure process](security-release-process.md#fix-disclosure-process) for additional places the announcement should be posted._

---

Hello Kubernetes Community,

A security issue was discovered in Kubernetes where $ACTOR may be able to $DO_SOMETHING.

This issue has been rated **$SEVERITY** (link to CVSS calculator https://www.first.org/cvss/calculator/3.1) (optional: $SCORE), and assigned **$CVE_NUMBER**

### Am I vulnerable?

_How to determine if a cluster is impacted. Include:_
- _Vulnerable configuration details_
- _Commands that indicate whether a component, version or configuration is used_

#### Affected Versions

- $COMPONENT $VERSION_RANGE_1
- $COMPONENT $VERSION_RANGE_2 ...
- ...

### How do I mitigate this vulnerability?

_(If additional steps required after upgrade)_
**ACTION REQUIRED:** The following steps must be taken to mitigate this vulnerability: ...

_(If possible):_ Prior to upgrading, this vulnerability can be mitigated by ...

#### Fixed Versions

- $COMPONENT $VERSION
- $COMPONENT $VERSION
- ...

_(If fix has side effects)_ **Fix impact:** details of impact.

To upgrade, refer to the documentation: ... ($COMPONENT upgrade documentation)

_For core Kubernetes:_ https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/

### Detection

_How can exploitation of this vulnerability be detected?_

If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io

#### Additional Details

See the GitHub issue for more details: $GITHUBISSUEURL

#### Acknowledgements

This vulnerability was reported by $REPORTER.

_(optional):_ The issue was fixed and coordinated by $FIXTEAM and $RELEASE_MANAGERS.

Thank You,

$PERSON on behalf of the Kubernetes Security Response Committee