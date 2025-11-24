_Use this issue template for filling out CVE placeholder issues._

TITLE: `CVE-####-######: $SUMMARY`

---

<!-- Copy URL after # as the link text -->
CVSS Rating: [CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L](https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L)

_Description of vulnerability_

<!-- Copy these sections from the announcement email -->

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
**ACTION REQUIRED:** The following steps must be taken to mitigate this
vulnerability: ...

_(If possible):_ Prior to upgrading, this vulnerability can be mitigated by ...

#### Fixed Versions

<!-- Add links to PRs & main/master branch -->
- $COMPONENT main/master - fixed by #12345678
- ...

_(If fix has side effects)_ **Fix impact:** details of impact.

To upgrade, refer to the documentation: ... ($COMPONENT upgrade documentation)

_For core Kubernetes:_ https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade

### Detection

_How can exploitation of this vulnerability be detected?_

If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io

## Additional Details

_Optional details:_
- Vulnerability background
- Technical explanation of vulnerability and/or fix
- Reproduction steps (avoid disclosing unnecessary details)

#### Acknowledgements

This vulnerability was reported by $REPORTER.

_(optional):_ The issue was fixed and coordinated by $FIXTEAM and $RELEASE_MANAGERS.

<!-- labels -->
/area security
/kind bug
/committee security-response
/label official-cve-feed
/sig $RELEVANT_SIGS
/area $IMPACTED_COMPONENTS