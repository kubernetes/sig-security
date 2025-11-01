package main

import (
	"fmt"
	"strings"
)

type Steps struct {
	Summary           Step
	CVSS              Step
	Description       Step
	Vulnerable        Step
	AffectedVersions  Step
	FixedVersions     Step
	Mitigate          Step
	Detection         Step
	AdditionalDetails Step
	Acknowledgements  Step
}

type Step struct {
	Value string `json:"value"`

	// Read-only fields
	ID    StepNumber `json:"id"`
	Title string     `json:"title"`

	// Unexported fields
	Example     string             `json:"-"`
	Help        string             `json:"-"`
	Placeholder string             `json:"-"`
	Validate    func(string) error `json:"-"`
	Multiline   bool
}

type StepNumber int

func (s StepNumber) ASCII() byte {
	return byte(s) + '0'
}

func (s StepNumber) String() string {
	switch s {
	case stepSummary:
		return "summary"
	case stepCVSS:
		return "cvss"
	case stepDescription:
		return "description"
	case stepVulnerable:
		return "vulnerable"
	case stepAffectedVersions:
		return "affected_versions"
	case stepFixedVersions:
		return "fixed_versions"
	case stepMitigate:
		return "mitigate"
	case stepDetection:
		return "detection"
	case stepAdditionalDetails:
		return "additional_details"
	case stepAcknowledgements:
		return "acknowledgements"
	case stepMax:
		fallthrough
	default:
		panic("this is a bug, please report")
	}
}

const (
	stepSummary StepNumber = iota
	stepCVSS
	stepDescription
	stepVulnerable
	stepAffectedVersions
	stepFixedVersions
	stepMitigate
	stepDetection
	stepAdditionalDetails
	stepAcknowledgements
	stepMax
)

// Compile time check that stepMax is <=10
var _ [10 - stepMax]int

var initSteps = map[string]Step{
	stepSummary.String(): {
		ID:      stepSummary,
		Title:   "Summary",
		Help:    "This is the summary of the CVE used in the issue title",
		Example: "Buffer overflow in whatever allows remote code execution",
		Validate: func(summary string) error {
			if strings.Contains(summary, "\n") {
				return fmt.Errorf("invalid summary, should contain only one line")
			}
			return nil
		},
	},
	stepCVSS.String(): {
		ID:    stepCVSS,
		Title: "CVSS",
		Help: `Go on https://www.first.org/cvss/calculator/3-0#CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L
Adjust the ratings for each sections and copy the resulting URL`,
		Example: "https://www.first.org/cvss/calculator/3-0#CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
	},
	stepDescription.String(): {
		ID:        stepDescription,
		Title:     "Description",
		Multiline: true,
		Help:      "Please provide the description of the vulnerability",
		Example: `A vulnerability exists in the Kubernetes C# client where the certificate
validation logic accepts properly constructed certificates from any Certificate
Authority (CA) without properly verifying the trust chain. This flaw allows a
malicious actor to present a forged certificate and potentially intercept or
manipulate communication with the Kubernetes API server, leading to possible
man-in-the-middle attacks and API impersonation.`,
	},
	stepVulnerable.String(): {
		ID:        stepVulnerable,
		Title:     "Am I vulnerable?",
		Multiline: true,
		Help: `How to determine if a cluster is impacted.
Include:
- Vulnerable configuration details
- Commands that indicate whether a component, version or configuration is used`,
		Example: `To check if tokens are being logged, examine the manager container log:
` + "```" + `shell
kubectl logs -l 'app.kubernetes.io/part-of=secrets-store-sync-controller' -c manager -f | grep --line-buffered "csi.storage.k8s.io/serviceAccount.tokens"
` + "```",
	},
	stepAffectedVersions.String(): {
		ID:        stepAffectedVersions,
		Title:     "Affected Versions",
		Multiline: true,
		Help: `- $COMPONENT $VERSION_RANGE_1
- $COMPONENT $VERSION_RANGE_2 ...
- ...`,
		Example: `kube-apiserver: <= v1.31.11
kube-apiserver: <= v1.32.7
kube-apiserver: <= v1.33.3`,
	},
	stepFixedVersions.String(): {
		ID:        stepFixedVersions,
		Title:     "Fixed Versions",
		Multiline: true,
		Help: `- $COMPONENT $VERSION
- $COMPONENT $VERSION
- ...

_(If fix has side effects)_ **Fix impact:** details of impact.

To upgrade, refer to the documentation: ... ($COMPONENT upgrade documentation)

_For core Kubernetes:_ https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/`,
		Example: `kube-apiserver: >= v1.31.12
kube-apiserver: >= v1.32.8
kube-apiserver: >= v1.33.4`,
	},
	stepMitigate.String(): {
		ID:        stepMitigate,
		Title:     "How do I mitigate this vulnerability?",
		Multiline: true,
		Help: `(If additional steps required after upgrade)
**ACTION REQUIRED:** The following steps must be taken to mitigate this vulnerability: ...

(If possible): Prior to upgrading, this vulnerability can be mitigated by ...`,
		Example: `This issue can be mitigated by upgrading to a kube-apiserver binary running one
of patched minor versions for 1.31 through 1.33 listed below. These fixed
versions have added functionality to the NodeRestriction admission controller to
prevent node users from modifying their own OwnerReferences.

Alternatively, this vulnerability can be mitigated by enabling the
OwnerReferencesPermissionEnforcement admission controller, which will prevent
any user without delete permissions on an object from modifying the
OwnerReferences on that object. Note that this admission controller will apply
to all users and object types.`,
	},
	stepDetection.String(): {
		ID:        stepDetection,
		Title:     "Detection",
		Multiline: true,
		Help: `_How can exploitation of this vulnerability be detected?_

If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io`,
		Example: `This issue can be detected on clusters which have NodeRestriction but not OwnerReferencesPermissionEnforcement enabled by analyzing API audit logs for node patch requests issued by node users which modify OwnerReferences. In normal operation, a Kubelet will never issue a patch request which modifies its own OwnerReferences.

If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io`,
	},
	stepAdditionalDetails.String(): {
		ID:        stepAdditionalDetails,
		Title:     "Additional Details",
		Multiline: true,
	},
	stepAcknowledgements.String(): {
		ID:        stepAcknowledgements,
		Title:     "Acknowledgements",
		Multiline: true,
		Help: `This vulnerability was reported by $REPORTER.

_(optional):_ The issue was fixed and coordinated by $FIXTEAM and $RELEASE_MANAGERS.

Thank You,

$PERSON on behalf of the Kubernetes Security Response Committee`,
		Example: `This vulnerability was reported by Paul Viossat.

The issue was fixed and coordinated by:

Sergey Kanzhelev @SergeyKanzhelev
Jordan Liggitt @liggitt
Marko Mudrinić @xmudrii`,
	},
}
