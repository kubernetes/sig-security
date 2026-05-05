package state

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	StepSummary StepNumber = iota
	StepCVSS
	StepDescription
	StepVulnerable
	StepAffectedVersions
	StepUpgrade
	StepMitigate
	StepDetection
	StepAdditionalDetails
	StepAcknowledgements
	StepGitHubIssue
	StepFixLead
	StepMax
)

// Compile time check that stepMax is <=12 (0-9 + a-b).
var _ [12 - StepMax]int

type StepNumber int

func (s StepNumber) ASCII() byte {
	if s < 0 || s > 35 {
		panic(fmt.Sprintf("this is a bug, please report: StepNumber.ToChar: value %d out of valid range [0, 35]", s))
	}
	if s < 10 {
		return byte(s) + '0'
	}
	return byte(s-10) + 'a'
}

// StepNumberFromASCII converts an ASCII character to a StepNumber.
// Returns -1 if the character is not a valid step key.
func StepNumberFromASCII(b byte) StepNumber {
	switch {
	case b >= '0' && b <= '9':
		return StepNumber(b - '0')
	case b >= 'a' && b <= 'b':
		return StepNumber(b - 'a' + 10)
	case b >= 'A' && b <= 'B':
		return StepNumber(b - 'A' + 10)
	default:
		return -1
	}
}

type StepName = string

func (s StepNumber) Name() StepName {
	switch s {
	case StepSummary:
		return "summary"
	case StepCVSS:
		return "cvss"
	case StepDescription:
		return "description"
	case StepVulnerable:
		return "vulnerable"
	case StepAffectedVersions:
		return "affected_versions"
	case StepUpgrade:
		return "upgrade"
	case StepMitigate:
		return "mitigate"
	case StepDetection:
		return "detection"
	case StepAdditionalDetails:
		return "additional_details"
	case StepAcknowledgements:
		return "acknowledgements"
	case StepGitHubIssue:
		return "github_issue"
	case StepFixLead:
		return "fix_lead"
	case StepMax:
		fallthrough
	default:
		panic("this is a bug, please report")
	}
}

type Step struct {
	Value string

	// Unexported fields
	ID          StepNumber
	Title       string
	Example     string
	Help        string
	Placeholder string
	Markdown    bool
	Validate    func(string) error
	PrePopulate func() string
}

var initSteps = map[StepName]Step{
	StepSummary.Name(): {
		ID:      StepSummary,
		Title:   "Summary",
		Help:    "This is the summary of the CVE used in the issue title",
		Example: "Buffer overflow in whatever allows remote code execution",
		Validate: func(summary string) error {
			if strings.Contains(summary, "\n") {
				return errors.New("invalid summary, should contain only one line")
			}
			return nil
		},
	},
	StepCVSS.Name(): {
		ID:    StepCVSS,
		Title: "CVSS",
		Help: `Go on https://www.first.org/cvss/calculator/3-0#CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L,
adjust the ratings for each sections and copy the resulting URL`,
		Example: "https://www.first.org/cvss/calculator/3-0#CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
	},
	StepDescription.Name(): {
		ID:       StepDescription,
		Title:    "Description",
		Markdown: true,
		Help:     "Please provide the description of the vulnerability",
		Example: `A vulnerability exists in the Kubernetes C# client where the certificate
validation logic accepts properly constructed certificates from any Certificate
Authority (CA) without properly verifying the trust chain. This flaw allows a
malicious actor to present a forged certificate and potentially intercept or
manipulate communication with the Kubernetes API server, leading to possible
man-in-the-middle attacks and API impersonation.`,
	},
	StepVulnerable.Name(): {
		ID:       StepVulnerable,
		Title:    "Am I vulnerable?",
		Markdown: true,
		Help: `How to determine if a cluster is impacted. Include:
- Vulnerable configuration details
- Commands that indicate whether a component, version or configuration is used`,
		Example: `To check if tokens are being logged, examine the manager container log:
` + "```" + `shell
kubectl logs -l 'app.kubernetes.io/part-of=secrets-store-sync-controller' -c manager -f | grep --line-buffered "csi.storage.k8s.io/serviceAccount.tokens"
` + "```",
	},
	StepAffectedVersions.Name(): {
		ID:    StepAffectedVersions,
		Title: "Affected Versions",
		Help: `component [introduced] < fixedVersion
component [introduced] < fixedVersion
[...]

Component should be identical for every lines, introduced version is optional
and fixedVersion is required`,
		Example: `kube-apiserver < v1.31.12
kube-apiserver < v1.32.8
kube-apiserver < v1.33.4`,
		Validate: func(input string) error {
			_, err := parseAffectedVersions(input)
			if err != nil {
				return err
			}
			return nil
		},
	},
	StepUpgrade.Name(): {
		ID:       StepUpgrade,
		Title:    "How to upgrade?",
		Markdown: true,
		Help: `To upgrade, refer to the documentation: ... ($COMPONENT upgrade documentation)

_For core Kubernetes:_ https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/

_(If fix has side effects)_ **Fix impact:** details of impact.`,
		Example: `TODO`,
	},
	StepMitigate.Name(): {
		ID:       StepMitigate,
		Title:    "How to mitigate?",
		Markdown: true,
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
	StepDetection.Name(): {
		ID:       StepDetection,
		Title:    "Detection",
		Markdown: true,
		Help:     "Explain how can exploitation of this vulnerability be detected.",
		Example: `This issue can be detected on clusters which have NodeRestriction but not
OwnerReferencesPermissionEnforcement enabled by analyzing API audit logs for
node patch requests issued by node users which modify OwnerReferences. In normal
operation, a Kubelet will never issue a patch request which modifies its own
OwnerReferences.`,
	},
	StepAdditionalDetails.Name(): {
		ID:       StepAdditionalDetails,
		Title:    "Additional Details",
		Markdown: true,
		Help:     "Add any additional details that don't fit in other sections.",
	},
	StepAcknowledgements.Name(): {
		ID:       StepAcknowledgements,
		Title:    "Acknowledgements",
		Markdown: true,
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
	StepGitHubIssue.Name(): {
		ID:      StepGitHubIssue,
		Title:   "GitHub Issue",
		Help:    "The full GitHub issue URL for this CVE",
		Example: "https://github.com/kubernetes/kubernetes/issues/136680",
		Validate: func(issueURL string) error {
			if issueURL == "" {
				return nil
			}
			_, err := parseGitHubIssueURL(issueURL)
			return err
		},
	},
	StepFixLead.Name(): {
		ID:    StepFixLead,
		Title: "Fix Lead",
		Help: `The name of the person issuing the CVE announcement from the SRC (used to sign
the in email template)`,
		Example: "Tabitha Sable",
		PrePopulate: func() string {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			cmd := exec.CommandContext(ctx, "git", "config", "user.name")
			out, err := cmd.Output()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(out))
		},
		Validate: func(name string) error {
			if strings.Contains(name, "\n") {
				return errors.New("invalid fix lead name, should contain only one line")
			}
			return nil
		},
	},
}
