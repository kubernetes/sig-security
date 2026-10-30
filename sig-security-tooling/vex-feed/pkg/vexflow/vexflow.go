// Package vexflow prepares issue bodies and metadata for vexflow triage.
package vexflow

import "fmt"

const (
	// DefaultKubernetesRepo is the source repository.
	DefaultKubernetesRepo = "github.com/kubernetes/kubernetes"

	// DefaultVexflowRepo is the target repository for vexflow issues.
	DefaultVexflowRepo = "github.com/kubernetes/.vexflow"

	// DefaultTargetBranch is the branch we're creating VEX data for.
	DefaultTargetBranch = "master"

	// DefaultLabel is the label used to identify issues for vex feed.
	DefaultLabel = "vex-unaffected-feed"

	// VexflowDataSeparator is the HTML comment separator used by vexflow.
	VexflowDataSeparator = "### VEXFLOW==DATA ###"
)

// MergeSource records another source for the same branch, CVE, and component.
// Different (including missing) justifications require human review; the
// exported issue never presents a disputed justification as authoritative.
func (issue *VexflowIssue) MergeSource(other *VexflowIssue) {
	source := other.Sources[0]
	for _, existing := range issue.Sources {
		if existing.Number == source.Number && existing.URL == source.URL {
			return
		}
	}
	if len(issue.Sources) == 1 {
		issue.Body += "\n## Additional source issues\n"
	}
	issue.Body += fmt.Sprintf("\n- [kubernetes/kubernetes#%d](%s)\n", source.Number, source.URL)
	if source.Justification != issue.Sources[0].Justification && !issue.JustificationConflict {
		issue.JustificationConflict = true
		issue.Justification = ""
		issue.JustificationDetails = ""
		issue.Body += "\n> [!WARNING]\n> Source issues have differing or missing justifications. Review all sources before triage.\n"
	}
	issue.Sources = append(issue.Sources, source)
}
