package vexflow

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/cve"
)

// BuildVexflowMetadata constructs the vexflow metadata for an issue
// based on a CVE and component information.
func BuildVexflowMetadata(cveID string, component *Component, branchID string, now time.Time) *VexflowMetadata {
	if component == nil {
		// Create a default golang component for kubernetes
		component = &Component{
			Type:    "golang",
			Name:    "k8s.io/kubernetes",
			Version: "master",
			PURL:    "pkg:golang/k8s.io/kubernetes@master",
		}
	}
	if branchID == "" {
		branchID = fmt.Sprintf("%s@%s", DefaultKubernetesRepo, DefaultTargetBranch)
	}

	return &VexflowMetadata{
		BranchID:  branchID,
		BackendID: "",
		Vulnerability: &VulnerabilityInfo{
			ID:        cveID,
			Aliases:   []string{cveID},
			Component: component,
		},
		Branch: &BranchInfo{
			Repo: DefaultKubernetesRepo,
			Name: DefaultTargetBranch,
		},
		Status:    "WAITING_USER",
		CreatedAt: &now,
	}
}

// GenerateVexflowIssueBody creates the issue body with embedded vexflow metadata
// and human-readable instructions.
func GenerateVexflowIssueBody(cveID string, metadata *VexflowMetadata, sourceURL string, sourceIssueNumber int) (string, error) {
	// Marshal the metadata to JSON
	data, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("marshaling vexflow metadata: %w", err)
	}

	// Create the embedded data section
	embed := fmt.Sprintf("<!--\n%s\n%s\n%s\n-->\n",
		VexflowDataSeparator, string(data), VexflowDataSeparator)

	// Build the issue body with instructions
	backtick := "`"
	body := fmt.Sprintf(
		`# Exploitability triage for %s

This issue tracks the exploitability triage process for `+backtick+`%s`+backtick+`.

Based on the outcome of this issue, VEX (vulnerability exploitability exchange) data will be published to describe the impact on the project.

## Triage Information

| Field | Value |
|-------|-------|
| **Vulnerability** | %s |
| **Repository** | %s |
| **Branch** | %s |
| **Component** | %s |
| **Source Issue** | [kubernetes/kubernetes#%d](%s) |

## Triage Instructions

If you are an authorized maintainer, comment on this issue to signal the vexflow client how to move forward.

First, determine if the vulnerability affects the project branch, and follow the relevant section below.

### Not Affected

If the vulnerability does not impact the software project branch, issue a `+backtick+`not_affected`+backtick+` statement. Follow the slash command with one of the VEX justification labels. Any extra text will be treated as the VEX impact statement.

`+backtick+backtick+backtick+`
/not_affected:component_not_present
/not_affected:vulnerable_code_not_present
/not_affected:vulnerable_code_not_in_execute_path
/not_affected:vulnerable_code_cannot_be_controlled_by_adversary
/not_affected:inline_mitigations_already_exist
`+backtick+backtick+backtick+`

**Example Comment:**

> /not_affected:inline_mitigations_already_exist
> The released artifacts have been patched with a custom fix, the vulnerability is no longer present.

### Affected

To assess that the project _is_ affected by a vulnerability, issue an `+backtick+`affected`+backtick+` statement. Any text after the slash command will be treated as the action_statement to be published along the status:

`+backtick+backtick+backtick+`
/affected Upgrade to version X.Y.Z or later, see [kubernetes/kubernetes#%d](%s) for details.
`+backtick+backtick+backtick+`

### Fixed

For completeness, you can issue a `+backtick+`fixed`+backtick+` statement:

`+backtick+backtick+backtick+`
/fixed
`+backtick+backtick+backtick+`

## Note

> [!NOTE]
> This issue's body contains hidden machine-readable data to keep track of the triage process.
> Don't modify the data section below.

%s
`,
		cveID, cveID, // Title and intro
		cveID, // Table vulnerability
		metadata.Branch.Repo,
		metadata.Branch.Name,
		metadata.Vulnerability.Component.PURL,
		sourceIssueNumber, sourceURL, // Source issue link (placeholder for issue number)
		sourceIssueNumber, sourceURL, // Affected example
		embed,
	)

	return body, nil
}

// RenderVexflowIssue creates a complete VexflowIssue from kubernetes/kubernetes issue data
func RenderVexflowIssue(sourceNumber int, sourceURL string, comments []string, cveID string, component *Component, branchID string, now time.Time) (*VexflowIssue, error) {
	// Extract justification from comments
	justification, justificationDetails := cve.ExtractJustification(comments)

	// Build vexflow metadata
	metadata := BuildVexflowMetadata(cveID, component, branchID, now)

	// Generate issue body
	body, err := GenerateVexflowIssueBody(cveID, metadata, sourceURL, sourceNumber)
	if err != nil {
		return nil, err
	}

	return &VexflowIssue{
		Title:                cveID,
		Body:                 body,
		Labels:               []string{"vex-unaffected-feed"},
		SourceRepo:           DefaultKubernetesRepo,
		SourceIssue:          sourceNumber,
		SourceURL:            sourceURL,
		Sources:              []SourceAssessment{{Number: sourceNumber, URL: sourceURL, Justification: justification, JustificationDetails: justificationDetails}},
		CVEIDs:               []string{cveID},
		Component:            metadata.Vulnerability.Component,
		Justification:        justification,
		JustificationDetails: justificationDetails,
		VexflowData:          metadata,
	}, nil
}
