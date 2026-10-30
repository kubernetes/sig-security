package vexflow

import "time"

// VexflowIssue describes an issue to be created in kubernetes/.vexflow.
type VexflowIssue struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`

	SourceRepo  string             `json:"source_repo"`
	SourceIssue int                `json:"source_issue_number"`
	SourceURL   string             `json:"source_url"`
	Sources     []SourceAssessment `json:"sources"`

	CVEIDs                []string         `json:"cve_ids"`
	Component             *Component       `json:"component,omitempty"`
	Justification         string           `json:"justification,omitempty"`
	JustificationDetails  string           `json:"justification_details,omitempty"`
	JustificationConflict bool             `json:"justification_conflict,omitempty"`
	VexflowData           *VexflowMetadata `json:"vexflow_data,omitempty"`
}

// SourceAssessment retains each source issue's assessment, even when sources disagree.
type SourceAssessment struct {
	Number               int    `json:"number"`
	URL                  string `json:"url"`
	Justification        string `json:"justification,omitempty"`
	JustificationDetails string `json:"justification_details,omitempty"`
}

// Component identifies the component recorded in vexflow metadata.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// VexflowMetadata is embedded in the issue body between VEXFLOW==DATA markers.
type VexflowMetadata struct {
	BranchID      string             `json:"branch_id"`
	BackendID     string             `json:"backend_id"`
	Vulnerability *VulnerabilityInfo `json:"vulnerability"`
	Branch        *BranchInfo        `json:"branch"`
	Status        string             `json:"status"`
	CreatedAt     *time.Time         `json:"created_at,omitempty"`
}

type VulnerabilityInfo struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Component *Component `json:"component"`
}

type BranchInfo struct {
	Repo string `json:"repo"`
	Name string `json:"name"`
}

// VexflowIssueList is the JSON export containing proposed issues and a summary.
type VexflowIssueList struct {
	Issues   []*VexflowIssue `json:"issues"`
	Summary  *Summary        `json:"summary"`
	Metadata *Metadata       `json:"metadata"`
}

type Summary struct {
	TotalIssues           int            `json:"total_issues"`
	UniqueCVEs            int            `json:"unique_cves"`
	UniqueComponents      int            `json:"unique_components"`
	ConflictingIssues     int            `json:"conflicting_issues"`
	IssuesByJustification map[string]int `json:"issues_by_justification"`
	CVEIDCounts           map[string]int `json:"cve_id_counts"` // number of source issues mentioning each CVE
}

type Metadata struct {
	GeneratedAt  time.Time `json:"generated_at"`
	SourceRepo   string    `json:"source_repo"`
	VexflowRepo  string    `json:"vexflow_repo"`
	TargetBranch string    `json:"target_branch"`
	Label        string    `json:"label"`
}
