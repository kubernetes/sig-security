// Package bridge collects source issues and builds proposed vexflow issues.
package bridge

import (
	"fmt"
	"log"
	"time"

	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/cve"
	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/github"
	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/vexflow"
)

// IssueFetcher is the source of issues for the bridge. Tests can supply a fake.
type IssueFetcher interface {
	SearchIssues(query string) ([]github.KubernetesIssue, error)
	GetIssueDetails(owner, repo string, issueNumber int) (*github.KubernetesIssue, error)
}

type issueRenderer func(sourceNumber int, sourceURL string, comments []string, cveID string, component *vexflow.Component, branchID string, now time.Time) (*vexflow.VexflowIssue, error)

// Collect builds a deduplicated list of proposed vexflow issues from source issues.
func Collect(fetcher IssueFetcher, sourceRepo, label string, maxResults int, now time.Time) (*vexflow.VexflowIssueList, error) {
	owner, repo, err := github.ParseOwnerRepo(sourceRepo)
	if err != nil {
		return nil, err
	}

	issues, err := fetcher.SearchIssues(github.BuildSearchQuery(sourceRepo, label))
	if err != nil {
		return nil, fmt.Errorf("searching for issues: %w", err)
	}

	result := &vexflow.VexflowIssueList{
		Issues: make([]*vexflow.VexflowIssue, 0),
		Summary: &vexflow.Summary{
			IssuesByJustification: make(map[string]int),
			CVEIDCounts:           make(map[string]int),
		},
		Metadata: &vexflow.Metadata{
			GeneratedAt:  now,
			SourceRepo:   sourceRepo,
			VexflowRepo:  "kubernetes/.vexflow",
			TargetBranch: vexflow.DefaultTargetBranch,
			Label:        label,
		},
	}
	components := make(map[string]struct{})
	// issueKey is is the unique identifier of a CVE per component and branch
	type issueKey struct{ branchID, cveID, purl string }
	// when several github issues have referenced the same `issueKey`, vexFlowIssueByKey will help us merge
	// the info into a single vexFlowIssue
	vexFlowIssueByKey := make(map[issueKey]*vexflow.VexflowIssue)

	for i, issue := range issues {
		if i >= maxResults {
			break
		}
		vexIssues, err := toVexIssues(fetcher, owner, repo, issue.Number, now, vexflow.RenderVexflowIssue)
		if err != nil {
			return nil, err
		}
		for _, proposed := range vexIssues {
			key := issueKey{proposed.VexflowData.BranchID, proposed.VexflowData.Vulnerability.ID, proposed.Component.PURL}
			if existing, ok := vexFlowIssueByKey[key]; ok {
				existing.MergeSource(proposed)
				continue
			}
			vexFlowIssueByKey[key] = proposed
			result.Issues = append(result.Issues, proposed)
			components[proposed.Component.PURL] = struct{}{}
		}
	}

	result.Summary.TotalIssues = len(vexFlowIssueByKey)
	result.Summary.UniqueComponents = len(components)
	for _, issue := range result.Issues {
		result.Summary.CVEIDCounts[issue.VexflowData.Vulnerability.ID] += len(issue.Sources)
		if issue.JustificationConflict {
			result.Summary.ConflictingIssues++
		} else if issue.Justification != "" {
			result.Summary.IssuesByJustification[issue.Justification]++
		}
	}
	result.Summary.UniqueCVEs = len(result.Summary.CVEIDCounts)
	return result, nil
}

func toVexIssues(fetcher IssueFetcher, owner, repo string, issueNumber int, now time.Time, render issueRenderer) ([]*vexflow.VexflowIssue, error) {
	issues := []*vexflow.VexflowIssue{}
	fullIssue, err := fetcher.GetIssueDetails(owner, repo, issueNumber)
	if err != nil {
		log.Printf("Warning: failed to get details for issue #%d: %v", issueNumber, err)
		return issues, nil
	}
	comments := make([]string, len(fullIssue.Comments))
	for j, comment := range fullIssue.Comments {
		comments[j] = comment.Body
	}
	for _, cveID := range cve.ExtractCVEs(fullIssue.Title, fullIssue.Body, comments) {
		component := &vexflow.Component{
			Type:    "golang",
			Name:    "k8s.io/kubernetes",
			Version: vexflow.DefaultTargetBranch,
			PURL:    "pkg:golang/k8s.io/kubernetes@master",
		}
		vexIssue, err := render(fullIssue.Number, fullIssue.URL, comments, cveID, component, "", now)
		if err != nil {
			return nil, fmt.Errorf("rendering issue #%d/%s: %w", fullIssue.Number, cveID, err)
		}
		issues = append(issues, vexIssue)
	}
	return issues, nil
}
