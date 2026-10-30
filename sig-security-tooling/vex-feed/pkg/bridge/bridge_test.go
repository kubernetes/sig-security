package bridge

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/github"
	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/vexflow"
)

type fakeFetcher struct {
	issues  []github.KubernetesIssue
	details map[int]*github.KubernetesIssue
	query   string
	err     error
}

func (f *fakeFetcher) SearchIssues(query string) ([]github.KubernetesIssue, error) {
	f.query = query
	return f.issues, f.err
}

func (f *fakeFetcher) GetIssueDetails(owner, repo string, number int) (*github.KubernetesIssue, error) {
	if owner != "kubernetes" || repo != "kubernetes" {
		return nil, errors.New("wrong source repository")
	}
	issue, ok := f.details[number]
	if !ok {
		return nil, errors.New("issue not found")
	}
	return issue, nil
}

func TestCollect(t *testing.T) {
	const shared = "CVE-2026-12345"
	tests := []struct {
		name       string
		fetcher    *fakeFetcher
		repo       string
		maxResults int
		wantErr    string
		want       vexflow.Summary
		check      func(*testing.T, *vexflow.VexflowIssueList)
	}{
		{
			name: "nominal case - 2 issues with a CVE each",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 12}, {Number: 13}},
				details: map[int]*github.KubernetesIssue{
					12: {
						Number: 12, Title: "CVE-2026-12345",
						URL:      "https://github.com/kubernetes/kubernetes/issues/12",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present\nAbsent from Kubernetes."}},
					},
					13: {
						Number: 13, Title: "CVE-2026-67890",
						URL:      "https://github.com/kubernetes/kubernetes/issues/13",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present\nAbsent from Kubernetes."}},
					},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 2, UniqueCVEs: 2, UniqueComponents: 1,
				CVEIDCounts:           map[string]int{"CVE-2026-12345": 1, "CVE-2026-67890": 1},
				IssuesByJustification: map[string]int{"component_not_present": 2},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				proposal := output.Issues[0]
				if proposal.SourceIssue != 12 || proposal.Justification != "component_not_present" {
					t.Errorf("unexpected issue: %+v", proposal)
				}
				if proposal.VexflowData.BranchID != "github.com/kubernetes/kubernetes@master" {
					t.Errorf("unexpected branch ID: %q", proposal.VexflowData.BranchID)
				}
				if !strings.Contains(proposal.Body, "### VEXFLOW==DATA ###") ||
					!strings.Contains(proposal.Body, "github.com/kubernetes/kubernetes/issues/12") {
					t.Error("issue body missing embedded metadata or source link")
				}
				data, err := json.Marshal(output)
				if err != nil || !json.Valid(data) {
					t.Fatalf("invalid JSON output: %v", err)
				}
			},
		},
		{
			name: "comments without justifications (the k/k case)",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}},
				details: map[int]*github.KubernetesIssue{
					21: {
						Number: 21, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/21",
						Comments: []github.Comment{{Body: "This CVE has been investigated, but no determination yet."}},
					},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 1, UniqueCVEs: 1, UniqueComponents: 1,
				CVEIDCounts: map[string]int{shared: 1}, IssuesByJustification: map[string]int{},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				proposal := output.Issues[0]
				if proposal.Justification != "" || proposal.JustificationDetails != "" || proposal.JustificationConflict ||
					len(proposal.Sources) != 1 || proposal.Sources[0].Justification != "" {
					t.Errorf("missing justification should not be inferred: %+v", proposal)
				}
			},
		},
		{
			name:    "search error",
			fetcher: &fakeFetcher{err: errors.New("search failed")},
			wantErr: "search failed",
		},
		{
			name: "issue details error skips source and continues",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}, {Number: 22}},
				details: map[int]*github.KubernetesIssue{
					22: {Number: 22, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/22"},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 1, UniqueCVEs: 1, UniqueComponents: 1,
				CVEIDCounts: map[string]int{shared: 1}, IssuesByJustification: map[string]int{},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				if output.Issues[0].SourceIssue != 22 {
					t.Errorf("failed issue should be skipped: %+v", output.Issues[0])
				}
			},
		},
		{
			name:    "invalid repository",
			fetcher: &fakeFetcher{},
			repo:    "not-a-repo",
			wantErr: "invalid repo format",
		},

		{
			name: "source issue with no CVE",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}},
				details: map[int]*github.KubernetesIssue{
					21: {Number: 21, Title: "Unrelated issue"},
				},
			},
			want: vexflow.Summary{
				CVEIDCounts: map[string]int{}, IssuesByJustification: map[string]int{},
			},
		},
		{
			// TODO: we need to think how we treat cases where there are too many results from the query.
			// At the moment, we loop on all pages from the github results, and add all of them to the list, up until maxResults.
			// but this should be done differently in the future
			name: "limits source issues, not generated proposals",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 12}, {Number: 13}},
				details: map[int]*github.KubernetesIssue{
					12: {
						Number: 12, Title: shared, Body: "also CVE-2026-23456",
						URL:      "https://github.com/kubernetes/kubernetes/issues/12",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present\nAbsent from Kubernetes."}},
					},
					13: {Number: 13, Title: "CVE-2026-34567", URL: "https://github.com/kubernetes/kubernetes/issues/13"},
				},
			},
			maxResults: 1,
			want: vexflow.Summary{
				TotalIssues: 2, UniqueCVEs: 2, UniqueComponents: 1,
				CVEIDCounts:           map[string]int{shared: 1, "CVE-2026-23456": 1},
				IssuesByJustification: map[string]int{"component_not_present": 2},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				if output.Issues[0].SourceIssue != 12 || output.Issues[1].SourceIssue != 12 {
					t.Errorf("second source issue should not be processed: %+v", output.Issues)
				}
			},
		},
		{
			name: "conflicting justifications from multiple issues",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}, {Number: 22}},
				details: map[int]*github.KubernetesIssue{
					21: {
						Number: 21, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/21",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present\nNot included."}},
					},
					22: {
						Number: 22, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/22",
						Comments: []github.Comment{{Body: "/not_affected:vulnerable_code_not_in_execute_path\nNot reached."}},
					},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 1, UniqueCVEs: 1, UniqueComponents: 1, ConflictingIssues: 1,
				CVEIDCounts:           map[string]int{shared: 2},
				IssuesByJustification: map[string]int{},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				proposal := output.Issues[0]
				if proposal.Title != shared || len(proposal.Sources) != 2 ||
					proposal.Sources[0].Number != 21 || proposal.Sources[1].Number != 22 ||
					proposal.Sources[0].Justification != "component_not_present" ||
					proposal.Sources[1].Justification != "vulnerable_code_not_in_execute_path" {
					t.Fatalf("unexpected proposed issue: %+v", proposal)
				}
				if !proposal.JustificationConflict || proposal.Justification != "" || proposal.JustificationDetails != "" ||
					!strings.Contains(proposal.Body, "github.com/kubernetes/kubernetes/issues/21") ||
					!strings.Contains(proposal.Body, "github.com/kubernetes/kubernetes/issues/22") ||
					!strings.Contains(proposal.Body, "Review all sources") {
					t.Errorf("conflicting evidence was not retained or flagged: %+v", proposal)
				}
				parts := strings.Split(proposal.Body, "### VEXFLOW==DATA ###")
				if len(parts) != 3 || !json.Valid([]byte(strings.TrimSpace(parts[1]))) {
					t.Error("merged issue lost its embedded vexflow metadata")
				}
			},
		},
		{
			name: "overlapping CVE sets",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}, {Number: 22}},
				details: map[int]*github.KubernetesIssue{
					21: {Number: 21, Title: shared, Body: "CVE-2026-23456 and CVE-2026-12345", URL: "https://github.com/kubernetes/kubernetes/issues/21"},
					22: {Number: 22, Title: shared, Body: "CVE-2026-34567", URL: "https://github.com/kubernetes/kubernetes/issues/22"},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 3, UniqueCVEs: 3, UniqueComponents: 1,
				CVEIDCounts:           map[string]int{shared: 2, "CVE-2026-23456": 1, "CVE-2026-34567": 1},
				IssuesByJustification: map[string]int{},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				if output.Issues[0].Title != shared || len(output.Issues[0].Sources) != 2 ||
					output.Issues[1].Title != "CVE-2026-23456" || output.Issues[2].Title != "CVE-2026-34567" {
					t.Errorf("overlapping CVEs should merge without dropping distinct CVEs: %+v", output.Issues)
				}
			},
		},
		{
			name: "matching justifications retain both sources",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}, {Number: 22}},
				details: map[int]*github.KubernetesIssue{
					21: {
						Number: 21, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/21",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present\nMissing library."}},
					},
					22: {
						Number: 22, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/22",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present\nNot imported."}},
					},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 1, UniqueCVEs: 1, UniqueComponents: 1,
				CVEIDCounts:           map[string]int{shared: 2},
				IssuesByJustification: map[string]int{"component_not_present": 1},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				proposal := output.Issues[0]
				if proposal.Justification != "component_not_present" || len(proposal.Sources) != 2 ||
					proposal.Sources[0].JustificationDetails != "Missing library." ||
					proposal.Sources[1].JustificationDetails != "Not imported." {
					t.Errorf("matching assessments should retain both sources: %+v", proposal)
				}
			},
		},
		{
			name: "missing justification requires review",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}, {Number: 22}},
				details: map[int]*github.KubernetesIssue{
					21: {Number: 21, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/21"},
					22: {
						Number: 22, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/22",
						Comments: []github.Comment{{Body: "/not_affected:component_not_present"}},
					},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 1, UniqueCVEs: 1, UniqueComponents: 1, ConflictingIssues: 1,
				CVEIDCounts:           map[string]int{shared: 2},
				IssuesByJustification: map[string]int{},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				if !output.Issues[0].JustificationConflict || output.Issues[0].Justification != "" {
					t.Errorf("missing assessment should require review: %+v", output.Issues[0])
				}
			},
		},
		{
			name: "duplicate search result does not double-count source",
			fetcher: &fakeFetcher{
				issues: []github.KubernetesIssue{{Number: 21}, {Number: 21}},
				details: map[int]*github.KubernetesIssue{
					21: {Number: 21, Title: shared, URL: "https://github.com/kubernetes/kubernetes/issues/21"},
				},
			},
			want: vexflow.Summary{
				TotalIssues: 1, UniqueCVEs: 1, UniqueComponents: 1,
				CVEIDCounts:           map[string]int{shared: 1},
				IssuesByJustification: map[string]int{},
			},
			check: func(t *testing.T, output *vexflow.VexflowIssueList) {
				if len(output.Issues[0].Sources) != 1 {
					t.Errorf("duplicate search result should not duplicate source evidence: %+v", output.Issues[0])
				}
			},
		},
	}

	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := tt.repo
			if repo == "" {
				repo = "kubernetes/kubernetes"
			}
			maxResults := tt.maxResults
			if maxResults == 0 {
				maxResults = 10
			}
			output, err := Collect(tt.fetcher, repo, "vex-unaffected-feed", maxResults, now)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.fetcher.query != "is:issue label:vex-unaffected-feed repo:kubernetes/kubernetes" {
				t.Errorf("search query: %q", tt.fetcher.query)
			}
			if !reflect.DeepEqual(*output.Summary, tt.want) {
				t.Errorf("summary = %+v, want %+v", *output.Summary, tt.want)
			}
			if len(output.Issues) != tt.want.TotalIssues {
				t.Fatalf("got %d proposed issues, want %d", len(output.Issues), tt.want.TotalIssues)
			}
			if tt.check != nil {
				tt.check(t, output)
			}
		})
	}
}

func TestToVexIssues(t *testing.T) {
	renderErr := errors.New("render failed")
	tests := []struct {
		name              string
		issue             *github.KubernetesIssue
		render            issueRenderer
		wantCVEs          []string
		wantJustification string
		wantErr           error
	}{
		{
			name: "one CVE with a justification",
			issue: &github.KubernetesIssue{
				Number: 21,
				Title:  "CVE-2026-12345",
				URL:    "https://github.com/kubernetes/kubernetes/issues/21",
				Comments: []github.Comment{
					{Body: "/not_affected:component_not_present\nNot in Kubernetes."},
				},
			},
			wantCVEs:          []string{"CVE-2026-12345"},
			wantJustification: "component_not_present",
		},
		{
			name: "deduplicates repeated mentions within a source issue",
			issue: &github.KubernetesIssue{
				Number: 21,
				Title:  "CVE-2026-12345 and CVE-2026-23456",
				Body:   "This mentions cve-2026-12345 again",
				URL:    "https://github.com/kubernetes/kubernetes/issues/21",
				Comments: []github.Comment{
					{Body: "/not_affected:component_not_present\nCVE-2026-23456 is also not present."},
				},
			},
			wantCVEs:          []string{"CVE-2026-12345", "CVE-2026-23456"},
			wantJustification: "component_not_present",
		},
		{
			name:  "renderer error is propagated",
			issue: &github.KubernetesIssue{Number: 21, Title: "CVE-2026-12345"},
			render: func(_ int, _ string, _ []string, _ string, _ *vexflow.Component, _ string, _ time.Time) (*vexflow.VexflowIssue, error) {
				return nil, renderErr
			},
			wantErr: renderErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := &fakeFetcher{details: map[int]*github.KubernetesIssue{21: tt.issue}}
			now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
			render := tt.render
			if render == nil {
				render = vexflow.RenderVexflowIssue
			}
			issues, err := toVexIssues(fetcher, "kubernetes", "kubernetes", 21, now, render)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || !strings.Contains(err.Error(), "rendering issue #21/CVE-2026-12345") {
					t.Fatalf("expected wrapped renderer error, got %v", err)
				}
				if issues != nil {
					t.Errorf("expected no partial results, got %+v", issues)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(issues) != len(tt.wantCVEs) {
				t.Fatalf("got %d proposed issues, want %d", len(issues), len(tt.wantCVEs))
			}
			for i, want := range tt.wantCVEs {
				if issues[i].Title != want || len(issues[i].CVEIDs) != 1 || issues[i].CVEIDs[0] != want {
					t.Errorf("issue %d: got title %q and CVE IDs %v, want %q", i, issues[i].Title, issues[i].CVEIDs, want)
				}
				if issues[i].SourceIssue != 21 || issues[i].Justification != tt.wantJustification {
					t.Errorf("issue %d: wrong source or justification: %+v", i, issues[i])
				}
				if len(issues[i].Sources) != 1 || issues[i].Sources[0].Number != 21 || !issues[i].VexflowData.CreatedAt.Equal(now) {
					t.Errorf("issue %d: wrong source list or timestamp: %+v", i, issues[i])
				}
			}
		})
	}
}
