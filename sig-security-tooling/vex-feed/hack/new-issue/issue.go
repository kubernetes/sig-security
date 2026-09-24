package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

const (
	repo        = "kubernetes/kubernetes"
	productPURL = "pkg:golang/k8s.io/kubernetes"
)

var (
	issueNumberRE = regexp.MustCompile(`^[0-9]+$`)
	cveRE         = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
)

// ghIssue is the subset of `gh issue view --json ...` output this tool needs.
type ghIssue struct {
	Number   int    `json:"number"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	URL      string `json:"url"`
	Comments []struct {
		Body string `json:"body"`
	} `json:"comments"`
}

// issueFetcher fetches one kubernetes/kubernetes issue. The production
// implementation shells out to gh; tests inject a fake to avoid requiring
// gh or network access.
type issueFetcher func(number string) (ghIssue, error)

// fetchIssueViaGH fetches issue number via the gh CLI. number must already
// be validated as digits-only by the caller.
func fetchIssueViaGH(number string) (ghIssue, error) {
	// #nosec G204 -- number is validated ^[0-9]+$ by run() before this is
	// ever invoked; repo and the --json flag list are fixed literals.
	cmd := exec.Command("gh", "issue", "view", number, "--repo", repo,
		"--json", "number,title,body,url,comments")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return ghIssue{}, fmt.Errorf("gh failed for issue #%s: %s", number, msg)
	}
	var iss ghIssue
	if err := json.Unmarshal(stdout.Bytes(), &iss); err != nil {
		return ghIssue{}, fmt.Errorf("failed to parse gh output for issue #%s: %w", number, err)
	}
	return iss, nil
}

// extractCVEs returns the sorted, deduplicated, upper-cased set of CVE IDs
// mentioned in blob.
func extractCVEs(blob string) []string {
	matches := cveRE.FindAllString(blob, -1)
	upper := make([]string, len(matches))
	for i, m := range matches {
		upper[i] = strings.ToUpper(m)
	}
	return openvex.Unique(upper)
}

// issueBlob joins the issue's title, body, and every comment body with a
// space, for CVE-scanning.
func issueBlob(iss ghIssue) string {
	parts := make([]string, 0, 2+len(iss.Comments))
	parts = append(parts, iss.Title, iss.Body)
	for _, c := range iss.Comments {
		parts = append(parts, c.Body)
	}
	return strings.Join(parts, " ")
}
