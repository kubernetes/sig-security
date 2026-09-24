package openvex

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
)

// IssueFilesDir is the directory, relative to the vex-feed module root, that
// holds per-issue OpenVEX documents.
const IssueFilesDir = "files"

// IssueFilesGlob matches every per-issue OpenVEX document under IssueFilesDir.
const IssueFilesGlob = IssueFilesDir + "/issue-*.openvex.json"

var issueNumRE = regexp.MustCompile(`issue-(\d+)`)

// IssueFilePath returns the per-issue document path for issue number n.
func IssueFilePath(n string) string {
	return filepath.Join(IssueFilesDir, fmt.Sprintf("issue-%s.openvex.json", n))
}

// ParseIssueNumber extracts the numeric issue id from a
// files/issue-<n>.openvex.json path.
func ParseIssueNumber(path string) (int, error) {
	m := issueNumRE.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return 0, fmt.Errorf("%s does not match issue-<N>.openvex.json", path)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("failed to parse issue number from %s: %w", path, err)
	}
	return n, nil
}
