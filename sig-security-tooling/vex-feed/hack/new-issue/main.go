// Command new-issue scaffolds a per-issue OpenVEX document from a
// kubernetes/kubernetes issue. Run it from the vex-feed/ directory.
//
// It fetches the issue with `gh`, pulls the CVE IDs it mentions, and writes
// a skeleton files/issue-<n>.openvex.json with one statement per CVE for a
// human to complete.
//
// The VEX determination — status (fixed / not_affected / under_investigation),
// justification, and the explanatory notes — is a judgment call made by
// reading the issue discussion, so it is intentionally left as a TODO. This
// command only removes the boilerplate: it sets the document @id to the
// issue URL, fills in the author/context, and stubs one statement per CVE
// as under_investigation.
//
// Usage:  go run ./hack/new-issue <issue-number>
//
// Then edit status / justification / status_notes (and add a subcomponent
// PURL if the CVE is in a dependency), add a merge-overrides.json entry if
// the CVE is also reported by other issues, and run: go run ./hack/build-feed
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

func main() {
	if err := run(os.Args[1:], fetchIssueViaGH); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, fetch issueFetcher) error {
	if len(args) != 1 || !issueNumberRE.MatchString(args[0]) {
		return errors.New("usage: go run ./hack/new-issue <issue-number>")
	}
	n := args[0]
	outPath := openvex.IssueFilePath(n)

	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", outPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to check for existing %s: %w", outPath, err)
	}

	iss, err := fetch(n)
	if err != nil {
		return err
	}

	cves := extractCVEs(issueBlob(iss))
	if len(cves) == 0 {
		fmt.Printf("warning: no CVE IDs found in issue #%s; stubbing one TODO statement\n", n)
		cves = []string{"CVE-XXXX-XXXX"}
	}

	url := iss.URL
	if url == "" {
		url = fmt.Sprintf("https://github.com/%s/issues/%s", repo, n)
	}
	title := strings.TrimSpace(strings.ReplaceAll(iss.Title, "\n", " "))

	statements := make([]openvex.Statement, len(cves))
	for i, cve := range cves {
		statements[i] = openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: openvex.VulnerabilityID(cve)},
			Products:      []openvex.Product{{Component: openvex.Component{ID: productPURL}}},
			Status:        "under_investigation",
			StatusNotes:   fmt.Sprintf("TODO: determine status and justification for %s. Source issue: \"%s\". [ref: %s]", cve, title, url),
		}
	}

	now := time.Now()
	doc := openvex.Document{
		Metadata: openvex.Metadata{
			Context:   openvex.ContextV02,
			ID:        url,
			Author:    openvex.DefaultAuthor,
			Timestamp: &now,
			Version:   1,
		},
		Statements: statements,
	}

	if err := os.MkdirAll(openvex.IssueFilesDir, 0o750); err != nil {
		return fmt.Errorf("failed to create %s: %w", openvex.IssueFilesDir, err)
	}
	if err := openvex.Save(outPath, doc); err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", outPath)
	fmt.Printf("  %d statement(s): %s\n", len(cves), strings.Join(cves, ", "))
	fmt.Println("Next: fill in status / justification / status_notes (add a subcomponent")
	fmt.Println("PURL if the CVE is in a dependency), add a merge-overrides.json entry if")
	fmt.Printf("the CVE spans multiple issues, then run: %s\n", openvex.BuildFeedHint)
	return nil
}
