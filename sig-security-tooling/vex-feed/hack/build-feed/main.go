// Command build-feed assembles the combined Kubernetes CVE VEX feed
// (../kubernetes-vex-feed-draft.openvex.json) from the per-issue OpenVEX
// documents in ../files/. Run it from the vex-feed/ directory.
//
// The per-issue files under files/ are the source of truth (one document
// per GitHub issue, preserving provenance). This command merges them into a
// single consumer-facing feed with one statement per (product, CVE):
//
//   - statements are grouped by (product @id, CVE);
//   - status and justification must agree across all issues that report a
//     CVE (the build fails loudly if they conflict, rather than guessing);
//   - subcomponents are unioned (version variants of one package collapse
//     to the unversioned base);
//   - for a CVE reported by more than one issue, the merged note/remediation
//     come from merge-overrides.json (curated, since prose can't be merged
//     mechanically); single-source CVEs keep their per-issue note verbatim.
//
// Ordering matches a newest-issue-first walk (first occurrence wins), so
// the feed lists the most recently reported CVEs first.
//
// Usage:  go run ./hack/build-feed [--check]
//
//	(default) writes ../kubernetes-vex-feed-draft.openvex.json
//	--check   exits non-zero if the on-disk feed is stale (for CI); writes nothing
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// hasCheckFlag reports whether "--check" appears anywhere in args. This is
// deliberately permissive: any other arguments are silently ignored, and
// "--check" is not required to be args[0].
func hasCheckFlag(args []string) bool {
	for _, a := range args {
		if a == "--check" {
			return true
		}
	}
	return false
}

func run(args []string) error {
	check := hasCheckFlag(args)

	overrides, err := loadOverrides(overridesPath)
	if err != nil {
		return err
	}
	result, err := buildStatements(openvex.IssueFilesGlob, overrides)
	if err != nil {
		return err
	}
	if len(result.conflicts) > 0 {
		return fmt.Errorf("build failed — resolve these before regenerating:\n  - %s", strings.Join(result.conflicts, "\n  - "))
	}

	existing, exists, err := loadExistingFeed(feedPath)
	if err != nil {
		return err
	}
	statementsChanged, metadataChanged := diffFeed(existing, exists, result.statements)

	if check {
		if statementsChanged || metadataChanged {
			return fmt.Errorf("feed is STALE — run: %s", openvex.BuildFeedHint)
		}
		fmt.Printf("feed up to date (%d statements)\n", len(result.statements))
		return nil
	}

	if !statementsChanged && !metadataChanged {
		fmt.Printf("no change (%d statements); feed left as-is\n", len(result.statements))
		return nil
	}

	var ts *time.Time
	var ver int
	if statementsChanged {
		now := time.Now()
		ts = &now
		ver = 1
		if exists {
			ver = existing.Version + 1
		}
	} else {
		ts, ver = existing.Timestamp, existing.Version
	}

	feed := openvex.Document{
		Metadata: openvex.Metadata{
			Context:   openvex.ContextV02,
			ID:        feedID,
			Author:    openvex.DefaultAuthor,
			Timestamp: ts,
			Version:   ver,
		},
		Statements: result.statements,
	}
	if err := openvex.Save(feedPath, feed); err != nil {
		return err
	}

	cveSet := make(map[string]struct{}, len(result.statements))
	for _, s := range result.statements {
		cveSet[string(s.Vulnerability.Name)] = struct{}{}
	}
	what := "metadata only"
	if statementsChanged {
		what = "statements + metadata"
	}
	fmt.Printf("wrote %s (%s)\n  %d statements / %d CVEs, version %d\n", feedPath, what, len(result.statements), len(cveSet), ver)
	return nil
}
