package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/bridge"
	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/github"
	"github.com/kubernetes/sig-security/sig-security-tooling/vex-feed/pkg/vexflow"
)

func main() {
	outputFile := flag.String("output", "", "Output file for JSON results (default: stdout)")
	sourceRepo := flag.String("repo", "kubernetes/kubernetes", "Source repository (owner/name)")
	label := flag.String("label", vexflow.DefaultLabel, "Label to search for on source issues")
	dryRun := flag.Bool("dry-run", true, "Only output JSON (issue creation is not implemented)")
	maxResults := flag.Int("max-results", 100, "Maximum number of source issues to process")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	if !*dryRun {
		log.Fatal("Creating issues in kubernetes/.vexflow is not yet implemented")
	}
	if *maxResults < 0 {
		log.Fatal("-max-results must not be negative")
	}
	if *verbose {
		log.Printf("Searching for issues with query: %s", github.BuildSearchQuery(*sourceRepo, *label))
	}

	fetcher, err := github.NewGitHubClient()
	if err != nil {
		log.Fatal(err)
	}
	output, err := bridge.Collect(fetcher, *sourceRepo, *label, *maxResults, time.Now())
	if err != nil {
		log.Fatal(err)
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	data = append(data, '\n')
	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, data, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Output written to %s\n", *outputFile)
	} else if _, err := os.Stdout.Write(data); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "\n=== Summary ===\nTotal vexflow issues to be created: %d\nUnique CVEs: %d\nUnique components: %d\nConflicting issues for review: %d\n",
		output.Summary.TotalIssues, output.Summary.UniqueCVEs, output.Summary.UniqueComponents, output.Summary.ConflictingIssues)
	if len(output.Summary.IssuesByJustification) > 0 {
		fmt.Fprintln(os.Stderr, "Issues by justification:")
		for justification, count := range output.Summary.IssuesByJustification {
			fmt.Fprintf(os.Stderr, "  %s: %d\n", justification, count)
		}
	}
}
