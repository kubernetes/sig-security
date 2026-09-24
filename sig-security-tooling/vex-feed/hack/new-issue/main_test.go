package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%s): %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatalf("Chdir(%s): %v", old, err)
		}
	})
}

func failingFetcher(t *testing.T) issueFetcher {
	return func(number string) (ghIssue, error) {
		t.Fatalf("fetch should not have been called for issue #%s", number)
		return ghIssue{}, nil
	}
}

func TestRun_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no args", args: nil},
		{name: "two args", args: []string{"140092", "extra"}},
		{name: "non-numeric arg", args: []string{"abc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args, failingFetcher(t))
			if err == nil {
				t.Fatalf("expected an error for args %v", tt.args)
			}
		})
	}
}

func TestRun_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.Mkdir(openvex.IssueFilesDir, 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	existing := filepath.Join(openvex.IssueFilesDir, "issue-1.openvex.json")
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := run([]string{"1"}, failingFetcher(t))
	if err == nil {
		t.Fatal("expected an overwrite-refusal error")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRun_WritesStub(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	fetch := func(number string) (ghIssue, error) {
		if number != "42" {
			t.Fatalf("unexpected issue number %s", number)
		}
		return ghIssue{
			Number: 42,
			Title:  "CVE-2025-68121: kubectl issue",
			Body:   "found CVE-2025-68121 in kubectl",
			URL:    "https://github.com/kubernetes/kubernetes/issues/42",
		}, nil
	}

	if err := run([]string{"42"}, fetch); err != nil {
		t.Fatalf("run: %v", err)
	}

	doc, err := openvex.Load(filepath.Join(openvex.IssueFilesDir, "issue-42.openvex.json"))
	if err != nil {
		t.Fatalf("Load written doc: %v", err)
	}
	if doc.ID != "https://github.com/kubernetes/kubernetes/issues/42" {
		t.Errorf("unexpected @id: %s", doc.ID)
	}
	if doc.Author != openvex.DefaultAuthor || doc.Version != 1 {
		t.Errorf("unexpected author/version: %+v", doc)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	st := doc.Statements[0]
	if st.Vulnerability.Name != "CVE-2025-68121" || st.Status != "under_investigation" {
		t.Errorf("unexpected statement: %+v", st)
	}
	if !strings.Contains(st.StatusNotes, "TODO: determine status and justification for CVE-2025-68121") {
		t.Errorf("unexpected status_notes: %s", st.StatusNotes)
	}
}

func TestRun_NoCVEsFound(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	fetch := func(number string) (ghIssue, error) {
		return ghIssue{Title: "unrelated bug", Body: "no security content here", URL: "https://example.com/issues/7"}, nil
	}

	if err := run([]string{"7"}, fetch); err != nil {
		t.Fatalf("run: %v", err)
	}

	doc, err := openvex.Load(filepath.Join(openvex.IssueFilesDir, "issue-7.openvex.json"))
	if err != nil {
		t.Fatalf("Load written doc: %v", err)
	}
	if len(doc.Statements) != 1 || doc.Statements[0].Vulnerability.Name != "CVE-XXXX-XXXX" {
		t.Errorf("expected a single CVE-XXXX-XXXX stub statement, got %+v", doc.Statements)
	}
}

func TestRun_FallsBackToConstructedURL(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	fetch := func(number string) (ghIssue, error) {
		return ghIssue{Title: "CVE-2025-68121 issue", Body: ""}, nil // no URL
	}

	if err := run([]string{"9"}, fetch); err != nil {
		t.Fatalf("run: %v", err)
	}
	doc, err := openvex.Load(filepath.Join(openvex.IssueFilesDir, "issue-9.openvex.json"))
	if err != nil {
		t.Fatalf("Load written doc: %v", err)
	}
	if doc.ID != "https://github.com/kubernetes/kubernetes/issues/9" {
		t.Errorf("expected constructed fallback URL, got %s", doc.ID)
	}
}
