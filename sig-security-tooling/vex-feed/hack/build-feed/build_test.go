package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

func TestQuotedStrList(t *testing.T) {
	got := quotedStrList([]string{"a", "b"})
	want := "['a', 'b']"
	if got != want {
		t.Errorf("quotedStrList = %q, want %q", got, want)
	}
}

func TestIntList(t *testing.T) {
	got := intList([]int{1, 2})
	want := "[1, 2]"
	if got != want {
		t.Errorf("intList = %q, want %q", got, want)
	}
}

func TestLoadOverridesSkipsCommentKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "merge-overrides.json")
	content := `{
		"_comment": "this is a bare string, not an override object",
		"CVE-2000-0001": {"status_notes": "notes for 0001"},
		"CVE-2000-0002": {"action_statement": "do this"}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := loadOverrides(path)
	if err != nil {
		t.Fatalf("loadOverrides: %v", err)
	}
	if _, ok := got["_comment"]; ok {
		t.Errorf("expected _comment key to be skipped")
	}
	if got["CVE-2000-0001"].StatusNotes != "notes for 0001" {
		t.Errorf("CVE-2000-0001 status_notes = %q", got["CVE-2000-0001"].StatusNotes)
	}
	if got["CVE-2000-0002"].ActionStatement != "do this" {
		t.Errorf("CVE-2000-0002 action_statement = %q", got["CVE-2000-0002"].ActionStatement)
	}
}

func writeFixture(t *testing.T, dir, name string, doc openvex.Document) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := openvex.Save(path, doc); err != nil {
		t.Fatalf("Save(%s): %v", path, err)
	}
	return path
}

func TestBuildStatements_SingleSourcePassThrough(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "fixed",
			StatusNotes:   "fixed upstream",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", result.conflicts)
	}
	if len(result.statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.statements))
	}
	got := result.statements[0]
	if got.Status != "fixed" || got.StatusNotes != "fixed upstream" {
		t.Errorf("unexpected statement: %+v", got)
	}
}

func TestBuildStatements_MultiSourceWithOverride(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "fixed",
			StatusNotes:   "from issue 100",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "fixed",
			StatusNotes:   "from issue 200",
		}},
	})

	overrides := map[string]override{
		"CVE-2000-0001": {StatusNotes: "merged notes"},
	}
	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), overrides)
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", result.conflicts)
	}
	if len(result.statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.statements))
	}
	if result.statements[0].StatusNotes != "merged notes" {
		t.Errorf("expected override notes, got %q", result.statements[0].StatusNotes)
	}
}

func TestBuildStatements_MultiSourceWithoutOverrideConflicts(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "fixed",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "fixed",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", result.conflicts)
	}
	if len(result.statements) != 0 {
		t.Fatalf("expected 0 statements when conflict occurs, got %d", len(result.statements))
	}
}

func TestBuildStatements_ConflictingStatus(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "fixed",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "not_affected",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{
		"CVE-2000-0001": {StatusNotes: "would be ignored anyway"},
	})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", result.conflicts)
	}
}

func TestBuildStatements_ConflictingJustificationEmptyVsValue(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "not_affected",
			Justification: "vulnerable_code_not_present",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
			Status:        "not_affected",
			// no justification here -- empty vs a real value is a conflict
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{
		"CVE-2000-0001": {StatusNotes: "would be ignored anyway"},
	})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %v", result.conflicts)
	}
}

func TestBuildStatements_SubcomponentUnionAndCollapse(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "issue-100.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products: []openvex.Product{{
				Component:     openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"},
				Subcomponents: []openvex.Subcomponent{{Component: openvex.Component{ID: "pkg:golang/stdlib@v1.25.6"}}},
			}},
			Status: "fixed",
		}},
	})
	writeFixture(t, dir, "issue-200.openvex.json", openvex.Document{
		Statements: []openvex.Statement{{
			Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
			Products: []openvex.Product{{
				Component:     openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"},
				Subcomponents: []openvex.Subcomponent{{Component: openvex.Component{ID: "pkg:golang/stdlib"}}},
			}},
			Status: "fixed",
		}},
	})

	result, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{
		"CVE-2000-0001": {StatusNotes: "merged"},
	})
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %v", result.conflicts)
	}
	subs := result.statements[0].Products[0].Subcomponents
	if len(subs) != 1 || subs[0].ID != "pkg:golang/stdlib" {
		t.Errorf("expected collapsed subcomponent pkg:golang/stdlib, got %v", subs)
	}
}

func TestBuildStatements_NoFilesFound(t *testing.T) {
	dir := t.TempDir()
	_, err := buildStatements(filepath.Join(dir, "issue-*.openvex.json"), map[string]override{})
	if err == nil {
		t.Fatal("expected an error when no per-issue files are found")
	}
}

// TestBuildStatements_RealCorpus is the load-bearing regression test: it
// rebuilds the feed from the real per-issue files and merge-overrides.json
// and checks it matches the committed kubernetes-vex-feed-draft.openvex.json
// exactly.
func TestBuildStatements_RealCorpus(t *testing.T) {
	overrides, err := loadOverrides("../merge-overrides.json")
	if err != nil {
		t.Fatalf("loadOverrides: %v", err)
	}
	result, err := buildStatements("../../files/issue-*.openvex.json", overrides)
	if err != nil {
		t.Fatalf("buildStatements: %v", err)
	}
	if len(result.conflicts) != 0 {
		t.Fatalf("unexpected conflicts against real corpus: %v", result.conflicts)
	}

	want, err := openvex.Load("../../kubernetes-vex-feed-draft.openvex.json")
	if err != nil {
		t.Fatalf("Load real feed: %v", err)
	}

	if !reflect.DeepEqual(result.statements, want.Statements) {
		t.Errorf("built statements do not match the committed feed.\ngot:  %+v\nwant: %+v", result.statements, want.Statements)
	}
}
