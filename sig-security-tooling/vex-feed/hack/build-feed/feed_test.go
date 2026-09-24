package main

import (
	"path/filepath"
	"testing"
	"time"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

func TestHasCheckFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "no args", args: nil, want: false},
		{name: "only check", args: []string{"--check"}, want: true},
		{name: "check with other args", args: []string{"--check", "--foo", "bar"}, want: true},
		{name: "check not first", args: []string{"--foo", "--check"}, want: true},
		{name: "other args only", args: []string{"--foo"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasCheckFlag(tt.args); got != tt.want {
				t.Errorf("hasCheckFlag(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestLoadExistingFeed_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, exists, err := loadExistingFeed(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("loadExistingFeed: %v", err)
	}
	if exists {
		t.Errorf("expected exists = false for a missing file")
	}
}

func TestDiffFeed(t *testing.T) {
	ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	statements := []openvex.Statement{{
		Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0001"},
		Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
		Status:        "fixed",
	}}
	base := openvex.Document{
		Metadata: openvex.Metadata{
			Context: openvex.ContextV02, ID: feedID, Author: openvex.DefaultAuthor,
			Timestamp: &ts, Version: 1,
		},
		Statements: statements,
	}

	tests := []struct {
		name              string
		existing          openvex.Document
		exists            bool
		newStatements     []openvex.Statement
		wantStatementsChg bool
		wantMetadataChg   bool
	}{
		{
			name:   "no existing file",
			exists: false, newStatements: statements,
			wantStatementsChg: true, wantMetadataChg: true,
		},
		{
			name: "identical", existing: base, exists: true, newStatements: statements,
			wantStatementsChg: false, wantMetadataChg: false,
		},
		{
			name: "statements changed", existing: base, exists: true,
			newStatements: []openvex.Statement{{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2000-0002"},
				Products:      []openvex.Product{{Component: openvex.Component{ID: "pkg:golang/k8s.io/kubernetes"}}},
				Status:        "fixed",
			}},
			wantStatementsChg: true, wantMetadataChg: false,
		},
		{
			name: "metadata changed", existing: openvex.Document{
				Metadata: openvex.Metadata{
					Context: "stale-context", ID: feedID, Author: openvex.DefaultAuthor,
					Timestamp: &ts, Version: 1,
				},
				Statements: statements,
			}, exists: true, newStatements: statements,
			wantStatementsChg: false, wantMetadataChg: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS, gotM := diffFeed(tt.existing, tt.exists, tt.newStatements)
			if gotS != tt.wantStatementsChg {
				t.Errorf("statementsChanged = %v, want %v", gotS, tt.wantStatementsChg)
			}
			if gotM != tt.wantMetadataChg {
				t.Errorf("metadataChanged = %v, want %v", gotM, tt.wantMetadataChg)
			}
		})
	}
}
