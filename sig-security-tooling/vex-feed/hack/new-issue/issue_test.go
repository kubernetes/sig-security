package main

import (
	"reflect"
	"testing"
)

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name string
		blob string
		want []string
	}{
		{name: "no CVEs", blob: "nothing to see here", want: []string{}},
		{
			name: "mixed case dedup",
			blob: "cve-2025-68121 and CVE-2025-68121 reported",
			want: []string{"CVE-2025-68121"},
		},
		{
			name: "multiple distinct CVEs sorted",
			blob: "found CVE-2026-33814 then CVE-2025-68121 and CVE-2026-33811",
			want: []string{"CVE-2025-68121", "CVE-2026-33811", "CVE-2026-33814"},
		},
		{
			name: "CVE substring embedded in larger token still matches",
			blob: "trivy:CVE-2025-68121:high",
			want: []string{"CVE-2025-68121"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCVEs(tt.blob)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractCVEs(%q) = %v, want %v", tt.blob, got, tt.want)
			}
		})
	}
}

func TestIssueBlob(t *testing.T) {
	iss := ghIssue{
		Title: "CVE-2025-68121 found",
		Body:  "some body text",
		Comments: []struct {
			Body string `json:"body"`
		}{
			{Body: "comment one"},
			{Body: "comment two"},
		},
	}
	want := "CVE-2025-68121 found some body text comment one comment two"
	if got := issueBlob(iss); got != want {
		t.Errorf("issueBlob = %q, want %q", got, want)
	}
}

func TestIssueBlob_EmptyBodyAndComments(t *testing.T) {
	// Go's json.Unmarshal leaves string fields at their zero value ("")
	// when the source JSON field is missing or null, so a missing body
	// or comments needs no extra fallback handling here.
	iss := ghIssue{Title: "just a title"}
	want := "just a title "
	if got := issueBlob(iss); got != want {
		t.Errorf("issueBlob = %q, want %q", got, want)
	}
}
