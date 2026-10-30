package cve

import (
	"testing"
)

func TestExtractCVEs(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		body     string
		comments []string
		want     []string
	}{
		{
			name:     "Single CVE in title",
			title:    "CVE-2026-25681 affects Kubernetes",
			body:     "",
			comments: nil,
			want:     []string{"CVE-2026-25681"},
		},
		{
			name:     "Multiple CVEs",
			title:    "CVE-2026-25681",
			body:     "Also affects CVE-2026-25682",
			comments: []string{"Related to CVE-2026-25683"},
			want:     []string{"CVE-2026-25681", "CVE-2026-25682", "CVE-2026-25683"},
		},
		{
			name:     "Case insensitive",
			title:    "cve-2026-25681 CVE-2026-25682",
			body:     "",
			comments: nil,
			want:     []string{"CVE-2026-25681", "CVE-2026-25682"},
		},
		{
			name:     "Duplicate CVEs deduplicated",
			title:    "CVE-2026-25681",
			body:     "CVE-2026-25681 is mentioned again",
			comments: []string{"And here: CVE-2026-25681"},
			want:     []string{"CVE-2026-25681"},
		},
		{
			name:     "Sorted alphabetically",
			title:    "CVE-2026-25683",
			body:     "CVE-2026-25681",
			comments: []string{"CVE-2026-25682"},
			want:     []string{"CVE-2026-25681", "CVE-2026-25682", "CVE-2026-25683"},
		},
		{
			name:     "No CVEs",
			title:    "Regular issue without CVE",
			body:     "Some discussion",
			comments: []string{"More discussion"},
			want:     []string{},
		},
		{
			name:     "Invalid CVE formats ignored",
			title:    "CVE-20-1 or CVE-2026",
			body:     "Not valid CVE formats",
			comments: nil,
			want:     []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCVEs(tt.title, tt.body, tt.comments)
			if !slicesEqual(got, tt.want) {
				t.Errorf("ExtractCVEs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractJustification(t *testing.T) {
	tests := []struct {
		name           string
		comments       []string
		wantJust       string
		wantHasDetails bool
	}{
		{
			name: "component_not_present",
			comments: []string{
				"/not_affected:component_not_present\n\nThe component is not used in Kubernetes.",
			},
			wantJust:       "component_not_present",
			wantHasDetails: true,
		},
		{
			name: "vulnerable_code_not_present",
			comments: []string{
				"Some text\n/not_affected:vulnerable_code_not_present\nMore details.",
			},
			wantJust:       "vulnerable_code_not_present",
			wantHasDetails: true,
		},
		{
			name: "Case insensitive command",
			comments: []string{
				"/NOT_AFFECTED:inline_mitigations_already_exist\nDetails here.",
			},
			wantJust:       "inline_mitigations_already_exist",
			wantHasDetails: true,
		},
		{
			name:           "No justification found",
			comments:       []string{"Just some regular comments"},
			wantJust:       "",
			wantHasDetails: false,
		},
		{
			name:           "Empty comments",
			comments:       []string{},
			wantJust:       "",
			wantHasDetails: false,
		},
		{
			name: "First matching justification is used",
			comments: []string{
				"/not_affected:component_not_present\n",
				"/not_affected:vulnerable_code_not_present\n",
			},
			wantJust:       "component_not_present",
			wantHasDetails: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotJust, gotDetails := ExtractJustification(tt.comments)
			if gotJust != tt.wantJust {
				t.Errorf("ExtractJustification() justification = %q, want %q", gotJust, tt.wantJust)
			}
			if tt.wantHasDetails && gotDetails == "" {
				t.Errorf("ExtractJustification() expected details but got empty string")
			}
			if !tt.wantHasDetails && gotDetails != "" {
				t.Errorf("ExtractJustification() expected no details but got %q", gotDetails)
			}
		})
	}
}

// Helper function to compare string slices
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
