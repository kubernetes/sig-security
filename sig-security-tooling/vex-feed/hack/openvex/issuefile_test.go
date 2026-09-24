package openvex

import "testing"

func TestIssueFilePath(t *testing.T) {
	got := IssueFilePath("140092")
	want := "files/issue-140092.openvex.json"
	if got != want {
		t.Errorf("IssueFilePath(140092) = %q, want %q", got, want)
	}
}

func TestParseIssueNumber(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      int
		wantError bool
	}{
		{name: "typical", path: "files/issue-140092.openvex.json", want: 140092},
		{name: "small number", path: "issue-1.openvex.json", want: 1},
		{name: "no match", path: "files/not-an-issue.json", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIssueNumber(tt.path)
			if tt.wantError {
				if err == nil {
					t.Fatalf("ParseIssueNumber(%s) = %d, nil; want error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIssueNumber(%s): %v", tt.path, err)
			}
			if got != tt.want {
				t.Errorf("ParseIssueNumber(%s) = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}
