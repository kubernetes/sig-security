package state

import (
	"strings"
	"testing"
)

func TestToIssue(t *testing.T) {
	data := CVEData{
		CVE:     "CVE-2024-1234",
		Summary: "Buffer overflow in kube-apiserver",
		CVSS: CVSS{
			URL:      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Severity: "HIGH",
			Score:    8.8,
		},
		Description: "A vulnerability was found in kube-apiserver.",
		Vulnerable:  "Clusters running kube-apiserver versions below v1.31.12 are affected.",
		Versions: []Versions{
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.30.0", FixedVersion: "v1.31.12"},
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.32.0", FixedVersion: "v1.32.8"},
		},
		Upgrade:           "Upgrade to the latest patched version.",
		Mitigate:          "Apply network policies to restrict access.",
		Detection:         "Check audit logs for suspicious activity.",
		AdditionalDetails: "See the GitHub issue for more details.",
		Acknowledgements:  "Reported by Security Researcher.",
	}

	output, err := data.ToIssue()
	if err != nil {
		t.Fatalf("ToIssue() error: %v", err)
	}

	result := string(output)

	expectedStrings := []string{
		"ISSUE TITLE: `CVE-2024-1234: Buffer overflow in kube-apiserver`",
		"CVSS Rating: **8.8** (HIGH)",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		"A vulnerability was found in kube-apiserver.",
		"### Am I vulnerable?",
		"Clusters running kube-apiserver versions below v1.31.12 are affected.",
		"#### Affected Versions",
		"kube-apiserver: v1.30.0 < v1.31.12",
		"kube-apiserver: v1.32.0 < v1.32.8",
		"### How do I mitigate this vulnerability?",
		"Apply network policies to restrict access.",
		"#### How to upgrade?",
		"Upgrade to the latest patched version.",
		"### Detection",
		"Check audit logs for suspicious activity.",
		"## Additional Details",
		"See the GitHub issue for more details.",
		"#### Acknowledgements",
		"Reported by Security Researcher.",
		"/area security",
		"/kind bug",
		"/committee security-response",
		"/label official-cve-feed",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("ToIssue() output missing expected string: %q", expected)
		}
	}
}

func TestToEmail(t *testing.T) {
	data := CVEData{
		CVE:     "CVE-2024-1234",
		Summary: "Buffer overflow in kube-apiserver",
		CVSS: CVSS{
			URL:      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Severity: "HIGH",
			Score:    8.8,
		},
		Description: "A vulnerability was found in kube-apiserver.",
		Vulnerable:  "Clusters running kube-apiserver versions below v1.31.12 are affected.",
		Versions: []Versions{
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.30.0", FixedVersion: "v1.31.12"},
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.32.0", FixedVersion: "v1.32.8"},
		},
		Upgrade:           "Upgrade to the latest patched version.",
		Mitigate:          "Apply network policies to restrict access.",
		Detection:         "Check audit logs for suspicious activity.",
		AdditionalDetails: "See the GitHub issue for more details.",
		Acknowledgements:  "Reported by Security Researcher.",
	}

	output, err := data.ToEmail()
	if err != nil {
		t.Fatalf("ToEmail() error: %v", err)
	}

	result := string(output)

	expectedStrings := []string{
		"SUBJECT: `[Security Advisory] CVE-2024-1234: Buffer overflow in kube-apiserver`",
		"SUBJECT: `[kubernetes] CVE-2024-1234: Buffer overflow in kube-apiserver`",
		"Hello Kubernetes Community,",
		"A vulnerability was found in kube-apiserver.",
		"**8.8** (HIGH)",
		"[CVSS calculator](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)",
		"### Am I vulnerable?",
		"Clusters running kube-apiserver versions below v1.31.12 are affected.",
		"#### Affected Versions",
		"kube-apiserver: v1.30.0 < v1.31.12",
		"kube-apiserver: v1.32.0 < v1.32.8",
		"### How do I mitigate this vulnerability?",
		"Apply network policies to restrict access.",
		"#### Fixed Versions",
		"kube-apiserver: v1.31.12",
		"kube-apiserver: v1.32.8",
		"#### How to upgrade?",
		"Upgrade to the latest patched version.",
		"### Detection",
		"Check audit logs for suspicious activity.",
		"If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io",
		"#### Additional Details",
		"See the GitHub issue for more details.",
		"#### Acknowledgements",
		"Reported by Security Researcher.",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("ToEmail() output missing expected string: %q", expected)
		}
	}
}

func TestToSlack(t *testing.T) {
	data := CVEData{
		CVE:     "CVE-2024-1234",
		Summary: "Buffer overflow in kube-apiserver",
		CVSS: CVSS{
			URL:      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Severity: "HIGH",
			Score:    8.8,
		},
	}

	output, err := data.ToSlack()
	if err != nil {
		t.Fatalf("ToSlack() error: %v", err)
	}

	result := string(output)

	expectedStrings := []string{
		"**8.8** (HIGH)",
		"**CVE-2024-1234**",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(result, expected) {
			t.Errorf("ToSlack() output missing expected string: %q", expected)
		}
	}
}

func TestToEmailWithoutCVSS(t *testing.T) {
	data := CVEData{
		CVE:      "CVE-2024-5678",
		Summary:  "Minor issue in kubelet",
		Mitigate: "Upgrade to the latest version.",
		Upgrade:  "Follow standard upgrade procedures.",
	}

	output, err := data.ToEmail()
	if err != nil {
		t.Fatalf("ToEmail() error: %v", err)
	}

	result := string(output)

	if !strings.Contains(result, "This issue has been assigned **CVE-2024-5678**") {
		t.Error("ToEmail() should show fallback text when CVSS is not provided")
	}

	if strings.Contains(result, "CVSS calculator") {
		t.Error("ToEmail() should not show CVSS calculator link when CVSS is not provided")
	}
}

func TestToEmailAffectedVersionsFormat(t *testing.T) {
	// Regression test: old template only showed '<' when both FirstAffectedVersion and FixedVersion existed
	data := CVEData{
		CVE: "CVE-2024-1234",
		Versions: []Versions{
			{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
		},
	}

	output, err := data.ToEmail()
	if err != nil {
		t.Fatalf("ToEmail() error: %v", err)
	}

	result := string(output)
	if !strings.Contains(result, "kube-apiserver: < v1.31.12") {
		t.Error("ToEmail() should show '<' even when FirstAffectedVersion is empty")
	}
}

func TestToIssueMinimalData(t *testing.T) {
	data := CVEData{
		CVE:      "CVE-2024-9999",
		Mitigate: "Upgrade immediately.",
		Upgrade:  "See docs.",
	}

	output, err := data.ToIssue()
	if err != nil {
		t.Fatalf("ToIssue() error: %v", err)
	}

	result := string(output)

	if !strings.Contains(result, "ISSUE TITLE: `CVE-2024-9999`") {
		t.Error("ToIssue() should contain CVE in title")
	}

	if strings.Contains(result, "### Am I vulnerable?") {
		t.Error("ToIssue() should not show 'Am I vulnerable?' section when Vulnerable is empty")
	}

	if strings.Contains(result, "#### Affected Versions") {
		t.Error("ToIssue() should not show 'Affected Versions' section when Versions is empty")
	}
}
