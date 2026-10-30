package vexflow

import (
	"strings"
	"testing"
	"time"
)

func TestBuildVexflowMetadata(t *testing.T) {
	now := time.Now()
	component := &Component{
		Type:    "golang",
		Name:    "golang.org/x/net",
		Version: "v0.0.0-20220127200216-cd36cc0744dd",
		PURL:    "pkg:golang/golang.org/x/net@v0.0.0-20220127200216-cd36cc0744dd",
	}

	metadata := BuildVexflowMetadata("CVE-2026-25681", component, "github.com/kubernetes/kubernetes@master", now)

	if metadata.BranchID != "github.com/kubernetes/kubernetes@master" {
		t.Errorf("BranchID = %q, want %q", metadata.BranchID, "github.com/kubernetes/kubernetes@master")
	}

	if metadata.Vulnerability.ID != "CVE-2026-25681" {
		t.Errorf("Vulnerability.ID = %q, want %q", metadata.Vulnerability.ID, "CVE-2026-25681")
	}

	if metadata.Status != "WAITING_USER" {
		t.Errorf("Status = %q, want %q", metadata.Status, "WAITING_USER")
	}

	if metadata.Branch.Repo != DefaultKubernetesRepo {
		t.Errorf("Branch.Repo = %q, want %q", metadata.Branch.Repo, DefaultKubernetesRepo)
	}

	if metadata.Branch.Name != DefaultTargetBranch {
		t.Errorf("Branch.Name = %q, want %q", metadata.Branch.Name, DefaultTargetBranch)
	}
}

func TestBuildVexflowMetadataDefaultComponent(t *testing.T) {
	now := time.Now()

	metadata := BuildVexflowMetadata("CVE-2026-25681", nil, "github.com/kubernetes/kubernetes@master", now)

	if metadata.Vulnerability.Component == nil {
		t.Fatal("Component should not be nil when defaulting")
	}

	if metadata.Vulnerability.Component.Name != "k8s.io/kubernetes" {
		t.Errorf("Component.Name = %q, want %q", metadata.Vulnerability.Component.Name, "k8s.io/kubernetes")
	}

	if metadata.Vulnerability.Component.PURL != "pkg:golang/k8s.io/kubernetes@master" {
		t.Errorf("Component.PURL = %q, want %q", metadata.Vulnerability.Component.PURL, "pkg:golang/k8s.io/kubernetes@master")
	}
}

func TestGenerateVexflowIssueBody(t *testing.T) {
	now := time.Now()
	component := &Component{
		Type:    "golang",
		Name:    "golang.org/x/net",
		Version: "v0.0.0-20220127200216-cd36cc0744dd",
		PURL:    "pkg:golang/golang.org/x/net@v0.0.0-20220127200216-cd36cc0744dd",
	}

	metadata := BuildVexflowMetadata("CVE-2026-25681", component, "github.com/kubernetes/kubernetes@master", now)
	sourceURL := "https://github.com/kubernetes/kubernetes/issues/123456"

	body, err := GenerateVexflowIssueBody("CVE-2026-25681", metadata, sourceURL, 123456)
	if err != nil {
		t.Fatalf("GenerateVexflowIssueBody() error = %v", err)
	}

	// Check that body contains expected sections
	if !strings.Contains(body, "CVE-2026-25681") {
		t.Error("Body should contain CVE ID")
	}

	if !strings.Contains(body, "Triage Instructions") {
		t.Error("Body should contain Triage Instructions section")
	}

	if !strings.Contains(body, "Not Affected") {
		t.Error("Body should contain Not Affected section")
	}

	if !strings.Contains(body, "/not_affected:") {
		t.Error("Body should contain slash command examples")
	}

	if !strings.Contains(body, VexflowDataSeparator) {
		t.Error("Body should contain vexflow data separator")
	}

	// Check that metadata is embedded
	if !strings.Contains(body, "branch_id") {
		t.Error("Body should contain embedded branch_id in JSON metadata")
	}

	if !strings.Contains(body, "WAITING_USER") {
		t.Error("Body should contain WAITING_USER status")
	}
}

func TestRenderVexflowIssue(t *testing.T) {
	now := time.Now()
	sourceURL := "https://github.com/kubernetes/kubernetes/issues/123456"
	comments := []string{"/not_affected:vulnerable_code_not_present\nThe code path is not used."}

	component := &Component{
		Type:    "golang",
		Name:    "golang.org/x/net",
		Version: "v0.0.0-20220127200216-cd36cc0744dd",
		PURL:    "pkg:golang/golang.org/x/net@v0.0.0-20220127200216-cd36cc0744dd",
	}

	vexIssue, err := RenderVexflowIssue(123456, sourceURL, comments, "CVE-2026-25681", component, "github.com/kubernetes/kubernetes@master", now)
	if err != nil {
		t.Fatalf("RenderVexflowIssue() error = %v", err)
	}

	if vexIssue.Title != "CVE-2026-25681" {
		t.Errorf("Title = %q, want %q", vexIssue.Title, "CVE-2026-25681")
	}

	if vexIssue.SourceIssue != 123456 {
		t.Errorf("SourceIssue = %d, want %d", vexIssue.SourceIssue, 123456)
	}

	if len(vexIssue.CVEIDs) != 1 || vexIssue.CVEIDs[0] != "CVE-2026-25681" {
		t.Errorf("CVEIDs = %v, want [CVE-2026-25681]", vexIssue.CVEIDs)
	}

	if vexIssue.Justification != "vulnerable_code_not_present" {
		t.Errorf("Justification = %q, want %q", vexIssue.Justification, "vulnerable_code_not_present")
	}

	if !strings.Contains(vexIssue.Body, "Exploitability triage") {
		t.Error("Body should contain exploitability triage header")
	}

	if vexIssue.VexflowData == nil {
		t.Error("VexflowData should not be nil")
	} else if vexIssue.VexflowData.Status != "WAITING_USER" {
		t.Errorf("VexflowData.Status = %q, want %q", vexIssue.VexflowData.Status, "WAITING_USER")
	}
}

func TestVexflowIssueWithoutJustification(t *testing.T) {
	now := time.Now()
	sourceURL := "https://github.com/kubernetes/kubernetes/issues/123456"

	vexIssue, err := RenderVexflowIssue(123456, sourceURL, nil, "CVE-2026-25681", nil, "github.com/kubernetes/kubernetes@master", now)
	if err != nil {
		t.Fatalf("RenderVexflowIssue() error = %v", err)
	}

	if vexIssue.Justification != "" {
		t.Errorf("Justification should be empty but got %q", vexIssue.Justification)
	}

	if vexIssue.VexflowData == nil {
		t.Fatal("VexflowData should not be nil")
	}

	if vexIssue.VexflowData.Status != "WAITING_USER" {
		t.Errorf("Status = %q, want %q", vexIssue.VexflowData.Status, "WAITING_USER")
	}
	if vexIssue.Component == nil || vexIssue.Component.PURL != vexIssue.VexflowData.Vulnerability.Component.PURL {
		t.Error("exported component should match the embedded metadata")
	}
}
