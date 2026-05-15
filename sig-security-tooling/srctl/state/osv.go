package state

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OSV represents the Open Source Vulnerability format.
// See: https://ossf.github.io/osv-schema/
type OSV struct {
	SchemaVersion string        `json:"schema_version"`
	ID            string        `json:"id"`
	Modified      string        `json:"modified"`
	Published     string        `json:"published,omitempty"`
	Aliases       []string      `json:"aliases,omitempty"`
	Summary       string        `json:"summary,omitempty"`
	Details       string        `json:"details,omitempty"`
	Severity      []OSVSeverity `json:"severity,omitempty"`
	Affected      []OSVAffected `json:"affected,omitempty"`
	References    []OSVRef      `json:"references,omitempty"`
	Credits       []OSVCredit   `json:"credits,omitempty"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package  OSVPackage    `json:"package"`
	Ranges   []OSVRange    `json:"ranges,omitempty"`
	Versions []string      `json:"versions,omitempty"`
	Severity []OSVSeverity `json:"severity,omitempty"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type OSVRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVCredit struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// ToOSV converts CVEData to the OSV format.
func (d CVEData) ToOSV() OSV {
	now := time.Now().UTC().Format(time.RFC3339)

	osv := OSV{
		SchemaVersion: "1.6.0", //nolint:goconst
		ID:            d.CVE,
		Modified:      now,
		Summary:       d.Summary,
		Details:       d.Description,
	}

	// Add CVSS severity if available
	if d.CVSS.Vector != "" {
		severityType := "CVSS_V3"
		if strings.HasPrefix(d.CVSS.Vector, "CVSS:4.0") {
			severityType = "CVSS_V4"
		} else if strings.HasPrefix(d.CVSS.Vector, "CVSS:2.0") || !strings.HasPrefix(d.CVSS.Vector, "CVSS:") {
			severityType = "CVSS_V2"
		}
		osv.Severity = []OSVSeverity{
			{Type: severityType, Score: d.CVSS.Vector},
		}
	}

	// Add affected packages/versions
	if len(d.Versions) > 0 {
		// Group by component
		componentVersions := make(map[string][]Versions)
		for _, v := range d.Versions {
			componentVersions[v.Component] = append(componentVersions[v.Component], v)
		}

		for component, versions := range componentVersions {
			affected := OSVAffected{
				Package: OSVPackage{
					Ecosystem: "Kubernetes", //nolint:goconst
					Name:      component,
				},
			}

			var events []OSVEvent
			for _, v := range versions {
				if v.FirstAffectedVersion != "" {
					events = append(events, OSVEvent{Introduced: v.FirstAffectedVersion})
				} else {
					events = append(events, OSVEvent{Introduced: "0"})
				}
				if v.FixedVersion != "" {
					events = append(events, OSVEvent{Fixed: v.FixedVersion})
				}
			}

			if len(events) > 0 {
				affected.Ranges = []OSVRange{
					{Type: "SEMVER", Events: events},
				}
			}

			osv.Affected = append(osv.Affected, affected)
		}
	}

	// Add CVE.org URL as ADVISORY reference
	osv.References = append(osv.References, OSVRef{
		Type: "ADVISORY", //nolint:goconst
		URL:  "https://www.cve.org/cverecord?id=" + d.CVE,
	})

	// Add GitHub issue URL as ADVISORY reference if available
	if d.GitHubIssue.URL != "" {
		osv.References = append(osv.References, OSVRef{
			Type: "ADVISORY",
			URL:  d.GitHubIssue.URL,
		})
	}

	// Add CVSS URL as reference if available
	if d.CVSS.URL != "" {
		osv.References = append(osv.References, OSVRef{
			Type: "WEB",
			URL:  d.CVSS.URL,
		})
	}

	// Add acknowledgements as credits
	if d.Acknowledgements != "" {
		osv.Credits = []OSVCredit{
			{Name: d.Acknowledgements, Type: "FINDER"},
		}
	}

	return osv
}

// ToOSVJSON converts CVEData to OSV format as indented JSON bytes.
func (d CVEData) ToOSVJSON() ([]byte, error) {
	osv := d.ToOSV()
	b, err := json.MarshalIndent(osv, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV to JSON: %w", err)
	}
	return b, nil
}

// OSVString returns the OSV JSON as a string for use in templates.
func (d CVEData) OSVString() string {
	b, err := d.ToOSVJSON()
	if err != nil {
		return ""
	}
	return string(b)
}
