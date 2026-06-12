package state

import (
	"fmt"
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToOSVOfficial converts CVEData to the official OSV protobuf format.
//
// This implementation uses the official OSSF OSV schema library
// (github.com/ossf/osv-schema/bindings/go/osvschema) and exists solely for
// testing purposes. We use it in TestOSVCustomVsOfficialIdentical to validate
// that our custom lightweight implementation (osv.go) produces equivalent JSON
// output to the official library.
//
// The custom implementation is preferred for production use because:
// - It has fewer dependencies (only encoding/json from stdlib)
// - It produces cleaner, more predictable JSON output
// - It gives us full control over field names and formatting
//
// This file ensures we maintain compatibility with the official OSV schema.
func (d CVEData) ToOSVOfficial() *osvschema.Vulnerability {
	vuln := &osvschema.Vulnerability{
		SchemaVersion: osvSchemaVersion,
		Id:            d.CVE,
		Modified:      timestamppb.New(time.Now().UTC()),
		Summary:       d.Summary,
		Details:       d.Description,
	}

	// Add CVSS severity if available
	if d.CVSS.Vector != "" {
		severityType := osvschema.Severity_CVSS_V3
		if strings.HasPrefix(d.CVSS.Vector, "CVSS:4.0") {
			severityType = osvschema.Severity_CVSS_V4
		} else if strings.HasPrefix(d.CVSS.Vector, "CVSS:2.0") || !strings.HasPrefix(d.CVSS.Vector, "CVSS:") {
			severityType = osvschema.Severity_CVSS_V2
		}
		vuln.Severity = []*osvschema.Severity{
			{Type: severityType, Score: d.CVSS.Vector},
		}
	}

	// Add affected packages/versions
	if len(d.Versions) > 0 {
		componentVersions := make(map[string][]Versions)
		for _, v := range d.Versions {
			componentVersions[v.Component] = append(componentVersions[v.Component], v)
		}

		for component, versions := range componentVersions {
			affected := &osvschema.Affected{
				Package: &osvschema.Package{
					Ecosystem: osvEcosystem,
					Name:      component,
				},
			}

			var events []*osvschema.Event
			for _, v := range versions {
				if v.FirstAffectedVersion != "" {
					events = append(events, &osvschema.Event{Introduced: v.FirstAffectedVersion})
				} else {
					events = append(events, &osvschema.Event{Introduced: "0"})
				}
				if v.FixedVersion != "" {
					events = append(events, &osvschema.Event{Fixed: v.FixedVersion})
				}
			}

			if len(events) > 0 {
				affected.Ranges = []*osvschema.Range{
					{Type: osvschema.Range_SEMVER, Events: events},
				}
			}

			vuln.Affected = append(vuln.Affected, affected)
		}
	}

	// Add CVSS URL as reference
	if d.CVSS.URL != "" {
		vuln.References = []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: d.CVSS.URL},
		}
	}

	// Add acknowledgements as credits
	if d.Acknowledgements != "" {
		vuln.Credits = []*osvschema.Credit{
			{Name: d.Acknowledgements, Type: osvschema.Credit_FINDER},
		}
	}

	return vuln
}

// ToOSVJSONOfficial converts CVEData to OSV format as indented JSON bytes using official library.
func (d CVEData) ToOSVJSONOfficial() ([]byte, error) {
	vuln := d.ToOSVOfficial()
	opts := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true, // Use snake_case (schema_version) instead of camelCase (schemaVersion)
	}
	b, err := opts.Marshal(vuln)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV to JSON: %w", err)
	}
	return b, nil
}
