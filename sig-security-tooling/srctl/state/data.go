package state

import (
	"bytes"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"

	"github.com/Kunde21/markdownfmt/v3"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

var (
	affectedVersionRegex = regexp.MustCompile(`^\s*([A-Za-z0-9._\-]+)(?:\s+([vV]?\S+))?\s*<\s*([vV]?\S+)`)
)

type CVSS struct {
	URL      string
	Vector   string
	Severity string
	Score    float64
}

type Versions struct {
	Component            string
	FirstAffectedVersion string
	FixedVersion         string
}

type CVEData struct {
	CVE               string
	Summary           string
	CVSS              CVSS
	Description       string
	Vulnerable        string
	Versions          []Versions
	Upgrade           string
	Mitigate          string
	Detection         string
	AdditionalDetails string
	Acknowledgements  string
}

func parseCVSS(cvssURL string) (CVSS, error) {
	out := CVSS{
		URL: cvssURL,
	}

	parsedCVSSURL, err := url.Parse(cvssURL)
	if err != nil {
		return CVSS{}, fmt.Errorf("failed to parse URL %q: %w", cvssURL, err)
	}
	out.Vector = parsedCVSSURL.Fragment

	switch {
	default: // Should be CVSS v2.0 or is invalid
		cvss, err := gocvss20.ParseVector(out.Vector)
		if err != nil {
			log.Fatal(err)
		}
		out.Score = cvss.BaseScore()
	case strings.HasPrefix(out.Vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(out.Vector)
		if err != nil {
			log.Fatal(err)
		}
		out.Score = cvss.BaseScore()
		out.Severity, err = gocvss30.Rating(cvss.BaseScore())
		if err != nil {
			return CVSS{}, fmt.Errorf("failed to rate CVSS %q: %w", out.Vector, err)
		}
	case strings.HasPrefix(out.Vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(out.Vector)
		if err != nil {
			log.Fatal(err)
		}
		out.Score = cvss.BaseScore()
		out.Severity, err = gocvss31.Rating(cvss.BaseScore())
		if err != nil {
			return CVSS{}, fmt.Errorf("failed to rate CVSS %q: %w", out.Vector, err)
		}
	case strings.HasPrefix(out.Vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(out.Vector)
		if err != nil {
			log.Fatal(err)
		}
		out.Score = cvss.Score()
		out.Severity, err = gocvss40.Rating(cvss.Score())
		if err != nil {
			return CVSS{}, fmt.Errorf("failed to rate CVSS %q: %w", out.Vector, err)
		}
	}

	return out, nil
}

func parseAffectedVersions(input string) ([]Versions, error) {
	var results []Versions

	for line := range strings.SplitSeq(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := affectedVersionRegex.FindStringSubmatch(line)
		if matches == nil {
			return []Versions{}, fmt.Errorf("invalid version line %q", line)
		}

		results = append(results, Versions{
			Component:            matches[1],
			FirstAffectedVersion: matches[2],
			FixedVersion:         matches[3],
		})
	}

	return results, nil
}

func (s Internal) ToProcessedData() (CVEData, error) {
	data := CVEData{CVE: s.CVE}
	linter := markdownfmt.NewGoldmark()

	// Existing entries
	for key, step := range s.steps {
		value := step.Value
		if step.Markdown {
			var lintedValue bytes.Buffer
			err := linter.Convert([]byte(value), &lintedValue)
			if err != nil {
				return CVEData{}, fmt.Errorf("failed to lint entry %q: %w", key, err)
			}
			value = strings.TrimSpace(lintedValue.String())
		}

		switch step.ID {
		case StepCVSS:
			cvss, err := parseCVSS(value)
			if err != nil {
				return CVEData{}, fmt.Errorf("failed to parse CVSS: %w", err)
			}
			data.CVSS = cvss
		case StepAffectedVersions:
			var err error
			data.Versions, err = parseAffectedVersions(value)
			if err != nil {
				return CVEData{}, fmt.Errorf("failed to parse affected versions: %w", err)
			}
		case StepSummary:
			data.Summary = value
		case StepDescription:
			data.Description = value
		case StepVulnerable:
			data.Vulnerable = value
		case StepMitigate:
			data.Mitigate = value
		case StepUpgrade:
			data.Upgrade = value
		case StepDetection:
			data.Detection = value
		case StepAdditionalDetails:
			data.AdditionalDetails = value
		case StepAcknowledgements:
			data.Acknowledgements = value
		}
	}

	return data, nil
}
