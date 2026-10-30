// Package cve extracts CVE IDs and not_affected justifications from issue text.
package cve

import (
	"regexp"
	"slices"
	"strings"
)

// cveRE matches CVE identifiers in the format CVE-YYYY-NNNNN (case-insensitive)
var cveRE = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)

// ExtractCVEs returns the sorted, deduplicated, upper-cased set of CVE IDs
// found in the provided text (title, body, and comments).
func ExtractCVEs(title, body string, comments []string) []string {
	// Combine all text
	allText := strings.Join(append([]string{title, body}, comments...), " ")

	// Find all matches
	matches := cveRE.FindAllString(allText, -1)

	// Convert to uppercase and deduplicate
	seen := make(map[string]struct{})
	var unique []string
	for _, m := range matches {
		upper := strings.ToUpper(m)
		if _, ok := seen[upper]; !ok {
			seen[upper] = struct{}{}
			unique = append(unique, upper)
		}
	}

	// Sort
	slices.Sort(unique)
	return unique
}

// ExtractJustification attempts to extract the vexflow slash command
// from the issue comments. Returns the justification type (e.g.,
// "component_not_present") and the first matching comment.
func ExtractJustification(comments []string) (justification, details string) {
	// Patterns for vexflow not_affected slash commands
	patterns := []string{
		"component_not_present",
		"vulnerable_code_not_present",
		"vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist",
	}

	for _, comment := range comments {
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(comment), "/not_affected:"+pattern) {
				// Extract the comment text after the command as details
				lines := strings.Split(comment, "\n")
				var detailLines []string
				for _, line := range lines {
					// Skip the slash command line itself
					if !strings.Contains(strings.ToLower(line), "/not_affected:") {
						detailLines = append(detailLines, strings.TrimSpace(line))
					}
				}
				details = strings.Join(detailLines, " ")
				details = strings.TrimSpace(details)

				return pattern, details
			}
		}
	}

	return "", ""
}
