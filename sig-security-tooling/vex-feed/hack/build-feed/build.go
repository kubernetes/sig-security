package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"k8s.io/sig-security/sig-security-tooling/vex-feed/hack/openvex"
)

// groupKey identifies a (product, CVE) pair that statements are merged by.
type groupKey struct {
	product string
	cve     string
}

// group accumulates every per-issue statement seen for one groupKey.
type group struct {
	statuses       []string
	justifications []string
	subs           map[string]struct{}
	sources        []int
	first          openvex.Statement
}

// override is a curated merge-overrides.json entry.
type override struct {
	StatusNotes     string `json:"status_notes,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
}

// loadOverrides reads path, skipping any top-level key that starts with "_"
// (a comment, not an override entry) -- merge-overrides.json mixes a bare
// string "_comment" value alongside object-valued override entries, so this
// must be decoded permissively before typed access.
func loadOverrides(path string) (map[string]override, error) {
	// #nosec G304 -- fixed, repo-relative constant, not user input.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	out := make(map[string]override, len(raw))
	for k, v := range raw {
		if strings.HasPrefix(k, "_") {
			continue
		}
		var ov override
		if err := json.Unmarshal(v, &ov); err != nil {
			return nil, fmt.Errorf("failed to parse %s entry %q: %w", path, k, err)
		}
		out[k] = ov
	}
	return out, nil
}

// buildResult is the outcome of buildStatements: either statements ready to
// write, or a list of conflicts that must be resolved first.
type buildResult struct {
	statements []openvex.Statement
	conflicts  []string
}

// buildStatements groups every statement found by filesGlob (newest issue
// first) by (product, CVE), resolves per-CVE overrides, and returns the
// merged statements plus any unresolved conflicts.
func buildStatements(filesGlob string, overrides map[string]override) (buildResult, error) {
	paths, err := filepath.Glob(filesGlob)
	if err != nil {
		return buildResult{}, fmt.Errorf("failed to glob %s: %w", filesGlob, err)
	}
	if len(paths) == 0 {
		return buildResult{}, fmt.Errorf("no per-issue files found at %s", filesGlob)
	}

	nums := make(map[string]int, len(paths))
	for _, p := range paths {
		n, err := openvex.ParseIssueNumber(p)
		if err != nil {
			return buildResult{}, err
		}
		nums[p] = n
	}
	sort.Slice(paths, func(i, j int) bool { return nums[paths[i]] > nums[paths[j]] }) // newest issue first

	var order []groupKey
	groups := make(map[groupKey]*group)

	for _, path := range paths {
		n := nums[path]
		doc, err := openvex.Load(path)
		if err != nil {
			return buildResult{}, err
		}
		for _, st := range doc.Statements {
			if len(st.Products) == 0 {
				return buildResult{}, fmt.Errorf("issue #%d: statement for %s has no products", n, st.Vulnerability.Name)
			}
			key := groupKey{product: st.Products[0].ID, cve: string(st.Vulnerability.Name)}
			g, ok := groups[key]
			if !ok {
				g = &group{subs: map[string]struct{}{}, first: st}
				groups[key] = g
				order = append(order, key)
			}
			g.statuses = append(g.statuses, string(st.Status))
			g.justifications = append(g.justifications, string(st.Justification))
			for _, sc := range st.Products[0].Subcomponents {
				g.subs[sc.ID] = struct{}{}
			}
			g.sources = append(g.sources, n)
		}
	}

	var conflicts []string
	var statements []openvex.Statement
	for _, key := range order {
		g := groups[key]

		if u := openvex.Unique(g.statuses); len(u) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("%s: conflicting status %s", key.cve, quotedStrList(u)))
			continue
		}
		if u := openvex.Unique(g.justifications); len(u) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("%s: conflicting justification %s", key.cve, quotedStrList(u)))
			continue
		}

		product := openvex.Product{Component: openvex.Component{ID: key.product}}
		if subs := openvex.CollapseSubcomponents(setKeys(g.subs)); len(subs) > 0 {
			product.Subcomponents = make([]openvex.Subcomponent, len(subs))
			for i, s := range subs {
				product.Subcomponents[i] = openvex.Subcomponent{Component: openvex.Component{ID: s}}
			}
		}

		stmt := openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: openvex.VulnerabilityID(key.cve)},
			Products:      []openvex.Product{product},
			Status:        openvex.Status(g.statuses[0]),
			Justification: openvex.Justification(g.justifications[0]),
		}

		multiSources := openvex.Unique(g.sources)
		var statusNotes, actionStatement string
		if ov, hasOverride := overrides[key.cve]; hasOverride {
			statusNotes, actionStatement = ov.StatusNotes, ov.ActionStatement
		} else if len(multiSources) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("%s: reported by %s but no merge-overrides.json entry", key.cve, intList(multiSources)))
			continue
		} else {
			statusNotes, actionStatement = g.first.StatusNotes, g.first.ActionStatement
		}
		if statusNotes != "" {
			stmt.StatusNotes = statusNotes
		}
		if actionStatement != "" {
			stmt.ActionStatement = actionStatement
		}

		statements = append(statements, stmt)
	}

	return buildResult{statements: statements, conflicts: conflicts}, nil
}

// setKeys returns the keys of a string set as a slice (order not
// significant -- CollapseSubcomponents sorts internally).
func setKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// bracketList renders vs as a bracketed, comma-separated list using elem to
// render each value, e.g. bracketList([]int{1, 2}, strconv.Itoa) -> "[1, 2]".
func bracketList[T any](vs []T, elem func(T) string) string {
	strs := make([]string, len(vs))
	for i, v := range vs {
		strs[i] = elem(v)
	}
	return "[" + strings.Join(strs, ", ") + "]"
}

// quotedStrList renders vs as a bracketed, single-quoted, comma-separated
// list, e.g. ["a", "b"] -> "['a', 'b']", for compact conflict messages.
func quotedStrList(vs []string) string {
	return bracketList(vs, func(s string) string { return "'" + s + "'" })
}

// intList renders vs as a bracketed, comma-separated list, e.g.
// [1, 2] -> "[1, 2]", for compact conflict messages.
func intList(vs []int) string {
	return bracketList(vs, strconv.Itoa)
}
