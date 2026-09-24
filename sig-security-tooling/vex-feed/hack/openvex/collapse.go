package openvex

import (
	"sort"
	"strings"
)

// CollapseSubcomponents sorts ids, and when every id shares exactly one base
// package (the part before "@"), collapses them to a single unversioned
// base id. Zero or one input id, or a genuine mix of distinct base
// packages, is returned unchanged (still sorted).
func CollapseSubcomponents(ids []string) []string {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	if len(sorted) <= 1 {
		return sorted
	}
	base, _, _ := strings.Cut(sorted[0], "@")
	for _, id := range sorted[1:] {
		b, _, _ := strings.Cut(id, "@")
		if b != base {
			return sorted
		}
	}
	return []string{base}
}
