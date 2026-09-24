package openvex

import (
	"cmp"
	"slices"
)

// Unique returns the sorted set of distinct values in vs.
func Unique[T cmp.Ordered](vs []T) []T {
	seen := make(map[T]struct{}, len(vs))
	var out []T
	for _, v := range vs {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
