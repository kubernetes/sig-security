package openvex

import (
	"reflect"
	"testing"
)

func TestCollapseSubcomponents(t *testing.T) {
	tests := []struct {
		name string
		ids  []string
		want []string
	}{
		{
			name: "empty",
			ids:  []string{},
			want: nil,
		},
		{
			name: "single id keeps its version",
			ids:  []string{"pkg:golang/golang.org/x/net@v0.49.0"},
			want: []string{"pkg:golang/golang.org/x/net@v0.49.0"},
		},
		{
			name: "same base different versions collapses (real CVE-2025-68121 case)",
			ids:  []string{"pkg:golang/stdlib@v1.25.6", "pkg:golang/stdlib"},
			want: []string{"pkg:golang/stdlib"},
		},
		{
			name: "duplicate ids still collapse",
			ids:  []string{"pkg:golang/stdlib@v1.25.7", "pkg:golang/stdlib@v1.25.7"},
			want: []string{"pkg:golang/stdlib"},
		},
		{
			name: "different base packages stay separate and sorted",
			ids:  []string{"pkg:golang/x/net@v0.49.0", "pkg:golang/stdlib"},
			want: []string{"pkg:golang/stdlib", "pkg:golang/x/net@v0.49.0"},
		},
		{
			name: "three same-base ids in arbitrary order collapse to one",
			ids:  []string{"pkg:golang/stdlib@v1.25.9", "pkg:golang/stdlib", "pkg:golang/stdlib@v1.25.7"},
			want: []string{"pkg:golang/stdlib"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CollapseSubcomponents(tt.ids)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CollapseSubcomponents(%v) = %v, want %v", tt.ids, got, tt.want)
			}
		})
	}
}
