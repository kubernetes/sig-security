package state

import (
	"reflect"
	"testing"
)

func TestParseAffectedVersions(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []Versions
		wantError bool
	}{
		{
			name:  "single component without introduced version",
			input: "kube-apiserver < v1.31.12",
			want: []Versions{
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
			},
		},
		{
			name:  "single component with introduced version",
			input: "etcd v3.5.0 < v3.5.8",
			want: []Versions{
				{Component: "etcd", FirstAffectedVersion: "v3.5.0", FixedVersion: "v3.5.8"},
			},
		},
		{
			name: "multiple components mixed",
			input: `kube-apiserver < v1.31.12
etcd v3.5.0 < v3.5.8
kubelet < v1.30.7`,
			want: []Versions{
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
				{Component: "etcd", FirstAffectedVersion: "v3.5.0", FixedVersion: "v3.5.8"},
				{Component: "kubelet", FirstAffectedVersion: "", FixedVersion: "v1.30.7"},
			},
		},
		{
			name: "extra spaces and mixed casing",
			input: `

	kube-apiserver    <    v1.31.12
Etcd V3.5.0    <   V3.5.8
`,
			want: []Versions{
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
				{Component: "Etcd", FirstAffectedVersion: "V3.5.0", FixedVersion: "V3.5.8"},
			},
		},
		{
			name: "invalid lines",
			input: `kube-apiserver < v1.31.12
invalid line here
kubelet < v1.30.7`,
			want:      []Versions{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAffectedVersions(tt.input)
			if err != nil && !tt.wantError {
				t.Errorf("unexpected error %s", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
