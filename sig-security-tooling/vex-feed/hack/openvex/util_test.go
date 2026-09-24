package openvex

import (
	"reflect"
	"testing"
)

func TestUniqueStrings(t *testing.T) {
	got := Unique([]string{"b", "a", "b", "c", "a"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Unique = %v, want %v", got, want)
	}
}

func TestUniqueInts(t *testing.T) {
	got := Unique([]int{3, 1, 3, 2, 1})
	want := []int{1, 2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Unique = %v, want %v", got, want)
	}
}
