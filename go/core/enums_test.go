package core

import (
	"reflect"
	"slices"
	"testing"
)

func TestEnumValid(t *testing.T) {
	type validator interface{ Valid() bool }
	for et, set := range enumSets {
		for _, s := range set {
			if !reflect.ValueOf(s).Convert(et).Interface().(validator).Valid() {
				t.Errorf("%s(%q).Valid() = false", et.Name(), s)
			}
		}
		for _, bad := range []string{"", "bogus", " ", "Enforced", "enforced "} {
			if slices.Contains(set, bad) {
				continue
			}
			if reflect.ValueOf(bad).Convert(et).Interface().(validator).Valid() {
				t.Errorf("%s(%q).Valid() = true", et.Name(), bad)
			}
		}
	}
}
