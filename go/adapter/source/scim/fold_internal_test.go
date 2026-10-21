package scim

import "testing"

// Attribute names are ASCII and compared without regard to ASCII case only
// (RFC 7643 2.1). strings.ToLower maps U+0130 LATIN CAPITAL LETTER I WITH DOT
// ABOVE to "i", so a name with it is another attribute, which the service
// ignores.

func replace(path string, value any) patchOp {
	return patchOp{op: "replace", path: path, value: value, hasValue: true}
}

// TestUserAttrFoldASCII: "d\u0130splayName" is not displayName, with a path
// and without one.
func TestUserAttrFoldASCII(t *testing.T) {
	for name, op := range map[string]patchOp{
		"path":     replace("d\u0130splayName", "x"),
		"pathless": replace("", map[string]any{"d\u0130splayName": "x"}),
	} {
		u := &user{displayName: "a"}
		if err := applyUserOp(u, op); err != nil || u.displayName != "a" {
			t.Errorf("%s: displayName = %q, %v", name, u.displayName, err)
		}
	}
	u := &user{displayName: "a"}
	if err := applyUserOp(u, replace("DISPLAYNAME", "x")); err != nil || u.displayName != "x" {
		t.Errorf("ASCII case variant: displayName = %q, %v", u.displayName, err)
	}
}

// TestGroupAttrFoldASCII: "d\u0130splayName" is not displayName, with a path
// and without one.
func TestGroupAttrFoldASCII(t *testing.T) {
	s := &Server{}
	for name, op := range map[string]patchOp{
		"path":     replace("d\u0130splayName", "x"),
		"pathless": replace("", map[string]any{"d\u0130splayName": "x"}),
	} {
		g := &group{displayName: "a"}
		if err := s.applyGroupOp(g, &memberView{overlay: map[string]bool{}}, op); err != nil || g.displayName != "a" {
			t.Errorf("%s: displayName = %q, %v", name, g.displayName, err)
		}
	}
	g := &group{displayName: "a"}
	if err := s.applyGroupOp(g, &memberView{overlay: map[string]bool{}}, replace("DISPLAYNAME", "x")); err != nil || g.displayName != "x" {
		t.Errorf("ASCII case variant: displayName = %q, %v", g.displayName, err)
	}
}
