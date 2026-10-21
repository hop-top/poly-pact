package ldap

import (
	"encoding/hex"
	"errors"
	"strings"
)

// PrincipalID is the identifier of a principal, a workload, or a group under
// the profile: ldap:{realm_id}:{unique_id} (profile LR-2). A name is never
// part of it.
func PrincipalID(realmID, uniqueID string) string { return "ldap:" + realmID + ":" + uniqueID }

// parseID splits an identifier of the form ldap:{realm_id}:{unique_id}.
func parseID(id string) (realmID, uniqueID string, ok bool) {
	rest, ok := strings.CutPrefix(id, "ldap:")
	if !ok {
		return "", "", false
	}
	realmID, uniqueID, ok = strings.Cut(rest, ":")
	if !ok || realmID == "" || !isUUID(uniqueID) {
		return "", "", false
	}
	return realmID, uniqueID, true
}

// isUUID reports whether s is a UUID in the lower-case hyphenated form of
// RFC 4122, section 3, which is how LR-2 writes a unique id.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// GUIDCodec converts the 16 octets of an Active Directory objectGUID to the
// lower-case UUID text of an identifier and back. The octet order of
// objectGUID on the wire is not established by the documents the profile
// read (Appendix H, P3), so a deployment states it.
type GUIDCodec interface {
	Text(octets []byte) (string, error)
	Octets(text string) ([]byte, error)
}

// OctetOrderGUID reads the 16 octets in the order received as the hyphenated
// hexadecimal form of RFC 4122, section 3. Use it only for a directory where
// probe P3 established that order.
var OctetOrderGUID GUIDCodec = octetOrder{}

type octetOrder struct{}

func (octetOrder) Text(b []byte) (string, error) {
	if len(b) != 16 {
		return "", errors.New("objectGUID is not 16 octets")
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

func (octetOrder) Octets(s string) ([]byte, error) {
	if !isUUID(s) {
		return nil, errors.New("not a lower-case UUID")
	}
	return hex.DecodeString(strings.ReplaceAll(s, "-", ""))
}

// uniqueText returns the unique id of an entry as identifier text, or false
// when the entry has none or its value does not convert (profile LR-3).
func (r *realm) uniqueText(e Entry) (string, bool) {
	v := e.Values(r.uniqueAttr)
	if len(v) != 1 {
		return "", false
	}
	if r.Kind == KindActiveDirectory {
		s, err := r.GUIDText.Text(v[0])
		return s, err == nil && isUUID(s)
	}
	s := strings.ToLower(string(v[0]))
	return s, isUUID(s)
}

// uniqueValue is the assertion value of an equality filter on the unique id
// attribute: the UUID text for entryUUID, the 16 octets for objectGUID.
func (r *realm) uniqueValue(id string) ([]byte, error) {
	if r.Kind == KindActiveDirectory {
		return r.GUIDText.Octets(id)
	}
	if !isUUID(id) {
		return nil, errors.New("not a lower-case UUID")
	}
	return []byte(id), nil
}

// isDenied reports whether id is one of the realm's denied principals.
func (r *realm) isDenied(id string) bool {
	for _, d := range r.DeniedPrincipals {
		if d == id {
			return true
		}
	}
	return false
}
