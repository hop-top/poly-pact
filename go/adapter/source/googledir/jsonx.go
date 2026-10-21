package googledir

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// member decodes the required member name of m into dst, which is a *string,
// a *bool or a *int64. A member that is absent, null or of another type is an
// error: a reply the source cannot read is never read as a default.
func member(m map[string]json.RawMessage, name string, dst any) error {
	raw, ok := m[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("no %s", name)
	}
	switch d := dst.(type) {
	case *string:
		if err := json.Unmarshal(raw, d); err != nil {
			return fmt.Errorf("%s is not a string", name)
		}
	case *bool:
		if err := json.Unmarshal(raw, d); err != nil {
			return fmt.Errorf("%s is not a boolean", name)
		}
	case *int64:
		if err := json.Unmarshal(raw, d); err != nil {
			return fmt.Errorf("%s is not an integer", name)
		}
	default:
		return errors.New("member: unsupported target")
	}
	return nil
}

// optString is like member for a string that may be absent, which reads as
// the empty string.
func optString(m map[string]json.RawMessage, name string) (string, error) {
	if _, ok := m[name]; !ok {
		return "", nil
	}
	var s string
	err := member(m, name, &s)
	return s, err
}
