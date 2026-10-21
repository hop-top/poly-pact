package manifest

import (
	"errors"
	"os"
	"path/filepath"
)

// Check runs every check of pactfix check manifest over the fixture
// directory root and the spec map at specMapPath: Load, Validate,
// Completeness, ParseSpecMap and CheckSpecMap. It returns all problems; an
// unreadable or non-strict manifest stops it after the RuleJSON problem.
func Check(root, specMapPath string) Problems {
	m, err := Load(root)
	if err != nil {
		var ps Problems
		if errors.As(err, &ps) {
			return ps
		}
		return Problems{{Rule: RuleJSON, Where: FileName, Msg: err.Error(), Err: err}}
	}
	ps := m.Validate()
	ps = append(ps, Completeness(root, m)...)
	text, err := os.ReadFile(specMapPath)
	if err != nil {
		return append(ps, Problem{Rule: RuleSpecMap, Where: filepath.Base(specMapPath), Msg: err.Error(), Err: err})
	}
	sm, sps := ParseSpecMap(text)
	ps = append(ps, sps...)
	if sm != nil {
		ps = append(ps, CheckSpecMap(root, m, sm)...)
	}
	return ps
}
