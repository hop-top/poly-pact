package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"hop.top/pact-go/runner/evalcase"
)

// genResult is one generated file: its path relative to the fixture
// directory and whether generate wrote it (or, in check mode, would write
// it). A decoded file is listed when its signing.json entry fills digests.
type genResult struct {
	File    string
	Changed bool
}

// generate signs the cases under the fixture directory fixtures, all of them
// or those whose manifest ids are in only. The cases are the manifest
// entries whose directories have a signing.json (evalcase.Dirs). A signed
// file that verifies under its key and whose header and payload are what
// generate would write is kept as it is; any other is signed again. With
// check, nothing is written.
func generate(fixtures string, check bool, only []string) ([]genResult, error) {
	dirs, err := evalcase.Dirs(fixtures)
	if err != nil {
		return nil, err
	}
	for _, name := range only {
		if !slices.ContainsFunc(dirs, func(d evalcase.Dir) bool { return d.Entry == name }) {
			return nil, fmt.Errorf("unknown case %q: no manifest entry of kind evaluate, outcomes or learning with a signing.json", name)
		}
	}
	keys, err := evalcase.LoadKeys(fixtures)
	if err != nil {
		return nil, err
	}
	var out []genResult
	for _, d := range dirs {
		if len(only) > 0 && !slices.Contains(only, d.Entry) {
			continue
		}
		res, err := generateCase(fixtures, d, keys, check)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.ID, err)
		}
		out = append(out, res...)
	}
	return out, nil
}

// generateCase signs the directory d: each file evalcase.Walk hands over is
// kept or signed again, and a decoded file whose digests change is written
// back.
func generateCase(fixtures string, d evalcase.Dir, keys map[string]evalcase.Key, check bool) ([]genResult, error) {
	dir := filepath.Join(fixtures, filepath.FromSlash(d.Path))
	var res []genResult
	err := evalcase.Walk(fixtures, d, keys, func(f evalcase.File) (string, error) {
		if f.Digested {
			if f.DigestsChanged && !check {
				if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(f.Decoded)), f.Payload, 0o644); err != nil {
					return "", err
				}
			}
			res = append(res, genResult{File: d.ID + "/" + f.Decoded, Changed: f.DigestsChanged})
		}
		compact, changed, err := signOrKeep(filepath.Join(dir, filepath.FromSlash(f.Signed)), f, check)
		if err != nil {
			return "", err
		}
		res = append(res, genResult{File: d.ID + "/" + f.Signed, Changed: changed})
		return compact, nil
	})
	return res, err
}

// signOrKeep returns the compact JWS for path: the file at path when
// f.Check accepts it, otherwise a fresh JWS (f.Sign), which is written
// unless check is set.
func signOrKeep(path string, f evalcase.File, check bool) (string, bool, error) {
	if old, err := os.ReadFile(path); err == nil && f.Check(string(old)) == nil {
		return string(old), false, nil
	}
	fresh, err := f.Sign()
	if err != nil {
		return "", false, err
	}
	if !check {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(path, []byte(fresh), 0o644); err != nil {
			return "", false, err
		}
	}
	return fresh, true, nil
}
