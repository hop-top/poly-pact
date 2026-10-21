package manifest

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Completeness checks m against the fixture directory root:
//
//   - every entry path exists, is not a dangling symbolic link and resolves
//     inside root (RulePathMissing);
//   - every expected file does too, and is a file (RuleExpectedMissing);
//   - every file under root, except manifest.json, manifest.schema.json,
//     README.md files and files whose name starts with LICENSE, is inside an
//     entry's path, is an entry's expected file, or is under expected/<id>/
//     for the id of an entry (RuleUncovered; fixture format v2);
//   - every file has a neutral extension, or a native-asset extension inside
//     the path of an adapter-asset entry, written in lower case
//     (RuleExtension).
//
// A root that is itself a symbolic link is followed once, as a POSIX utility
// follows a link named on its command line (find -H): the files checked are
// those of the directory it resolves to. Symbolic links inside the tree are
// not followed.
//
// Entries whose path or expected file breaks a field rule are skipped here;
// Validate reports them.
func Completeness(root string, m *Manifest) Problems {
	var ps Problems
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		ps = append(ps, Problem{Rule: RulePathMissing, Where: ".", Msg: "fixture directory: " + err.Error(), Err: err})
		return ps
	}

	var paths, assets []string
	expected := map[string]bool{}
	for i, e := range m.Entries {
		where := e.ID
		if where == "" {
			where = "entries[" + strconv.Itoa(i) + "]"
		}
		// Format v2: every file under expected/<id>/ belongs to the entry.
		if dir := "expected/" + e.ID; e.ID != "" && pathRE.MatchString(dir) {
			paths = append(paths, dir)
		}
		if pathRE.MatchString(e.Path) {
			if msg := locate(root, realRoot, e.Path); msg != "" {
				ps.add(RulePathMissing, where, "path %q %s", e.Path, msg)
			}
			paths = append(paths, e.Path)
			if e.Kind == KindAdapterAsset {
				assets = append(assets, e.Path)
			}
		}
		if e.Expected != nil && pathRE.MatchString(*e.Expected) {
			x := *e.Expected
			msg := locate(root, realRoot, x)
			if msg == "" {
				if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(x))); err == nil && !info.Mode().IsRegular() {
					msg = "is not a file"
				}
			}
			if msg != "" {
				ps.add(RuleExpectedMissing, where, "expected %q %s", x, msg)
			}
			expected[x] = true
		}
	}

	err = filepath.WalkDir(realRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(realRoot, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		inAsset := slices.ContainsFunc(assets, func(a string) bool { return within(rel, a) })
		ext := path.Ext(rel)
		switch {
		case slices.Contains(neutralExtensions, ext):
		case slices.Contains(nativeExtensions, ext) && inAsset:
		case slices.Contains(nativeExtensions, ext):
			ps.add(RuleExtension, rel, "extension %s is allowed only inside the path of an %s entry", ext, KindAdapterAsset)
		default:
			ps.add(RuleExtension, rel, "extension %q is not language-neutral; allowed: %s, and %s inside an %s entry",
				ext, strings.Join(neutralExtensions, " "), strings.Join(nativeExtensions, " "), KindAdapterAsset)
		}
		if exempt(rel) || expected[rel] || slices.ContainsFunc(paths, func(p string) bool { return within(rel, p) }) {
			return nil
		}
		ps.add(RuleUncovered, rel, "no manifest entry covers this file: add one, or put it inside an entry's path")
		return nil
	})
	if err != nil {
		ps = append(ps, Problem{Rule: RulePathMissing, Where: ".", Msg: "walk: " + err.Error(), Err: err})
	}
	return ps
}

// locate says why rel is not an existing path inside root, or "" when it is.
// realRoot is root with symbolic links resolved.
func locate(root, realRoot, rel string) string {
	full := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Lstat(full); err != nil {
		return "does not exist"
	}
	real, err := filepath.EvalSymlinks(full)
	if errors.Is(err, fs.ErrNotExist) {
		return "is a dangling symbolic link"
	}
	if err != nil {
		return "cannot be resolved: " + err.Error()
	}
	if !strings.HasPrefix(real, realRoot+string(filepath.Separator)) {
		return "resolves outside the fixture directory"
	}
	return ""
}
