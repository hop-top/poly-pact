package evalcase

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

// Dir is one directory the generator signs: a case directory, or an
// exchange directory of a multi-exchange case.
type Dir struct {
	// Entry is the manifest id. ID names the directory: the entry id or,
	// for an exchange, the entry id and the exchange path.
	Entry, ID string
	// Path is the directory, slash-separated, relative to the fixture
	// directory.
	Path string
	// Signing is the directory's signing.json.
	Signing Signing
}

// signedKinds are the manifest kinds whose case directories are signed.
var signedKinds = []manifest.Kind{manifest.KindEvaluate, manifest.KindOutcomes, manifest.KindLearning}

// Dirs walks the manifest of the fixture directory and returns, in manifest
// order, every directory with a signing.json: the case directory of each
// entry of kind evaluate, outcomes or learning, or each exchange directory
// its sequence.json names. A directory that holds a signed file (a .jws
// file) but no signing.json, or a signed file its signing.json does not
// name, is an error. An entry whose path is not a directory is left to the
// manifest check.
func Dirs(fixtures string) ([]Dir, error) {
	m, err := manifest.Load(fixtures)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", manifest.FileName, err)
	}
	var out []Dir
	for _, e := range m.Entries {
		if !slices.Contains(signedKinds, e.Kind) {
			continue
		}
		ds, err := entryDirs(fixtures, e)
		if err != nil {
			return nil, err
		}
		out = append(out, ds...)
	}
	return out, nil
}

// entryDirs returns the signed directories of the entry e.
func entryDirs(fixtures string, e manifest.Entry) ([]Dir, error) {
	dir := filepath.Join(fixtures, filepath.FromSlash(e.Path))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, nil // not a case directory: check manifest reports it
	}
	exchanges, err := sequenceExchanges(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.ID, err)
	}
	if exchanges == nil {
		d, ok, err := loadDir(fixtures, e.ID, e.ID, e.Path, nil)
		if err != nil || !ok {
			return nil, err
		}
		return []Dir{d}, nil
	}
	if err := noSignedFiles(fixtures, e.Path, exchanges); err != nil {
		return nil, err
	}
	var out []Dir
	for _, x := range exchanges {
		d, ok, err := loadDir(fixtures, e.ID, e.ID+"/"+x, e.Path+"/"+x, nil)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

// sequence is sequence.json of a multi-exchange case.
type sequence struct {
	Exchanges []string `json:"exchanges"`
	Subject   string   `json:"subject"`
}

// readSequence reads sequence.json of the case directory dir; ok is false
// when there is none.
func readSequence(dir string) (seq sequence, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(dir, "sequence.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return seq, false, nil
	}
	if err != nil {
		return seq, false, err
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &seq); err != nil {
		return seq, false, fmt.Errorf("sequence.json: %w", err)
	}
	if len(seq.Exchanges) == 0 {
		return seq, false, errors.New("sequence.json: exchanges is empty")
	}
	for _, x := range seq.Exchanges {
		if !relPath.MatchString(x) {
			return seq, false, fmt.Errorf("sequence.json: exchange %q is not a relative path", x)
		}
	}
	return seq, true, nil
}

// sequenceExchanges returns the exchange directories of a multi-exchange
// case, or nil when dir has no sequence.json.
func sequenceExchanges(dir string) ([]string, error) {
	seq, ok, err := readSequence(dir)
	if err != nil || !ok {
		return nil, err
	}
	return seq.Exchanges, nil
}

// loadDir reads signing.json of the directory rel. ok is false when there
// is none and the directory holds no signed file outside skip.
func loadDir(fixtures, entry, id, rel string, skip []string) (Dir, bool, error) {
	d := Dir{Entry: entry, ID: id, Path: rel}
	b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(rel), "signing.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return d, false, noSignedFiles(fixtures, rel, skip)
	}
	if err != nil {
		return d, false, err
	}
	if d.Signing, err = parseSigning(b); err != nil {
		return d, false, fmt.Errorf("%s/signing.json: %w", id, err)
	}
	named := map[string]bool{}
	for _, a := range d.Signing.Artifacts {
		named[a.Signed] = true
	}
	for _, p := range d.Signing.Presentations {
		named[p.Signed] = true
	}
	files, err := signedFilesUnder(fixtures, rel, skip)
	if err != nil {
		return d, false, err
	}
	for _, f := range files {
		if !named[f] {
			return d, false, fmt.Errorf("%s: signed file %s is named by no entry of signing.json", id, f)
		}
	}
	return d, true, nil
}

// noSignedFiles fails when the directory rel holds a signed file outside
// the subdirectories skip, since nothing names it.
func noSignedFiles(fixtures, rel string, skip []string) error {
	files, err := signedFilesUnder(fixtures, rel, skip)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		return fmt.Errorf("%s: holds signed files (%s) but no signing.json", rel, strings.Join(files, ", "))
	}
	return nil
}

// signedFilesUnder lists the .jws files under the directory rel, as paths
// relative to it, leaving out the subdirectories skip.
func signedFilesUnder(fixtures, rel string, skip []string) ([]string, error) {
	root := filepath.Join(fixtures, filepath.FromSlash(rel))
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		r = filepath.ToSlash(r)
		if d.IsDir() {
			if slices.Contains(skip, r) {
				return filepath.SkipDir
			}
			return nil
		}
		if path.Ext(r) == ".jws" {
			out = append(out, r)
		}
		return nil
	})
	return out, err
}
