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

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

// Case is an evaluation case: a manifest entry of kind evaluate, read with
// every file of its directory, or of each exchange directory of a
// multi-exchange case.
type Case struct {
	// ID is the manifest id; Path the case directory, relative to the
	// fixture directory.
	ID, Path string
	// Exchanges holds the case's one exchange, or the exchanges of its
	// sequence.json in order.
	Exchanges []*Exchange
	// Subject is the index in Exchanges of the exchange whose expected file
	// is the manifest entry's expected file.
	Subject int
}

// Exchange is one admission exchange: a case directory, or an exchange
// directory of a multi-exchange case.
type Exchange struct {
	// Name is the exchange path sequence.json names, such as
	// "exchanges/1", or "" for a case of one exchange. Path is the
	// directory relative to the fixture directory.
	Name, Path string
	// Config and NativeContext are config.json and native_context.json.
	Config        Config
	NativeContext NativeContext
	// Signing is signing.json; it is empty when the directory has none.
	Signing Signing
	// Submissions, Availability and Handoff are exchange.json with its
	// defaults: without the file, one submission of
	// signed/presentation.jws, everything available and no handoff.
	Submissions  []Submission
	Availability Availability
	Handoff      []HandoffAttempt
	// Decoded holds the bytes of every other JSON file of the directory,
	// by path relative to it: the decoded artifacts, the profile, intent and
	// operations. They are kept as bytes since a case may hold an object
	// that a validator must reject.
	Decoded map[string][]byte
	// Signed holds the committed signed files, verified (Verify).
	Signed []Signed
	// Expected is the expected file ExpectedPath, relative to the fixture
	// directory.
	Expected     Decision
	ExpectedPath string
}

// controlFiles are the files of a case directory that are not decoded
// objects.
var controlFiles = []string{"config.json", "native_context.json", "signing.json", "exchange.json", "sequence.json"}

// Load reads the evaluation case id of the fixture directory fixtures (the
// directory of manifest.json) and verifies its signed files. It fails when
// the manifest does not list id as an entry of kind evaluate, when a file
// is missing or is not strict JSON of its format, when the expected file
// does not have one response per submission and one entry per handoff
// attempt, or when a signed file is stale (Verify). A signed file that
// fails its trust records is not an error: its Signed.Trust says why.
func Load(fixtures, id string) (*Case, error) { return load(fixtures, id, true) }

// Read reads the evaluation case id as Load does but does not verify the
// signed files: it loads no test key, so a fixture directory without the
// private values of KeysFile reads, and a stale signed file is not an error.
// Every Signed.Trust and the Signed list of each Exchange are empty. A
// consumer that judges an implementation against the case, not the case
// itself, reads with Read; the generator and its checks use Load.
func Read(fixtures, id string) (*Case, error) { return load(fixtures, id, false) }

func load(fixtures, id string, check bool) (*Case, error) {
	m, err := manifest.Load(fixtures)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", manifest.FileName, err)
	}
	i := slices.IndexFunc(m.Entries, func(e manifest.Entry) bool { return e.ID == id })
	if i < 0 {
		return nil, fmt.Errorf("%s: no manifest entry", id)
	}
	e := m.Entries[i]
	if e.Kind != manifest.KindEvaluate {
		return nil, fmt.Errorf("%s: manifest kind %s, not %s", id, e.Kind, manifest.KindEvaluate)
	}
	if e.Expected == nil {
		return nil, fmt.Errorf("%s: the manifest entry names no expected file", id)
	}
	var keys map[string]Key
	if check {
		if keys, err = LoadKeys(fixtures); err != nil {
			return nil, err
		}
	}
	dir := filepath.Join(fixtures, filepath.FromSlash(e.Path))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s: path %s is not a case directory", id, e.Path)
	}
	c := &Case{ID: id, Path: e.Path}
	seq, multi, err := readSequence(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if !multi {
		x, err := loadExchange(fixtures, keys, check, e.ID, "", e.Path, *e.Expected)
		if err != nil {
			return nil, err
		}
		c.Exchanges = []*Exchange{x}
		return c, nil
	}
	if err := noSignedFiles(fixtures, e.Path, seq.Exchanges); err != nil {
		return nil, err
	}
	c.Subject = slices.Index(seq.Exchanges, seq.Subject)
	if c.Subject < 0 {
		return nil, fmt.Errorf("%s/sequence.json: subject %q is not one of its exchanges", id, seq.Subject)
	}
	for _, name := range seq.Exchanges {
		exp := "expected/" + id + "/" + name + "/decision.json"
		if name == seq.Subject && exp != *e.Expected {
			return nil, fmt.Errorf("%s: manifest expected %s is not %s, the expected file of the subject exchange", id, *e.Expected, exp)
		}
		x, err := loadExchange(fixtures, keys, check, e.ID, name, e.Path+"/"+name, exp)
		if err != nil {
			return nil, err
		}
		c.Exchanges = append(c.Exchanges, x)
	}
	return c, nil
}

// loadExchange reads the exchange directory rel of the entry.
func loadExchange(fixtures string, keys map[string]Key, check bool, entry, name, rel, expected string) (*Exchange, error) {
	id := entry
	if name != "" {
		id += "/" + name
	}
	dir := filepath.Join(fixtures, filepath.FromSlash(rel))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory of the case", id)
	}
	x := &Exchange{Name: name, Path: rel, ExpectedPath: expected, Decoded: map[string][]byte{}}
	for _, f := range []struct {
		name string
		v    any
	}{{"config.json", &x.Config}, {"native_context.json", &x.NativeContext}} {
		if err := readStrict(filepath.Join(dir, f.name), f.v); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", id, f.name, err)
		}
	}
	if err := x.Config.Gateway.checkAlgorithms(); err != nil {
		return nil, fmt.Errorf("%s/config.json: %w", id, err)
	}
	if err := x.Config.ReputationContext.check(); err != nil {
		return nil, fmt.Errorf("%s/config.json: %w", id, err)
	}
	if err := x.NativeContext.Authenticated.check(); err != nil {
		return nil, fmt.Errorf("%s/native_context.json: %w", id, err)
	}
	if err := x.Config.checkSources(x.NativeContext); err != nil {
		return nil, fmt.Errorf("%s/config.json: %w", id, err)
	}
	d, ok, err := loadDir(fixtures, entry, id, rel, nil)
	if err != nil {
		return nil, err
	}
	if ok {
		x.Signing = d.Signing
	}
	if ok && check {
		var jkt core.Digest
		if a := x.NativeContext.Authenticated; a != nil {
			jkt = deref(a.HolderJKT)
		}
		if x.Signed, err = verify(fixtures, d, keys, x.Config.Trust, jkt); err != nil {
			return nil, err
		}
	}
	if err := x.readExchange(dir); err != nil {
		return nil, fmt.Errorf("%s/exchange.json: %w", id, err)
	}
	if err := x.readDecoded(dir); err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if err := readStrict(filepath.Join(fixtures, filepath.FromSlash(expected)), &x.Expected); err != nil {
		return nil, fmt.Errorf("%s: expected file %s: %w", id, expected, err)
	}
	if n, want := len(x.Expected.ExpectedResponses()), len(x.Submissions); n != want {
		return nil, fmt.Errorf("%s: expected file %s: %d expected responses for %d submissions", id, expected, n, want)
	}
	if n, want := len(x.Expected.Handoff), len(x.Handoff); n != want {
		return nil, fmt.Errorf("%s: expected file %s: %d expected handoff results for %d handoff attempts", id, expected, n, want)
	}
	return x, nil
}

// readExchange reads exchange.json, when there is one, and applies the
// defaults of README section exchange.json.
func (x *Exchange) readExchange(dir string) error {
	var f struct {
		Presentations *[]struct {
			Signed             string  `json:"signed"`
			JTI                string  `json:"jti"`
			Replica            *string `json:"replica"`
			Concurrent         *bool   `json:"concurrent"`
			EvictReplayRecords *bool   `json:"evict_replay_records"`
			ActualOperation    *string `json:"actual_operation"`
			Transport          *string `json:"transport"`
			Evaluation         *struct {
				StartedAt     *int64 `json:"started_at"`
				NativeReadsAt *int64 `json:"native_reads_at"`
				CancelledAt   *int64 `json:"cancelled_at"`
			} `json:"evaluation"`
		} `json:"presentations"`
		Availability *struct {
			Sources          []string `json:"sources"`
			ReplayStore      *string  `json:"replay_store"`
			EnrollmentSource *string  `json:"enrollment_source"`
		} `json:"availability"`
		Handoff []struct {
			Presentation    *string `json:"presentation"`
			ActualOperation *string `json:"actual_operation"`
			At              *int64  `json:"at"`
		} `json:"handoff"`
	}
	if err := readStrict(filepath.Join(dir, "exchange.json"), &f); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	or := func(p *string, def string) string {
		if p != nil {
			return *p
		}
		return def
	}
	const defaultOperation, defaultPresentation, defaultTransport = "actual_operation.json", "signed/presentation.jws", "https"
	if f.Presentations == nil {
		jti := ""
		if i := slices.IndexFunc(x.Signing.Presentations, func(p Presentation) bool { return p.Signed == defaultPresentation }); i >= 0 {
			jti = x.Signing.Presentations[i].JTI
		}
		x.Submissions = []Submission{{
			Signed: defaultPresentation, JTI: jti, Replica: "r1",
			ActualOperation: defaultOperation, Transport: defaultTransport, Evaluation: Evaluation{StartedAt: x.Config.Now},
		}}
	} else if len(*f.Presentations) == 0 {
		return errors.New("presentations is empty")
	}
	if f.Presentations != nil {
		for i, p := range *f.Presentations {
			if p.Signed == "" || p.JTI == "" {
				return fmt.Errorf("presentations[%d]: signed and jti are required", i)
			}
			s := Submission{
				Signed: p.Signed, JTI: p.JTI, Replica: or(p.Replica, "r1"),
				Concurrent: p.Concurrent != nil && *p.Concurrent, EvictReplayRecords: p.EvictReplayRecords != nil && *p.EvictReplayRecords,
				ActualOperation: or(p.ActualOperation, defaultOperation), Transport: or(p.Transport, defaultTransport),
				Evaluation: Evaluation{StartedAt: x.Config.Now},
			}
			if s.Transport != "https" && s.Transport != "stdio-ipc" {
				return fmt.Errorf("presentations[%d]: transport %q is not https or stdio-ipc", i, s.Transport)
			}
			if e := p.Evaluation; e != nil {
				if e.StartedAt != nil {
					s.Evaluation.StartedAt = *e.StartedAt
				}
				s.Evaluation.NativeReadsAt, s.Evaluation.CancelledAt = e.NativeReadsAt, e.CancelledAt
			}
			x.Submissions = append(x.Submissions, s)
		}
	}
	x.Availability = Availability{Sources: []string{}, ReplayStore: "available", EnrollmentSource: "available"}
	if a := f.Availability; a != nil {
		if a.Sources != nil {
			x.Availability.Sources = a.Sources
		}
		x.Availability.ReplayStore = or(a.ReplayStore, "available")
		x.Availability.EnrollmentSource = or(a.EnrollmentSource, "available")
		if s := x.Availability.EnrollmentSource; s != "available" && s != "unavailable" {
			return fmt.Errorf("availability.enrollment_source %q is not available or unavailable", s)
		}
	}
	for i, h := range f.Handoff {
		// The attempt's submission: the one its presentation jti names, by
		// default the first.
		s := x.Submissions[0]
		if h.Presentation != nil {
			j := slices.IndexFunc(x.Submissions, func(s Submission) bool { return s.JTI == *h.Presentation })
			if j < 0 {
				return fmt.Errorf("handoff[%d]: presentation %q is the jti of no submission", i, *h.Presentation)
			}
			s = x.Submissions[j]
		}
		at := s.Evaluation.StartedAt
		if h.At != nil {
			at = *h.At
		}
		x.Handoff = append(x.Handoff, HandoffAttempt{Presentation: s.JTI, ActualOperation: or(h.ActualOperation, defaultOperation), At: at})
	}
	return nil
}

// readDecoded reads every JSON file under dir other than the control files
// at its top level.
func (x *Exchange) readDecoded(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(d.Name()) != ".json" {
			return err
		}
		r, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		r = filepath.ToSlash(r)
		if !strings.Contains(r, "/") && slices.Contains(controlFiles, r) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		x.Decoded[r] = b
		return nil
	})
}

// readStrict parses the strict JSON file p into v. A missing file is an
// error that wraps fs.ErrNotExist.
func readStrict(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return strictjson.Unmarshal(b, strictjson.Limits{}, v)
}
