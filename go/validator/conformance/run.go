package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
	"hop.top/pact-go/validator"
)

// Locate returns the fixture directory that holds dir, the nearest directory
// at or above it with a manifest.json, and the id of the evaluate entry whose
// path is dir.
func Locate(dir string) (fixtures, id string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	for fixtures = abs; ; fixtures = filepath.Dir(fixtures) {
		if _, err := os.Stat(filepath.Join(fixtures, "manifest.json")); err == nil {
			break
		}
		if filepath.Dir(fixtures) == fixtures {
			return "", "", fmt.Errorf("%s: no manifest.json in it or above it", dir)
		}
	}
	rel, err := filepath.Rel(fixtures, abs)
	if err != nil {
		return "", "", err
	}
	m, err := manifest.Load(fixtures)
	if err != nil {
		return "", "", err
	}
	for _, e := range m.Entries {
		if e.Kind == manifest.KindEvaluate && e.Path == filepath.ToSlash(rel) {
			return fixtures, e.ID, nil
		}
	}
	return "", "", fmt.Errorf("%s: not the path of an evaluate entry", dir)
}

// Evaluate runs the evaluation case in dir and writes its responses to w,
// one per line (spec/v1.0/fixtures/README.md, Evaluate output). When state is
// not empty it records the receipts there for Receipt.
func Evaluate(dir, state string, w io.Writer) error {
	fixtures, id, err := Locate(dir)
	if err != nil {
		return err
	}
	c, err := evalcase.Read(fixtures, id)
	if err != nil {
		return err
	}
	keys, err := loadPrivateKeys(fixtures)
	if err != nil {
		return err
	}
	gs := newGatewayState()
	var lines []string
	for _, x := range c.Exchanges {
		out, err := runExchange(fixtures, x, keys, gs)
		if err != nil {
			return fmt.Errorf("%s %s: %w", id, x.Name, err)
		}
		lines = append(lines, out...)
	}
	if state != "" {
		if err := writeState(state, gs.receipts.All()); err != nil {
			return err
		}
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

// Receipt writes the compact receipt whose jti is id, as an Evaluate with
// the same state recorded it.
func Receipt(state, id string, w io.Writer) error {
	b, err := os.ReadFile(state)
	if err != nil {
		return err
	}
	var rs map[string]string
	if err := json.Unmarshal(b, &rs); err != nil {
		return err
	}
	r, ok := rs[id]
	if !ok {
		return fmt.Errorf("no receipt with jti %q", id)
	}
	_, err = fmt.Fprintln(w, r)
	return err
}

func writeState(state string, rs map[string]validator.Result) error {
	out := make(map[string]string, len(rs))
	for jti, r := range rs {
		out[jti] = r.Receipt
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(state, b, 0o600)
}

// runExchange evaluates the submissions of one exchange, then its handoff
// attempts, and returns one line per response.
func runExchange(fixtures string, x *evalcase.Exchange, keys map[string]privateKey, gs *gatewayState) ([]string, error) {
	g, err := buildGateway(fixtures, x, keys, gs)
	if err != nil {
		return nil, err
	}
	results := make(map[string]validator.Result)
	lines := make([]string, len(x.Submissions))
	for i := 0; i < len(x.Submissions); {
		batch := []int{i}
		for x.Submissions[i].Concurrent && i+len(batch) < len(x.Submissions) && x.Submissions[i+len(batch)].Concurrent {
			batch = append(batch, i+len(batch))
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, k := range batch {
			sub := x.Submissions[k]
			g.prepareSubmission(sub)
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, line, err := g.submit(sub)
				mu.Lock()
				defer mu.Unlock()
				if err == nil && res.Receipt != "" {
					results[sub.JTI] = res
				}
				lines[k] = line
			}()
			if len(batch) == 1 {
				wg.Wait()
			}
		}
		wg.Wait()
		i += len(batch)
	}
	for _, h := range x.Handoff {
		lines = append(lines, g.handoff(h, results[h.Presentation]))
	}
	return lines, nil
}

// line is the response line of a submission: its compact receipt, or the
// Problem of its rejection.
func line(res validator.Result, err error, requestID string) string {
	if res.Receipt != "" {
		return res.Receipt
	}
	p, ok := validator.ProblemOf(err, requestID)
	if !ok {
		p = core.Problem{Type: "about:blank", Title: "Dependency unavailable", Status: 503, Code: "DEPENDENCY_UNAVAILABLE", RequestID: requestID}
	}
	b, merr := json.Marshal(p)
	if merr != nil {
		return `{"code":"DEPENDENCY_UNAVAILABLE"}`
	}
	return string(b)
}

func readCase(fixtures string, x *evalcase.Exchange, rel string) ([]byte, error) {
	if b, ok := x.Decoded[rel]; ok {
		return b, nil
	}
	return os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(x.Path), filepath.FromSlash(rel)))
}

func readText(fixtures string, x *evalcase.Exchange, rel string) (string, error) {
	b, err := readCase(fixtures, x, rel)
	return strings.TrimSpace(string(b)), err
}

var errNoReceipt = errors.New("the presentation got no receipt")
