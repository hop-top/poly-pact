package reputation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"hop.top/pact-go/core/jcs"
	score "hop.top/pact-go/reputation"
)

// toleranceMembers are the members of a ReputationValue compared within
// score.ToleranceBPS (spec/v1.0/fixtures/README.md, section snapshot.json).
var toleranceMembers = map[string]bool{"score_bps": true, "confidence_bps": true}

// MatchValue compares the JSON value got with want, the subset of a
// ReputationValue an expected snapshot names: every member of want, at any
// depth, must be in got; score_bps and confidence_bps match within
// score.ToleranceBPS, and every other member exactly, as JSON values, so an array
// matches only an equal array. It returns one problem per difference, each
// naming the member by its JSON Pointer.
func MatchValue(want, got json.RawMessage) []string {
	w, err := decodeNumbers(want)
	if err != nil {
		return []string{"expected value: " + err.Error()}
	}
	g, err := decodeNumbers(got)
	if err != nil {
		return []string{"value: " + err.Error()}
	}
	return matchAt("/value", "", w, g)
}

func decodeNumbers(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

func matchAt(ptr, name string, want, got any) []string {
	if wm, ok := want.(map[string]any); ok {
		gm, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s is %s, want an object", ptr, show(got))}
		}
		var out []string
		for _, k := range slices.Sorted(maps.Keys(wm)) {
			gv, ok := gm[k]
			p := ptr + "/" + strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
			if !ok {
				out = append(out, p+" is missing")
				continue
			}
			out = append(out, matchAt(p, k, wm[k], gv)...)
		}
		return out
	}
	if toleranceMembers[name] {
		wn, wok := want.(json.Number)
		gn, gok := got.(json.Number)
		wi, werr := wn.Int64()
		gi, gerr := gn.Int64()
		if !wok || !gok || werr != nil || gerr != nil {
			return []string{fmt.Sprintf("%s is %s, want the integer %s", ptr, show(got), show(want))}
		}
		if !score.WithinTolerance(gi, wi) {
			return []string{fmt.Sprintf("%s is %d, want %d within %d bp (draft Section 15.3)", ptr, gi, wi, score.ToleranceBPS)}
		}
		return nil
	}
	wc, werr := canonical(want)
	gc, gerr := canonical(got)
	if werr != nil || gerr != nil || wc != gc {
		return []string{fmt.Sprintf("%s is %s, want %s", ptr, gc, wc)}
	}
	return nil
}

func canonical(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	c, err := jcs.Canonicalize(b)
	return string(c), err
}

func show(v any) string {
	s, err := canonical(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return s
}
