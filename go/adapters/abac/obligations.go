package abac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"slices"
	"strconv"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/strictjson"
)

// maxContent is the largest content the reference executor holds.
const maxContent = 16 << 20

// DefaultRedactionMarker is the redaction marker of an [Enforcer] that names
// none.
const DefaultRedactionMarker = "[redacted]"

// Errors of [Enforcer.Release]. Neither names the obligation, the policy or
// the content (draft 13.4: public errors avoid private detail).
var (
	// ErrNoEnvelope is a read that arrived without the envelope of profile
	// ABAC-29, or with its obligations absent.
	ErrNoEnvelope = errors.New("abac: no decision envelope; nothing is released")
	// ErrObligationUnmet is an obligation that is unknown, malformed, or that
	// the executor cannot apply or verify (profile ABAC-28): nothing is
	// released.
	ErrObligationUnmet = errors.New("abac: an obligation is unknown or cannot be met; nothing is released")
)

// Envelope is what the gateway gives the executor with a read (profile
// ABAC-29): the operation, the decision and its obligations. Obligations nil
// means absent, which is never "no obligations"; an empty slice is none.
type Envelope struct {
	OperationID   string
	DecisionID    string
	PolicyVersion string
	Obligations   []adapter.Obligation
}

// EnvelopeFor is the envelope of a decision that [Gate] let through.
func EnvelopeFor(operationID string, d adapter.Decision) Envelope {
	obl := []adapter.Obligation{}
	obl = append(obl, d.Obligations...)
	return Envelope{OperationID: operationID, DecisionID: d.SourceRef, PolicyVersion: d.PolicyRevision, Obligations: obl}
}

// ParseEnvelope reads the wire form of an envelope, a JSON object with
// exactly operation_id, decision_id, policy_version and obligations, the last
// an array of {type, params}. An absent or non-array obligations member is
// [ErrNoEnvelope].
func ParseEnvelope(raw []byte) (Envelope, error) {
	var w struct {
		OperationID   string          `json:"operation_id"`
		DecisionID    string          `json:"decision_id"`
		PolicyVersion string          `json:"policy_version"`
		Obligations   json.RawMessage `json:"obligations"`
	}
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: maxAnswer}, &w); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrNoEnvelope, err)
	}
	if w.OperationID == "" || w.DecisionID == "" || !isArray(w.Obligations) {
		return Envelope{}, ErrNoEnvelope
	}
	a := answer{}
	doc := map[string]json.RawMessage{"allow": json.RawMessage("true"), "obligations": w.Obligations, "policy_version": json.RawMessage(`"-"`)}
	if err := a.readDocument(doc); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrNoEnvelope, err)
	}
	return Envelope{OperationID: w.OperationID, DecisionID: w.DecisionID, PolicyVersion: w.PolicyVersion, Obligations: a.obligations}, nil
}

// Watermark is the means of the watermark obligation for one content type,
// which the mapping revision declares (profile ABAC-25): Apply marks the
// content with the label and Present verifies that the label is there.
type Watermark struct {
	Apply   func(content []byte, label string) ([]byte, error)
	Present func(content []byte, label string) bool
}

// JSONMemberWatermark is a watermark means for a JSON object document: the
// top-level member name holds the label.
func JSONMemberWatermark(name string) Watermark {
	return Watermark{
		Apply: func(content []byte, label string) ([]byte, error) {
			v, err := parseJSON(content)
			if err != nil {
				return nil, err
			}
			o, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("the document is not an object")
			}
			o[name] = label
			return encodeJSON(o)
		},
		Present: func(content []byte, label string) bool {
			v, err := parseJSON(content)
			o, ok := v.(map[string]any)
			return err == nil && ok && o[name] == label
		},
	}
}

// Enforcer is the reference executor's enforcement of the obligations of a
// decision before disclosure (profile ABAC-25 to ABAC-29).
type Enforcer struct {
	// Installed is the installed obligation set. Nil means the three types of
	// ABAC-25.
	Installed []string
	// Marker replaces a redacted value. Nil means [DefaultRedactionMarker].
	Marker any
	// Watermarks are the watermark means by media type. A content type with
	// none cannot carry a watermark.
	Watermarks map[string]Watermark
}

// Release applies the obligations of the envelope to the content and returns
// what may be disclosed. It holds the content, checks every obligation,
// applies them in the order filter_fields, redact, watermark whatever their
// order in the array, verifies the postcondition of each on the result, and
// only then returns it. On any failure it returns no byte of content and
// [ErrObligationUnmet] or [ErrNoEnvelope] (ABAC-27 to ABAC-29).
func (e Enforcer) Release(env Envelope, mediaType string, content []byte) (out []byte, err error) {
	if env.Obligations == nil || env.OperationID == "" || env.DecisionID == "" {
		return nil, ErrNoEnvelope
	}
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, ErrObligationUnmet
		}
	}()
	plan, err := e.plan(env.Obligations)
	if err != nil {
		return nil, err
	}
	if len(content) > maxContent {
		return nil, ErrObligationUnmet
	}
	out = content
	if plan.keep != nil || plan.redact != nil {
		if !isJSONType(mediaType) {
			return nil, ErrObligationUnmet
		}
		doc, err := parseJSON(content)
		if err != nil {
			return nil, ErrObligationUnmet
		}
		if plan.keep != nil {
			if doc, err = filterFields(doc, plan.keep); err != nil || !onlyKept(doc, plan.keep) {
				return nil, ErrObligationUnmet
			}
		}
		if plan.redact != nil {
			marker := e.marker()
			doc = redact(doc, plan.redact, marker)
			if !redacted(doc, plan.redact, marker) {
				return nil, ErrObligationUnmet
			}
		}
		if out, err = encodeJSON(doc); err != nil {
			return nil, ErrObligationUnmet
		}
	}
	if plan.label != "" {
		mt, _, perr := mime.ParseMediaType(mediaType)
		w, ok := e.Watermarks[mt]
		if perr != nil || !ok || w.Apply == nil || w.Present == nil {
			return nil, ErrObligationUnmet
		}
		marked, err := w.Apply(out, plan.label)
		if err != nil || !w.Present(marked, plan.label) {
			return nil, ErrObligationUnmet
		}
		out = marked
	}
	return out, nil
}

func (e Enforcer) marker() any {
	if e.Marker == nil {
		return DefaultRedactionMarker
	}
	return e.Marker
}

// plan is the checked obligations of an envelope.
type plan struct {
	keep   [][]string // nil: no filter_fields
	redact [][]string // nil: no redact
	label  string     // empty: no watermark
}

// plan checks every obligation: its type is installed and appears once, and
// its params are the closed object of ABAC-25 with well-formed pointers.
func (e Enforcer) plan(obligations []adapter.Obligation) (plan, error) {
	set := e.Installed
	if set == nil {
		set = []string{ObligationFilterFields, ObligationRedact, ObligationWatermark}
	}
	var p plan
	seen := map[string]bool{}
	for _, o := range obligations {
		if !slices.Contains(set, o.ID) || seen[o.ID] {
			return plan{}, ErrObligationUnmet
		}
		seen[o.ID] = true
		var err error
		switch o.ID {
		case ObligationFilterFields:
			p.keep, err = pointerParam(o.Attributes, "keep")
		case ObligationRedact:
			p.redact, err = pointerParam(o.Attributes, "paths")
		case ObligationWatermark:
			label, ok := o.Attributes["label"].(string)
			if len(o.Attributes) != 1 || !ok || label == "" {
				err = ErrObligationUnmet
			}
			p.label = label
		default:
			err = ErrObligationUnmet
		}
		if err != nil {
			return plan{}, ErrObligationUnmet
		}
	}
	return p, nil
}

// pointerParam reads params that are exactly {name: [pointer, ...]}.
func pointerParam(params map[string]any, name string) ([][]string, error) {
	raw, ok := params[name]
	if len(params) != 1 || !ok {
		return nil, ErrObligationUnmet
	}
	var items []any
	switch v := raw.(type) {
	case []any:
		items = v
	case []string:
		for _, s := range v {
			items = append(items, s)
		}
	default:
		return nil, ErrObligationUnmet
	}
	out := [][]string{}
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			return nil, ErrObligationUnmet
		}
		toks, err := ParsePointer(s)
		if err != nil {
			return nil, ErrObligationUnmet
		}
		out = append(out, toks)
	}
	return out, nil
}

// ParsePointer parses a JSON Pointer by RFC 6901 section 3 into its reference
// tokens, unescaped. A pointer that does not conform, and one with the token
// "-", which RFC 6901 section 4 makes an error condition for an application
// that does not define it, are malformed (profile ABAC-25).
func ParsePointer(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	if s[0] != '/' {
		return nil, fmt.Errorf("pointer %q does not start with /", s)
	}
	toks := strings.Split(s[1:], "/")
	for i, t := range toks {
		var b strings.Builder
		for j := 0; j < len(t); j++ {
			if t[j] != '~' {
				b.WriteByte(t[j])
				continue
			}
			if j+1 >= len(t) || (t[j+1] != '0' && t[j+1] != '1') {
				return nil, fmt.Errorf("pointer %q has an invalid escape", s)
			}
			if t[j+1] == '0' {
				b.WriteByte('~')
			} else {
				b.WriteByte('/')
			}
			j++
		}
		toks[i] = b.String()
		if toks[i] == "-" {
			return nil, fmt.Errorf("pointer %q has the token -", s)
		}
	}
	return toks, nil
}

// arrayIndex returns the array index a token names (RFC 6901 section 4: "0"
// or digits without a leading zero).
func arrayIndex(tok string, n int) (int, bool) {
	if tok == "" || len(tok) > 1 && tok[0] == '0' {
		return 0, false
	}
	for _, c := range tok {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	i, err := strconv.Atoi(tok)
	return i, err == nil && i < n
}

// keepTree is the set of kept pointers as a tree of tokens.
type keepTree struct {
	all      bool
	children map[string]*keepTree
}

func buildKeep(ptrs [][]string) *keepTree {
	root := &keepTree{children: map[string]*keepTree{}}
	for _, p := range ptrs {
		n := root
		for _, t := range p {
			c, ok := n.children[t]
			if !ok {
				c = &keepTree{children: map[string]*keepTree{}}
				n.children[t] = c
			}
			n = c
		}
		n.all = true
	}
	return root
}

// filterFields keeps only the values at the pointers, with the containers
// needed to hold them. An array keeps the kept elements in their order.
func filterFields(doc any, keep [][]string) (any, error) {
	switch doc.(type) {
	case map[string]any, []any:
	default:
		return nil, errors.New("the document is not an object or an array")
	}
	v, _ := filterNode(doc, buildKeep(keep))
	if v == nil {
		if _, isArr := doc.([]any); isArr {
			return []any{}, nil
		}
		return map[string]any{}, nil
	}
	return v, nil
}

func filterNode(node any, t *keepTree) (any, bool) {
	if t.all {
		return node, true
	}
	switch v := node.(type) {
	case map[string]any:
		out := map[string]any{}
		for tok, child := range t.children {
			if m, ok := v[tok]; ok {
				if fv, ok := filterNode(m, child); ok {
					out[tok] = fv
				}
			}
		}
		return out, true
	case []any:
		out := []any{}
		for i, el := range v {
			if child, ok := t.children[strconv.Itoa(i)]; ok {
				if fv, ok := filterNode(el, child); ok {
					out = append(out, fv)
				}
			}
		}
		return out, true
	}
	return nil, false
}

// onlyKept verifies the postcondition of filter_fields: every member of the
// result lies on or under a kept pointer. An array position matches any index
// token, since an array keeps its kept elements in order.
func onlyKept(doc any, keep [][]string) bool {
	var walk func(v any, path []string, arr []bool) bool
	walk = func(v any, path []string, arr []bool) bool {
		if !onKeptPath(path, arr, keep) {
			return false
		}
		switch x := v.(type) {
		case map[string]any:
			for k, m := range x {
				if !walk(m, append(slices.Clone(path), k), append(slices.Clone(arr), false)) {
					return false
				}
			}
		case []any:
			for _, m := range x {
				if !walk(m, append(slices.Clone(path), ""), append(slices.Clone(arr), true)) {
					return false
				}
			}
		}
		return true
	}
	return walk(doc, nil, nil)
}

// onKeptPath reports whether path is a prefix of a kept pointer or lies under
// one.
func onKeptPath(path []string, arr []bool, keep [][]string) bool {
	if len(path) == 0 {
		return true
	}
	for _, k := range keep {
		n := min(len(k), len(path))
		match := true
		for i := range n {
			if arr[i] {
				if _, ok := arrayIndex(k[i], int(^uint(0)>>1)); !ok {
					match = false
					break
				}
			} else if k[i] != path[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// redact replaces the value at each pointer that resolves with the marker.
func redact(doc any, ptrs [][]string, marker any) any {
	for _, p := range ptrs {
		if len(p) == 0 {
			doc = marker
			continue
		}
		parent, ok := resolve(doc, p[:len(p)-1])
		if !ok {
			continue
		}
		last := p[len(p)-1]
		switch c := parent.(type) {
		case map[string]any:
			if _, ok := c[last]; ok {
				c[last] = marker
			}
		case []any:
			if i, ok := arrayIndex(last, len(c)); ok {
				c[i] = marker
			}
		}
	}
	return doc
}

// redacted verifies the postcondition of redact: each pointer, or a prefix of
// it, holds the marker, or the pointer resolves to nothing.
func redacted(doc any, ptrs [][]string, marker any) bool {
	for _, p := range ptrs {
		for n := 0; n <= len(p); n++ {
			v, ok := resolve(doc, p[:n])
			if !ok {
				break
			}
			if equalJSON(v, marker) {
				break
			}
			if n == len(p) {
				return false
			}
		}
	}
	return true
}

// resolve evaluates the tokens against doc (RFC 6901 section 4).
func resolve(doc any, toks []string) (any, bool) {
	v := doc
	for _, t := range toks {
		switch c := v.(type) {
		case map[string]any:
			m, ok := c[t]
			if !ok {
				return nil, false
			}
			v = m
		case []any:
			i, ok := arrayIndex(t, len(c))
			if !ok {
				return nil, false
			}
			v = c[i]
		default:
			return nil, false
		}
	}
	return v, true
}

func equalJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// isJSONType reports whether the media type is application/json or a +json
// type.
func isJSONType(mediaType string) bool {
	mt, _, err := mime.ParseMediaType(mediaType)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

// parseJSON parses a document strictly (draft 7.1), keeping numbers as
// written.
func parseJSON(raw []byte) (any, error) {
	var check json.RawMessage
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: maxContent}, &check); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func encodeJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
