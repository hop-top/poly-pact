package validator

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
)

// principalPath is the profile path of the principal the presentation claims
// to act for (draft 17.5). A field rule on it that does not match its native
// value is a principal that differs: CONTEXT_MISMATCH (draft 13.4).
const principalPath = "/attributes/environment/principal_id"

// reputationPath is the profile path a reputation snapshot is mapped to
// (draft 15.2, A.2).
const reputationPath = "/attributes/reputation"

// authClaim is an authoritative value the validator accepted for a profile
// path: an evidence claim or a reputation snapshot value (draft 8.3, A.2).
type authClaim struct {
	path       string
	issuer     string
	value      any
	observedAt time.Time
	statusAt   time.Time
	evidenceID string
	sourceID   string
	// holdCheck marks a snapshot value, whose status check is the
	// validator's own security-hold check (Appendix A.2).
	holdCheck bool
}

// rule evaluates a self or evidence field rule (draft 9.2, 8.4).
func (e *evaluation) rule(r core.FieldRule) outcome {
	value, o, ok := e.presented(r)
	if !ok {
		return o
	}
	if r.Source == core.RuleSourceSelf {
		return pass()
	}
	if r.Source != core.RuleSourceEvidence {
		return unknown(reasonUnsupported)
	}
	var found []authClaim
	for _, c := range e.claims {
		if c.path == r.Path && slices.Contains(r.AllowedIssuers, c.issuer) {
			found = append(found, c)
		}
	}
	if len(found) == 0 {
		if reason, pending := e.pendingPaths[r.Path]; pending {
			return unknown(reason)
		}
		if reason, failed := e.failedPaths[r.Path]; failed {
			return fail(reason)
		}
		return fail(reasonMissingField)
	}
	for _, c := range found[1:] {
		if !jsonEqual(c.value, found[0].value) {
			return fail(reasonConflictingEvidence)
		}
	}
	auth := found[0]
	// A snapshot value was observed at the snapshot's iat; its status check
	// is the validator's security-hold check (Appendix A.2).
	claim := adapter.NativeClaim{ObservedAt: auth.observedAt, StatusCheckedAt: auth.statusAt, SourceID: auth.sourceID}
	res, code := e.fresh(r, claim)
	if res == core.CheckUnknown && auth.holdCheck && e.holdsErr != nil {
		return unknown(reasonUnavailable)
	}
	if res != core.CheckPass {
		return outcome{result: res, reason: string(code)}
	}
	if !compare(r.Comparison, value, auth.value) {
		return fail(reasonInvalidClaim)
	}
	o = pass()
	o.observed, o.status, o.evidence = unixOf(auth.observedAt), unixOf(auth.statusAt), []string{auth.evidenceID}
	return o
}

// presented applies the checks every field rule shares: the path is present
// and the presented value satisfies the rule's schema (draft 9.2). It
// returns the value, or the outcome of the rule and false.
func (e *evaluation) presented(r core.FieldRule) (any, outcome, bool) {
	schema, err := compileSchema(r.Schema)
	if err != nil {
		return nil, unknown(reasonUnsupported), false
	}
	value, ok := pointer(e.profile, r.Path)
	if !ok {
		return nil, fail(reasonMissingField), false
	}
	if !matches(schema, value) {
		return nil, fail(reasonInvalidClaim), false
	}
	return value, outcome{}, true
}

// nativeRule evaluates a native field rule: the presented value is compared
// with the value read_native_claim returns for the approved native path
// (draft 8.5, 9.2, 17.2).
func (e *evaluation) nativeRule(ctx context.Context, r core.FieldRule) outcome {
	value, o, ok := e.presented(r)
	if !ok {
		return o
	}
	var m *NativeMapping
	for i := range e.v.Config.NativeMappings {
		nm := &e.v.Config.NativeMappings[i]
		if r.NativePath != nil && nm.Path == r.Path && nm.NativePath == *r.NativePath {
			m = nm
		}
	}
	if m == nil {
		return unknown(reasonUnsupported)
	}
	if s := m.Source; s != nil && (r.MaxAgeSeconds < s.BestMaxAgeSeconds || r.StatusMaxAgeSeconds < s.BestStatusMaxAgeSeconds) {
		// The source cannot meet the demanded freshness (draft 17.2).
		return unknown(reasonUnsupported)
	}
	claim, err := e.v.Native.ReadNativeClaim(ctx, m.NativePath, adapter.ClaimContext{
		Principal: e.req.Principal, Intent: e.p.Intent, Operation: e.req.Operation,
	})
	if err != nil {
		switch code, _ := adapter.CodeOf(err); code {
		case adapter.CodeMissingField:
			return fail(reasonMissingField)
		case adapter.CodeUnsupportedRequirement:
			return unknown(reasonUnsupported)
		}
		return unknown(reasonUnavailable)
	}
	res, code := e.fresh(r, claim)
	if code != freshness.ClockAhead && m.Source != nil && !m.Source.LiveCheck && !claim.StatusCheckedAt.IsZero() &&
		e.start.Sub(claim.StatusCheckedAt) > time.Duration(r.StatusMaxAgeSeconds)*time.Second {
		// A cached answer the source cannot refresh, such as a stopped push
		// feed: the check cannot currently be completed (draft 18).
		return unknown(reasonUnavailable)
	}
	if res != core.CheckPass {
		return outcome{result: res, reason: string(code)}
	}
	if !compare(r.Comparison, value, claim.Value) {
		if r.Path == principalPath {
			return fail(reasonContextMismatch)
		}
		return fail(reasonInvalidClaim)
	}
	o = pass()
	o.observed, o.status, o.sourceID = unixOf(claim.ObservedAt), unixOf(claim.StatusCheckedAt), claim.SourceID
	if claim.SourceRef != "" {
		o.sourceRef = &claim.SourceRef
	}
	return o
}

// fresh applies the age limits of r to a source's times (draft 9.2), the
// limit zero meaning a time no earlier than the start of this evaluation.
func (e *evaluation) fresh(r core.FieldRule, c adapter.NativeClaim) (core.CheckStatus, freshness.ReasonCode) {
	ev := freshness.Evaluator{Skew: e.v.Config.Skew, Start: e.start}
	return ev.Evaluate(r, c, e.v.Clock.Now())
}

// compare is the claim comparison of draft 8.4.
func compare(c core.Comparison, presented, authoritative any) bool {
	switch c {
	case core.ComparisonEqual:
		return jsonEqual(presented, authoritative)
	case core.ComparisonSubset:
		p, ok1 := scalarSet(presented)
		a, ok2 := scalarSet(authoritative)
		if !ok1 || !ok2 {
			return false
		}
		for k := range p {
			if !a[k] {
				return false
			}
		}
		return true
	}
	return false
}

// scalarSet returns the canonical forms of an array of unique scalars.
func scalarSet(v any) (map[string]bool, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	set := make(map[string]bool, len(arr))
	for _, item := range arr {
		switch item.(type) {
		case map[string]any, []any:
			return nil, false
		}
		c, err := canonical(item)
		if err != nil || set[c] {
			return nil, false
		}
		set[c] = true
	}
	return set, true
}

// pointer resolves an RFC 6901 JSON Pointer in JSON data.
func pointer(doc any, p string) (any, bool) {
	if p == "" {
		return doc, true
	}
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	cur := doc
	for _, tok := range strings.Split(p[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(c) || (len(tok) > 1 && tok[0] == '0') {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// actualDigest is the object_digest of the actual operation (draft 12.1).
func (e *evaluation) actualDigest() core.Digest {
	d, err := digest.ObjectDigest(e.req.Operation)
	if err != nil {
		return ""
	}
	return d
}
