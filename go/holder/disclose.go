package holder

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// disclosure builds the profile view one contract asks for.
type disclosure struct {
	h        *Holder
	key      holderKey
	now      time.Time
	source   json.RawMessage // the source profile as JSON
	sourceAt core.Object     // its attributes
	evidence []evidence
	snap     *snapshot

	view     map[string]any // the disclosed attributes; leaves are json.RawMessage
	used     []bool         // used[i]: evidence[i] backs a rule
	snapUsed bool
}

// disclose returns the attributes of the view for rules, and marks the
// evidence and snapshot the rules use.
func (d *disclosure) disclose(rules []core.FieldRule) (core.Object, error) {
	d.view = map[string]any{}
	d.used = make([]bool, len(d.evidence))
	for _, r := range rules {
		if err := d.rule(r); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.RuleID, err)
		}
	}
	out := core.Object{}
	for k, v := range d.view {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: attribute %s: %v", ErrInvalidMessage, k, err)
		}
		out[k] = b
	}
	return out, nil
}

// rule discloses the value one field rule requires (draft 9.2: every listed
// path is required).
func (d *disclosure) rule(r core.FieldRule) error {
	tokens, err := pointer(r.Path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}
	if r.Source == core.RuleSourceEvidence && reputationPath(tokens) {
		return d.reputation(r, tokens)
	}
	value, ok := lookup(d.source, tokens)
	if r.Source == core.RuleSourceEvidence {
		value, err = d.fromEvidence(r, value, ok)
		if err != nil {
			return err
		}
	} else if !ok {
		// A native or self value the agent does not hold is missing; the
		// holder does not invent one (draft 8.6).
		return fmt.Errorf("%w: no value at %s", ErrMissingField, r.Path)
	}
	d.set(tokens, value)
	return nil
}

// reputationPath reports a path at or under /attributes/reputation, whose
// authoritative value is the snapshot's (Appendix A.2, draft 15.2).
func reputationPath(tokens []string) bool {
	return len(tokens) >= 2 && tokens[0] == "attributes" && tokens[1] == "reputation"
}

// reputation discloses the snapshot value at /attributes/reputation for an
// evidence rule on it or a descendant: the complete value, so that every
// required subfield matches the signed snapshot (draft 15.2). A
// self-asserted reputation in the source profile is never disclosed.
func (d *disclosure) reputation(r core.FieldRule, tokens []string) error {
	if d.snap == nil {
		return fmt.Errorf("%w: no reputation snapshot for %s", ErrMissingField, r.Path)
	}
	s := d.snap.claims
	if !slices.Contains(r.AllowedIssuers, s.Issuer) || !d.applies(s.Subject, s.Audience, s.TenantID, s.EnvironmentID, s.HolderJKT, s.IssuedAt, s.NotBefore, s.Expiry) {
		return fmt.Errorf("%w: the reputation snapshot does not apply to %s", ErrMissingField, r.Path)
	}
	if _, ok := lookup(d.snap.value, tokens[2:]); !ok {
		return fmt.Errorf("%w: the reputation snapshot has no value at %s", ErrMissingField, r.Path)
	}
	d.view["reputation"] = d.snap.value
	d.snapUsed = true
	return nil
}

// fromEvidence returns the value of an evidence rule: the profile value, or,
// when the profile has none, the value of the applicable evidence claims.
// Every applicable claim from an allowed issuer must equal it: a value that
// differs from any of them, or claims that disagree, conflict (draft 8.4:
// the holder does not pick the evidence that permits access). The first
// applicable evidence backs the rule.
func (d *disclosure) fromEvidence(r core.FieldRule, value json.RawMessage, held bool) (json.RawMessage, error) {
	var candidates []int
	for i, e := range d.evidence {
		c := e.claims
		if slices.Contains(r.AllowedIssuers, c.Issuer) && d.applies(c.Subject, c.Audience, c.TenantID, c.EnvironmentID, c.HolderJKT, c.IssuedAt, c.NotBefore, c.Expiry) && claimAt(c, r.Path) != nil {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: no applicable evidence for %s", ErrMissingField, r.Path)
	}
	if !held {
		value = claimAt(d.evidence[candidates[0]].claims, r.Path)
	}
	for _, i := range candidates {
		if !sameJSON(claimAt(d.evidence[i].claims, r.Path), value) {
			return nil, fmt.Errorf("%w: the profile value and the applicable evidence at %s disagree", ErrConflictingEvidence, r.Path)
		}
	}
	backed := candidates[0]
	d.used[backed] = true
	return value, nil
}

// claimAt returns the value of e's claim on exactly path, or nil (draft 8.4:
// the path must match).
func claimAt(e core.Evidence, path string) json.RawMessage {
	for _, c := range e.Claims {
		if c.Path == path {
			return c.Value
		}
	}
	return nil
}

// applies reports whether an artifact binds this agent, key, gateway and
// realm and is valid now (draft 7.5, 8.3, 15.2).
func (d *disclosure) applies(sub, aud, tenant, env string, jkt core.Digest, iat, nbf, exp int64) bool {
	return sub == d.h.AgentID && aud == d.h.Gateway && tenant == d.h.Realm.TenantID && env == d.h.Realm.EnvironmentID &&
		jkt == d.key.jkt && clock.CheckWindow(iat, nbf, exp, d.now, d.h.Skew) == nil
}

// set places value at tokens in the view. Only /attributes paths are view
// paths: the core fields of the profile are always disclosed. A path that
// passes through an array discloses the whole array, the smallest JSON
// value that holds it.
func (d *disclosure) set(tokens []string, value json.RawMessage) {
	if len(tokens) == 0 || tokens[0] != "attributes" {
		return
	}
	tokens = tokens[1:]
	if len(tokens) == 0 {
		for k, v := range d.sourceAt {
			d.view[k] = v
		}
		return
	}
	for i := 1; i < len(tokens); i++ {
		if v, ok := lookup(d.source, append([]string{"attributes"}, tokens[:i]...)); ok && firstByte(v) == '[' {
			tokens, value = tokens[:i], v
			break
		}
	}
	node := d.view
	for i, t := range tokens {
		if i == len(tokens)-1 {
			node[t] = value
			return
		}
		next, ok := node[t].(map[string]any)
		if !ok {
			if _, whole := node[t].(json.RawMessage); whole {
				return // an enclosing value is already disclosed
			}
			next = map[string]any{}
			node[t] = next
		}
		node = next
	}
}

// checkProfile applies the profile rules of draft 8.1, 11.2 and Appendix
// A.2 to the source profile: it names this agent, key and tenant, and it is
// current with a lifetime of at most 24 hours.
func (h *Holder) checkProfile(p core.AgentProfile, k holderKey, now time.Time) error {
	switch {
	case p.AgentID != h.AgentID:
		return fmt.Errorf("%w: profile agent_id %q", ErrContextMismatch, p.AgentID)
	case p.TenantID != h.Realm.TenantID:
		return fmt.Errorf("%w: profile tenant_id %q", ErrContextMismatch, p.TenantID)
	case p.HolderJKT != k.jkt:
		return fmt.Errorf("%w: profile holder_jkt %s, key source %s", ErrInvalidProof, p.HolderJKT, k.jkt)
	}
	if err := clock.CheckLifetime(clock.Profile, p.CreatedAt, p.ExpiresAt); err != nil {
		return fmt.Errorf("%w: profile: %v", ErrInvalidMessage, err)
	}
	if err := clock.CheckWindow(p.CreatedAt, p.CreatedAt, p.ExpiresAt, now, h.Skew); err != nil {
		if errors.Is(err, clock.ErrExpired) {
			return fmt.Errorf("%w: profile: %v", ErrExpired, err)
		}
		return fmt.Errorf("%w: profile: %v", ErrInvalidMessage, err)
	}
	return nil
}
