package ssf_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/core/clock"
)

var bg = context.Background()

func (r *rig) read(t testing.TB, p string) (adapter.NativeClaim, error) {
	t.Helper()
	return r.rx.Reader().ReadNativeClaim(bg, ssf.AccountStatePath, adapter.ClaimContext{Principal: adapter.Principal{ID: p}})
}

// wantState requires the principal's account_state and its event time.
func (r *rig) wantState(t testing.TB, p, state string, at int64) {
	t.Helper()
	c, err := r.read(t, p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	if c.Value != state {
		t.Fatalf("account_state %v, want %s", c.Value, state)
	}
	if c.ObservedAt.Unix() != at || c.StatusCheckedAt.Unix() != at {
		t.Fatalf("times %d/%d, want the event time %d", c.ObservedAt.Unix(), c.StatusCheckedAt.Unix(), at)
	}
	if c.SourceID != "ssf-test" {
		t.Fatalf("source id %q", c.SourceID)
	}
}

func (r *rig) wantNoFact(t testing.TB, p string) {
	t.Helper()
	_, err := r.read(t, p)
	if !errors.Is(err, adapter.ErrMissingField) {
		t.Fatalf("read %s: %v, want MISSING_FIELD", p, err)
	}
}

func (r *rig) accept(t testing.TB, compact string) ssf.Result {
	t.Helper()
	res, err := r.rx.Accept(bg, compact)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return res
}

func wantCode(t testing.TB, err error, code string) {
	t.Helper()
	var e *ssf.Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an *ssf.Error, want %s", err, code)
	}
	if e.Code != code {
		t.Fatalf("error code %s (%s), want %s", e.Code, e.Description, code)
	}
}

// The mapping of event types to account_state (CAEP 1.0 section 3; RISC
// section 2) with the event time as the as-of time.
func TestEventMapping(t *testing.T) {
	ev := nowSec - 100
	cases := []struct {
		name    string
		typ     string
		payload map[string]any
		state   string
	}{
		{"session-revoked", ssf.EventSessionRevoked, map[string]any{"event_timestamp": ev}, ssf.StateSessionRevoked},
		{"sessions-revoked deprecated alias", ssf.EventSessionsRevoked, map[string]any{"event_timestamp": ev}, ssf.StateSessionRevoked},
		{"credential-change update", ssf.EventCredentialChange, map[string]any{"credential_type": "password", "change_type": "update", "event_timestamp": ev}, ssf.StateCredentialChanged},
		{"credential-change revoke", ssf.EventCredentialChange, map[string]any{"credential_type": "x509", "change_type": "revoke", "event_timestamp": ev}, ssf.StateCredentialChanged},
		{"credential-change delete", ssf.EventCredentialChange, map[string]any{"credential_type": "app", "change_type": "delete", "event_timestamp": ev}, ssf.StateCredentialChanged},
		{"assurance decrease", ssf.EventAssuranceLevelChange, map[string]any{"namespace": "NIST-AAL", "current_level": "nist-aal1", "previous_level": "nist-aal2", "change_direction": "decrease", "event_timestamp": ev}, ssf.StateAssuranceChanged},
		{"assurance direction absent", ssf.EventAssuranceLevelChange, map[string]any{"namespace": "NIST-AAL", "current_level": "nist-aal1", "event_timestamp": ev}, ssf.StateAssuranceChanged},
		{"account-disabled", ssf.EventAccountDisabled, map[string]any{"reason": "hijacking", "event_timestamp": ev}, ssf.StateDisabled},
		{"account-enabled", ssf.EventAccountEnabled, map[string]any{"event_timestamp": ev}, ssf.StateActive},
		{"account-purged", ssf.EventAccountPurged, map[string]any{"event_timestamp": ev}, ssf.StateAbsent},
		{"credential-change-required", ssf.EventAccountCredentialChangeRequired, map[string]any{"event_timestamp": ev}, ssf.StatePasswordChangeRequired},
		{"credential-compromise", ssf.EventCredentialCompromise, map[string]any{"credential_type": "password", "event_timestamp": ev}, ssf.StateCredentialCompromised},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.accept(t, signed(t, claims("j-1", nowSec-90, issSub("u-1"), c.typ, c.payload)))
			r.wantState(t, principal("7a1f"), c.state, ev)
		})
	}
}

// Events that carry no invalidation leave the state alone (CAEP 3.3.1
// create; 3.4.1 increase), and are reported.
func TestNoEffectEvents(t *testing.T) {
	for name, c := range map[string]struct {
		typ     string
		payload map[string]any
	}{
		"credential created":  {ssf.EventCredentialChange, map[string]any{"credential_type": "fido2-roaming", "change_type": "create"}},
		"assurance increased": {ssf.EventAssuranceLevelChange, map[string]any{"namespace": "NIST-AAL", "current_level": "nist-aal3", "previous_level": "nist-aal2", "change_direction": "increase"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.accept(t, signed(t, claims("j-1", nowSec-90, issSub("u-1"), ssf.EventAccountEnabled, map[string]any{"event_timestamp": nowSec - 200})))
			r.tel.reset()
			r.accept(t, signed(t, claims("j-2", nowSec-80, issSub("u-1"), c.typ, c.payload)))
			r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-200)
			if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindNoEffect}) {
				t.Fatalf("telemetry %v", got)
			}
		})
	}
}

// Acceptance: a session-revoked event invalidates the cached status.
func TestSessionRevokedInvalidatesCachedStatus(t *testing.T) {
	r := newRig(t)
	r.accept(t, signed(t, claims("j-1", nowSec-300, issSub("u-1"), ssf.EventAccountEnabled, map[string]any{"event_timestamp": nowSec - 300})))
	r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-300)
	r.accept(t, signed(t, claims("j-2", nowSec-60, issSub("u-1"), ssf.EventSessionRevoked, map[string]any{"event_timestamp": nowSec - 61})))
	r.wantState(t, principal("7a1f"), ssf.StateSessionRevoked, nowSec-61)
	// Another principal is untouched.
	r.wantNoFact(t, principal("9c2e"))
}

// The event time is event_timestamp, else iat (design: a real source
// observation time).
func TestEventTimeFallsBackToIat(t *testing.T) {
	r := newRig(t)
	r.accept(t, signed(t, claims("j-1", nowSec-77, issSub("u-1"), ssf.EventAccountDisabled, nil)))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-77)
}

// An event cannot have happened after its SET was issued (plus the skew).
func TestEventTimestampAfterIat(t *testing.T) {
	r := newRig(t)
	_, err := r.rx.Accept(bg, signed(t, claims("j-1", nowSec-100, issSub("u-1"), ssf.EventAccountDisabled, map[string]any{"event_timestamp": nowSec - 50})))
	wantCode(t, err, ssf.CodeInvalidRequest)
	// Milliseconds written where seconds are defined (CAEP section 2).
	_, err = r.rx.Accept(bg, signed(t, claims("j-2", nowSec-100, issSub("u-1"), ssf.EventAccountDisabled, map[string]any{"event_timestamp": (nowSec - 100) * 1000})))
	wantCode(t, err, ssf.CodeInvalidRequest)
	r.wantNoFact(t, principal("7a1f"))
}

// An older event never overwrites a newer state.
func TestOutOfOrderEventIgnored(t *testing.T) {
	r := newRig(t)
	r.accept(t, signed(t, claims("j-2", nowSec-50, issSub("u-1"), ssf.EventAccountEnabled, map[string]any{"event_timestamp": nowSec - 50})))
	r.tel.reset()
	r.accept(t, signed(t, claims("j-1", nowSec-40, issSub("u-1"), ssf.EventAccountDisabled, map[string]any{"event_timestamp": nowSec - 500})))
	r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-50)
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindStaleEvent}) {
		t.Fatalf("telemetry %v", got)
	}
}

// Acceptance: a forged SET is rejected and changes nothing.
func TestForgedSETRejected(t *testing.T) {
	good := claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil)
	badSig := compact(t, key(t, 3), setHeader(), good) // adversarial key, real kid
	unknownKid := compact(t, key(t, 2), map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": "other"}, good)
	noneAlg := compact(t, nil, map[string]any{"alg": "none", "typ": "secevent+jwt"}, good)
	hs256 := compact(t, key(t, 2), map[string]any{"alg": "HS256", "typ": "secevent+jwt", "kid": kid}, good)
	tampered := func() string {
		s := signed(t, good)
		p := strings.Split(s, ".")
		p[1] = b64([]byte(strings.Replace(`{"iss":"https://tx.example.com","aud":"https://rx.example.com/ssf","jti":"j-1","iat":1792079990,"sub_id":{"format":"iss_sub","iss":"https://tx.example.com","sub":"u-2"},"events":{"https://schemas.openid.net/secevent/risc/event-type/account-disabled":{}}}`, "u-2", "u-2", 1)))
		return strings.Join(p, ".")
	}()
	for name, c := range map[string]struct {
		tok  string
		code string
	}{
		"signature by another key under the real kid": {badSig, ssf.CodeInvalidKey},
		"unknown kid":      {unknownKid, ssf.CodeInvalidKey},
		"alg none":         {noneAlg, ssf.CodeInvalidKey},
		"alg HS256":        {hs256, ssf.CodeInvalidKey},
		"payload replaced": {tampered, ssf.CodeInvalidKey},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			_, err := r.rx.Accept(bg, c.tok)
			wantCode(t, err, c.code)
			r.wantNoFact(t, principal("7a1f"))
			r.wantNoFact(t, principal("9c2e"))
			if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindRejected}) {
				t.Fatalf("telemetry %v", got)
			}
			if r.tel.last().Reason != c.code {
				t.Fatalf("telemetry reason %q", r.tel.last().Reason)
			}
			// A rejected SET leaves no replay record: the same jti is accepted
			// once it is validly signed.
			r.accept(t, signed(t, good))
			r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
		})
	}
}

// The profile of RFC 8417 section 2.2/2.3 and SSF 1.0 sections 4.1.1, 4.1.2,
// 4.1.7: explicit typing, no sub, no exp.
func TestClaimProfile(t *testing.T) {
	base := func() map[string]any { return claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil) }
	with := func(k string, v any) map[string]any { m := base(); m[k] = v; return m }
	without := func(k string) map[string]any { m := base(); delete(m, k); return m }
	hdr := func(typ any) map[string]any {
		h := setHeader()
		if typ == nil {
			delete(h, "typ")
		} else {
			h["typ"] = typ
		}
		return h
	}
	k2 := key(t, 2)
	for name, c := range map[string]struct {
		tok  string
		code string
	}{
		"no typ":                 {compact(t, k2, hdr(nil), base()), ssf.CodeInvalidRequest},
		"typ JWT":                {compact(t, k2, hdr("JWT"), base()), ssf.CodeInvalidRequest},
		"typ at+jwt":             {compact(t, k2, hdr("at+jwt"), base()), ssf.CodeInvalidRequest},
		"sub present":            {compact(t, k2, hdr("secevent+jwt"), with("sub", "u-1")), ssf.CodeInvalidRequest},
		"exp present":            {compact(t, k2, hdr("secevent+jwt"), with("exp", nowSec+100)), ssf.CodeInvalidRequest},
		"no jti":                 {compact(t, k2, hdr("secevent+jwt"), without("jti")), ssf.CodeInvalidRequest},
		"no iat":                 {compact(t, k2, hdr("secevent+jwt"), without("iat")), ssf.CodeInvalidRequest},
		"no iss":                 {compact(t, k2, hdr("secevent+jwt"), without("iss")), ssf.CodeInvalidRequest},
		"no events":              {compact(t, k2, hdr("secevent+jwt"), without("events")), ssf.CodeInvalidRequest},
		"empty events":           {compact(t, k2, hdr("secevent+jwt"), with("events", map[string]any{})), ssf.CodeInvalidRequest},
		"event payload scalar":   {compact(t, k2, hdr("secevent+jwt"), with("events", map[string]any{ssf.EventAccountDisabled: "x"})), ssf.CodeInvalidRequest},
		"not a JWT":              {"abc", ssf.CodeInvalidRequest},
		"four segments":          {"a.b.c.d", ssf.CodeInvalidRequest},
		"padded base64url":       {strings.Replace(signed(t, base()), ".", "=.", 1), ssf.CodeInvalidRequest},
		"unknown issuer":         {compact(t, k2, hdr("secevent+jwt"), with("iss", "https://evil.example")), ssf.CodeInvalidIssuer},
		"audience elsewhere":     {compact(t, k2, hdr("secevent+jwt"), with("aud", "https://other.example/ssf")), ssf.CodeInvalidAudience},
		"audience list lacks us": {compact(t, k2, hdr("secevent+jwt"), with("aud", []string{"https://a.example", "https://b.example"})), ssf.CodeInvalidAudience},
		"iat in the future":      {compact(t, k2, hdr("secevent+jwt"), with("iat", nowSec+60)), ssf.CodeInvalidRequest},
		"iat older than MaxAge":  {compact(t, k2, hdr("secevent+jwt"), with("iat", nowSec-90000)), ssf.CodeInvalidRequest},
		"header crit":            {compact(t, k2, map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": kid, "crit": []string{"x"}, "x": 1}, base()), ssf.CodeInvalidRequest},
		"header jku":             {compact(t, k2, map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": kid, "jku": "https://evil.example/jwks"}, base()), ssf.CodeInvalidRequest},
		"header jwk":             {compact(t, k2, map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": kid, "jwk": map[string]any{}}, base()), ssf.CodeInvalidRequest},
		"no kid":                 {compact(t, k2, map[string]any{"alg": "ES256", "typ": "secevent+jwt"}, base()), ssf.CodeInvalidKey},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(c *ssf.Config) { c.MaxAge = 24 * time.Hour })
			_, err := r.rx.Accept(bg, c.tok)
			wantCode(t, err, c.code)
			r.wantNoFact(t, principal("7a1f"))
		})
	}
	// The registered media-type spelling of typ (RFC 8417 section 2.3) is accepted.
	r := newRig(t)
	r.accept(t, compact(t, k2, hdr("application/secevent+jwt"), base()))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
	// aud as an array that includes the receiver (SSF 4.1.8).
	r = newRig(t)
	r.accept(t, compact(t, k2, hdr("secevent+jwt"), with("aud", []string{"https://a.example", rxAud})))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
}

func TestSizeBound(t *testing.T) {
	r := newRig(t, func(c *ssf.Config) { c.MaxBytes = 512 })
	c := claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, map[string]any{"reason_admin": map[string]any{"en": strings.Repeat("x", 600)}})
	_, err := r.rx.Accept(bg, signed(t, c))
	wantCode(t, err, ssf.CodeInvalidRequest)
}

// Acceptance: a replayed jti is rejected: the SET applies once. The duplicate
// is answered as the first was (RFC 8935 section 2), so it carries no error;
// a different SET under the same jti is an error.
func TestReplayedJTIRejected(t *testing.T) {
	r := newRig(t)
	dis := signed(t, claims("j-1", nowSec-300, issSub("u-1"), ssf.EventAccountDisabled, map[string]any{"event_timestamp": nowSec - 300}))
	en := signed(t, claims("j-2", nowSec-200, issSub("u-1"), ssf.EventAccountEnabled, map[string]any{"event_timestamp": nowSec - 200}))
	if res := r.accept(t, dis); res.Replay {
		t.Fatal("first delivery is a replay")
	}
	r.accept(t, en)
	r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-200)
	r.tel.reset()
	// The old disabled SET arrives again: not applied, not an error.
	res := r.accept(t, dis)
	if !res.Replay || res.JTI != "j-1" {
		t.Fatalf("result %+v, want a replay of j-1", res)
	}
	r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-200)
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindReplay}) {
		t.Fatalf("telemetry %v", got)
	}
	// Same jti, other content, validly signed: the feed's jti uniqueness is broken.
	other := signed(t, claims("j-1", nowSec-300, issSub("u-2"), ssf.EventAccountDisabled, map[string]any{"event_timestamp": nowSec - 300}))
	_, err := r.rx.Accept(bg, other)
	wantCode(t, err, ssf.CodeInvalidRequest)
	r.wantNoFact(t, principal("9c2e"))
}

// A jti is unique within a feed (RFC 8417 section 2.2): the same jti from
// another issuer is another SET.
func TestReplayScopedByIssuer(t *testing.T) {
	k2 := key(t, 2)
	r := newRig(t, func(c *ssf.Config) {
		c.Issuers = append(c.Issuers, ssf.Issuer{Issuer: "https://tx2.example.com", Audience: rxAud, Keys: ssf.StaticKeys{jwkOf(t, k2, kid)}})
		c.Mappings = append(c.Mappings, ssf.Mapping{Issuer: "https://tx2.example.com", Format: "iss_sub", SubjectIss: "https://tx2.example.com", Value: "u-1", Local: "aaaa"})
	})
	r.accept(t, signed(t, claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil)))
	c2 := claims("j-1", nowSec-10, map[string]any{"format": "iss_sub", "iss": "https://tx2.example.com", "sub": "u-1"}, ssf.EventAccountDisabled, nil)
	c2["iss"] = "https://tx2.example.com"
	if res := r.accept(t, signed(t, c2)); res.Replay {
		t.Fatal("a jti of another issuer is a replay")
	}
	r.wantState(t, principal("aaaa"), ssf.StateDisabled, nowSec-10)
}

// A failed apply records no jti, so the transmitter's retry applies it.
func TestFailedApplyIsNotRecorded(t *testing.T) {
	r := newRig(t, func(c *ssf.Config) { c.HoldOn = []string{ssf.EventCredentialCompromise} })
	tok := signed(t, claims("j-1", nowSec-10, issSub("u-1"), ssf.EventCredentialCompromise, map[string]any{"credential_type": "password"}))
	r.holds.err = errors.New("sink down")
	if _, err := r.rx.Accept(bg, tok); err == nil {
		t.Fatal("a failed hold sink is not an error")
	} else if errors.As(err, new(*ssf.Error)) {
		t.Fatalf("sink failure reported as a rejection: %v", err)
	}
	r.holds.err = nil
	res := r.accept(t, tok)
	if res.Replay {
		t.Fatal("the retry is a replay")
	}
	if len(r.holds.got) != 1 {
		t.Fatalf("candidates %+v", r.holds.got)
	}
}

// Acceptance: an unknown subject is ignored with telemetry. Subjects resolve
// only through configured mappings.
func TestSubjectResolution(t *testing.T) {
	type tc struct {
		name   string
		sub    any
		local  string // principal that must change; "" none
		reason string
		format string
	}
	cases := []tc{
		{"iss_sub mapped", issSub("u-1"), "7a1f", "", ""},
		{"iss_sub unmapped", issSub("nobody"), "", "unmapped", "iss_sub"},
		{"iss_sub of another subject issuer", map[string]any{"format": "iss_sub", "iss": "https://evil.example", "sub": "u-1"}, "", "unmapped", "iss_sub"},
		{"opaque mapped", map[string]any{"format": "opaque", "id": "o-1"}, "5b3d", "", ""},
		{"opaque unmapped", map[string]any{"format": "opaque", "id": "o-9"}, "", "unmapped", "opaque"},
		{"email mapped exactly", map[string]any{"format": "email", "email": "ada@example.com"}, "4d4d", "", ""},
		{"email case variant is not the mapped address", map[string]any{"format": "email", "email": "Ada@Example.com"}, "", "unmapped", "email"},
		{"email plus-addressed variant", map[string]any{"format": "email", "email": "ada+x@example.com"}, "", "unmapped", "email"},
		{"email never joins by itself", map[string]any{"format": "email", "email": "u-1@example.com"}, "", "unmapped", "email"},
		{"no subject", nil, "", "no-subject", ""},
		{"unsupported format", map[string]any{"format": "phone_number", "phone_number": "+15551234"}, "", "unsupported-format", "phone_number"},
		{"complex with user", map[string]any{"format": "complex", "user": issSub("u-2"), "tenant": map[string]any{"format": "opaque", "id": "t"}}, "9c2e", "", ""},
		{"complex without user", map[string]any{"format": "complex", "device": map[string]any{"format": "opaque", "id": "d"}}, "", "unsupported-subject", "complex"},
		{"complex with an unmapped user", map[string]any{"format": "complex", "user": issSub("nobody")}, "", "unmapped", "iss_sub"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			res := r.accept(t, signed(t, claims("j-1", nowSec-10, c.sub, ssf.EventAccountDisabled, nil)))
			if res.Replay {
				t.Fatal("replay")
			}
			for _, l := range []string{"7a1f", "9c2e", "5b3d", "4d4d"} {
				if l == c.local {
					r.wantState(t, principal(l), ssf.StateDisabled, nowSec-10)
				} else {
					r.wantNoFact(t, principal(l))
				}
			}
			if c.local != "" {
				if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindApplied}) {
					t.Fatalf("telemetry %v", got)
				}
				return
			}
			if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindUnknownSubject}) {
				t.Fatalf("telemetry %v", got)
			}
			rec := r.tel.last()
			if rec.Reason != c.reason || rec.SubjectFormat != c.format || rec.JTI != "j-1" || rec.Issuer != txIssuer || rec.EventType != ssf.EventAccountDisabled {
				t.Fatalf("record %+v", rec)
			}
			// The telemetry carries the format, never the identifier.
			if strings.Contains(strings.Join([]string{rec.Principal, rec.Reason, rec.SubjectFormat}, "|"), "nobody") {
				t.Fatalf("record leaks the identifier: %+v", rec)
			}
		})
	}
}

// A mapping is for one SET issuer: a subject of another transmitter that
// repeats a mapped value resolves nothing.
func TestMappingIsPerIssuer(t *testing.T) {
	r := newRig(t, func(c *ssf.Config) {
		c.Issuers = append(c.Issuers, ssf.Issuer{Issuer: "https://tx2.example.com", Audience: rxAud, Keys: ssf.StaticKeys{jwkOf(t, key(t, 2), kid)}})
	})
	cl := claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil)
	cl["iss"] = "https://tx2.example.com"
	r.accept(t, signed(t, cl))
	r.wantNoFact(t, principal("7a1f"))
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindUnknownSubject}) {
		t.Fatalf("telemetry %v", got)
	}
}

// Critical subject members the receiver cannot process discard the event
// (SSF 1.0 section 3.6).
func TestCriticalSubjectMember(t *testing.T) {
	r := newRig(t, func(c *ssf.Config) { c.CriticalSubjectMembers = []string{"device"} })
	sub := map[string]any{"format": "complex", "user": issSub("u-1"), "device": map[string]any{"format": "opaque", "id": "d"}}
	r.accept(t, signed(t, claims("j-1", nowSec-10, sub, ssf.EventAccountDisabled, nil)))
	r.wantNoFact(t, principal("7a1f"))
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindDiscarded}) {
		t.Fatalf("telemetry %v", got)
	}
}

// Legacy subject placement of the RISC profile, as Google documents it: the
// subject is a member of the event, with subject_type.
func TestLegacyEventSubject(t *testing.T) {
	r := newRig(t)
	payload := map[string]any{"subject": map[string]any{"subject_type": "iss-sub", "iss": txIssuer, "sub": "u-1"}, "reason": "hijacking"}
	r.accept(t, signed(t, claims("j-1", nowSec-10, nil, ssf.EventAccountDisabled, payload)))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
}

func TestUnsupportedEvent(t *testing.T) {
	r := newRig(t)
	const dev = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	r.accept(t, signed(t, claims("j-1", nowSec-10, issSub("u-1"), dev, map[string]any{"previous_status": "compliant", "current_status": "not-compliant"})))
	r.wantNoFact(t, principal("7a1f"))
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindUnsupportedEvent}) {
		t.Fatalf("telemetry %v", got)
	}
	if r.tel.last().EventType != dev {
		t.Fatalf("record %+v", r.tel.last())
	}
}

// A SET with several events applies each; the SSF profile says one (4.2.1)
// but RFC 8417 allows several.
func TestSeveralEvents(t *testing.T) {
	r := newRig(t)
	c := claims("j-1", nowSec-10, issSub("u-1"), ssf.EventSessionRevoked, map[string]any{"event_timestamp": nowSec - 20})
	c["events"].(map[string]any)[ssf.EventAccountDisabled] = map[string]any{"event_timestamp": nowSec - 15}
	r.accept(t, signed(t, c))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-15)
}

// Hold candidates: only where configured, and a candidate is not a hold.
func TestHoldCandidates(t *testing.T) {
	compromise := claims("j-1", nowSec-10, issSub("u-1"), ssf.EventCredentialCompromise, map[string]any{"credential_type": "password", "event_timestamp": nowSec - 12, "reason_admin": map[string]any{"en": "found in a breach"}})
	t.Run("configured", func(t *testing.T) {
		r := newRig(t, func(c *ssf.Config) { c.HoldOn = []string{ssf.EventCredentialCompromise, ssf.EventAccountDisabled} })
		r.accept(t, signed(t, compromise))
		if len(r.holds.got) != 1 {
			t.Fatalf("candidates %+v", r.holds.got)
		}
		h := r.holds.got[0]
		if h.Principal != principal("7a1f") || h.EventType != ssf.EventCredentialCompromise || h.Issuer != txIssuer || h.JTI != "j-1" || h.EventTime.Unix() != nowSec-12 {
			t.Fatalf("candidate %+v", h)
		}
		if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindApplied, ssf.KindHoldCandidate}) {
			t.Fatalf("telemetry %v", got)
		}
	})
	t.Run("not configured", func(t *testing.T) {
		r := newRig(t)
		r.accept(t, signed(t, compromise))
		if len(r.holds.got) != 0 {
			t.Fatalf("candidates %+v", r.holds.got)
		}
		r.wantState(t, principal("7a1f"), ssf.StateCredentialCompromised, nowSec-12)
	})
	t.Run("configured event for an unknown subject", func(t *testing.T) {
		r := newRig(t, func(c *ssf.Config) { c.HoldOn = []string{ssf.EventCredentialCompromise} })
		r.accept(t, signed(t, claims("j-1", nowSec-10, issSub("nobody"), ssf.EventCredentialCompromise, map[string]any{"credential_type": "password"})))
		if len(r.holds.got) != 0 {
			t.Fatalf("candidates %+v", r.holds.got)
		}
	})
	t.Run("stale event gives no candidate", func(t *testing.T) {
		r := newRig(t, func(c *ssf.Config) { c.HoldOn = []string{ssf.EventCredentialCompromise} })
		r.accept(t, signed(t, claims("j-0", nowSec-5, issSub("u-1"), ssf.EventAccountEnabled, map[string]any{"event_timestamp": nowSec - 5})))
		r.accept(t, signed(t, compromise))
		if len(r.holds.got) != 1 {
			// A compromise is a hold candidate even when a newer state exists:
			// the state is not rolled back, the candidate is still raised.
			t.Fatalf("candidates %+v", r.holds.got)
		}
		r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-5)
	})
}

// Control events: verification (SSF 8.1.4) and stream-updated (8.1.5).
func TestControlEvents(t *testing.T) {
	r := newRig(t)
	ver := claims("j-v", nowSec-5, map[string]any{"format": "opaque", "id": "stream-1"}, ssf.EventVerification, map[string]any{"state": "s-123"})
	r.accept(t, signed(t, ver))
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindVerification}) {
		t.Fatalf("telemetry %v", got)
	}
	if !r.rx.Verified("s-123") || r.rx.Verified("other") {
		t.Fatal("Verified does not follow the verification events")
	}
	r.tel.reset()
	upd := claims("j-u", nowSec-4, map[string]any{"format": "opaque", "id": "stream-1"}, ssf.EventStreamUpdated, map[string]any{"status": "paused", "reason": "maintenance"})
	r.accept(t, signed(t, upd))
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindStreamUpdated}) {
		t.Fatalf("telemetry %v", got)
	}
	if rec := r.tel.last(); rec.Reason != "paused" {
		t.Fatalf("record %+v", rec)
	}
}

func TestNewReceiverValidatesConfig(t *testing.T) {
	base := func() ssf.Config {
		return ssf.Config{
			SourceID: "ssf-test", Store: source.NewMemory(), Clock: clock.NewFake(time.Unix(nowSec, 0)),
			PrincipalPrefix: prefix,
			Issuers:         []ssf.Issuer{{Issuer: txIssuer, Audience: rxAud, Keys: ssf.StaticKeys{jwkOf(t, key(t, 2), kid)}}},
			Mappings:        defaultMappings(),
		}
	}
	if _, err := ssf.NewReceiver(base()); err != nil {
		t.Fatalf("base config: %v", err)
	}
	for name, mod := range map[string]func(*ssf.Config){
		"no source id":              func(c *ssf.Config) { c.SourceID = "" },
		"no store":                  func(c *ssf.Config) { c.Store = nil },
		"no clock":                  func(c *ssf.Config) { c.Clock = nil },
		"no issuer":                 func(c *ssf.Config) { c.Issuers = nil },
		"issuer not https":          func(c *ssf.Config) { c.Issuers[0].Issuer = "http://tx.example.com" },
		"no audience":               func(c *ssf.Config) { c.Issuers[0].Audience = "" },
		"no keys":                   func(c *ssf.Config) { c.Issuers[0].Keys = nil },
		"duplicate issuer":          func(c *ssf.Config) { c.Issuers = append(c.Issuers, c.Issuers[0]) },
		"bad prefix":                func(c *ssf.Config) { c.PrincipalPrefix = "nobody" },
		"mapping format":            func(c *ssf.Config) { c.Mappings[0].Format = "phone_number" },
		"mapping issuer":            func(c *ssf.Config) { c.Mappings[0].Issuer = "https://unconfigured.example" },
		"mapping no local":          func(c *ssf.Config) { c.Mappings[0].Local = "" },
		"mapping no value":          func(c *ssf.Config) { c.Mappings[0].Value = "" },
		"iss_sub no subject issuer": func(c *ssf.Config) { c.Mappings[0].SubjectIss = "" },
		"duplicate mapping":         func(c *ssf.Config) { c.Mappings = append(c.Mappings, c.Mappings[0]) },
		"negative max age":          func(c *ssf.Config) { c.MaxAge = -time.Second },
		"hold on unknown event":     func(c *ssf.Config) { c.HoldOn = []string{"https://example.com/not-an-event"} },
		"hold without sink":         func(c *ssf.Config) { c.HoldOn = []string{ssf.EventCredentialCompromise}; c.Holds = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			mod(&c)
			if _, err := ssf.NewReceiver(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
