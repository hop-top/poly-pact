package ssf

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/core/clock"
)

// Issuer configures one transmitter whose SETs the receiver accepts.
type Issuer struct {
	// Issuer is the iss of its SETs: an https URL (SSF 1.0 section 7.2).
	Issuer string
	// Audience is the aud value that names this receiver at that transmitter.
	Audience string
	// Keys supplies the keys its SETs are signed with. Nil, a nil *JWKS or
	// any other nil pointer included, is a configuration error.
	Keys KeySource
	// Algorithms is the list of signature algorithms this transmitter's SETs
	// may be signed with: [AlgES256] and [AlgRS256]. A SET whose alg is not
	// listed is refused as invalid_key, whatever its key. Empty is
	// [AlgES256] alone. A list that names AlgRS256 requires Keys to implement
	// [RSAKeySource]. Any other entry, none and the HMAC algorithms included,
	// is a configuration error.
	Algorithms []string
}

// Config configures a [Receiver].
type Config struct {
	// SourceID identifies the source in every claim.
	SourceID string
	// Store holds the pushed state.
	Store source.Store
	// Clock is the receiver's only source of the current time.
	Clock clock.Clock
	// Issuers are the transmitters the receiver accepts SETs from, each once.
	Issuers []Issuer
	// PrincipalPrefix is the principal identifier up to its local part (see
	// [source.Join]): the mechanism's namespace and the realm components.
	PrincipalPrefix string
	// Mappings join subjects to principals; see [Mapping].
	Mappings []Mapping
	// MaxAge is the longest age of a SET, by its iat, that the receiver
	// accepts, and so the time a jti is remembered. Zero is 24 hours: a
	// deployment choice, not a standard value.
	MaxAge time.Duration
	// MaxBytes bounds a compact SET. Zero is 65536.
	MaxBytes int
	// CriticalSubjectMembers names the members of a complex subject that the
	// transmitter marks critical (SSF 1.0 sections 3.6, 7.1). The receiver
	// processes only the user member, so an event whose subject has a
	// critical member is discarded.
	CriticalSubjectMembers []string
	// Authorization is the value of the Authorization header that the push
	// endpoint requires of the transmitter (RFC 8935 section 3). Empty
	// requires none; a deployment that does not put the endpoint behind
	// mutual TLS or another authenticating layer must set it.
	Authorization string
	// Replay remembers applied SETs. Nil is a [ReplayMemory].
	Replay ReplayStore
	// HoldOn lists the mapped event types that also raise a hold candidate.
	HoldOn []string
	// Holds receives the hold candidates; required when HoldOn is not empty.
	Holds HoldSink
	// Telemetry receives one record per decision. Nil discards them.
	Telemetry Telemetry
}

// Result is the outcome of an accepted SET.
type Result struct {
	// JTI is the jti of the SET.
	JTI string
	// Replay is true when the receiver had applied this very SET before: it
	// is not applied again.
	Replay bool
}

// Receiver verifies Security Event Tokens and keeps the account state they
// report in a [source.Store]. It is safe for concurrent use.
type Receiver struct {
	c        Config
	issuers  map[string]Issuer
	mappings map[mapKey]string
	critical []string
	reader   *source.Reader
	skew     time.Duration

	mu       sync.Mutex // serializes verification-to-record, so a jti applies once
	verified map[string]bool
}

// NewReceiver returns a Receiver for c.
func NewReceiver(c Config) (*Receiver, error) {
	switch {
	case c.SourceID == "":
		return nil, errors.New("ssf: no source ID")
	case c.Store == nil:
		return nil, errors.New("ssf: no store")
	case c.Clock == nil:
		return nil, errors.New("ssf: no clock")
	case len(c.Issuers) == 0:
		return nil, errors.New("ssf: no issuer")
	case c.MaxAge < 0 || c.MaxBytes < 0:
		return nil, errors.New("ssf: negative limit")
	case len(c.HoldOn) > 0 && c.Holds == nil:
		return nil, errors.New("ssf: HoldOn without Holds")
	}
	if c.MaxAge == 0 {
		c.MaxAge = 24 * time.Hour
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 65536
	}
	issuers := map[string]Issuer{}
	known := map[string]bool{}
	for i, is := range c.Issuers {
		switch {
		case httpsURL(is.Issuer) != nil:
			return nil, fmt.Errorf("ssf: issuer %d: %q is not an https URL", i, is.Issuer)
		case is.Audience == "":
			return nil, fmt.Errorf("ssf: issuer %d: no audience", i)
		case is.Keys == nil || nilPointer(is.Keys):
			return nil, fmt.Errorf("ssf: issuer %d: no keys", i)
		case known[is.Issuer]:
			return nil, fmt.Errorf("ssf: issuer %q is configured twice", is.Issuer)
		}
		algs, err := issuerAlgorithms(is.Algorithms)
		if err != nil {
			return nil, fmt.Errorf("ssf: issuer %d: %w", i, err)
		}
		if slices.Contains(algs, AlgRS256) {
			if _, ok := is.Keys.(RSAKeySource); !ok {
				return nil, fmt.Errorf("ssf: issuer %d: %s is allowed but the key source serves no RSA keys", i, AlgRS256)
			}
		}
		if err := validateStatic(is.Keys); err != nil {
			return nil, fmt.Errorf("ssf: issuer %d: %w", i, err)
		}
		is.Algorithms = algs
		known[is.Issuer] = true
		issuers[is.Issuer] = is
	}
	for _, t := range c.HoldOn {
		if !mappedType(t) {
			return nil, fmt.Errorf("ssf: HoldOn: %q is not an event type the receiver maps", t)
		}
	}
	table, err := mappingTable(c.PrincipalPrefix, known, c.Mappings)
	if err != nil {
		return nil, err
	}
	if c.Replay == nil {
		c.Replay = NewReplayMemory(c.Clock)
	}
	reader, err := source.NewReader(source.Config{
		Store: c.Store, SourceID: c.SourceID, Paths: []string{AccountStatePath}, Clock: c.Clock,
	})
	if err != nil {
		return nil, err
	}
	return &Receiver{
		c: c, issuers: issuers, mappings: table, critical: slices.Clone(c.CriticalSubjectMembers),
		reader: reader, skew: clock.BaselineSkew, verified: map[string]bool{},
	}, nil
}

// Reader returns the [adapter.ClaimReader] over the state the receiver keeps.
// It serves [AccountStatePath] only, reports the event time of the last event
// as both the observation and the status time, and answers a principal that
// no event named with a missing-field error: the receiver learns only what
// the transmitter sends (draft 9.2, 17.2).
func (r *Receiver) Reader() adapter.ClaimReader { return r.reader }

// Verified reports whether a verification event carrying state arrived
// (SSF 1.0 section 8.1.4): the answer to Transmitter.RequestVerification.
func (r *Receiver) Verified(state string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verified[state]
}

func (r *Receiver) observe(rec Record) {
	if r.c.Telemetry != nil {
		rec.At = r.c.Clock.Now()
		r.c.Telemetry.Observe(rec)
	}
}

// Accept verifies one compact SET and applies its events. A SET that fails
// verification, or whose events do not conform to their definitions, is an
// *[Error] and changes nothing. A SET the receiver applied before is a Result
// with Replay set, not an error: RFC 8935 section 2 has a recipient answer a
// retransmission as it answered the first delivery. Any other error is a
// failure of a dependency, and the SET is accepted on a retry.
func (r *Receiver) Accept(ctx context.Context, compact string) (Result, error) {
	tok, err := r.verify(ctx, compact)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			rec := Record{Kind: KindRejected, Reason: e.Code}
			if tok != nil {
				rec.Issuer, rec.JTI = tok.issuer, tok.jti
			}
			r.observe(rec)
		}
		return Result{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	digest, seen, err := r.c.Replay.Lookup(ctx, tok.issuer, tok.jti)
	if err != nil {
		return Result{}, fmt.Errorf("ssf: replay store: %w", err)
	}
	if seen {
		if digest != tok.digest {
			e := reject(CodeInvalidRequest, "jti %q was used for another SET of this issuer", tok.jti)
			r.observe(Record{Kind: KindRejected, Issuer: tok.issuer, JTI: tok.jti, Reason: e.Code})
			return Result{}, e
		}
		r.observe(Record{Kind: KindReplay, Issuer: tok.issuer, JTI: tok.jti})
		return Result{JTI: tok.jti, Replay: true}, nil
	}
	plan, perr := r.plan(tok)
	if perr != nil {
		r.observe(Record{Kind: KindRejected, Issuer: tok.issuer, JTI: tok.jti, Reason: perr.Code})
		return Result{}, perr
	}
	for _, ev := range plan {
		if err := r.apply(ctx, tok, ev); err != nil {
			return Result{}, err
		}
	}
	until := tok.issuedAt.Add(r.c.MaxAge + r.skew)
	if err := r.c.Replay.Record(ctx, tok.issuer, tok.jti, tok.digest, until); err != nil {
		return Result{}, fmt.Errorf("ssf: replay store: %w", err)
	}
	return Result{JTI: tok.jti}, nil
}

// plannedEvent is one event of a SET after validation.
type plannedEvent struct {
	typ     string
	payload map[string]jsonRaw
	effect  effect
	at      time.Time
	subject jsonRaw
}

func (r *Receiver) plan(tok *token) ([]plannedEvent, *Error) {
	types := make([]string, 0, len(tok.events))
	for t := range tok.events {
		types = append(types, t)
	}
	sort.Strings(types)
	var out []plannedEvent
	for _, t := range types {
		payload := tok.events[t]
		ev := plannedEvent{typ: t, payload: payload, subject: tok.subID}
		if len(ev.subject) == 0 {
			ev.subject = payload["subject"]
		}
		at, err := eventTime(payload, tok.issuedAt, r.skew)
		if err != nil {
			return nil, reject(CodeInvalidRequest, "%s: %v", short(t), err)
		}
		ev.at = at
		if mappedType(t) {
			e, perr := interpret(t, payload)
			if perr != nil {
				return nil, perr
			}
			ev.effect = e
		}
		out = append(out, ev)
	}
	return out, nil
}

// apply carries out one validated event.
func (r *Receiver) apply(ctx context.Context, tok *token, ev plannedEvent) error {
	rec := Record{Issuer: tok.issuer, JTI: tok.jti, EventType: ev.typ}
	switch ev.typ {
	case EventVerification:
		var state string
		_ = unmarshalString(ev.payload["state"], &state)
		r.verified[state] = true
		rec.Kind = KindVerification
		r.observe(rec)
		return nil
	case EventStreamUpdated:
		var status string
		_ = unmarshalString(ev.payload["status"], &status)
		rec.Kind, rec.Reason = KindStreamUpdated, status
		r.observe(rec)
		return nil
	}
	if !mappedType(ev.typ) {
		rec.Kind = KindUnsupportedEvent
		r.observe(rec)
		return nil
	}
	res := r.resolve(tok.issuer, ev.subject)
	rec.SubjectFormat = res.format
	switch {
	case res.discard:
		rec.Kind = KindDiscarded
		r.observe(rec)
		return nil
	case res.principal == "":
		rec.Kind, rec.Reason = KindUnknownSubject, res.reason
		r.observe(rec)
		return nil
	}
	rec.Principal = res.principal
	if ev.effect.noEffect {
		rec.Kind = KindNoEffect
		r.observe(rec)
		return nil
	}
	cur, ok, err := r.c.Store.Get(ctx, res.principal, AccountStatePath)
	if err != nil {
		return fmt.Errorf("ssf: store: %w", err)
	}
	if ok && cur.ObservedAt.After(ev.at) {
		// A newer event already decided the state; an old one never rolls it back.
		rec.Kind = KindStaleEvent
		r.observe(rec)
	} else {
		f := source.Fact{Value: ev.effect.state, ObservedAt: ev.at, StatusCheckedAt: ev.at, SourceRef: tok.jti}
		if err := r.c.Store.Put(ctx, res.principal, AccountStatePath, f); err != nil {
			return fmt.Errorf("ssf: store: %w", err)
		}
		rec.Kind = KindApplied
		r.observe(rec)
	}
	if slices.Contains(r.c.HoldOn, ev.typ) {
		c := HoldCandidate{Principal: res.principal, Issuer: tok.issuer, JTI: tok.jti, EventType: ev.typ, EventTime: ev.at}
		if err := r.c.Holds.Candidate(ctx, c); err != nil {
			return fmt.Errorf("ssf: hold sink: %w", err)
		}
		rec.Kind = KindHoldCandidate
		r.observe(rec)
	}
	return nil
}

// nilPointer reports whether ks is a nil pointer in a non-nil interface, such
// as a nil *JWKS: a source that would panic on its first use.
func nilPointer(ks KeySource) bool {
	v := reflect.ValueOf(ks)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// issuerAlgorithms checks an issuer's algorithm list and returns it, or the
// default ES256 when it is empty.
func issuerAlgorithms(list []string) ([]string, error) {
	if len(list) == 0 {
		return []string{AlgES256}, nil
	}
	seen := map[string]bool{}
	for _, a := range list {
		if a != AlgES256 && a != AlgRS256 {
			return nil, fmt.Errorf("algorithm %q is not one of %s and %s", a, AlgES256, AlgRS256)
		}
		if seen[a] {
			return nil, fmt.Errorf("algorithm %s is listed twice", a)
		}
		seen[a] = true
	}
	return slices.Clone(list), nil
}
