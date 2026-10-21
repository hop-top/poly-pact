package graph

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/internal/ascii"
)

// Continuation is the record of an @odata.nextLink that Graph returned
// (RB-57, GR-24).
type Continuation struct {
	// Row is the row whose downstream response carried the link.
	Row Row
	// Principal, TaskID and AgentID are those of the operation.
	Principal, TaskID, AgentID string
	// MappingVersion is the installed version of the operation.
	MappingVersion string
	// Link is the recorded @odata.nextLink, sent unchanged (RB-59).
	Link string
	// TaskToken is the task ledger's token of the continuation, which binds
	// it to the native task (RB-57, MO-56); empty without a ledger, or when
	// the ledger's pager refused the link.
	TaskToken string
}

// ErrNoContinuation is the error of a store that holds no record for a
// token.
var ErrNoContinuation = errors.New("graph: no continuation record")

// ContinuationStore holds the continuation records of the gateway, shared by
// every replica (component C09).
type ContinuationStore interface {
	// Record stores c and returns the gateway token that refers to it, in
	// the grammar of page_token.
	Record(ctx context.Context, c Continuation) (string, error)
	// Lookup returns the record of token, [ErrNoContinuation] when there is
	// none, another error when the store cannot answer.
	Lookup(ctx context.Context, token string) (Continuation, error)
}

// MemoryContinuations is an in-memory [ContinuationStore] for one replica.
type MemoryContinuations struct {
	mu       sync.Mutex
	records  map[string]Continuation
	newToken func() (string, error)
}

// NewMemoryContinuations returns an empty store. newToken makes the gateway
// tokens; nil draws 32 random octets, 43 base64url characters.
func NewMemoryContinuations(newToken func() (string, error)) *MemoryContinuations {
	if newToken == nil {
		newToken = randomToken
	}
	return &MemoryContinuations{records: map[string]Continuation{}, newToken: newToken}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Record stores c under a new token.
func (m *MemoryContinuations) Record(_ context.Context, c Continuation) (string, error) {
	tok, err := m.newToken()
	if err != nil || !PageTokenPattern.MatchString(tok) {
		return "", fmt.Errorf("graph: no page token: %w", adapter.ErrDependencyUnavailable)
	}
	m.Put(tok, c)
	return tok, nil
}

// Put stores c under token, replacing a record of the same token.
func (m *MemoryContinuations) Put(token string, c Continuation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[token] = c
}

// Lookup returns the record of token.
func (m *MemoryContinuations) Lookup(_ context.Context, token string) (Continuation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.records[token]
	if !ok {
		return Continuation{}, ErrNoContinuation
	}
	return c, nil
}

// rowPath is the gateway path of the adapter's rows (profile section 2).
func (a *Adapter) rowPath() string {
	if a.cfg.Form == FormDelegated {
		return "/mail/messages"
	}
	return "/mailbox/messages"
}

// firstRow and nextRow are the adapter's rows.
func (a *Adapter) firstRow() Row {
	if a.cfg.Form == FormDelegated {
		return RowGD1
	}
	return RowGA1
}

func (a *Adapter) nextRow() Row {
	if a.cfg.Form == FormDelegated {
		return RowGD2
	}
	return RowGA2
}

// splitTarget returns the path and the raw query of a target URI the binding
// built.
func splitTarget(target string) (path, query string) {
	rest := strings.TrimPrefix(target, "https://")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "/", ""
	}
	path, query, _ = strings.Cut(rest[i:], "?")
	return path, query
}

// rowOf is the row of a target URI of this adapter's origin: the first-page
// row for the fixed query, the continuation row for a page_token.
func (a *Adapter) rowOf(target string) (Row, bool) {
	if !strings.HasPrefix(target, a.originNormalized()+"/") {
		return "", false
	}
	path, query := splitTarget(target)
	if path != a.rowPath() {
		return "", false
	}
	if query == FixedQuery {
		return a.firstRow(), true
	}
	if tok, ok := strings.CutPrefix(query, "page_token="); ok && PageTokenPattern.MatchString(tok) {
		return a.nextRow(), true
	}
	return "", false
}

// originNormalized is the origin as the binding writes it into target URIs.
func (a *Adapter) originNormalized() string {
	o := ascii.ToLower(a.cfg.Origin)
	return strings.TrimSuffix(o, ":443")
}

// downstreamPath is the Graph path of a first-page row (section 2).
func downstreamPath(row Row, mailbox string) string {
	if row == RowGD1 || row == RowGD2 {
		return "/v1.0/me/messages"
	}
	return "/v1.0/users/" + mailbox + "/messages"
}

// linkOK reports whether a recorded link has the origin of Graph, exactly
// path, and the pinned $select and $top once each (GR-24, RB-58).
func linkOK(link, path string) bool {
	u, err := url.Parse(link)
	if err != nil || !ascii.EqualFold(u.Scheme, "https") || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	host := strings.TrimSuffix(ascii.ToLower(u.Host), ":443")
	if "https://"+host != GraphOrigin {
		return false
	}
	rest := link[len(u.Scheme)+3+len(u.Host):]
	rawPath, query, _ := strings.Cut(rest, "?")
	if rawPath != path {
		return false
	}
	sel, top := 0, 0
	for _, pair := range strings.Split(query, "&") {
		name, value, _ := strings.Cut(pair, "=")
		switch name {
		case "$select":
			sel++
			if value != "id,subject,body" {
				return false
			}
		case "$top":
			top++
			if value != "10" {
				return false
			}
		}
	}
	return sel == 1 && top == 1
}

// operationID is a stable correlation identifier of a request.
func operationID(principal, method, target string, digest core.Digest, version string) string {
	h := sha256.New()
	for _, part := range []string{principal, method, target, string(digest), version} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "op-" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:22]
}

// mapRequest is map_operation. The rows of the adapter's form are mapped
// under MappingRevision; further routes under their own versions.
func (a *Adapter) mapRequest(ctx context.Context, r *http.Request, p adapter.Principal, version string) (core.OperationContext, Continuation, error) {
	if r == nil || r.URL == nil {
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: no request: %w", adapter.ErrInvalidMessage)
	}
	if p.Realm != a.cfg.Realm {
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the principal belongs to another realm: %w", adapter.ErrContextMismatch)
	}
	if version != MappingRevision {
		routes, ok := a.cfg.Mappings[version]
		if !ok {
			return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: mapping version %q is not installed (RB-46): %w", version, adapter.ErrUnsupportedRequirement)
		}
		op, err := installed.MapRequest(a.bindingConfig(version), routes, a.cfg.Realm.EnvironmentID, r, p)
		return op, Continuation{}, err
	}
	op, err := binding.FromRequest(a.bindingConfig(version), r, p.ID, "", nil)
	switch {
	case errors.Is(err, binding.ErrInvalidRequest):
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: %w: %w", err, adapter.ErrInvalidMessage)
	case errors.Is(err, binding.ErrBodyRead):
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: %w: %w", err, adapter.ErrDependencyUnavailable)
	case err != nil:
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: %w: %w", err, adapter.ErrUnsupportedRequirement)
	}
	path, query := splitTarget(op.TargetURI)
	if path != a.rowPath() || op.Method != http.MethodGet {
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: no row of %s for %s %s (RB-33): %w", version, op.Method, path, adapter.ErrUnsupportedRequirement)
	}
	row := a.firstRow()
	var token string
	if query != FixedQuery {
		tok, ok := strings.CutPrefix(query, "page_token=")
		if !ok || !PageTokenPattern.MatchString(tok) {
			return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the query is not the row's constant (GR-23): %w", adapter.ErrInvalidMessage)
		}
		row, token = a.nextRow(), tok
	}
	if string(op.BodyDigest) != emptyDigest {
		return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the row accepts no body (RB-37): %w", adapter.ErrInvalidMessage)
	}
	mailbox := ""
	resource := "mailbox:" + p.ID
	if a.cfg.Form == FormApplication {
		bs, err := a.bindings(ctx)
		if err != nil {
			return core.OperationContext{}, Continuation{}, err
		}
		mb, ok := a.mailboxOf(bs, row, p.ID)
		if !ok {
			return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the workload has no usable executor binding for %s (GR-13): %w", row, adapter.ErrUnsupportedRequirement)
		}
		mailbox, resource = mb, "mailbox:"+mb
	}
	var cont Continuation
	if token != "" {
		c, err := a.cfg.Continuations.Lookup(ctx, token)
		switch {
		case errors.Is(err, ErrNoContinuation):
			return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the page token has no record (RB-58): %w", adapter.ErrContextMismatch)
		case err != nil:
			return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the continuation store cannot answer: %w", adapter.ErrDependencyUnavailable)
		}
		if c.Principal != p.ID || (c.Row != a.firstRow() && c.Row != a.nextRow()) || c.MappingVersion != version || !linkOK(c.Link, downstreamPath(row, mailbox)) {
			return core.OperationContext{}, Continuation{}, fmt.Errorf("graph: the continuation is not one of this principal, row, version and downstream path (GR-24, RB-58): %w", adapter.ErrContextMismatch)
		}
		cont = c
	}
	op.OperationID = operationID(p.ID, op.Method, op.TargetURI, op.BodyDigest, version)
	op.EnvironmentID = a.cfg.Realm.EnvironmentID
	op.Action = ActionMailList
	op.Resources = []string{resource}
	return op, cont, nil
}

// now is the adapter's clock.
func (a *Adapter) now() time.Time { return a.cfg.Clock.Now() }
