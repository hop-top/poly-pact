package files_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/files"
	"hop.top/pact-go/core/clock"
)

// filesModel is the native-state model of the cases in
// spec/v1.0/fixtures/adapters/files (that directory's README).
const filesModel = "files/1"

type filesState struct {
	Model   string `json:"model"`
	Gateway struct {
		TenantID        string   `json:"tenant_id"`
		EnvironmentID   string   `json:"environment_id"`
		Origin          string   `json:"origin"`
		HeaderAllowlist []string `json:"header_allowlist"`
	} `json:"gateway"`
	Parameters struct {
		ContextMaxAge     int64 `json:"context_max_age_seconds"`
		HandleMaxLifetime int64 `json:"handle_max_lifetime_seconds"`
	} `json:"parameters"`
	ServiceAccount string         `json:"service_account"`
	Accounts       []accountState `json:"accounts"`
	Connection     *contextState  `json:"connection"`
	Contexts       []contextState `json:"contexts"`
	Impersonation  *struct {
		Enter  string `json:"enter"`
		Revert string `json:"revert"`
	} `json:"impersonation"`
	Unhealthy    bool              `json:"unhealthy"`
	OpenSourceID string            `json:"open_source_id"`
	Registry     []registryState   `json:"registry"`
	Objects      []objectState     `json:"objects"`
	Enrollments  []json.RawMessage `json:"enrollments"`
	Reporting    json.RawMessage   `json:"reporting"`
}

type accountState struct {
	Ref            string   `json:"ref"`
	SID            string   `json:"sid"`
	DisplayName    string   `json:"display_name"`
	Groups         []string `json:"groups"`
	NegotiateToken string   `json:"negotiate_token"`
}

type contextState struct {
	Account     string `json:"account"`
	CompletedAt int64  `json:"completed_at"`
}

type registryState struct {
	FileID       string `json:"file_id"`
	Path         string `json:"path"`
	FinalPath    string `json:"final_path"`
	VolumeSerial string `json:"volume_serial"`
	ObjectID     string `json:"object_id"`
}

type objectState struct {
	Path         string     `json:"path"`
	FinalPath    string     `json:"final_path"`
	VolumeSerial string     `json:"volume_serial"`
	ObjectID     string     `json:"object_id"`
	Attributes   []string   `json:"attributes"`
	ReparseTag   string     `json:"reparse_tag"`
	ACL          []aceState `json:"acl"`
	ContentB64   string     `json:"content_b64"`
}

type aceState struct {
	SID    string   `json:"sid"`
	Effect string   `json:"effect"`
	Access []string `json:"access"`
}

// modelOf returns the model member of a native state.
func modelOf(raw json.RawMessage) (string, error) {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("native_state: %w", err)
	}
	return m.Model, nil
}

// world is the native side of a files/1 case: the accounts, the security
// package, the impersonation of the one broker thread and the file system,
// as fakes that behave as the cases README says.
type world struct {
	st      filesState
	hooks   *adaptertest.Hooks
	byRef   map[string]*accountState
	bySID   map[string]*accountState
	byToken map[string]*accountState
	objects map[string]*objectState

	mu sync.Mutex
	// current is the identity the broker thread runs as: the service
	// account, or the user of the token it impersonates.
	current identity
	// opens counts the opens the file system was asked for; serviceOpens
	// those asked for as the service account.
	opens, serviceOpens int
	// handles are the handles the file system returned, open or closed.
	handles []*fakeHandle
	// revertFails overrides the state's revert mode when set.
	revertFails *bool
	// enterMode overrides the state's enter mode when set.
	enterMode string
}

// identity is a user SID with its group SIDs.
type identity struct {
	user   string
	groups []string
}

// loadWorld reads a files/1 state strictly and indexes it.
func loadWorld(raw json.RawMessage) (*world, error) {
	var st filesState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("files/1 state: %w", err)
	}
	if st.Model != filesModel {
		return nil, fmt.Errorf("model %q is not %s", st.Model, filesModel)
	}
	return buildWorld(st)
}

// buildWorld indexes a files/1 state.
func buildWorld(st filesState) (*world, error) {
	w := &world{st: st, byRef: map[string]*accountState{}, bySID: map[string]*accountState{},
		byToken: map[string]*accountState{}, objects: map[string]*objectState{}}
	for i := range st.Accounts {
		a := &w.st.Accounts[i]
		if a.Ref == "" || a.SID == "" || a.NegotiateToken == "" {
			return nil, fmt.Errorf("account %d lacks a ref, a SID or a token", i)
		}
		if _, dup := w.byRef[a.Ref]; dup {
			return nil, fmt.Errorf("account %s twice", a.Ref)
		}
		if _, dup := w.byToken[a.NegotiateToken]; dup {
			return nil, fmt.Errorf("account %s shares a token", a.Ref)
		}
		w.byRef[a.Ref], w.bySID[a.SID], w.byToken[a.NegotiateToken] = a, a, a
	}
	svc, ok := w.byRef[st.ServiceAccount]
	if !ok {
		return nil, fmt.Errorf("service account %q is not an account", st.ServiceAccount)
	}
	w.current = identity{user: svc.SID, groups: svc.Groups}
	for i := range st.Objects {
		o := &w.st.Objects[i]
		if _, dup := w.objects[o.Path]; dup {
			return nil, fmt.Errorf("two objects at %s", o.Path)
		}
		if _, err := objectOf(o); err != nil {
			return nil, fmt.Errorf("object %s: %w", o.Path, err)
		}
		w.objects[o.Path] = o
	}
	for _, r := range st.Registry {
		if _, err := entryOf(r); err != nil {
			return nil, fmt.Errorf("registry %s: %w", r.FileID, err)
		}
	}
	for _, c := range append(slices.Clone(st.Contexts), connections(st)...) {
		if _, ok := w.byRef[c.Account]; !ok {
			return nil, fmt.Errorf("context of unknown account %q", c.Account)
		}
	}
	return w, nil
}

func connections(st filesState) []contextState {
	if st.Connection == nil {
		return nil
	}
	return []contextState{*st.Connection}
}

func (w *world) service() *accountState { return w.byRef[w.st.ServiceAccount] }

// Credential attaches the Negotiate token of the account ref names
// (RFC 4559, section 4.2).
func (w *world) Credential(r *http.Request, ref string) error {
	a, ok := w.byRef[ref]
	if !ok {
		return fmt.Errorf("no account %q", ref)
	}
	r.Header.Set("Authorization", "Negotiate "+a.NegotiateToken)
	return nil
}

// negotiateRequest is a request of route R1 that carries the token of the
// account ref names.
func (w *world) negotiateRequest(ref string) (*http.Request, error) {
	r, err := http.NewRequest(http.MethodGet, w.st.Gateway.Origin+"/files/seed/content", nil)
	if err != nil {
		return nil, err
	}
	return r, w.Credential(r, ref)
}

// registry is the file registry of the state.
func (w *world) registry() (files.StaticRegistry, error) {
	reg := files.StaticRegistry{}
	for _, r := range w.st.Registry {
		e, err := entryOf(r)
		if err != nil {
			return nil, err
		}
		reg[e.Resource] = e
	}
	return reg, nil
}

func entryOf(r registryState) (files.Entry, error) {
	vs, err := strconv.ParseUint(r.VolumeSerial, 16, 64)
	if err != nil || len(r.VolumeSerial) != 16 {
		return files.Entry{}, fmt.Errorf("volume serial %q is not 16 hexadecimal digits", r.VolumeSerial)
	}
	id, err := objectID(r.ObjectID)
	if err != nil {
		return files.Entry{}, err
	}
	return files.Entry{Resource: "file:" + r.FileID, Path: r.Path, FinalPath: r.FinalPath, VolumeSerial: vs, ObjectID: id}, nil
}

func objectID(s string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return id, fmt.Errorf("object id %q is not 32 hexadecimal digits", s)
	}
	copy(id[:], b)
	return id, nil
}

var attributeBits = map[string]files.Attributes{
	"directory":             files.AttrDirectory,
	"reparse_point":         files.AttrReparsePoint,
	"offline":               files.AttrOffline,
	"recall_on_data_access": files.AttrRecallOnDataAccess,
}

func objectOf(o *objectState) (files.Object, error) {
	vs, err := strconv.ParseUint(o.VolumeSerial, 16, 64)
	if err != nil || len(o.VolumeSerial) != 16 {
		return files.Object{}, fmt.Errorf("volume serial %q is not 16 hexadecimal digits", o.VolumeSerial)
	}
	id, err := objectID(o.ObjectID)
	if err != nil {
		return files.Object{}, err
	}
	var attrs files.Attributes
	for _, a := range o.Attributes {
		bit, ok := attributeBits[a]
		if !ok {
			return files.Object{}, fmt.Errorf("attribute %q is not defined", a)
		}
		attrs |= bit
	}
	if _, err := base64.StdEncoding.DecodeString(o.ContentB64); err != nil {
		return files.Object{}, fmt.Errorf("content: %w", err)
	}
	for _, e := range o.ACL {
		if e.Effect != "allow" && e.Effect != "deny" {
			return files.Object{}, fmt.Errorf("entry effect %q", e.Effect)
		}
	}
	return files.Object{Attributes: attrs, VolumeSerial: vs, ObjectID: id, FinalPath: o.FinalPath}, nil
}

// fakePackage is the security package: a token completes in one leg for the
// account whose negotiate_token it is, and every other token is rejected.
type fakePackage struct{ w *world }

func (p fakePackage) NewExchange() (files.Exchange, error) { return &fakeExchange{w: p.w}, nil }

type fakeExchange struct {
	w      *world
	closed bool
}

func (e *fakeExchange) Accept(input []byte) ([]byte, files.Token, error) {
	a, ok := e.w.byToken[base64.StdEncoding.EncodeToString(input)]
	if !ok {
		return nil, nil, errors.New("fixture security package: the logon failed")
	}
	return nil, &fakeToken{acc: a}, nil
}

func (e *fakeExchange) Close() error { e.closed = true; return nil }

// fakeToken is the access token of a completed exchange.
type fakeToken struct {
	acc    *accountState
	closed bool
}

func (t *fakeToken) User() string       { return t.acc.SID }
func (t *fakeToken) Groups() []string   { return slices.Clone(t.acc.Groups) }
func (t *fakeToken) Level() files.Level { return files.LevelImpersonation }
func (t *fakeToken) Ref() string        { return "fixture-logon:" + t.acc.Ref }
func (t *fakeToken) Close() error       { t.closed = true; return nil }
func (w *world) identityOf(t files.Token) identity {
	return identity{user: t.User(), groups: t.Groups()}
}

// fakeImpersonator is the impersonation of the broker thread.
type fakeImpersonator struct{ w *world }

func (f fakeImpersonator) enter() string {
	if f.w.enterMode != "" {
		return f.w.enterMode
	}
	if f.w.st.Impersonation != nil && f.w.st.Impersonation.Enter != "" {
		return f.w.st.Impersonation.Enter
	}
	return "ok"
}

func (f fakeImpersonator) revertFails() bool {
	if f.w.revertFails != nil {
		return *f.w.revertFails
	}
	return f.w.st.Impersonation != nil && f.w.st.Impersonation.Revert == "fails"
}

func (f fakeImpersonator) Impersonate(t files.Token) error {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	switch f.enter() {
	case "fails":
		return errors.New("fixture impersonation: entering failed")
	case "service":
		return nil
	}
	f.w.current = f.w.identityOf(t)
	return nil
}

func (f fakeImpersonator) Effective() (string, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return f.w.current.user, nil
}

func (f fakeImpersonator) Revert() error {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	if f.revertFails() {
		return errors.New("fixture impersonation: the revert failed")
	}
	svc := f.w.service()
	f.w.current = identity{user: svc.SID, groups: svc.Groups}
	return nil
}

// fakeFS is the file system, opening as the thread's current identity.
type fakeFS struct{ w *world }

func (f fakeFS) Open(path string, access files.Access) (files.Handle, error) {
	w := f.w
	w.mu.Lock()
	id := w.current
	w.opens++
	asService := id.user == w.service().SID
	if asService {
		w.serviceOpens++
	}
	w.mu.Unlock()
	w.hooks.Fire("open")
	if asService {
		w.hooks.Fire("service-open")
	}
	o, ok := w.objects[path]
	if !ok {
		return nil, fmt.Errorf("fixture file system: %s: %w", path, errNotFound)
	}
	if !w.allowed(o, id, string(access)) {
		return nil, fmt.Errorf("fixture file system: %s: %w", path, files.ErrAccessDenied)
	}
	obj, _ := objectOf(o)
	content, _ := base64.StdEncoding.DecodeString(o.ContentB64)
	h := &fakeHandle{w: w, obj: obj, r: bytes.NewReader(content)}
	w.mu.Lock()
	w.handles = append(w.handles, h)
	w.mu.Unlock()
	return h, nil
}

var errNotFound = errors.New("not found")

// allowed reads the list in order: the first entry for the user or one of its
// groups that holds the right decides; with none, the open is denied.
func (w *world) allowed(o *objectState, id identity, right string) bool {
	for _, e := range o.ACL {
		if e.SID != id.user && !slices.Contains(id.groups, e.SID) {
			continue
		}
		if !slices.Contains(e.Access, right) {
			continue
		}
		return e.Effect == "allow"
	}
	return false
}

// fakeHandle is an open handle; a read fires the execute hook.
type fakeHandle struct {
	w      *world
	obj    files.Object
	r      io.Reader
	read   bool
	closed bool
}

func (h *fakeHandle) Object() (files.Object, error) {
	if h.closed {
		return files.Object{}, errors.New("fixture file system: closed handle")
	}
	return h.obj, nil
}

func (h *fakeHandle) Read(p []byte) (int, error) {
	if h.closed {
		return 0, errors.New("fixture file system: closed handle")
	}
	if !h.read {
		h.read = true
		h.w.hooks.Fire("execute")
	}
	return h.r.Read(p)
}

func (h *fakeHandle) Close() error { h.closed = true; return nil }

// seedClock is the broker's clock: env's clock, or a fixed instant while the
// harness completes the exchanges the state says completed earlier.
type seedClock struct {
	mu   sync.Mutex
	at   *time.Time
	base interface{ Now() time.Time }
}

func (c *seedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at != nil {
		return *c.at
	}
	return c.base.Now()
}

func (c *seedClock) set(t *time.Time) {
	c.mu.Lock()
	c.at = t
	c.mu.Unlock()
}

// realmOf is the broker's realm in the state.
func (w *world) realm() adapter.Realm {
	return adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID}
}

// config is the broker configuration of the world: its realm and origin, the
// three seams as the world's fakes, the file registry and the profile
// parameters. The caller adds the enrollment registry and the deployment's
// sources.
func (w *world) config(clk clock.Clock) (files.Config, error) {
	reg, err := w.registry()
	if err != nil {
		return files.Config{}, err
	}
	return files.Config{
		Realm:             w.realm(),
		Origin:            w.st.Gateway.Origin,
		HeaderAllowlist:   w.st.Gateway.HeaderAllowlist,
		Package:           fakePackage{w: w},
		Impersonator:      fakeImpersonator{w: w},
		FileSystem:        fakeFS{w: w},
		Files:             reg,
		OpenSourceID:      w.st.OpenSourceID,
		ContextMaxAge:     time.Duration(w.st.Parameters.ContextMaxAge) * time.Second,
		HandleMaxLifetime: time.Duration(w.st.Parameters.HandleMaxLifetime) * time.Second,
		Clock:             clk,
	}, nil
}

// seedContexts completes, at its completed_at, the exchange of every context
// of the state, so that the broker holds it as authentication left it.
func (w *world) seedContexts(b *files.Broker, clk *seedClock) error {
	for _, c := range w.st.Contexts {
		if err := w.complete(b, clk, c, nil); err != nil {
			return err
		}
	}
	return nil
}

// complete runs the Negotiate exchange of c's account at c.completed_at on
// the connection of conn, or on a new connection when conn is nil.
func (w *world) complete(b *files.Broker, clk *seedClock, c contextState, conn *http.Request) error {
	at := time.Unix(c.CompletedAt, 0)
	clk.set(&at)
	defer clk.set(nil)
	r, err := w.negotiateRequest(c.Account)
	if err != nil {
		return err
	}
	if conn != nil {
		r = r.WithContext(conn.Context())
	} else {
		r = b.Arrive(r)
	}
	if _, err := b.AuthenticateNative(r.Context(), r); err != nil {
		return fmt.Errorf("completing the exchange of %s: %w", c.Account, err)
	}
	return nil
}

// arrive is the Arrive hook of a world: a request of a new connection of the
// broker, on which the exchange of the state's connection, if any, already
// completed. A seed that fails returns no request, which fails the case.
func (w *world) arrive(b *files.Broker, clk *seedClock) func(*http.Request) *http.Request {
	return func(r *http.Request) *http.Request {
		r = b.Arrive(r)
		if c := w.st.Connection; c != nil {
			if err := w.complete(b, clk, *c, r); err != nil {
				return nil
			}
		}
		return r
	}
}
