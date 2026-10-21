package scim

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/core/clock"
)

// The native paths a Server answers.
const (
	// PathAccountState is the account state of the principal: "active" or
	// "disabled".
	PathAccountState = "/principal/account_state"
	// PathGroupIDs is the sorted list of the group identifiers (the groups'
	// externalId values) of the groups that list the principal as a member.
	PathGroupIDs = "/principal/group_ids"
)

// joinAttribute is the only attribute a record can join a principal by.
const joinAttribute = "externalId"

// maxBody bounds a request body (RFC 7644 section 3.12, Table 8, 413).
const maxBody = 1 << 20

// maxResults bounds the resources of one list page.
const maxResults = 1000

const (
	mediaType = "application/scim+json"
	userURN   = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupURN  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	patchURN  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	listURN   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorURN  = "urn:ietf:params:scim:api:messages:2.0:Error"
	configURN = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// tokenRE is the b64token syntax of a bearer token (RFC 6750 section 2.1).
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

// Credential is a bearer token the provisioning client may present.
type Credential struct {
	// Token is the secret. It is held only as a digest.
	Token string
	// Provisioning is the right to use the Users and Groups endpoints. A
	// token without it authenticates and is refused with 403.
	Provisioning bool
}

// Config configures a [Server].
type Config struct {
	// Store receives the facts. Nil selects a new [source.Memory].
	Store source.Store
	// SourceID identifies the source in every claim.
	SourceID string
	// BasePath is the path prefix of the endpoints, such as /scim/v2: empty,
	// or starting with "/" and not ending with one.
	BasePath string
	// Join joins a record to its principal. Its Attribute is externalId and
	// its Prefix is the principal identifier up to the local part
	// (source.Join).
	Join source.Join
	// Credentials are the tokens the server accepts: at least one, and at
	// least one with the provisioning right.
	Credentials []Credential
	// Lag is the declared provisioning lag, at least one second: the longest
	// time the pushed state can trail the identity provider, such as one
	// provisioning cycle. It is the age the claims report.
	Lag time.Duration
	// Clock is the server's only source of the current time.
	Clock clock.Clock
	// ErrorLog receives the provisioning errors that are not request
	// errors: a record that joins no principal. Nil discards them.
	ErrorLog *log.Logger
}

// Server is the SCIM service provider. It is safe for concurrent use.
type Server struct {
	cfg    Config
	creds  []credential
	reader *source.Reader

	mu        sync.RWMutex
	seq       uint64
	users     map[string]*user
	groups    map[string]*group
	userNames map[string]string              // lower-case userName -> user id
	userExt   map[string]string              // externalId -> user id
	groupExt  map[string]string              // externalId -> group id
	memberOf  map[string]map[string]struct{} // user id -> group ids
}

// New returns a Server for c, or an error when c is not usable.
func New(c Config) (*Server, error) {
	switch {
	case c.Clock == nil:
		return nil, errors.New("scim: no clock")
	case c.SourceID == "":
		return nil, errors.New("scim: no source ID")
	case c.Lag < time.Second:
		return nil, errors.New("scim: the declared lag is at least one second: a pushed source has no live check")
	case c.Join.Attribute != joinAttribute:
		return nil, fmt.Errorf("scim: the join attribute is %s, not %q: no other attribute is an immutable identifier", joinAttribute, c.Join.Attribute)
	case c.BasePath != "" && (!strings.HasPrefix(c.BasePath, "/") || strings.HasSuffix(c.BasePath, "/") || strings.ContainsAny(c.BasePath, "?#")):
		return nil, fmt.Errorf("scim: base path %q is not empty or a path with no trailing slash", c.BasePath)
	}
	if _, err := c.Join.Principal(map[string]string{joinAttribute: "x"}); err != nil {
		return nil, fmt.Errorf("scim: %w", err)
	}
	s := &Server{
		cfg: c, users: map[string]*user{}, groups: map[string]*group{},
		userNames: map[string]string{}, userExt: map[string]string{}, groupExt: map[string]string{},
		memberOf: map[string]map[string]struct{}{},
	}
	if s.cfg.Store == nil {
		s.cfg.Store = source.NewMemory()
	}
	if err := s.loadCredentials(c.Credentials); err != nil {
		return nil, err
	}
	r, err := source.NewReader(source.Config{
		Store: s.cfg.Store, SourceID: c.SourceID, Paths: []string{PathGroupIDs, PathAccountState},
		Lag: c.Lag, Clock: c.Clock,
	})
	if err != nil {
		return nil, fmt.Errorf("scim: %w", err)
	}
	s.reader = r
	return s, nil
}

func (s *Server) loadCredentials(cs []Credential) error {
	if len(cs) == 0 {
		return errors.New("scim: no credentials")
	}
	seen := map[string]bool{}
	provisioning := false
	for _, c := range cs {
		switch {
		case !tokenRE.MatchString(c.Token):
			return errors.New("scim: a token is not a bearer token (RFC 6750 section 2.1)")
		case seen[c.Token]:
			return errors.New("scim: two credentials have the same token")
		}
		seen[c.Token] = true
		provisioning = provisioning || c.Provisioning
		s.creds = append(s.creds, credential{digest: sha256.Sum256([]byte(c.Token)), provisioning: c.Provisioning})
	}
	if !provisioning {
		return errors.New("scim: no credential has the provisioning right")
	}
	return nil
}

// Reader returns the [adapter.ClaimReader] over the facts the server holds.
// It serves [PathAccountState] and [PathGroupIDs].
func (s *Server) Reader() adapter.ClaimReader { return s.reader }

func (s *Server) logf(format string, args ...any) {
	if s.cfg.ErrorLog != nil {
		s.cfg.ErrorLog.Printf(format, args...)
	}
}

// ServeHTTP implements [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, s.cfg.BasePath)
	if !ok || !strings.HasPrefix(rest, "/") {
		writeError(w, errNotFound("no such endpoint"))
		return
	}
	segs := strings.Split(rest[1:], "/")
	if len(segs) == 1 && segs[0] == "ServiceProviderConfig" {
		s.serveConfig(w, r)
		return
	}
	if res := s.authenticate(r); res != authOK {
		challenge(w, res)
		if res == authForbidden {
			writeError(w, newErr(http.StatusForbidden, "", "the token does not carry the provisioning right"))
		} else {
			writeError(w, newErr(http.StatusUnauthorized, "", "the Authorization header is missing or does not carry a valid bearer token"))
		}
		return
	}
	var kind string
	switch segs[0] {
	case "Users", "Groups":
		kind = segs[0]
	default:
		writeError(w, errNotFound("no such endpoint"))
		return
	}
	switch {
	case len(segs) == 1:
		s.collection(w, r, kind)
	case len(segs) == 2 && segs[1] != "":
		s.item(w, r, kind, segs[1])
	default:
		writeError(w, errNotFound("no such endpoint"))
	}
}

func (s *Server) collection(w http.ResponseWriter, r *http.Request, kind string) {
	switch r.Method {
	case http.MethodGet:
		s.list(w, r, kind)
	case http.MethodPost:
		s.create(w, r, kind)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (s *Server) item(w http.ResponseWriter, r *http.Request, kind, id string) {
	switch r.Method {
	case http.MethodGet:
		s.get(w, r, kind, id)
	case http.MethodPatch:
		s.patch(w, r, kind, id)
	case http.MethodDelete:
		s.remove(w, kind, id)
	case http.MethodPut:
		writeError(w, newErr(http.StatusNotImplemented, "", "PUT is not supported: use PATCH"))
	default:
		methodNotAllowed(w, "GET, PATCH, DELETE")
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, newErr(http.StatusMethodNotAllowed, "", "method not allowed"))
}

// serveConfig answers the public /ServiceProviderConfig (RFC 7644 section 4;
// RFC 7643 section 5: the authentication schemes are public).
func (s *Server) serveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	off := map[string]any{"supported": false}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{configURN},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": maxResults},
		"changePassword": off,
		"sort":           off,
		"etag":           off,
		"authenticationSchemes": []any{map[string]any{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "A bearer token the provisioning client presents in the Authorization header (RFC 6750).",
			"specUri":     "https://www.rfc-editor.org/info/rfc6750",
		}},
	})
}

// readBody reads and decodes a request body as strict JSON.
func readBody(w http.ResponseWriter, r *http.Request) (any, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, newErr(http.StatusRequestEntityTooLarge, "", "the request body is larger than 1048576 bytes")
		}
		return nil, newErr(http.StatusBadRequest, "invalidSyntax", "the request body cannot be read")
	}
	return decodeJSON(b)
}
