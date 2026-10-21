package googledir

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
)

// The endpoints of the vendor, used when a [ClientConfig] names none.
const (
	DefaultDirectoryURL = "https://admin.googleapis.com/admin/directory/v1"
	DefaultIdentityURL  = "https://cloudidentity.googleapis.com/v1"
	DefaultStopURL      = "https://www.googleapis.com/admin/directory_v1/channels/stop"
)

// maxResponse bounds a reply body.
const maxResponse = 1 << 20

// maxPageSize is the largest page of users the Directory API returns.
const maxPageSize = 500

// ErrNotFound: the API answered 404 for the resource asked for.
var ErrNotFound = errors.New("googledir: not found")

// APIError is a non-success answer of a Google API. Its text carries the
// status and the short reason code the API gave, never the message.
type APIError struct {
	Status int
	Reason string
}

func (e *APIError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("googledir: the API answered %d", e.Status)
	}
	return fmt.Sprintf("googledir: the API answered %d (%s)", e.Status, e.Reason)
}

// Is makes a 404 match [ErrNotFound].
func (e *APIError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// ClientConfig configures a [Client].
type ClientConfig struct {
	// DirectoryURL, IdentityURL and ChannelsStopURL are the endpoints; the
	// Default constants when empty. Each must be https.
	DirectoryURL    string
	IdentityURL     string
	ChannelsStopURL string
	// HTTP is the client for every call; a client with a 30 s timeout when
	// nil. It never follows a redirect.
	HTTP *http.Client
	// DirectoryTokens supplies the token of the Directory API calls and
	// IdentityTokens that of the Cloud Identity Groups API. The second may
	// be nil when no transitive membership is read.
	DirectoryTokens TokenSource
	IdentityTokens  TokenSource
	// Clock is the only source of the current time.
	Clock clock.Clock
}

// Client is a client of the Admin SDK Directory API and of the Cloud
// Identity Groups API, over HTTPS with the standard library.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// NewClient returns a Client for cfg.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = DefaultDirectoryURL
	}
	if cfg.IdentityURL == "" {
		cfg.IdentityURL = DefaultIdentityURL
	}
	if cfg.ChannelsStopURL == "" {
		cfg.ChannelsStopURL = DefaultStopURL
	}
	for name, u := range map[string]string{"directory": cfg.DirectoryURL, "identity": cfg.IdentityURL, "channels stop": cfg.ChannelsStopURL} {
		if err := requireHTTPS(u); err != nil {
			return nil, fmt.Errorf("googledir: %s URL: %w", name, err)
		}
	}
	switch {
	case cfg.DirectoryTokens == nil:
		return nil, errors.New("googledir: no Directory token source")
	case cfg.Clock == nil:
		return nil, errors.New("googledir: no clock")
	}
	cfg.DirectoryURL = strings.TrimRight(cfg.DirectoryURL, "/")
	cfg.IdentityURL = strings.TrimRight(cfg.IdentityURL, "/")
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{cfg: cfg, http: noRedirect(hc)}, nil
}

// User is the part of a Directory user the source reads.
type User struct {
	// ID is the user's unique ID, the join attribute.
	ID string
	// PrimaryEmail is the primary address; empty when the reply had none.
	// It is a name that changes, never a key.
	PrimaryEmail string
	Suspended    bool
	Archived     bool
}

// Channel is a push notification channel of the Directory API.
type Channel struct {
	// ID is the client-chosen channel ID, at most 64 characters.
	ID string
	// ResourceID identifies the watched resource; set by the API.
	ResourceID string
	// Address is the https URL notifications are delivered to.
	Address string
	// Token is the secret the API echoes in every notification, at most 256
	// characters.
	Token string
	// Expiration is when the channel stops, as the API reports it.
	Expiration time.Time
}

// do sends one request and returns the body of a 2xx reply.
func (c *Client) do(ctx context.Context, tokens TokenSource, method, target string, body any) ([]byte, error) {
	if tokens == nil {
		return nil, errors.New("googledir: no token source for this API")
	}
	tok, err := tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("googledir: %s %s: %w", method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("googledir: %s %s: %w", method, req.URL.Path, err)
	}
	if len(raw) > maxResponse {
		return nil, fmt.Errorf("googledir: %s %s: the reply is over %d bytes", method, req.URL.Path, maxResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &APIError{Status: resp.StatusCode, Reason: reasonOf(raw)}
	}
	return raw, nil
}

// reasonOf extracts the short reason code of a Google error body, if it has
// one made of letters, digits and underscores only.
func reasonOf(raw []byte) string {
	var e struct {
		Error struct {
			Status string `json:"status"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	r := e.Error.Status
	if r == "" && len(e.Error.Errors) > 0 {
		r = e.Error.Errors[0].Reason
	}
	if len(r) > 64 {
		return ""
	}
	for _, c := range r {
		letter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		if !letter && (c < '0' || c > '9') && c != '_' {
			return ""
		}
	}
	return r
}

// object decodes a reply that must be one JSON object.
func object(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &m); err != nil {
		return nil, fmt.Errorf("googledir: unusable reply: %w", err)
	}
	if m == nil {
		return nil, errors.New("googledir: unusable reply: not an object")
	}
	return m, nil
}

// userOf reads a user object. A reply without an id, or without the two
// flags, is unusable: an absent flag is never read as false.
func userOf(m map[string]json.RawMessage) (User, error) {
	var u User
	var err error
	if err = member(m, "id", &u.ID); err == nil && u.ID == "" {
		err = errors.New("empty id")
	}
	if err == nil {
		err = member(m, "suspended", &u.Suspended)
	}
	if err == nil {
		err = member(m, "archived", &u.Archived)
	}
	if err == nil {
		u.PrimaryEmail, err = optString(m, "primaryEmail")
	}
	if err != nil {
		return User{}, fmt.Errorf("googledir: unusable user: %w", err)
	}
	return u, nil
}

// User gets one user by key (users.get). The key may be the unique ID, an
// address or an alias; the caller passes an ID and checks the reply's ID.
func (c *Client) User(ctx context.Context, key string) (User, error) {
	raw, err := c.do(ctx, c.cfg.DirectoryTokens, http.MethodGet, c.cfg.DirectoryURL+"/users/"+url.PathEscape(key), nil)
	if err != nil {
		return User{}, err
	}
	m, err := object(raw)
	if err != nil {
		return User{}, err
	}
	return userOf(m)
}

// Users lists every user of the customer (users.list), page by page, and
// calls fn with each page and the time the request for it was made. A page
// size of 0 asks for the API's default; the API's own maximum is 500. fn's
// error stops the listing.
func (c *Client) Users(ctx context.Context, customer string, pageSize int, fn func(page []User, requested time.Time) error) error {
	if customer == "" {
		return errors.New("googledir: no customer")
	}
	if pageSize < 0 || pageSize > maxPageSize {
		return fmt.Errorf("googledir: page size %d is not 0 to %d", pageSize, maxPageSize)
	}
	seen := map[string]bool{}
	token := ""
	for {
		q := url.Values{"customer": {customer}}
		if pageSize > 0 {
			q.Set("maxResults", strconv.Itoa(pageSize))
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		requested := c.cfg.Clock.Now()
		raw, err := c.do(ctx, c.cfg.DirectoryTokens, http.MethodGet, c.cfg.DirectoryURL+"/users?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		m, err := object(raw)
		if err != nil {
			return err
		}
		var page []User
		if list, ok := m["users"]; ok {
			var items []map[string]json.RawMessage
			if err := json.Unmarshal(list, &items); err != nil {
				return fmt.Errorf("googledir: unusable user list: %w", err)
			}
			for _, it := range items {
				u, err := userOf(it)
				if err != nil {
					return err
				}
				page = append(page, u)
			}
		}
		if err := fn(page, requested); err != nil {
			return err
		}
		next, err := optString(m, "nextPageToken")
		if err != nil {
			return fmt.Errorf("googledir: unusable reply: %w", err)
		}
		if next == "" {
			return nil
		}
		if seen[next] {
			return errors.New("googledir: the listing repeats a page token")
		}
		seen[next] = true
		token = next
	}
}

// HasMember reports whether the user is a member of the group, directly or
// through a nested group of the same domain (members.hasMember). memberKey
// should be the user's unique ID.
func (c *Client) HasMember(ctx context.Context, group, memberKey string) (bool, error) {
	target := c.cfg.DirectoryURL + "/groups/" + url.PathEscape(group) + "/hasMember/" + url.PathEscape(memberKey)
	raw, err := c.do(ctx, c.cfg.DirectoryTokens, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	m, err := object(raw)
	if err != nil {
		return false, err
	}
	var is bool
	if err := member(m, "isMember", &is); err != nil {
		return false, fmt.Errorf("googledir: unusable reply: %w", err)
	}
	return is, nil
}

// TransitiveMember reports whether the member, named by address, is a
// member of the Cloud Identity group directly or through nested groups, also
// across domains (groups.memberships.checkTransitiveMembership). The member
// key of the API is an address.
func (c *Client) TransitiveMember(ctx context.Context, group, memberEmail string) (bool, error) {
	if !celSafe(memberEmail) {
		return false, errors.New("googledir: the member key cannot be put in a query literal")
	}
	q := url.Values{"query": {"member_key_id == '" + memberEmail + "'"}}
	target := c.cfg.IdentityURL + "/groups/" + url.PathEscape(group) + "/memberships:checkTransitiveMembership?" + q.Encode()
	raw, err := c.do(ctx, c.cfg.IdentityTokens, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	m, err := object(raw)
	if err != nil {
		return false, err
	}
	var is bool
	if err := member(m, "hasMembership", &is); err != nil {
		return false, fmt.Errorf("googledir: unusable reply: %w", err)
	}
	return is, nil
}

// celSafe reports whether s can sit between single quotes in a query
// expression: it is not empty, valid UTF-8, and has no quote, backslash or
// control character.
func celSafe(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\'' || r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// WatchUsers opens a push channel for the given user event of the customer
// (users.watch). A ttl above zero asks for that lifetime; the API applies
// the more restrictive of the request and its own limits, and the reply's
// expiration is the one that holds. The reply must name the channel, its
// resource and an expiration, or the channel is not used.
func (c *Client) WatchUsers(ctx context.Context, customer, event string, ch Channel, ttl time.Duration) (Channel, error) {
	switch {
	case customer == "":
		return Channel{}, errors.New("googledir: no customer")
	case ch.ID == "" || len(ch.ID) > 64:
		return Channel{}, errors.New("googledir: a channel ID is 1 to 64 characters")
	case len(ch.Token) > 256:
		return Channel{}, errors.New("googledir: a channel token is at most 256 characters")
	case ttl < 0:
		return Channel{}, errors.New("googledir: negative ttl")
	}
	if err := requireHTTPS(ch.Address); err != nil {
		return Channel{}, fmt.Errorf("googledir: channel address: %w", err)
	}
	body := map[string]any{"id": ch.ID, "type": "web_hook", "address": ch.Address}
	if ch.Token != "" {
		body["token"] = ch.Token
	}
	if ttl > 0 {
		body["params"] = map[string]string{"ttl": strconv.FormatInt(int64(ttl/time.Second), 10)}
	}
	q := url.Values{"customer": {customer}}
	if event != "" {
		q.Set("event", event)
	}
	raw, err := c.do(ctx, c.cfg.DirectoryTokens, http.MethodPost, c.cfg.DirectoryURL+"/users/watch?"+q.Encode(), body)
	if err != nil {
		return Channel{}, err
	}
	m, err := object(raw)
	if err != nil {
		return Channel{}, err
	}
	out := ch
	var id string
	if err := member(m, "id", &id); err != nil || id != ch.ID {
		return Channel{}, errors.New("googledir: unusable reply: the channel is not the one asked for")
	}
	if err := member(m, "resourceId", &out.ResourceID); err != nil || out.ResourceID == "" {
		return Channel{}, errors.New("googledir: unusable reply: no resourceId")
	}
	ms, err := expirationMillis(m["expiration"])
	if err != nil {
		return Channel{}, fmt.Errorf("googledir: unusable reply: %w", err)
	}
	out.Expiration = time.UnixMilli(ms)
	return out, nil
}

// expirationMillis reads the expiration of a channel: Unix milliseconds,
// written by the API as a JSON string of an int64 (a JSON number is also
// read).
func expirationMillis(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, errors.New("no expiration")
	}
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return 0, errors.New("expiration is not a string")
		}
		s = str
	}
	ms, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ms <= 0 {
		return 0, errors.New("expiration is not a positive number of milliseconds")
	}
	return ms, nil
}

// StopChannel stops a channel (channels.stop).
func (c *Client) StopChannel(ctx context.Context, ch Channel) error {
	if ch.ID == "" || ch.ResourceID == "" {
		return errors.New("googledir: a channel to stop needs its ID and resource ID")
	}
	_, err := c.do(ctx, c.cfg.DirectoryTokens, http.MethodPost, c.cfg.ChannelsStopURL, map[string]string{"id": ch.ID, "resourceId": ch.ResourceID})
	return err
}
