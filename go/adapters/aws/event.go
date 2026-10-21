package aws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/strictjson"
)

// Event is the payload format version 2.0 event that API Gateway passes to a
// Lambda proxy integration of an HTTP API, with the members of the 2.0
// example of the API Gateway Developer Guide page "Create AWS Lambda proxy
// integrations for HTTP APIs". It is decoded strictly: a member that is not
// listed here, a duplicate member, or a null where none is allowed refuses
// the event.
type Event struct {
	Version  string `json:"version"`
	RouteKey string `json:"routeKey"`
	RawPath  string `json:"rawPath"`
	// RawQueryString is required; a payload 1.0 or REST event has none
	// (AR-13).
	RawQueryString *string           `json:"rawQueryString"`
	Cookies        []string          `json:"cookies"`
	Headers        map[string]string `json:"headers"`
	// QueryStringParameters is never an input (AR-14).
	QueryStringParameters map[string]string `json:"queryStringParameters"`
	// PathParameters is only compared with the parameters taken from
	// RawPath (AR-16).
	PathParameters  map[string]string `json:"pathParameters"`
	StageVariables  map[string]string `json:"stageVariables"`
	RequestContext  RequestContext    `json:"requestContext"`
	Body            *string           `json:"body"`
	IsBase64Encoded bool              `json:"isBase64Encoded"`
}

// RequestContext is the requestContext member of an [Event].
type RequestContext struct {
	AccountID string `json:"accountId"`
	APIID     string `json:"apiId"`
	// Authentication carries a client certificate of mutual TLS; it is never
	// an identity input (AR-6).
	Authentication json.RawMessage `json:"authentication"`
	// Authorizer is kept by member name, so that any member besides iam
	// refuses the event as a native denial (AR-6).
	Authorizer   map[string]json.RawMessage `json:"authorizer"`
	DomainName   string                     `json:"domainName"`
	DomainPrefix string                     `json:"domainPrefix"`
	HTTP         HTTPContext                `json:"http"`
	RequestID    string                     `json:"requestId"`
	RouteKey     string                     `json:"routeKey"`
	Stage        string                     `json:"stage"`
	Time         string                     `json:"time"`
	// TimeEpoch is the request time in Unix milliseconds.
	TimeEpoch int64 `json:"timeEpoch"`
}

// HTTPContext is the requestContext.http member of an [Event].
type HTTPContext struct {
	Method string `json:"method"`
	// Path is decoded by API Gateway and never an input (AR-14).
	Path      string `json:"path"`
	Protocol  string `json:"protocol"`
	SourceIP  string `json:"sourceIp"`
	UserAgent string `json:"userAgent"`
}

// IAMContext is requestContext.authorizer.iam, with the member names of the
// test event apigw-v2-request-iam.json of the AWS Lambda library for Go,
// which are to be probed against a deployed API (profile AR-5, probe P1).
type IAMContext struct {
	AccessKey *string `json:"accessKey"`
	AccountID string  `json:"accountId"`
	CallerID  *string `json:"callerId"`
	// CognitoIdentity must be absent or null (AR-7).
	CognitoIdentity json.RawMessage `json:"cognitoIdentity"`
	PrincipalOrgID  *string         `json:"principalOrgId"`
	UserArn         string          `json:"userArn"`
	UserID          string          `json:"userId"`
}

// eventKey is the context key of the raw event a request carries.
type eventKey struct{}

// WithEvent returns a shallow copy of r that carries the raw JSON of the
// event API Gateway passed to the function. The adapter's functions read the
// event and nothing else of r: its URL, headers and body are never inputs.
func WithEvent(r *http.Request, raw []byte) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), eventKey{}, bytes.Clone(raw)))
}

// Invocation returns the request that carries the raw event of one
// invocation of the integration function, for the adapter's functions.
func Invocation(ctx context.Context, raw []byte) *http.Request {
	r := (&http.Request{Method: http.MethodGet, URL: &url.URL{}, Header: http.Header{}, Body: http.NoBody}).WithContext(ctx)
	return WithEvent(r, raw)
}

// rawEvent returns the raw event r carries.
func rawEvent(r *http.Request) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	raw, ok := r.Context().Value(eventKey{}).([]byte)
	return raw, ok
}

// DecodeEvent decodes an event strictly (draft 7.1 rules of package
// strictjson), with maxBytes as the size limit.
func DecodeEvent(raw []byte, maxBytes int) (Event, error) {
	var ev Event
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: maxBytes}, &ev); err != nil {
		return Event{}, fmt.Errorf("aws: the event does not decode: %w", adapter.ErrInvalidMessage)
	}
	return ev, nil
}

// FromEvent builds the request that package binding maps from an event: the
// method of requestContext.http.method; the request-target rawPath, followed
// by "?" and rawQueryString when that is not empty, in origin-form and octet
// for octet (AR-14); the URL of the configured origin, never of
// requestContext.domainName; the event's headers with their names as the
// event writes them; and the body octets of AR-19. A malformed body or header
// is [adapter.ErrInvalidMessage].
func FromEvent(ev Event, origin string) (*http.Request, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("aws: origin %q is not a URL", origin)
	}
	if !strings.HasPrefix(ev.RawPath, "/") {
		return nil, fmt.Errorf("aws: rawPath does not begin with /: %w", adapter.ErrInvalidMessage)
	}
	target := ev.RawPath
	if ev.RawQueryString != nil && *ev.RawQueryString != "" {
		target += "?" + *ev.RawQueryString
	}
	body, err := bodyOctets(ev)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for name, value := range ev.Headers {
		if name != strings.ToLower(name) || name == "" {
			return nil, fmt.Errorf("aws: a header name is not lowercase: %w", adapter.ErrInvalidMessage)
		}
		h[name] = []string{value}
	}
	r := &http.Request{
		Method:        ev.RequestContext.HTTP.Method,
		URL:           &url.URL{Scheme: u.Scheme, Host: u.Host},
		RequestURI:    target,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Host:          u.Host,
		ContentLength: int64(len(body)),
		Body:          http.NoBody,
	}
	if len(body) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return r, nil
}

// bodyOctets returns the body of an event (AR-19): the base64 decoding of
// body when isBase64Encoded is true, padded and with no other character, and
// otherwise the UTF-8 octets of the body string.
func bodyOctets(ev Event) ([]byte, error) {
	if ev.Body == nil {
		return nil, nil
	}
	if !ev.IsBase64Encoded {
		return []byte(*ev.Body), nil
	}
	s := *ev.Body
	if len(s)%4 != 0 {
		return nil, fmt.Errorf("aws: the base64 body is not padded: %w", adapter.ErrInvalidMessage)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' ||
			c == '=' && i >= len(s)-2
		if !ok {
			return nil, fmt.Errorf("aws: the base64 body has a character outside the alphabet: %w", adapter.ErrInvalidMessage)
		}
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("aws: the base64 body does not decode: %w", adapter.ErrInvalidMessage)
	}
	return b, nil
}

// iamContext returns the IAM context of an event, or the native denial of
// AR-5 and AR-6: NO_CREDENTIAL without one, CREDENTIAL_REJECTED for an
// authorizer member besides iam or an IAM context that does not decode.
func iamContext(ev Event) (IAMContext, error) {
	for name := range ev.RequestContext.Authorizer {
		if name != "iam" {
			return IAMContext{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
		}
	}
	raw, ok := ev.RequestContext.Authorizer["iam"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return IAMContext{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	var c IAMContext
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &c); err != nil {
		return IAMContext{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	return c, nil
}

// cognitoAbsent reports whether a cognitoIdentity member is absent or null.
func cognitoAbsent(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}
