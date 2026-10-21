package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
)

// Delivery methods (SSF 1.0 section 6.1).
const (
	DeliveryPush = "urn:ietf:rfc:8935"
	DeliveryPoll = "urn:ietf:rfc:8936"
)

// Stream statuses (SSF 1.0 section 8.1.2.1).
const (
	StatusEnabled  = "enabled"
	StatusPaused   = "paused"
	StatusDisabled = "disabled"
)

// Delivery is the delivery member of a stream configuration.
type Delivery struct {
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

// StreamRequest is what a receiver asks for when it creates a stream (SSF
// 1.0 section 8.1.1.1).
type StreamRequest struct {
	Delivery        Delivery
	EventsRequested []string
	Description     string
}

// Stream is a stream configuration as the transmitter reports it (SSF 1.0
// section 8.1.1). Audience is always a list, whichever form the transmitter
// wrote.
type Stream struct {
	StreamID                string
	Issuer                  string
	Audience                []string
	Delivery                Delivery
	EventsSupported         []string
	EventsRequested         []string
	EventsDelivered         []string
	MinVerificationInterval int
}

// TransmitterConfig configures a [Transmitter].
type TransmitterConfig struct {
	// Issuer is the transmitter's issuer; every stream it reports must carry it.
	Issuer string
	// ConfigurationEndpoint, StatusEndpoint and VerificationEndpoint are the
	// https endpoints of the transmitter metadata (SSF 1.0 section 7.1).
	ConfigurationEndpoint string
	StatusEndpoint        string
	VerificationEndpoint  string
	// Authorization is sent as the Authorization header of every request
	// (SSF 1.0 section 8: the management API uses standard HTTP schemes).
	Authorization string
	// Client is the HTTP client; nil is http.DefaultClient.
	Client *http.Client
}

// Transmitter is the receiver's client of a transmitter's stream management
// API (SSF 1.0 section 8.1).
type Transmitter struct{ c TransmitterConfig }

// NewTransmitter returns a Transmitter for c. Every endpoint it is given
// must be https.
func NewTransmitter(c TransmitterConfig) (*Transmitter, error) {
	if httpsURL(c.Issuer) != nil {
		return nil, fmt.Errorf("ssf: issuer %q is not an https URL", c.Issuer)
	}
	for name, u := range map[string]string{"configuration": c.ConfigurationEndpoint, "status": c.StatusEndpoint, "verification": c.VerificationEndpoint} {
		if u == "" {
			continue
		}
		if err := httpsURL(u); err != nil {
			return nil, fmt.Errorf("ssf: %s endpoint: %w", name, err)
		}
	}
	if c.Client == nil {
		c.Client = http.DefaultClient
	}
	return &Transmitter{c: c}, nil
}

const maxMgmtBody = 1 << 20

// do sends one request and returns the status and body.
func (t *Transmitter) do(ctx context.Context, method, endpoint string, query url.Values, body any) (int, []byte, error) {
	if endpoint == "" {
		return 0, nil, errors.New("ssf: the transmitter has no such endpoint configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return 0, nil, err
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t.c.Authorization != "" {
		req.Header.Set("Authorization", t.c.Authorization)
	}
	resp, err := t.c.Client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ssf: %s %s: %w", method, u.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMgmtBody+1))
	if err != nil || len(b) > maxMgmtBody {
		return 0, nil, errors.New("ssf: the response is unreadable or too large")
	}
	return resp.StatusCode, b, nil
}

type wireStream struct {
	StreamID                string          `json:"stream_id"`
	Iss                     string          `json:"iss"`
	Aud                     json.RawMessage `json:"aud"`
	Delivery                Delivery        `json:"delivery"`
	EventsSupported         []string        `json:"events_supported"`
	EventsRequested         []string        `json:"events_requested"`
	EventsDelivered         []string        `json:"events_delivered"`
	MinVerificationInterval int             `json:"min_verification_interval"`
}

// parseStream reads a stream configuration and checks its issuer.
func (t *Transmitter) parseStream(b []byte) (Stream, error) {
	var w wireStream
	if err := json.Unmarshal(b, &w); err != nil {
		return Stream{}, fmt.Errorf("ssf: the stream configuration is not JSON: %w", err)
	}
	if w.StreamID == "" {
		return Stream{}, errors.New("ssf: the stream configuration has no stream_id")
	}
	if w.Iss != t.c.Issuer {
		// SSF 1.0 section 8.1.1: the receiver confirms that iss is the issuer.
		return Stream{}, fmt.Errorf("ssf: the stream names issuer %q, not the transmitter's", w.Iss)
	}
	var aud []string
	if json.Unmarshal(w.Aud, &aud) != nil {
		var one string
		if err := json.Unmarshal(w.Aud, &one); err != nil {
			return Stream{}, errors.New("ssf: aud is not a string or an array of strings")
		}
		aud = []string{one}
	}
	return Stream{
		StreamID: w.StreamID, Issuer: w.Iss, Audience: aud, Delivery: w.Delivery,
		EventsSupported: w.EventsSupported, EventsRequested: w.EventsRequested, EventsDelivered: w.EventsDelivered,
		MinVerificationInterval: w.MinVerificationInterval,
	}, nil
}

func statusErr(op string, code int) error {
	return fmt.Errorf("ssf: %s: the transmitter answered %d", op, code)
}

// CreateStream creates the receiver's stream (SSF 1.0 section 8.1.1.1) and
// returns the configuration the transmitter assigned.
func (t *Transmitter) CreateStream(ctx context.Context, r StreamRequest) (Stream, error) {
	body := map[string]any{"delivery": r.Delivery}
	if len(r.EventsRequested) > 0 {
		body["events_requested"] = r.EventsRequested
	}
	if r.Description != "" {
		body["description"] = r.Description
	}
	code, b, err := t.do(ctx, http.MethodPost, t.c.ConfigurationEndpoint, nil, body)
	if err != nil {
		return Stream{}, err
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return Stream{}, statusErr("create stream", code)
	}
	return t.parseStream(b)
}

// Stream reads the configuration of one stream (SSF 1.0 section 8.1.1.2).
func (t *Transmitter) Stream(ctx context.Context, streamID string) (Stream, error) {
	code, b, err := t.do(ctx, http.MethodGet, t.c.ConfigurationEndpoint, url.Values{"stream_id": {streamID}}, nil)
	if err != nil {
		return Stream{}, err
	}
	if code != http.StatusOK {
		return Stream{}, statusErr("read stream", code)
	}
	return t.parseStream(b)
}

func parseStatus(b []byte) (string, error) {
	var s struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &s); err != nil || !slices.Contains([]string{StatusEnabled, StatusPaused, StatusDisabled}, s.Status) {
		return "", errors.New("ssf: the status response has no status of enabled, paused or disabled")
	}
	return s.Status, nil
}

// Status reads a stream's status (SSF 1.0 section 8.1.2.1).
func (t *Transmitter) Status(ctx context.Context, streamID string) (string, error) {
	code, b, err := t.do(ctx, http.MethodGet, t.c.StatusEndpoint, url.Values{"stream_id": {streamID}}, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", statusErr("read status", code)
	}
	return parseStatus(b)
}

// SetStatus asks for a stream status (SSF 1.0 section 8.1.2.2) and returns
// the status the transmitter reports.
func (t *Transmitter) SetStatus(ctx context.Context, streamID, status string) (string, error) {
	code, b, err := t.do(ctx, http.MethodPost, t.c.StatusEndpoint, nil, map[string]string{"stream_id": streamID, "status": status})
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", statusErr("set status", code)
	}
	return parseStatus(b)
}

// RequestVerification asks the transmitter to send a verification event with
// the given state (SSF 1.0 section 8.1.4.2). The 204 answer only says the
// event was or will be sent; [Receiver.Verified] says it arrived.
func (t *Transmitter) RequestVerification(ctx context.Context, streamID, state string) error {
	body := map[string]string{"stream_id": streamID}
	if state != "" {
		body["state"] = state
	}
	code, _, err := t.do(ctx, http.MethodPost, t.c.VerificationEndpoint, nil, body)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent {
		return statusErr("verification", code)
	}
	return nil
}
