package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"hop.top/pact-go/core/strictjson"
)

// PollConfig configures a [Poller].
type PollConfig struct {
	// URL is the transmitter's poll endpoint: an https URL (RFC 8936
	// section 2.1; SSF 1.0 section 6.1.2).
	URL string
	// Authorization is sent as the Authorization header of every request.
	Authorization string
	// Client is the HTTP client; nil is a client with a two minute timeout,
	// which covers a long poll.
	Client *http.Client
	// Receiver verifies and applies each SET.
	Receiver *Receiver
	// MaxEvents is maxEvents of the request; zero omits it.
	MaxEvents int
	// ReturnImmediately is returnImmediately; false is a long poll.
	ReturnImmediately bool
}

// PollResult counts what one poll returned.
type PollResult struct {
	// Received is the number of SETs the response held.
	Received int
	// Acknowledged is the number of SETs that will be acknowledged in the
	// next request: applied, replayed or deliberately ignored.
	Acknowledged int
	// Rejected is the number of SETs that will be reported in setErrs.
	Rejected int
	// MoreAvailable is moreAvailable of the response.
	MoreAvailable bool
}

// Poller receives SETs by polling (RFC 8936). Each request acknowledges the
// SETs the previous response delivered and reports the invalid ones in
// setErrs (section 2.4). A Poller is not safe for concurrent use.
type Poller struct {
	c       PollConfig
	acks    []string
	setErrs map[string]map[string]string
}

// maxPollBody bounds a poll response.
const maxPollBody = 4 << 20

// NewPoller returns a Poller for c.
func NewPoller(c PollConfig) (*Poller, error) {
	if err := httpsURL(c.URL); err != nil {
		return nil, fmt.Errorf("ssf: poll URL: %w", err)
	}
	if c.Receiver == nil {
		return nil, errors.New("ssf: no receiver")
	}
	if c.MaxEvents < 0 {
		return nil, errors.New("ssf: negative MaxEvents")
	}
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	return &Poller{c: c}, nil
}

// Poll makes one request and handles the SETs it returns. When a SET could
// not be handled because a dependency failed, Poll returns the first such
// error after handling the others; that SET is neither acknowledged nor
// reported, so the transmitter delivers it again. A failed request keeps the
// acknowledgments for the next one.
func (p *Poller) Poll(ctx context.Context) (PollResult, error) {
	reqBody := map[string]any{"returnImmediately": p.c.ReturnImmediately}
	if p.c.MaxEvents > 0 {
		reqBody["maxEvents"] = p.c.MaxEvents
	}
	if len(p.acks) > 0 {
		reqBody["ack"] = p.acks
	}
	if len(p.setErrs) > 0 {
		reqBody["setErrs"] = p.setErrs
	}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return PollResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.c.URL, bytes.NewReader(b))
	if err != nil {
		return PollResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if p.c.Authorization != "" {
		req.Header.Set("Authorization", p.c.Authorization)
	}
	resp, err := p.c.Client.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("ssf: poll: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPollBody+1))
	if err != nil || len(body) > maxPollBody {
		return PollResult{}, errors.New("ssf: poll: the response is unreadable or too large")
	}
	if resp.StatusCode != http.StatusOK {
		return PollResult{}, fmt.Errorf("ssf: poll: the endpoint answered %d", resp.StatusCode)
	}
	sets, more, err := parsePollResponse(body)
	if err != nil {
		return PollResult{}, err
	}
	// The response is in hand: what the request carried was delivered.
	p.acks, p.setErrs = nil, nil

	res := PollResult{Received: len(sets), MoreAvailable: more}
	jtis := make([]string, 0, len(sets))
	for jti := range sets {
		jtis = append(jtis, jti)
	}
	sort.Strings(jtis)
	var first error
	for _, jti := range jtis {
		out, err := p.c.Receiver.Accept(ctx, sets[jti])
		var e *Error
		switch {
		case err == nil && out.JTI != jti:
			// The key of sets is the jti of the SET (RFC 8936 section 2.3).
			p.reportErr(jti, reject(CodeInvalidRequest, "the SET's jti is not the key it was delivered under"))
			res.Rejected++
		case err == nil:
			p.acks = append(p.acks, jti)
			res.Acknowledged++
		case errors.As(err, &e):
			p.reportErr(jti, e)
			res.Rejected++
		default:
			if first == nil {
				first = err
			}
		}
	}
	return res, first
}

func (p *Poller) reportErr(jti string, e *Error) {
	if p.setErrs == nil {
		p.setErrs = map[string]map[string]string{}
	}
	p.setErrs[jti] = map[string]string{"err": e.Code, "description": e.Description}
}

// parsePollResponse reads the response body of RFC 8936 section 2.3: sets,
// an object of compact SETs by jti, and the optional moreAvailable.
func parsePollResponse(body []byte) (map[string]string, bool, error) {
	var top map[string]json.RawMessage
	if err := strictjson.Unmarshal(body, strictjson.Limits{}, &top); err != nil {
		return nil, false, fmt.Errorf("ssf: poll: the response is not a strict JSON object: %w", err)
	}
	rawSets, ok := top["sets"]
	if !ok {
		return nil, false, errors.New("ssf: poll: the response has no sets")
	}
	var sets map[string]string
	if err := json.Unmarshal(rawSets, &sets); err != nil || sets == nil {
		return nil, false, errors.New("ssf: poll: sets is not an object of strings")
	}
	var more bool
	if raw, ok := top["moreAvailable"]; ok && json.Unmarshal(raw, &more) != nil {
		return nil, false, errors.New("ssf: poll: moreAvailable is not a boolean")
	}
	return sets, more, nil
}
