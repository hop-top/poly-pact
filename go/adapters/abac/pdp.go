package abac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/strictjson"
)

// defaultTimeout bounds a PDP query when the configuration states none. It is
// well inside the 30 second evaluation deadline of draft 12.2.
const defaultTimeout = 5 * time.Second

// maxAnswer is the largest PDP answer the adapter reads.
const maxAnswer = 1 << 20

// PDP is the policy decision point: an OPA server reached through its REST
// Data API over TLS (profile ABAC-13, ABAC-19).
type PDP struct {
	// SourceID is the configured identifier of the PDP, which every decision
	// names (profile section 17). Required.
	SourceID string
	// URL is the HTTPS origin of the PDP, such as https://pdp.example:8181.
	// Required; any other scheme is refused, because TLS is mandatory on a
	// network path (draft 19, 13.3.1).
	URL string
	// DecisionPath is the slash-separated path of the decision document, such
	// as pact/abac/decision. Required.
	DecisionPath string
	// Client sends the queries; it verifies the PDP's certificate. Nil uses a
	// client with the system roots. The adapter never follows a redirect.
	Client *http.Client
	// Token, when set, is the bearer token that authenticates the adapter to
	// the PDP. It never appears in an error or a decision.
	Token string
	// Timeout bounds one query. Zero means five seconds.
	Timeout time.Duration
}

var pathSegment = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// pdpClient is the validated PDP configuration.
type pdpClient struct {
	cfg      PDP
	endpoint string
	client   *http.Client
	timeout  time.Duration
}

func newPDPClient(cfg PDP) (*pdpClient, error) {
	if cfg.SourceID == "" {
		return nil, errors.New("the PDP has no source id")
	}
	u, err := url.Parse(cfg.URL)
	switch {
	case err != nil:
		return nil, fmt.Errorf("the PDP URL: %w", err)
	case u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return nil, errors.New("the PDP URL is not an https origin")
	}
	segs := strings.Split(cfg.DecisionPath, "/")
	for _, s := range segs {
		if !pathSegment.MatchString(s) {
			return nil, fmt.Errorf("the decision path %q is not slash-separated names", cfg.DecisionPath)
		}
	}
	c := &http.Client{}
	if cfg.Client != nil {
		cp := *cfg.Client
		c = &cp
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t := cfg.Timeout
	if t <= 0 {
		t = defaultTimeout
	}
	return &pdpClient{
		cfg:      cfg,
		endpoint: "https://" + u.Host + "/v1/data/" + cfg.DecisionPath + "?strict-builtin-errors=true",
		client:   c,
		timeout:  t,
	}, nil
}

// answerStatus classifies a PDP answer by the rows of profile ABAC-14.
type answerStatus int

const (
	answerOK           answerStatus = iota // rows 8 to 10: a valid document
	answerTransport                        // row 1: no answer or a status other than 200
	answerMalformed                        // row 2: not one JSON object under strict parsing
	answerUndefined                        // row 3: no result
	answerUnattributed                     // row 4: no non-empty string decision_id
	answerNotObject                        // row 5: result is not an object
	answerNoVersion                        // row 6: policy_version absent, not a string, or empty
	answerBadDocument                      // row 7: result fails the decision document
)

// answer is a classified PDP answer.
type answer struct {
	status      answerStatus
	err         error
	decisionID  string
	version     string
	allow       bool
	obligations []adapter.Obligation
}

// query sends the request of ABAC-13 with the input and classifies the answer.
func (c *pdpClient) query(ctx context.Context, in map[string]any) answer {
	body, err := json.Marshal(map[string]any{"input": in})
	if err != nil {
		return answer{status: answerMalformed, err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return answer{status: answerTransport, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return answer{status: answerTransport, err: errors.New("the PDP did not answer")}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
		return answer{status: answerTransport, err: fmt.Errorf("the PDP answered status %d", resp.StatusCode)}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return answer{status: answerTransport, err: errors.New("the PDP answer was cut off")}
	}
	if len(raw) > maxAnswer {
		return answer{status: answerMalformed, err: errors.New("the PDP answer is too large")}
	}
	return classify(raw)
}

// classify applies rows 2 to 10 of ABAC-14 to a 200 answer body, in order.
func classify(raw []byte) answer {
	var top map[string]json.RawMessage
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: maxAnswer}, &top); err != nil {
		return answer{status: answerMalformed, err: fmt.Errorf("the PDP answer is not one JSON object: %w", err)}
	}
	if top == nil {
		return answer{status: answerMalformed, err: errors.New("the PDP answer is null")}
	}
	id, idOK := jsonString(top["decision_id"])
	res, hasResult := top["result"]
	if !hasResult {
		a := answer{status: answerUndefined, err: errors.New("the document is undefined")}
		if idOK && id != "" {
			a.decisionID = id
		}
		return a
	}
	if !idOK || id == "" {
		return answer{status: answerUnattributed, err: errors.New("the answer has no decision_id")}
	}
	a := answer{decisionID: id}
	if !isObject(res) {
		a.status, a.err = answerNotObject, errors.New("result is not an object")
		return a
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(res, &doc); err != nil {
		a.status, a.err = answerNotObject, err
		return a
	}
	v, vOK := jsonString(doc["policy_version"])
	if !vOK || v == "" {
		a.status, a.err = answerNoVersion, errors.New("the decision has no policy_version")
		return a
	}
	a.version = v
	if err := a.readDocument(doc); err != nil {
		a.status, a.err, a.obligations = answerBadDocument, err, nil
		return a
	}
	return a
}

// readDocument reads the decision document of profile ABAC-15: exactly
// allow, obligations and policy_version, each obligation exactly a non-empty
// type and an object params, no type twice.
func (a *answer) readDocument(doc map[string]json.RawMessage) error {
	if len(doc) != 3 {
		return errors.New("the decision does not have exactly allow, obligations and policy_version")
	}
	switch string(bytes.TrimSpace(doc["allow"])) {
	case "true":
		a.allow = true
	case "false":
		a.allow = false
	default:
		return errors.New("allow is not a boolean")
	}
	obl, ok := doc["obligations"]
	if !ok || !isArray(obl) {
		return errors.New("obligations is not an array")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(obl, &items); err != nil {
		return err
	}
	a.obligations = []adapter.Obligation{}
	seen := map[string]bool{}
	for _, item := range items {
		var o map[string]json.RawMessage
		if !isObject(item) || json.Unmarshal(item, &o) != nil || len(o) != 2 {
			return errors.New("an obligation is not exactly type and params")
		}
		typ, ok := jsonString(o["type"])
		if !ok || typ == "" {
			return errors.New("an obligation type is not a non-empty string")
		}
		if seen[typ] {
			return errors.New("an obligation type appears twice")
		}
		seen[typ] = true
		params, ok := o["params"]
		if !ok || !isObject(params) {
			return errors.New("an obligation's params is not an object")
		}
		attrs := map[string]any{}
		d := json.NewDecoder(bytes.NewReader(params))
		d.UseNumber()
		if err := d.Decode(&attrs); err != nil {
			return err
		}
		a.obligations = append(a.obligations, adapter.Obligation{ID: typ, Attributes: attrs})
	}
	return nil
}

// jsonString decodes raw when it is a JSON string.
func jsonString(raw json.RawMessage) (string, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(t, &s) != nil {
		return "", false
	}
	return s, true
}

func isObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{'
}

func isArray(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '['
}
