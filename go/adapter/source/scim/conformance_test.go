package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/scim"
	"hop.top/pact-go/adapter/sourcetest"
	"hop.top/pact-go/core/clock"
)

// This file is the Go driver of the model scim/1 of the source cases under
// spec/v1.0/fixtures/sources/scim, defined by spec/v1.0/profiles/sources/scim.md. The
// source member is {model, source_id, lag_seconds, base_path, join:
// {attribute, prefix}, credentials: [{token, provisioning}]}. An inbound
// message is an HTTP request {method, path, query, authorization, body}; a
// step's expect is {status, scim_type, challenge: {scheme, error}, save_id_as,
// body}. A string ${name} in a later inbound message or expectation is the
// id the service issued to the resource saved as name.

type srcCfg struct {
	Model      string `json:"model"`
	SourceID   string `json:"source_id"`
	LagSeconds int64  `json:"lag_seconds"`
	BasePath   string `json:"base_path"`
	Join       struct {
		Attribute string `json:"attribute"`
		Prefix    string `json:"prefix"`
	} `json:"join"`
	Credentials []struct {
		Token        string `json:"token"`
		Provisioning bool   `json:"provisioning"`
	} `json:"credentials"`
}

type inbound struct {
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         map[string]string `json:"query"`
	Authorization string            `json:"authorization"`
	Body          json.RawMessage   `json:"body"`
}

type challengeWant struct {
	Scheme string `json:"scheme"`
	Error  string `json:"error"`
}

type stepWant struct {
	Status    int             `json:"status"`
	ScimType  string          `json:"scim_type"`
	Challenge *challengeWant  `json:"challenge"`
	SaveIDAs  string          `json:"save_id_as"`
	Body      json.RawMessage `json:"body"`
}

// strict decodes b into v and rejects members v does not have.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// config builds the Config of a case's source member.
func (s srcCfg) config(clk clock.Clock, logw io.Writer) scim.Config {
	cfg := scim.Config{
		SourceID: s.SourceID,
		BasePath: s.BasePath,
		Join:     source.Join{Attribute: s.Join.Attribute, Prefix: s.Join.Prefix},
		Lag:      time.Duration(s.LagSeconds) * time.Second,
		Clock:    clk,
	}
	if logw != nil {
		cfg.ErrorLog = log.New(logw, "", 0)
	}
	for _, c := range s.Credentials {
		cfg.Credentials = append(cfg.Credentials, scim.Credential{Token: c.Token, Provisioning: c.Provisioning})
	}
	return cfg
}

func driver() sourcetest.Driver {
	return sourcetest.Driver{Model: "scim/1", Open: open}
}

func open(t testing.TB, env sourcetest.Env) (sourcetest.Subject, error) {
	var cfg srcCfg
	if err := strict(env.Source, &cfg); err != nil {
		return sourcetest.Subject{}, err
	}
	srv, err := scim.New(cfg.config(env.Clock, nil))
	if err != nil {
		return sourcetest.Subject{}, err
	}
	saved := map[string]string{}
	sub := func(s string) string {
		for k, v := range saved {
			s = strings.ReplaceAll(s, "${"+k+"}", v)
		}
		return s
	}
	apply := func(_ context.Context, in, expect json.RawMessage) error {
		var m inbound
		if err := strict(in, &m); err != nil {
			return fmt.Errorf("inbound: %w", err)
		}
		var want stepWant
		if len(expect) > 0 {
			if err := strict([]byte(sub(string(expect))), &want); err != nil {
				return fmt.Errorf("expect: %w", err)
			}
		}
		q := url.Values{}
		for k, v := range m.Query {
			q.Set(k, sub(v))
		}
		target := sub(m.Path)
		if len(q) > 0 {
			target += "?" + q.Encode()
		}
		req := httptest.NewRequest(m.Method, target, strings.NewReader(sub(string(m.Body))))
		req.Header.Set("Content-Type", "application/scim+json")
		if m.Authorization != "" {
			req.Header.Set("Authorization", m.Authorization)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		res := rec.Result()
		defer func() { _ = res.Body.Close() }()
		body, _ := io.ReadAll(res.Body)
		if want.Status != 0 && res.StatusCode != want.Status {
			return fmt.Errorf("%s %s: status %d, want %d: %s", m.Method, target, res.StatusCode, want.Status, body)
		}
		var got map[string]any
		_ = json.Unmarshal(body, &got)
		if want.ScimType != "" && got["scimType"] != want.ScimType {
			return fmt.Errorf("scimType %v, want %s: %s", got["scimType"], want.ScimType, body)
		}
		if c := want.Challenge; c != nil {
			if err := checkChallenge(res.Header.Get("WWW-Authenticate"), c); err != nil {
				return err
			}
		}
		if len(want.Body) > 0 {
			var w any
			if err := json.Unmarshal(want.Body, &w); err != nil {
				return err
			}
			var g any
			if err := json.Unmarshal(body, &g); err != nil {
				return fmt.Errorf("the body is not JSON: %s", body)
			}
			if err := subset(w, g, "body"); err != nil {
				return fmt.Errorf("%w: %s", err, body)
			}
		}
		if want.SaveIDAs != "" {
			id, _ := got["id"].(string)
			if id == "" {
				return fmt.Errorf("no id to save as %s: %s", want.SaveIDAs, body)
			}
			saved[want.SaveIDAs] = id
		}
		return nil
	}
	return sourcetest.Subject{Reader: srv.Reader(), Apply: apply}, nil
}

// checkChallenge checks a WWW-Authenticate value: the scheme, and the error
// auth-param, which is absent when want.Error is empty.
func checkChallenge(h string, want *challengeWant) error {
	if h == "" {
		return fmt.Errorf("no WWW-Authenticate header")
	}
	if !strings.HasPrefix(h, want.Scheme+" ") {
		return fmt.Errorf("WWW-Authenticate %q does not start with the scheme %s", h, want.Scheme)
	}
	has := strings.Contains(h, `error="`)
	switch {
	case want.Error == "" && has:
		return fmt.Errorf("WWW-Authenticate %q carries an error, want none", h)
	case want.Error != "" && !strings.Contains(h, `error="`+want.Error+`"`):
		return fmt.Errorf("WWW-Authenticate %q does not carry error %q", h, want.Error)
	}
	return nil
}

// subset checks that got contains want: every member of a want object is in
// the got object with a contained value, arrays have the same length and
// contain element by element, and anything else is equal.
func subset(want, got any, where string) error {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not an object", where)
		}
		for k, wv := range w {
			gv, ok := g[k]
			if !ok {
				return fmt.Errorf("%s.%s is absent", where, k)
			}
			if err := subset(wv, gv, where+"."+k); err != nil {
				return err
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s is %v, want %d elements", where, got, len(w))
		}
		for i := range w {
			if err := subset(w[i], g[i], fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
	default:
		if fmt.Sprint(want) != fmt.Sprint(got) {
			return fmt.Errorf("%s is %v, want %v", where, got, want)
		}
	}
	return nil
}

// TestConformance runs every case of sources/scim against the service.
func TestConformance(t *testing.T) {
	sourcetest.Run(t, driver(), sourcetest.Options{Source: "scim"})
}
