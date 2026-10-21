package ssf_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/source/ssf"
)

func post(h http.Handler, ct, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ssf/push", strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func errBody(t testing.TB, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q, want application/json (RFC 8935 section 2.3)", ct)
	}
	var b struct {
		Err         string `json:"err"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return b.Err, b.Description
}

const secevent = "application/secevent+jwt"

// RFC 8935 section 2.1 to 2.3.
func TestPushHandler(t *testing.T) {
	good := func(t testing.TB, jti string) string {
		return signed(t, claims(jti, nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil))
	}
	t.Run("accepted is 202", func(t *testing.T) {
		r := newRig(t)
		rec := post(r.rx.PushHandler(), secevent, "", good(t, "j-1"))
		if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
			t.Fatalf("%d %q", rec.Code, rec.Body.String())
		}
		r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
	})
	t.Run("a duplicate is answered as the first was", func(t *testing.T) {
		r := newRig(t)
		h := r.rx.PushHandler()
		a, b := post(h, secevent, "", good(t, "j-1")), post(h, secevent, "", good(t, "j-1"))
		if a.Code != http.StatusAccepted || b.Code != http.StatusAccepted {
			t.Fatalf("%d then %d", a.Code, b.Code)
		}
	})
	t.Run("media type parameters are tolerated", func(t *testing.T) {
		r := newRig(t)
		if rec := post(r.rx.PushHandler(), secevent+"; charset=utf-8", "", good(t, "j-1")); rec.Code != http.StatusAccepted {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	for name, c := range map[string]struct {
		ct, body, err string
	}{
		"wrong content type": {"application/jwt", good(t, "j-1"), ssf.CodeInvalidRequest},
		"no content type":    {"", good(t, "j-1"), ssf.CodeInvalidRequest},
		"json body":          {secevent, `{"jti":"x"}`, ssf.CodeInvalidRequest},
		"empty body":         {secevent, "", ssf.CodeInvalidRequest},
		"forged":             {secevent, compact(t, key(t, 3), setHeader(), claims("j-1", nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil)), ssf.CodeInvalidKey},
		"oversize":           {secevent, strings.Repeat("a", 70000), ssf.CodeInvalidRequest},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			rec := post(r.rx.PushHandler(), c.ct, "", c.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", rec.Code)
			}
			if e, d := errBody(t, rec); e != c.err || d == "" {
				t.Fatalf("err %q description %q", e, d)
			}
			r.wantNoFact(t, principal("7a1f"))
		})
	}
	t.Run("only POST", func(t *testing.T) {
		r := newRig(t)
		rec := httptest.NewRecorder()
		r.rx.PushHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ssf/push", nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Fatalf("%d %q", rec.Code, rec.Header().Get("Allow"))
		}
	})
	t.Run("transmitter authentication", func(t *testing.T) {
		r := newRig(t, func(c *ssf.Config) { c.Authorization = "Bearer s3cret" })
		h := r.rx.PushHandler()
		for _, a := range []string{"", "Bearer wrong", "bearer s3cret", "Bearer s3cret "} {
			rec := post(h, secevent, a, good(t, "j-1"))
			if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatalf("authorization %q: %d", a, rec.Code)
			}
			if e, _ := errBody(t, rec); e != ssf.CodeAuthenticationFailed {
				t.Fatalf("err %q", e)
			}
		}
		r.wantNoFact(t, principal("7a1f"))
		if rec := post(h, secevent, "Bearer s3cret", good(t, "j-1")); rec.Code != http.StatusAccepted {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("a store that cannot answer is a retryable failure", func(t *testing.T) {
		r := newRig(t, func(c *ssf.Config) { c.HoldOn = []string{ssf.EventAccountDisabled} })
		r.holds.err = errors.New("down")
		rec := post(r.rx.PushHandler(), secevent, "", good(t, "j-1"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%d, want 503", rec.Code)
		}
	})
}
