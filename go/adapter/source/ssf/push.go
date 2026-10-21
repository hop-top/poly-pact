package ssf

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// PushHandler returns the push endpoint of RFC 8935: the transmitter POSTs
// one SET per request with the content type application/secevent+jwt. The
// handler answers 202 with no body when it accepted the SET, including a SET
// it had applied before, and 400 with the JSON body {err, description} of
// RFC 8935 section 2.3 when it rejected it. A request without the configured
// Authorization header is answered 401 with err authentication_failed (RFC
// 8935 section 3 puts authentication under HTTP's schemes, RFC 7235). A
// failure of a dependency is 503, after which the transmitter retransmits.
//
// The handler must be served over TLS; the caller's server does that.
func (r *Receiver) PushHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if want := r.c.Authorization; want != "" &&
			subtle.ConstantTimeCompare([]byte(req.Header.Get("Authorization")), []byte(want)) != 1 {
			r.observe(Record{Kind: KindRejected, Reason: CodeAuthenticationFailed})
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, &Error{Code: CodeAuthenticationFailed, Description: "the transmitter did not authenticate"})
			return
		}
		if mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mt != "application/secevent+jwt" {
			e := reject(CodeInvalidRequest, "the content type must be application/secevent+jwt")
			r.observe(Record{Kind: KindRejected, Reason: e.Code})
			writeErr(w, http.StatusBadRequest, e)
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, int64(r.c.MaxBytes)+1))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		_, err = r.Accept(req.Context(), string(body))
		var e *Error
		switch {
		case err == nil:
			w.WriteHeader(http.StatusAccepted)
		case errors.As(err, &e):
			writeErr(w, http.StatusBadRequest, e)
		default:
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		}
	})
}

func writeErr(w http.ResponseWriter, status int, e *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"err": e.Code, "description": e.Description})
}
