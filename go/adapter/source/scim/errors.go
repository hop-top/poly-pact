package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"hop.top/pact-go/core/strictjson"
)

// scimErr is an error response (RFC 7644 section 3.12).
type scimErr struct {
	status   int
	scimType string
	detail   string
}

func (e *scimErr) Error() string { return fmt.Sprintf("%d %s: %s", e.status, e.scimType, e.detail) }

func newErr(status int, scimType, detail string) *scimErr {
	return &scimErr{status: status, scimType: scimType, detail: detail}
}

func errNotFound(detail string) *scimErr { return newErr(http.StatusNotFound, "", detail) }

func errInternal(err error) *scimErr {
	return newErr(http.StatusInternalServerError, "", "the service could not update its state: "+err.Error())
}

func invalidValue(format string, args ...any) *scimErr {
	return newErr(http.StatusBadRequest, "invalidValue", fmt.Sprintf(format, args...))
}

func uniqueness(format string, args ...any) *scimErr {
	return newErr(http.StatusConflict, "uniqueness", fmt.Sprintf(format, args...))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"schemas":["`+errorURN+`"],"status":"500"}`)
	}
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeError writes err as a SCIM error; an error that is not a scimErr is a
// 500 with no detail.
func writeError(w http.ResponseWriter, err error) {
	var e *scimErr
	if !errors.As(err, &e) {
		e = newErr(http.StatusInternalServerError, "", "")
	}
	body := map[string]any{"schemas": []string{errorURN}, "status": fmt.Sprint(e.status)}
	if e.scimType != "" {
		body["scimType"] = e.scimType
	}
	if e.detail != "" {
		body["detail"] = e.detail
	}
	writeJSON(w, e.status, body)
}

// decodeJSON decodes b as one JSON value, rejecting duplicate member names,
// invalid UTF-8 and integers beyond 2^53-1 (package strictjson).
func decodeJSON(b []byte) (any, error) {
	var v any
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxBytes: maxBody}, &v); err != nil {
		return nil, newErr(http.StatusBadRequest, "invalidSyntax", "the request body is not acceptable JSON: "+err.Error())
	}
	return v, nil
}

// contextBackground is the context of a store call: a provisioning request
// does not carry a deadline into the store.
var contextBackground = context.Background()
