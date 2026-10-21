package binding

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"hop.top/pact-go/internal/ascii"
)

// checkCodings refuses a request with any Content-Encoding field, since the
// baseline forbids HTTP content encodings on protected requests (draft 10.2),
// and one with a transfer coding other than chunked, which net/http is the
// only one to decode, so the body would not be known to be transfer-decoded.
func checkCodings(r *http.Request) error {
	for k := range r.Header {
		if ascii.EqualFold(k, "content-encoding") {
			return refuse(RuleContentEncoding, "the request has a Content-Encoding field")
		}
	}
	codings := append([]string{}, r.TransferEncoding...)
	for k, vs := range r.Header {
		if ascii.EqualFold(k, "transfer-encoding") {
			for _, v := range vs {
				codings = append(codings, strings.Split(v, ",")...)
			}
		}
	}
	for _, c := range codings {
		if c = strings.Trim(c, " \t"); c != "" && !ascii.EqualFold(c, "chunked") {
			return refuse(RuleTransferCoding, "the request has the transfer coding %q", c)
		}
	}
	return nil
}

// readBody returns the body bytes, which net/http has already transfer-decoded,
// and puts an in-memory copy back in r. A body over max bytes is refused; r
// then still yields all of it.
func readBody(r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if r.ContentLength > max {
		return nil, refuse(RuleBodyTooLarge, "Content-Length %d is over %d", r.ContentLength, max)
	}
	// One byte more than max tells a body over the limit from one at it.
	limit := max
	if limit < math.MaxInt64 {
		limit++
	}
	orig := r.Body
	b, err := io.ReadAll(io.LimitReader(orig, limit))
	if err != nil {
		r.Body = readCloser{io.MultiReader(bytes.NewReader(b), orig), orig}
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, refuse(RuleBodyTooLarge, "the server limit of %d bytes was reached", tooBig.Limit)
		}
		return nil, fmt.Errorf("%w: %w", ErrBodyRead, err)
	}
	if int64(len(b)) > max {
		r.Body = readCloser{io.MultiReader(bytes.NewReader(b), orig), orig}
		return nil, refuse(RuleBodyTooLarge, "the body is over %d bytes", max)
	}
	_ = orig.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	return b, nil
}

// readCloser reads the bytes already taken and then the rest of the original
// body, and closes the original.
type readCloser struct {
	io.Reader
	io.Closer
}
