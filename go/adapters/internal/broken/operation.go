package broken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// emptyDigest is the digest of the empty byte string.
const emptyDigest core.Digest = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

// viaClone calls f on a clone of r that mutate has changed, and gives the body
// state of the clone back to r, so the caller sees what the memory adapter did
// with the body.
func viaClone(ctx context.Context, r *http.Request, mutate func(*http.Request), f func(*http.Request) (core.OperationContext, error)) (core.OperationContext, error) {
	c := r.Clone(ctx)
	c.Body, c.GetBody = r.Body, r.GetBody
	mutate(c)
	op, err := f(c)
	r.Body, r.GetBody = c.Body, c.GetBody
	return op, err
}

// MapOperation is the memory adapter's, with the mapping defects.
func (b *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if b.on[IgnoreRealmMapping] {
		p.Realm = adapter.Realm{
			TenantID:      b.State().Gateway.TenantID,
			EnvironmentID: b.State().Gateway.EnvironmentID,
		}
	}
	op, err := viaClone(ctx, r, func(c *http.Request) {
		if b.on[AcceptFragment] {
			c.URL.Fragment, c.URL.RawFragment = "", ""
			c.RequestURI, _, _ = strings.Cut(c.RequestURI, "#")
		}
		if b.on[AcceptUserinfo] {
			c.URL.User = nil
			c.RequestURI = withoutUserinfo(c.RequestURI)
		}
		if b.on[AcceptContentEncoding] {
			c.Header.Del("Content-Encoding")
		}
		if b.on[NormalizeAmbiguousEncoding] {
			c.RequestURI = normalizeEncoding(c.RequestURI)
		}
	}, func(c *http.Request) (core.OperationContext, error) {
		return b.Adapter.MapOperation(ctx, c, p, mappingVersion)
	})
	if b.on[BodyNotRestored] && r.Body != nil {
		// The digest is right; the request is left with nothing in it.
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body = http.NoBody
	}

	if err != nil {
		if b.on[WrongMalformedCode] && errors.Is(err, adapter.ErrInvalidMessage) {
			// The message says what was wrong; the chain no longer holds the
			// INVALID_MESSAGE sentinel, only another code.
			err = fmt.Errorf("%v: %w", err, adapter.ErrUnsupportedRequirement)
		}
		if b.on[LeakCredentialInMapError] {
			return op, fmt.Errorf("%w (request had Authorization %q and Cookie %q)", err, r.Header.Get("Authorization"), r.Header.Get("Cookie"))
		}
		return op, err
	}
	b.corrupt(&op, r)
	return op, nil
}

// withoutUserinfo drops the userinfo of an absolute-form request-target.
func withoutUserinfo(rt string) string {
	scheme, rest, ok := strings.Cut(rt, "://")
	if !ok {
		return rt
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
		rest = rest[at+1:]
	}
	return scheme + "://" + rest
}

// normalizeEncoding rewrites the path and query of a request-target the way a
// lenient gateway reads them: an escape of an unreserved character, of "/" in
// the path, or an overlong two-octet form of either is decoded, every other
// escape is written with uppercase hex digits, and the dot segments of the
// path are removed (RFC 3986 5.2.4).
func normalizeEncoding(rt string) string {
	prefix := ""
	if scheme, rest, ok := strings.Cut(rt, "://"); ok {
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		prefix, rt = scheme+"://"+rest[:end], rest[end:]
	}
	rt, fragment, hasFragment := strings.Cut(rt, "#")
	path, query, hasQuery := strings.Cut(rt, "?")
	out := prefix + removeDotSegments(normalizeComponent(path, true))
	if hasQuery {
		out += "?" + normalizeComponent(query, false)
	}
	if hasFragment {
		out += "#" + fragment
	}
	return out
}

func normalizeComponent(s string, isPath bool) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		b, ok := escapeAt(s, i)
		if !ok {
			out.WriteByte(s[i])
			continue
		}
		i += 2
		if next, ok := escapeAt(s, i+1); ok && (b == 0xC0 || b == 0xC1) && next&0xC0 == 0x80 {
			b, i = (b&0x1F)<<6|next&0x3F, i+3
		}
		if isUnreservedByte(b) || isPath && b == '/' {
			out.WriteByte(b)
		} else {
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String()
}

// removeDotSegments is remove_dot_segments of RFC 3986 5.2.4 for a path that
// starts with "/". Another path is returned unchanged.
func removeDotSegments(path string) string {
	if !strings.HasPrefix(path, "/") {
		return path
	}
	var out []string
	segments := strings.Split(path, "/")[1:]
	for i, seg := range segments {
		last := i == len(segments)-1
		switch seg {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
}

// escapeAt decodes the escape at s[i], if there is one.
func escapeAt(s string, i int) (byte, bool) {
	if i+2 >= len(s) || s[i] != '%' {
		return 0, false
	}
	v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
	return byte(v), err == nil
}

func isUnreservedByte(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || strings.IndexByte("-._~", b) >= 0
}

// corrupt applies the defects that change a mapped operation.
func (b *Adapter) corrupt(op *core.OperationContext, r *http.Request) {
	query := ""
	if i := strings.IndexByte(op.TargetURI, '?'); i >= 0 {
		query = op.TargetURI[i+1:]
	}
	pathOnly, _, _ := strings.Cut(strings.TrimPrefix(op.TargetURI, "https://"), "?")
	_, pathPart, _ := strings.Cut(pathOnly, "/")

	if b.on[ForwardedHostOrigin] {
		host := header(r, "X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		op.TargetURI = "https://" + host + "/" + pathPart
		if query != "" {
			op.TargetURI += "?" + query
		}
	}
	if b.on[NormalizeQuery] && query != "" {
		if v, err := url.ParseQuery(query); err == nil {
			op.TargetURI = strings.SplitN(op.TargetURI, "?", 2)[0] + "?" + v.Encode()
		}
	}
	if b.on[BodyNotCovered] {
		sum := sha256.Sum256(nil)
		op.BodyDigest = core.Digest(base64.RawURLEncoding.EncodeToString(sum[:]))
	}
	if b.on[BlankEmptyDigest] && op.BodyDigest == emptyDigest {
		op.BodyDigest = ""
	}
	if b.on[EchoAllHeaders] {
		for name, vals := range r.Header {
			op.Headers[strings.ToLower(name)] = strings.Join(vals, ", ")
		}
	}
	if b.on[TrustClientResources] {
		if v := r.Header.Get("X-Resources"); v != "" {
			op.Resources = []string{v}
		}
	}
	if b.on[PrincipalFromHeader] {
		if v := r.Header.Get("X-Principal"); v != "" {
			op.PrincipalID = v
		}
	}
}
