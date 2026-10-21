package ssf

import (
	"encoding/json"
	"fmt"
	"slices"

	"hop.top/pact-go/adapter/source"
)

// The subject identifier formats a [Mapping] can name (RFC 9493 section 3.2;
// SSF 1.0 section 3.2).
const (
	FormatIssSub = "iss_sub"
	FormatOpaque = "opaque"
	FormatEmail  = "email"
)

// Mapping joins one subject of one transmitter to a principal. A subject
// resolves to a principal only through a mapping the deployment configured:
// no attribute of the event, and in particular no e-mail address, names a
// principal by itself, and an e-mail address matches a mapping only byte for
// byte (RFC 9493 section 3.2.2.1 leaves canonicalization to the recipient,
// and this receiver applies none).
type Mapping struct {
	// Issuer is the iss of the SETs the mapping applies to.
	Issuer string
	// Format is FormatIssSub, FormatOpaque or FormatEmail.
	Format string
	// SubjectIss is the iss member of an iss_sub subject; empty for the other
	// formats.
	SubjectIss string
	// Value is the sub member of an iss_sub subject, the id of an opaque
	// subject, or the address of an email subject.
	Value string
	// Local is the immutable local part of the principal identifier; the
	// namespace and realm components come from Config.PrincipalPrefix, never
	// from an event (identity mapping IM-4, IM-5).
	Local string
}

type mapKey struct{ issuer, format, subjectIss, value string }

// mappingTable validates the mappings and indexes them to principals.
func mappingTable(prefix string, issuers map[string]bool, ms []Mapping) (map[mapKey]string, error) {
	join := source.Join{Attribute: "local", Prefix: prefix}
	if _, err := join.Principal(map[string]string{"local": "x"}); err != nil {
		return nil, fmt.Errorf("ssf: PrincipalPrefix: %w", err)
	}
	out := map[mapKey]string{}
	for i, m := range ms {
		switch {
		case !issuers[m.Issuer]:
			return nil, fmt.Errorf("ssf: mapping %d: issuer %q is not configured", i, m.Issuer)
		case !slices.Contains([]string{FormatIssSub, FormatOpaque, FormatEmail}, m.Format):
			return nil, fmt.Errorf("ssf: mapping %d: format %q is not iss_sub, opaque or email", i, m.Format)
		case m.Value == "":
			return nil, fmt.Errorf("ssf: mapping %d: no value", i)
		case m.Format == FormatIssSub && m.SubjectIss == "":
			return nil, fmt.Errorf("ssf: mapping %d: an iss_sub mapping needs the subject's iss", i)
		case m.Format != FormatIssSub && m.SubjectIss != "":
			return nil, fmt.Errorf("ssf: mapping %d: only an iss_sub mapping has a subject iss", i)
		}
		p, err := join.Principal(map[string]string{"local": m.Local})
		if err != nil {
			return nil, fmt.Errorf("ssf: mapping %d: %w", i, err)
		}
		k := mapKey{m.Issuer, m.Format, m.SubjectIss, m.Value}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("ssf: mapping %d repeats an earlier subject", i)
		}
		out[k] = p
	}
	return out, nil
}

// Reasons of a subject that resolves to no principal.
const (
	reasonNoSubject          = "no-subject"
	reasonUnmapped           = "unmapped"
	reasonUnsupportedFormat  = "unsupported-format"
	reasonUnsupportedSubject = "unsupported-subject"
	reasonMalformedSubject   = "malformed-subject"
)

// resolution is the outcome of resolving one subject.
type resolution struct {
	principal string
	format    string // the format of the subject that decided the outcome
	reason    string // empty when principal is set
	discard   bool   // a critical member the receiver cannot process
}

// resolve resolves the subject of an event of a SET issued by issuer. raw is
// the sub_id member, or the legacy subject member of the event, or nil.
func (r *Receiver) resolve(issuer string, raw json.RawMessage) resolution {
	if len(raw) == 0 {
		return resolution{reason: reasonNoSubject}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return resolution{reason: reasonMalformedSubject}
	}
	str := func(name string) string {
		var s string
		if json.Unmarshal(m[name], &s) != nil {
			return ""
		}
		return s
	}
	format := str("format")
	if format == "" && str("subject_type") == "iss-sub" {
		// The RISC profile of 2022 (section 3.1) deprecated subject_type, which
		// a transmitter documents using, with the value iss-sub.
		format = FormatIssSub
	}
	lookup := func(k mapKey) resolution {
		if p, ok := r.mappings[k]; ok {
			return resolution{principal: p, format: k.format}
		}
		return resolution{format: k.format, reason: reasonUnmapped}
	}
	switch format {
	case FormatIssSub:
		iss, sub := str("iss"), str("sub")
		if iss == "" || sub == "" {
			return resolution{format: format, reason: reasonMalformedSubject}
		}
		return lookup(mapKey{issuer, FormatIssSub, iss, sub})
	case FormatOpaque:
		id := str("id")
		if id == "" {
			return resolution{format: format, reason: reasonMalformedSubject}
		}
		return lookup(mapKey{issuer, FormatOpaque, "", id})
	case FormatEmail:
		e := str("email")
		if e == "" {
			return resolution{format: format, reason: reasonMalformedSubject}
		}
		return lookup(mapKey{issuer, FormatEmail, "", e})
	case "complex":
		// SSF 1.0 section 3.6: an event with a critical member the receiver
		// cannot process is discarded. The receiver processes only user.
		for name := range m {
			if slices.Contains(r.critical, name) && name != "format" {
				return resolution{format: format, discard: true}
			}
		}
		u, ok := m["user"]
		if !ok {
			return resolution{format: format, reason: reasonUnsupportedSubject}
		}
		var um map[string]json.RawMessage
		if json.Unmarshal(u, &um) != nil {
			return resolution{format: format, reason: reasonMalformedSubject}
		}
		if _, nested := um["user"]; nested {
			return resolution{format: format, reason: reasonUnsupportedSubject}
		}
		return r.resolve(issuer, u)
	default:
		return resolution{format: format, reason: reasonUnsupportedFormat}
	}
}
