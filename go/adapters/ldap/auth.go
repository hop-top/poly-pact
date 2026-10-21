package ldap

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
)

// WhoAmIOID is the object identifier of the "Who am I?" operation (RFC 4532,
// section 2).
const WhoAmIOID = "1.3.6.1.4.1.4203.1.11.3"

// AuthenticateNative authenticates r against the directory of the login
// realm (profile Appendix B).
//
// A request without the enforcement marker is refused before its
// credentials are read: NO_CREDENTIAL when it carries no Authorization
// header, CREDENTIAL_REJECTED otherwise. The name and the password are those
// of a single Basic Authorization header (RFC 7617, section 2); another
// scheme or a malformed value is CREDENTIAL_REJECTED. An empty name, an empty
// password, and a password that SASLprep maps to nothing are NO_CREDENTIAL,
// and a name with a control character or a password with a character
// SASLprep prohibits is CREDENTIAL_REJECTED; none of them reaches the
// directory (LR-6).
//
// The lookup account then searches the user bases for exactly one entry of
// the account class whose login attribute equals the name, escaped (LR-11);
// no entry, two entries, or a size limit are CREDENTIAL_REJECTED alike. A
// denied principal, the lookup account among them, is CREDENTIAL_REJECTED
// without a bind (LR-13). The password is bound as the DN of the matched
// entry on a connection of its own (LR-7), and where the server lists the
// "Who am I?" operation an empty authorization identity after the bind is
// CREDENTIAL_REJECTED (LR-8). The bind result maps by the table of LR-9.
// Every failure to reach the directory, to protect the connection, or to bind
// the lookup account wraps [adapter.ErrDependencyUnavailable].
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	switch {
	case len(r.Header.Values("Authorization")) == 0:
		return adapter.Principal{}, denied(adapter.DenialNoCredential)
	case !Marked(r):
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	name, password, err := credentials(r)
	if err != nil {
		return adapter.Principal{}, err
	}
	rlm := a.realms[a.cfg.LoginRealm]
	s, err := a.lookupSession(ctx, rlm, "authenticate")
	if err != nil {
		return adapter.Principal{}, err
	}
	e, err := a.loginEntry(ctx, s, rlm, name)
	_ = s.Close()
	if err != nil {
		return adapter.Principal{}, err
	}
	uid, ok := rlm.uniqueText(e)
	if !ok {
		return adapter.Principal{}, outage("authenticate", "the matched entry has no unique id")
	}
	id := PrincipalID(rlm.ID, uid)
	if rlm.isDenied(id) || rlm.isLookup(e.DN) {
		return adapter.Principal{}, denied(adapter.DenialCredentialRejected)
	}
	if err := a.userBind(ctx, rlm, e.DN, password); err != nil {
		return adapter.Principal{}, err
	}
	return adapter.Principal{
		ID:              id,
		Realm:           rlm.pact,
		Workload:        adapter.Workload(id),
		Mechanism:       Mechanism,
		AuthenticatedAt: a.cfg.Clock.Now(),
	}, nil
}

// credentials returns the name and the prepared password of the single Basic
// Authorization header of r, or the native denial.
func credentials(r *http.Request) (name, password string, err error) {
	if len(r.Header.Values("Authorization")) != 1 {
		return "", "", denied(adapter.DenialCredentialRejected)
	}
	name, raw, ok := r.BasicAuth()
	switch {
	case !ok:
		return "", "", denied(adapter.DenialCredentialRejected)
	case name == "":
		return "", "", denied(adapter.DenialNoCredential)
	case strings.ContainsFunc(name, func(c rune) bool { return c < 0x20 || c == 0x7f }):
		return "", "", denied(adapter.DenialCredentialRejected)
	}
	password, perr := preparePassword(raw)
	switch {
	case perr != nil:
		return "", "", denied(adapter.DenialCredentialRejected)
	case password == "":
		return "", "", denied(adapter.DenialNoCredential)
	}
	return name, password, nil
}

// lookupSession opens a session and binds the lookup account on it. Any
// failure is an outage: an unbound session is anonymous and would read other
// data than the lookup account (RFC 4513, section 4; profile LR-13).
func (a *Adapter) lookupSession(ctx context.Context, rlm *realm, fn string) (Session, error) {
	s, err := rlm.Directory.Open(ctx)
	if err != nil {
		return nil, outage(fn, "the directory cannot be reached over a protected connection")
	}
	if err := s.Bind(ctx, rlm.LookupDN, rlm.LookupPassword); err != nil {
		_ = s.Close()
		return nil, outage(fn, "the lookup account cannot bind")
	}
	return s, nil
}

// loginEntry runs the login search of LR-11 and returns the one entry it
// matched.
func (a *Adapter) loginEntry(ctx context.Context, s Session, rlm *realm, name string) (Entry, error) {
	f := And{Equal{Attr: "objectClass", Value: []byte(rlm.AccountClass)}, Equal{Attr: rlm.LoginAttribute, Value: []byte(name)}}
	var found []Entry
	for _, base := range rlm.UserBases {
		res, err := s.Search(ctx, Query{
			Base: base, Scope: ScopeSubtree, Filter: f,
			Attributes: []string{rlm.uniqueAttr}, SizeLimit: 2, TimeLimit: rlm.TimeLimit,
		})
		if err != nil {
			return Entry{}, outage("authenticate", "the login search could not be completed")
		}
		switch {
		case len(res.References) > 0:
			return Entry{}, outage("authenticate", "the login search returned a reference")
		case res.Code == ResultSizeLimitExceeded:
			return Entry{}, denied(adapter.DenialCredentialRejected)
		case res.Code != ResultSuccess:
			return Entry{}, outage("authenticate", "the login search did not complete")
		}
		found = append(found, res.Entries...)
	}
	if len(found) != 1 {
		return Entry{}, denied(adapter.DenialCredentialRejected)
	}
	return found[0], nil
}

// userBind binds the password as dn on a connection of its own, then checks
// for an anonymous association where the server offers "Who am I?".
func (a *Adapter) userBind(ctx context.Context, rlm *realm, dn, password string) error {
	s, err := rlm.Directory.Open(ctx)
	if err != nil {
		return outage("authenticate", "the directory cannot be reached over a protected connection")
	}
	defer func() { _ = s.Close() }()
	if err := s.Bind(ctx, dn, password); err != nil {
		var re *ResultError
		if errors.As(err, &re) && bindDenial(re.Code) {
			return denied(adapter.DenialCredentialRejected)
		}
		return outage("authenticate", "the bind could not be completed")
	}
	root, err := s.Search(ctx, Query{
		Base: "", Scope: ScopeBase, Filter: Present{Attr: "objectClass"},
		Attributes: []string{"supportedExtension"}, TimeLimit: rlm.TimeLimit,
	})
	if err != nil || root.Code != ResultSuccess {
		return outage("authenticate", "the root DSE cannot be read")
	}
	if !listsExtension(root, WhoAmIOID) {
		return nil
	}
	authz, present, err := s.WhoAmI(ctx)
	switch {
	case err != nil || !present:
		return outage("authenticate", "the authorization identity cannot be read")
	case authz == "":
		return denied(adapter.DenialCredentialRejected)
	}
	return nil
}

// bindDenial reports whether a bind result is a refusal of the credential
// rather than an outage (profile LR-9).
func bindDenial(c ResultCode) bool {
	return slices.Contains([]ResultCode{
		ResultInvalidCredentials, ResultInappropriateAuthentication, ResultUnwillingToPerform,
		ResultInsufficientAccessRights, ResultNoSuchObject, ResultInvalidDNSyntax,
	}, c)
}

// listsExtension reports whether the root DSE lists oid in supportedExtension.
func listsExtension(root Result, oid string) bool {
	for _, e := range root.Entries {
		for _, v := range e.Values("supportedExtension") {
			if string(v) == oid {
				return true
			}
		}
	}
	return false
}

// isLookup reports whether dn names the realm's lookup account.
func (r *realm) isLookup(dn string) bool {
	d, err := parseDN(dn)
	return err == nil && d.EqualFold(r.lookupDN)
}
