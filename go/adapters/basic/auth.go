package basic

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
)

// ErrNoAccount is the answer of an [AccountStore] that holds no such account.
var ErrNoAccount = errors.New("basic: no such account")

// AccountStore is the account database: the existing identity system of the
// deployment. An error other than [ErrNoAccount] means the database could not
// answer.
type AccountStore interface {
	// SourceID names the account database as a source of claims.
	SourceID() string
	// ByUserID returns the account whose login is userID.
	ByUserID(ctx context.Context, userID string) (Account, error)
	// ByPrincipal returns the account whose principal ID is principal in
	// realm.
	ByPrincipal(ctx context.Context, realm adapter.Realm, principal string) (Account, error)
}

// Account is an account of the database as the adapter reads it. The
// database keeps no password, only its hash.
type Account struct {
	// Principal is the namespaced principal ID of the account, under the
	// profile [PrincipalID] of the store-id and the immutable account-id.
	Principal string
	// Workload is the workload of the account; under the profile, the same
	// identifier as Principal.
	Workload adapter.Workload
	// Realm is the realm the account authenticates in.
	Realm adapter.Realm
	// Password is the hash of the account's password.
	Password PasswordHash
	// Roles are the native role names of the account.
	Roles []string
	// Disabled says the account may not authenticate.
	Disabled bool
	// Attributes are further authenticated attributes, such as a display
	// name. Each value is JSON-compatible.
	Attributes map[string]any
	// AnsweredAt is the database's own time of this answer; zero when it
	// gives none (profile section 8, F1).
	AnsweredAt time.Time
}

// PrincipalID is the principal ID, and the workload, of an account under the
// profile: basic:{store-id}:{account-id} (profile section 7). The user-id is
// never part of it.
func PrincipalID(storeID, accountID string) string {
	return "basic:" + storeID + ":" + accountID
}

// PasswordHash is a PBKDF2 hash with HMAC-SHA-256 (RFC 8018, section 5.2) of
// the UTF-8 octets of a password.
type PasswordHash struct {
	Iterations int
	Salt       []byte
	Key        []byte
}

func (h PasswordHash) validate() error {
	if h.Iterations < 1 || len(h.Salt) == 0 || len(h.Key) == 0 {
		return errors.New("a password hash needs an iteration count, a salt and a key")
	}
	return nil
}

// HashPassword returns the hash of password with the given parameters.
func HashPassword(password string, salt []byte, iterations, keyLen int) (PasswordHash, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{Iterations: iterations, Salt: salt, Key: key}, nil
}

// Matches reports, in time that does not depend on where the keys differ,
// whether password has this hash.
func (h PasswordHash) Matches(password string) bool {
	if h.validate() != nil {
		return false
	}
	key, err := pbkdf2.Key(sha256.New, password, h.Salt, h.Iterations, len(h.Key))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, h.Key) == 1
}

// AuthenticateNative authenticates r against the account database.
//
// A request without the enforcement marker is refused before its
// credentials are read: NO_CREDENTIAL when it carries no Authorization
// header, CREDENTIAL_REJECTED otherwise. The credential is then the Basic
// value of a single Authorization header (RFC 7617, section 2); another
// scheme, a value that is not Base64, a value without a colon, and a user-id
// or password with a control character are CREDENTIAL_REJECTED without a
// lookup. An unknown user-id, a wrong password and a disabled account are
// CREDENTIAL_REJECTED alike, so a denial does not disclose whether an account
// exists (draft 13.4). A database that cannot answer is an error that wraps
// [adapter.ErrDependencyUnavailable].
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	presented := len(r.Header.Values("Authorization")) > 0
	switch {
	case !presented:
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	case !Marked(r):
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	user, password, ok := credentials(r)
	if !ok {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	acct, err := a.cfg.Accounts.ByUserID(ctx, user)
	switch {
	case errors.Is(err, ErrNoAccount):
		a.cfg.Decoy.Matches(password)
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	case err != nil:
		return adapter.Principal{}, dependency("authenticate", err)
	}
	if !acct.Password.Matches(password) || acct.Disabled {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	if acct.Principal == "" || acct.Workload == "" || acct.Realm.TenantID == "" || acct.Realm.EnvironmentID == "" {
		return adapter.Principal{}, fmt.Errorf("basic: authenticate: the account database gives no principal, workload or realm: %w", adapter.ErrDependencyUnavailable)
	}
	return adapter.Principal{
		ID:              acct.Principal,
		Realm:           acct.Realm,
		Workload:        acct.Workload,
		Mechanism:       Mechanism,
		AuthenticatedAt: a.cfg.Clock.Now(),
		Attributes:      maps.Clone(acct.Attributes),
	}, nil
}

// credentials returns the user-id and password of the single Basic
// Authorization header of r. The first colon separates them; a value that is
// not Base64, has no colon, or has a control character in either part is not
// a credential (RFC 7617, section 2).
func credentials(r *http.Request) (user, password string, ok bool) {
	if len(r.Header.Values("Authorization")) != 1 {
		return "", "", false
	}
	user, password, ok = r.BasicAuth()
	if !ok || hasControl(user) || hasControl(password) {
		return "", "", false
	}
	return user, password, true
}

// hasControl reports whether s has a control character, CTL of RFC 5234
// appendix B.1: %x00-1F or %x7F.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f })
}
