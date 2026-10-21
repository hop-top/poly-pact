package basic_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// basicModel is the model of the native state of the Basic cases, defined in
// spec/v1.0/fixtures/adapters/basic/README.md.
const basicModel = "basic/1"

// casesDir is the directory of the Basic cases in the fixture tree; the
// account database path of a state is relative to it.
const casesDir = "adapters/basic"

// hookAccountLookup is the native hook a Basic harness fires each time the
// adapter asks the account database for an account.
const hookAccountLookup = "account_lookup"

// permissionSource is the source id of the native permission lookup of the
// basic/1 model.
const permissionSource = "legacy-permissions"

// basicState is the basic/1 native state of a case.
type basicState struct {
	Model              string              `json:"model"`
	Gateway            memory.Gateway      `json:"gateway"`
	Accounts           string              `json:"accounts"`
	AccountsAnsweredAt *int64              `json:"accounts_answered_at"`
	Credentials        []credential        `json:"credentials"`
	RoleMap            map[string]string   `json:"role_map"`
	Purposes           []purpose           `json:"purposes"`
	Enrollments        []memory.Enrollment `json:"enrollments"`
	Invoices           []invoice           `json:"invoices"`
	Reporting          *memory.Reporting   `json:"reporting"`
	UnavailableSources []string            `json:"unavailable_sources"`
}

// credential is what a client holds: a user-id and a password.
type credential struct {
	Ref      string `json:"ref"`
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

// purpose is an installed purpose of purpose-operation-v1.
type purpose struct {
	PurposeID string   `json:"purpose_id"`
	Actions   []string `json:"actions"`
}

// invoice is the department an invoice belongs to.
type invoice struct {
	ID         string `json:"id"`
	Department string `json:"department"`
}

// accountFile is the account database asset.
type accountFile struct {
	StoreID  string          `json:"store_id"`
	Accounts []accountRecord `json:"accounts"`
}

// accountRecord is one account of the asset. The password is stored only as
// its PBKDF2 hash.
type accountRecord struct {
	AccountID  string         `json:"account_id"`
	UserID     string         `json:"user_id"`
	Password   passwordRecord `json:"password"`
	Roles      []string       `json:"roles"`
	Department string         `json:"department"`
	Status     string         `json:"status"`
}

// passwordRecord is a PBKDF2-HMAC-SHA-256 hash with its parameters; salt and
// key are base64url without padding.
type passwordRecord struct {
	Scheme     string `json:"scheme"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Key        string `json:"key"`
}

// world is a parsed basic/1 state with its account database.
type world struct {
	st    basicState
	store accountFile
}

// modelOf returns the model member of a native state.
func modelOf(raw []byte) (string, error) {
	var probe struct {
		Model string `json:"model"`
	}
	// Only the model member is read here; the full parse is strict.
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	return probe.Model, nil
}

// loadWorld parses a basic/1 state strictly and reads its account database
// from the fixture tree.
func loadWorld(raw []byte, fsys fs.FS) (*world, error) {
	var st basicState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("basic/1 state: %w", err)
	}
	if st.Model != basicModel {
		return nil, fmt.Errorf("model is %q, want %q", st.Model, basicModel)
	}
	if st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "" {
		return nil, errors.New("basic/1 state: gateway needs a tenant_id, an environment_id and an origin")
	}
	if st.Accounts == "" || path.IsAbs(st.Accounts) || strings.Contains(st.Accounts, "..") {
		return nil, fmt.Errorf("basic/1 state: accounts %q is not a path inside %s", st.Accounts, casesDir)
	}
	data, err := fs.ReadFile(fsys, path.Join(casesDir, st.Accounts))
	if err != nil {
		return nil, fmt.Errorf("basic/1 state: %w", err)
	}
	var af accountFile
	if err := strictjson.Unmarshal(data, strictjson.Limits{}, &af); err != nil {
		return nil, fmt.Errorf("account database %s: %w", st.Accounts, err)
	}
	if af.StoreID == "" {
		return nil, fmt.Errorf("account database %s has no store_id", st.Accounts)
	}
	for _, a := range af.Accounts {
		if a.AccountID == "" || a.UserID == "" || a.Password.Scheme != "pbkdf2-sha256" || a.Password.Iterations < 1 {
			return nil, fmt.Errorf("account database %s: account %q is incomplete", st.Accounts, a.AccountID)
		}
		if a.Status != "active" && a.Status != "disabled" {
			return nil, fmt.Errorf("account database %s: account %q has status %q", st.Accounts, a.AccountID, a.Status)
		}
	}
	refs := map[string]bool{}
	for _, c := range st.Credentials {
		if c.Ref == "" || refs[c.Ref] {
			return nil, fmt.Errorf("basic/1 state: credential ref %q is empty or used twice", c.Ref)
		}
		refs[c.Ref] = true
	}
	return &world{st: st, store: af}, nil
}

// realm is the realm of the gateway, and of every account of the world.
func (w *world) realm() adapter.Realm {
	return adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID}
}

// unavailable reports whether the source named id cannot answer.
func (w *world) unavailable(id string) bool {
	for _, s := range w.st.UnavailableSources {
		if s == id {
			return true
		}
	}
	return false
}

// basicCredential is the Authorization value of user-id and password
// (RFC 7617, section 2).
func basicCredential(userID, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userID+":"+password))
}

// attachCredential sets the credential of ref from creds on r, unless r
// already carries an Authorization header.
func attachCredential(creds []credential, r *http.Request, ref string) error {
	for _, c := range creds {
		if c.Ref != ref {
			continue
		}
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", basicCredential(c.UserID, c.Password))
		}
		return nil
	}
	return fmt.Errorf("no credential %q", ref)
}

// commonState returns the common/1 state of the enrollments of the world, for
// the reference enrollment source.
func (w *world) commonState() memory.State {
	return memory.State{
		Model:              memory.Model,
		Gateway:            w.st.Gateway,
		Enrollments:        w.st.Enrollments,
		UnavailableSources: w.st.UnavailableSources,
	}
}

// fixtures is the fixture tree of the source repository.
func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }
