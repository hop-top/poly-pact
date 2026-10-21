//go:build windows

package files

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"hop.top/pact-go/adapter"
	enrollmem "hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// The Windows tier runs in the Windows job of CI, which creates a local test
// user and two files before it runs the tests (.github/workflows/ci-go.yml):
//
//	PACT_TEST_FILES_USER, PACT_TEST_FILES_PASSWORD  the test user
//	PACT_TEST_FILES_RESTRICTED  a file whose list grants the job's own
//	                            account, the broker's service identity, and
//	                            not the test user
//	PACT_TEST_FILES_GRANTED     a file whose list grants the test user
//	                            directly, through no group
//
// Without them the tier is skipped.
type windowsTier struct {
	user, password, restricted, granted string
}

func tierOf(t *testing.T) windowsTier {
	t.Helper()
	w := windowsTier{
		user:       os.Getenv("PACT_TEST_FILES_USER"),
		password:   os.Getenv("PACT_TEST_FILES_PASSWORD"),
		restricted: os.Getenv("PACT_TEST_FILES_RESTRICTED"),
		granted:    os.Getenv("PACT_TEST_FILES_GRANTED"),
	}
	if w.user == "" || w.password == "" || w.restricted == "" || w.granted == "" {
		t.Skip("PACT_TEST_FILES_USER, PACT_TEST_FILES_PASSWORD, PACT_TEST_FILES_RESTRICTED and PACT_TEST_FILES_GRANTED are not set")
	}
	return w
}

var (
	modadvapi32    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = modadvapi32.NewProc("LogonUserW")
)

// Logon values of winbase.h; the LogonUserW page does not state them. To
// probe in the Windows job: a wrong value fails the logon.
const (
	logon32LogonNetwork    = 3
	logon32ProviderDefault = 0
)

// logon returns an impersonation token of the test user. LogonUserW with
// LOGON32_LOGON_NETWORK returns an impersonation token (LogonUserW, phToken).
// It stands in for the token of a completed Negotiate exchange: the broker
// itself never handles a password (profile IA-4). newWinToken takes
// ownership of the handle.
func (w windowsTier) logon(t *testing.T) windows.Token {
	t.Helper()
	user, _ := windows.UTF16PtrFromString(w.user)
	domain, _ := windows.UTF16PtrFromString(".")
	pass, _ := windows.UTF16PtrFromString(w.password)
	var tok windows.Token
	r, _, err := procLogonUserW.Call(uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(pass)),
		logon32LogonNetwork, logon32ProviderDefault, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		t.Fatalf("LogonUserW(%s): %v", w.user, err)
	}
	return tok
}

// tokenPackage completes every exchange with one token.
type tokenPackage struct{ tok Token }

func (p tokenPackage) NewExchange() (Exchange, error) { return tokenExchange(p), nil }

type tokenExchange struct{ tok Token }

func (e tokenExchange) Accept([]byte) ([]byte, Token, error) { return nil, e.tok, nil }
func (tokenExchange) Close() error                           { return nil }

// tierBroker is a broker with the Windows impersonation and file system, the
// two files registered by the job's account, and a security package that
// completes every exchange as the test user.
func tierBroker(t *testing.T, w windowsTier) (*Broker, adapter.Principal) {
	t.Helper()
	tok, err := newWinToken(w.logon(t))
	if err != nil {
		t.Fatal(err)
	}
	fs := NTFS()
	reg := StaticRegistry{}
	for res, path := range map[string]string{"file:restricted": w.restricted, "file:granted": w.granted} {
		e, err := Register(fs, res, path)
		if err != nil {
			t.Fatalf("registering %s as the job's account: %v", path, err)
		}
		reg[res] = e
	}
	b, err := New(Config{
		Realm:        adapter.Realm{TenantID: "ci", EnvironmentID: "https://files.ci.example/environments/windows"},
		Origin:       "https://files.ci.example",
		Package:      tokenPackage{tok: tok},
		Impersonator: ThreadImpersonator(),
		FileSystem:   fs,
		Files:        reg,
		Registry:     enrollmem.New(enrollmem.WithSharedWorkloads()),
		Clock:        clock.NewFake(time.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, "https://files.ci.example/files/granted/content", nil)
	r.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString([]byte("ci")))
	r = b.Arrive(r)
	p, err := b.AuthenticateNative(r.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	return b, p
}

func tierOp(p adapter.Principal, res string) core.OperationContext {
	return core.OperationContext{
		OperationID: "op-" + res, EnvironmentID: p.Realm.EnvironmentID, PrincipalID: p.ID, Action: ActionRead,
		Resources: []string{res}, Method: http.MethodGet, TargetURI: "https://files.ci.example/files/x/content",
		BodyDigest: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", Headers: map[string]string{},
	}
}

// TestWindowsRestrictedACL is FILES-W01: the open of a file that the job's
// account can read and the test user cannot is denied by the system under the
// user's impersonation token, so the open ran as the user (profile 3.2, B2).
func TestWindowsRestrictedACL(t *testing.T) {
	w := tierOf(t)
	b, p := tierBroker(t, w)
	d, err := b.AuthorizeNative(context.Background(), p, tierOp(p, "file:restricted"))
	if err != nil || d.Effect != adapter.EffectDeny {
		t.Fatalf("restricted file: %+v, %v; want a native DENY", d, err)
	}
}

// TestWindowsDirectGrant is FILES-W02: a file that grants the test user
// directly opens and reads without any group grant; the right comes from the
// native check (profile 3.2).
func TestWindowsDirectGrant(t *testing.T) {
	w := tierOf(t)
	b, p := tierBroker(t, w)
	ctx := WithTask(context.Background(), TaskBinding{TaskID: "ci-task", AgentID: "https://agents.ci.example/a"})
	d, err := b.AuthorizeNative(ctx, p, tierOp(p, "file:granted"))
	if err != nil || d.Effect != adapter.EffectAllow {
		t.Fatalf("granted file: %+v, %v; want ALLOW", d, err)
	}
	var out bytes.Buffer
	key := HandleKey{Realm: p.Realm, PrincipalID: p.ID, TaskID: "ci-task", OperationID: "op-file:granted", AgentID: "https://agents.ci.example/a"}
	if _, err := b.Execute(context.Background(), key, &out); err != nil {
		t.Fatalf("Execute: %v (whether a handle stays readable after the revert is OI-4)", err)
	}
	want, err := os.ReadFile(w.granted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("read %q, want %q", out.Bytes(), want)
	}
}

// TestWindowsEffectiveIdentity checks the impersonation seam on its own: on a
// locked thread, impersonating the test user's token makes it the effective
// user, and the revert gives the job's account back (profile TA-1, TA-4,
// TA-5).
func TestWindowsEffectiveIdentity(t *testing.T) {
	w := tierOf(t)
	tok, err := newWinToken(w.logon(t))
	if err != nil {
		t.Fatal(err)
	}
	imp := ThreadImpersonator()
	done := make(chan error, 1)
	go func() {
		lockThread()
		before, err := imp.Effective()
		if err != nil {
			done <- err
			return
		}
		if err := imp.Impersonate(tok); err != nil {
			done <- err
			unlockThread()
			return
		}
		during, err := imp.Effective()
		if rerr := imp.Revert(); rerr != nil {
			done <- rerr // the thread is not returned: it ends with the goroutine
			return
		}
		after, _ := imp.Effective()
		unlockThread()
		switch {
		case err != nil:
			done <- err
		case during != tok.User():
			done <- errors.New("impersonating: effective user " + during + ", want " + tok.User())
		case after != before || after == tok.User():
			done <- errors.New("after the revert: effective user " + after + ", want " + before)
		default:
			done <- nil
		}
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestWindowsNegotiateLoopback runs a Negotiate exchange between a client
// context of the job's own credentials and the broker's security package, in
// one process, and checks that the completed context's token is the job's
// account (profile IA-2, IA-5). It needs no test user.
func TestWindowsNegotiateLoopback(t *testing.T) {
	if os.Getenv("PACT_TEST_FILES_SSPI") == "" {
		t.Skip("PACT_TEST_FILES_SSPI is not set")
	}
	pkg, err := NewSSPI()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pkg.Close() }()
	ex, err := pkg.NewExchange()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ex.Close() }()
	cl, err := newLoopbackClient()
	if err != nil {
		t.Fatal(err)
	}
	defer cl.close()
	var in []byte
	for leg := 0; leg < 8; leg++ {
		out, done, err := cl.step(in)
		if err != nil {
			t.Fatalf("client leg %d: %v", leg, err)
		}
		reply, tok, err := ex.Accept(out)
		if err != nil {
			t.Fatalf("server leg %d: %v", leg, err)
		}
		if tok != nil {
			self, err := currentUser()
			if err != nil {
				t.Fatal(err)
			}
			if tok.User() != self {
				t.Errorf("completed context user %s, want the job's account %s", tok.User(), self)
			}
			if tok.Level() < LevelImpersonation {
				t.Errorf("level %d: a loopback context cannot be impersonated (IA-6)", tok.Level())
			}
			return
		}
		if done {
			t.Fatal("the client finished but the server needs another leg")
		}
		in = reply
	}
	t.Fatal("no completed context after 8 legs")
}
