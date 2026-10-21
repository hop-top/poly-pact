package googledir_test

import (
	context_ "context"
	"io"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/core/clock"
)

// client builds a Client for the stand-in, with one service account token
// source per API, each holding only the scopes of that API.
func (f *fakeGoogle) client(t testing.TB, clk clock.Clock) (*googledir.Client, error) {
	mk := func(scopes ...string) (*googledir.ServiceAccount, error) {
		return googledir.NewServiceAccount(googledir.ServiceAccountConfig{
			Key: testKey(t), Subject: fakeSubject, Scopes: scopes,
			TokenURL: f.srv.URL + "/token", HTTP: f.srv.Client(), Clock: clk,
		})
	}
	dir, err := mk("https://www.googleapis.com/auth/admin.directory.user.readonly", "https://www.googleapis.com/auth/admin.directory.group.member.readonly")
	if err != nil {
		return nil, err
	}
	ci, err := mk(ciScope)
	if err != nil {
		return nil, err
	}
	return googledir.NewClient(googledir.ClientConfig{
		DirectoryURL: f.srv.URL + "/directory", IdentityURL: f.srv.URL + "/identity",
		ChannelsStopURL: f.srv.URL + "/channels/stop", HTTP: f.srv.Client(),
		DirectoryTokens: dir, IdentityTokens: ci, Clock: clk,
	})
}

func bg() context_.Context { return context_.Background() }

func cancelled() (context_.Context, context_.CancelFunc) {
	ctx, cancel := context_.WithCancel(context_.Background())
	cancel()
	return ctx, cancel
}

func nopBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
