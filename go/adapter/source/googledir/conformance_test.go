package googledir_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/adapter/sourcetest"
)

// This file is the Go driver of the model googledir/1 of the source cases
// under spec/v1.0/fixtures/sources/googledir, defined by
// spec/v1.0/profiles/sources/googledir.md section 10.1.

type gdSource struct {
	Model            string   `json:"model"`
	SourceID         string   `json:"source_id"`
	PrincipalPrefix  string   `json:"principal_prefix"`
	Groups           []string `json:"groups"`
	TransitiveGroups []string `json:"transitive_groups"`
	Cache            *struct {
		PollIntervalSeconds int64 `json:"poll_interval_seconds"`
		MaxAgeSeconds       int64 `json:"max_age_seconds"`
		Channel             struct {
			Address            string `json:"address"`
			Token              string `json:"token"`
			TTLSeconds         int64  `json:"ttl_seconds"`
			RenewBeforeSeconds int64  `json:"renew_before_seconds"`
		} `json:"channel"`
	} `json:"cache"`
	Directory struct {
		Customer          string       `json:"customer"`
		PageSize          int          `json:"page_size"`
		ChannelMaxSeconds int64        `json:"channel_max_seconds"`
		Users             []*fakeUser  `json:"users"`
		Groups            []*fakeGroup `json:"groups"`
	} `json:"directory"`
}

type gdInbound struct {
	Admin  *gdAdmin  `json:"admin"`
	Tick   *struct{} `json:"tick"`
	Notify *gdNotify `json:"notify"`
}

type gdAdmin struct {
	Op           string `json:"op"`
	User         string `json:"user"`
	Group        string `json:"group"`
	Child        string `json:"child"`
	PrimaryEmail string `json:"primary_email"`
	API          string `json:"api"`
	Status       int    `json:"status"`
}

type gdNotify struct {
	Channel int    `json:"channel"`
	Token   string `json:"token"`
	State   string `json:"state"`
	Message int    `json:"message"`
	User    string `json:"user"`
	Body    string `json:"body"`
}

type gdExpect struct {
	Status    *int   `json:"status"`
	Mode      string `json:"mode"`
	Channel   *int   `json:"channel"`
	ExpiresAt *int64 `json:"expires_at"`
	Error     *bool  `json:"error"`
	Sweeps    *int   `json:"sweeps"`
	Stopped   *[]int `json:"stopped"`
}

func driver() sourcetest.Driver {
	return sourcetest.Driver{Model: "googledir/1", Open: func(t testing.TB, env sourcetest.Env) (sourcetest.Subject, error) {
		dec := json.NewDecoder(bytes.NewReader(env.Source))
		dec.DisallowUnknownFields()
		var s gdSource
		if err := dec.Decode(&s); err != nil {
			return sourcetest.Subject{}, err
		}
		fg := newFakeGoogle(t, env.Clock, env.Hooks)
		fg.users, fg.groups = s.Directory.Users, s.Directory.Groups
		if s.Directory.PageSize > 0 {
			fg.pageSize = s.Directory.PageSize
		}
		if s.Directory.ChannelMaxSeconds > 0 {
			fg.channelMax = time.Duration(s.Directory.ChannelMaxSeconds) * time.Second
		}
		client, err := fg.client(t, env.Clock)
		if err != nil {
			return sourcetest.Subject{}, err
		}
		rc := googledir.Config{SourceID: s.SourceID, PrincipalPrefix: s.PrincipalPrefix, Client: client,
			Clock: env.Clock, Groups: s.Groups, TransitiveGroups: s.TransitiveGroups}
		var feed *googledir.Feed
		if c := s.Cache; c != nil {
			store := source.NewMemory()
			rc.Cache, rc.MaxAge = store, time.Duration(c.MaxAgeSeconds)*time.Second
			n := 0
			feed, err = googledir.NewFeed(googledir.FeedConfig{
				Client: client, Store: store, Clock: env.Clock, PrincipalPrefix: s.PrincipalPrefix,
				Customer: s.Directory.Customer, Address: c.Channel.Address, Token: c.Channel.Token,
				PollInterval: time.Duration(c.PollIntervalSeconds) * time.Second,
				ChannelTTL:   time.Duration(c.Channel.TTLSeconds) * time.Second,
				RenewBefore:  time.Duration(c.Channel.RenewBeforeSeconds) * time.Second,
				PageSize:     s.Directory.PageSize,
				NewID:        func() string { n++; return fmt.Sprintf("chan-%d", n) },
			})
			if err != nil {
				return sourcetest.Subject{}, err
			}
		}
		rd, err := googledir.NewReader(rc)
		if err != nil {
			return sourcetest.Subject{}, err
		}
		apply := func(ctx context.Context, in, ex json.RawMessage) error {
			var i gdInbound
			var e gdExpect
			if err := json.Unmarshal(in, &i); err != nil {
				return err
			}
			if len(ex) > 0 {
				if err := json.Unmarshal(ex, &e); err != nil {
					return err
				}
			}
			switch {
			case i.Admin != nil:
				return fg.admin(i.Admin)
			case i.Tick != nil:
				if feed == nil {
					return errors.New("tick: the source has no cache")
				}
				return checkTick(ctx, fg, feed, e)
			case i.Notify != nil:
				if feed == nil {
					return errors.New("notify: the source has no cache")
				}
				return notify(fg, feed, s.Cache.Channel.Address, s.Cache.Channel.Token, i.Notify, e)
			}
			return errors.New("inbound is none of admin, tick, notify")
		}
		return sourcetest.Subject{Reader: rd, Apply: apply}, nil
	}}
}

func checkTick(ctx context.Context, fg *fakeGoogle, feed *googledir.Feed, e gdExpect) error {
	err := feed.Tick(ctx)
	var fail []string
	if e.Error != nil && (err != nil) != *e.Error {
		fail = append(fail, fmt.Sprintf("error %v, want error=%v", err, *e.Error))
	}
	st := feed.Status()
	if e.Mode != "" && string(st.Mode) != e.Mode {
		fail = append(fail, fmt.Sprintf("mode %s, want %s", st.Mode, e.Mode))
	}
	if e.Channel != nil {
		if got := fg.seq(st.ChannelID); got != *e.Channel {
			fail = append(fail, fmt.Sprintf("channel %d, want %d", got, *e.Channel))
		}
	}
	if e.ExpiresAt != nil && st.ChannelExpires.Unix() != *e.ExpiresAt {
		fail = append(fail, fmt.Sprintf("channel expires %d, want %d", st.ChannelExpires.Unix(), *e.ExpiresAt))
	}
	if e.Sweeps != nil && st.Sweeps != *e.Sweeps {
		fail = append(fail, fmt.Sprintf("sweeps %d, want %d", st.Sweeps, *e.Sweeps))
	}
	if e.Stopped != nil {
		fg.mu.Lock()
		var got []int
		for i, c := range fg.channels {
			if c.Stopped {
				got = append(got, i+1)
			}
		}
		fg.mu.Unlock()
		if !slices.Equal(got, *e.Stopped) {
			fail = append(fail, fmt.Sprintf("stopped %v, want %v", got, *e.Stopped))
		}
	}
	return joinFail(fail)
}

func notify(fg *fakeGoogle, feed *googledir.Feed, addr, token string, n *gdNotify, e gdExpect) error {
	fg.mu.Lock()
	chID, res := "unknown-channel", "res-unknown"
	if n.Channel >= 1 && n.Channel <= len(fg.channels) {
		chID, res = fg.channels[n.Channel-1].ID, fg.channels[n.Channel-1].ResourceID
	}
	fg.mu.Unlock()
	body := n.Body
	if body == "" && n.User != "" {
		body = fmt.Sprintf(`{"kind":"admin#directory#user","id":%q,"etag":"\"e1\"","primaryEmail":"x@northstar.example"}`, n.User)
	}
	r := httptest.NewRequest(http.MethodPost, addr, strings.NewReader(body))
	r.Header.Set("X-Goog-Channel-ID", chID)
	r.Header.Set("X-Goog-Resource-ID", res)
	r.Header.Set("X-Goog-Resource-State", n.State)
	r.Header.Set("X-Goog-Message-Number", strconv.Itoa(max(n.Message, 1)))
	switch n.Token {
	case "":
		r.Header.Set("X-Goog-Channel-Token", token)
	case "-":
	default:
		r.Header.Set("X-Goog-Channel-Token", n.Token)
	}
	rec := httptest.NewRecorder()
	feed.Handler().ServeHTTP(rec, r)
	if e.Status != nil && rec.Code != *e.Status {
		return fmt.Errorf("status %d, want %d", rec.Code, *e.Status)
	}
	return nil
}

// admin changes the stand-in directory, as an administrator or an outage.
func (f *fakeGoogle) admin(a *gdAdmin) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.key(a.User)
	g := f.group(a.Group)
	need := func(ok bool, what string) error {
		if !ok {
			return fmt.Errorf("admin %s: no %s", a.Op, what)
		}
		return nil
	}
	switch a.Op {
	case "suspend", "unsuspend", "archive", "delete", "rename":
		if err := need(u != nil, "user "+a.User); err != nil {
			return err
		}
		switch a.Op {
		case "suspend":
			u.Suspended = true
		case "unsuspend":
			u.Suspended = false
		case "archive":
			u.Archived = true
		case "delete":
			u.Deleted = true
		case "rename":
			u.Aliases = append(u.Aliases, u.Email)
			u.Email = a.PrimaryEmail
		}
	case "add_member", "remove_member":
		if err := need(u != nil && g != nil, "user or group"); err != nil {
			return err
		}
		if a.Op == "add_member" {
			g.Members = append(g.Members, u.ID)
		} else {
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == u.ID })
		}
	case "nest":
		if err := need(g != nil && f.group(a.Child) != nil, "group"); err != nil {
			return err
		}
		g.Children = append(g.Children, a.Child)
	case "fail":
		f.fail[a.API] = a.Status
	case "heal":
		delete(f.fail, a.API)
	default:
		return fmt.Errorf("admin: unknown op %q", a.Op)
	}
	return nil
}

func (f *fakeGoogle) seq(channelID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.channels {
		if c.ID == channelID {
			return i + 1
		}
	}
	return 0
}

func joinFail(f []string) error {
	if len(f) == 0 {
		return nil
	}
	return errors.New(strings.Join(f, "; "))
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func TestConformance(t *testing.T) {
	sourcetest.Run(t, driver(), sourcetest.Options{Source: "googledir"})
}
