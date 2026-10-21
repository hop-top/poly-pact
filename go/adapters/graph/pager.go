package graph

import (
	"errors"
	"net/url"
	"strings"

	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/internal/ascii"
)

// errLink is the error of a next link the pager refuses.
var errLink = errors.New("graph: the next link is not one of Graph's origin, the form's downstream path and the pinned options (GR-24)")

// pager is the [task.Pager] of a form.
type pager struct{ form Form }

// NewPager returns the pager of the task ledger for the rows of form f: it
// accepts a next link only with Graph's origin, the downstream path of the
// form, and $select=id,subject,body and $top=10 once each (GR-24, RB-58).
// In form D the path is /v1.0/me/messages; in form A it is
// /v1.0/users/{mailbox}/messages for one mailbox segment, and
// [Adapter.Execute] requires the registered mailbox of the workload when it
// follows the link.
func NewPager(f Form) task.Pager { return pager{f} }

// CheckNext implements [task.Pager].
func (p pager) CheckNext(link string) error {
	path := downstreamPath(RowGD1, "")
	if p.form == FormApplication {
		u, err := url.Parse(link)
		if err != nil {
			return errLink
		}
		mailbox, ok := strings.CutPrefix(u.EscapedPath(), "/v1.0/users/")
		mailbox, ok2 := strings.CutSuffix(mailbox, "/messages")
		if !ok || !ok2 || mailbox == "" || strings.ContainsAny(mailbox, "/%") || ascii.ToLower(mailbox) == "me" {
			return errLink
		}
		path = downstreamPath(RowGA1, mailbox)
	}
	if !linkOK(link, path) {
		return errLink
	}
	return nil
}
