package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// TaskBinding is the task and the agent of a request, from its admitted
// presentation, reconciled with the authoritative task context (draft 10.1,
// 17.5). The gateway puts it on the context of AuthorizeNative with WithTask.
type TaskBinding struct {
	TaskID  string
	AgentID string
}

type taskKey struct{}

// WithTask returns ctx carrying the task binding of the request, which keys
// the handle AuthorizeNative opens (profile HI-1).
func WithTask(ctx context.Context, t TaskBinding) context.Context {
	return context.WithValue(ctx, taskKey{}, t)
}

func taskOf(ctx context.Context) TaskBinding {
	t, _ := ctx.Value(taskKey{}).(TaskBinding)
	return t
}

// HandleKey is the tuple a verified handle belongs to (profile HI-1).
type HandleKey struct {
	Realm       adapter.Realm
	PrincipalID string
	TaskID      string
	OperationID string
	AgentID     string
}

type handleRecord struct {
	h        Handle
	openedAt time.Time
}

// AuthorizeNative decides by the native open (profile 3.2): it opens the
// registered path of the operation's one resource under the principal's
// impersonation token, with the access right of the operation's action,
// and checks the object it opened before anything is read (profile PB-4).
//
//   - An open the access check refuses is a DENY of the open's source, with
//     no obligation: a native denial is final (draft 2.3).
//   - A verified open is an ALLOW of the open's source. Its handle is kept
//     for [Broker.Execute] under the request's [HandleKey]; nothing is read.
//   - A handle whose object is a reparse point, a directory, offline or not
//     fully present, or whose volume serial number, file identifier or final
//     path differs from the registry, is closed: [ErrObjectMismatch].
//   - An action with no access right, or an operation of another principal,
//     realm or of not exactly one resource, is [adapter.ErrContextMismatch];
//     a resource the registry does not hold is a DENY of the registry.
//   - No completed context, a failed or ineffective impersonation, a failed
//     revert and an unhealthy broker open nothing, or keep nothing.
//
// The decision carries no decision time, record or revision: the access
// check reports none.
func (b *Broker) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	if err := b.Healthy(); err != nil {
		return adapter.Decision{}, err
	}
	switch {
	case p.ID == "" || p.Realm != b.cfg.Realm || op.PrincipalID != p.ID:
		return adapter.Decision{}, fmt.Errorf("files: authorize: the operation is not the principal's in the broker's realm: %w", adapter.ErrContextMismatch)
	case len(op.Resources) != 1:
		return adapter.Decision{}, fmt.Errorf("files: authorize: an operation names one file: %w", adapter.ErrContextMismatch)
	}
	access, ok := b.actions[op.Action]
	if !ok {
		return adapter.Decision{}, fmt.Errorf("files: authorize: action %q has no access right; the broker opens files for reading only: %w", op.Action, adapter.ErrContextMismatch)
	}
	entry, ok := b.cfg.Files.Lookup(op.Resources[0])
	if !ok {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "the resource is not a registered file", SourceID: RegistrySourceID}, nil
	}
	c, ok := b.context(p.Realm, p.ID)
	if !ok {
		return adapter.Decision{}, fmt.Errorf("%w: no current Negotiate context for the principal", ErrImpersonationUnavailable)
	}
	var (
		h      Handle
		denied bool
	)
	err := b.impersonate(c, func() error {
		opened, err := b.cfg.FileSystem.Open(entry.Path, access)
		if errors.Is(err, ErrAccessDenied) {
			denied = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("files: the open failed: %v: %w", err, adapter.ErrDependencyUnavailable)
		}
		obj, err := opened.Object()
		if err == nil {
			err = verify(entry, obj)
		} else {
			err = fmt.Errorf("files: the handle cannot be queried: %v: %w", err, adapter.ErrDependencyUnavailable)
		}
		if err != nil {
			_ = opened.Close()
			return err
		}
		h = opened
		return nil
	})
	if err != nil {
		if h != nil {
			_ = h.Close()
		}
		return adapter.Decision{}, fmt.Errorf("files: authorize: %w", err)
	}
	if denied {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "the native access check denied the open", SourceID: b.cfg.OpenSourceID}, nil
	}
	t := taskOf(ctx)
	b.keep(HandleKey{Realm: p.Realm, PrincipalID: p.ID, TaskID: t.TaskID, OperationID: op.OperationID, AgentID: t.AgentID}, h)
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: b.cfg.OpenSourceID}, nil
}

// served refuses an object the broker never serves: a reparse point, a
// directory, and a file whose data is not immediately available (profile
// PB-4 (1), (2)).
func served(obj Object) error {
	switch {
	case obj.Attributes&AttrReparsePoint != 0:
		return fmt.Errorf("%w: a reparse point", ErrObjectMismatch)
	case obj.Attributes&(AttrDirectory|AttrOffline|AttrRecallOnDataAccess) != 0:
		return fmt.Errorf("%w: a directory, or a file whose data is not present", ErrObjectMismatch)
	}
	return nil
}

// verify is PB-4 in order: the attributes, then the volume serial number and
// the file identifier, then the final path, compared code unit for code unit.
func verify(e Entry, obj Object) error {
	if err := served(obj); err != nil {
		return err
	}
	if obj.VolumeSerial != e.VolumeSerial || obj.ObjectID != e.ObjectID {
		return fmt.Errorf("%w: another file identity", ErrObjectMismatch)
	}
	if obj.FinalPath != e.FinalPath {
		return fmt.Errorf("%w: another final path", ErrObjectMismatch)
	}
	return nil
}

// keep stores the verified handle of key, closing one it replaces and every
// handle past its lifetime.
func (b *Broker) keep(key HandleKey, h Handle) {
	now := b.cfg.Clock.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.handles[key]; ok {
		_ = old.h.Close()
	}
	b.handles[key] = &handleRecord{h: h, openedAt: now}
	b.expireLocked(now)
}

func (b *Broker) expireLocked(now time.Time) {
	for k, r := range b.handles {
		if now.Sub(r.openedAt) > b.cfg.HandleMaxLifetime {
			_ = r.h.Close()
			delete(b.handles, k)
		}
	}
}

// Execute serves the read of the operation key names: it writes the contents
// of the verified handle to w and closes it, so a handle serves one
// operation. A key that names no handle, because the tuple is another task's,
// operation's, agent's or principal's, is [adapter.ErrContextMismatch] and
// leaves every other handle as it is (profile HI-1). A handle older than its
// lifetime is closed unread, [ErrHandleExpired] (HI-2). The read runs outside
// the impersonation window, through the handle only, and a failed read is
// never retried as another identity (PB-7, HI-5).
func (b *Broker) Execute(ctx context.Context, key HandleKey, w io.Writer) (int64, error) {
	if err := live(ctx, "execute"); err != nil {
		return 0, err
	}
	if err := b.Healthy(); err != nil {
		return 0, err
	}
	now := b.cfg.Clock.Now()
	b.mu.Lock()
	r, ok := b.handles[key]
	if ok {
		delete(b.handles, key)
	}
	b.expireLocked(now)
	b.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("files: execute: no handle of this task, operation, agent and principal: %w", adapter.ErrContextMismatch)
	}
	defer func() { _ = r.h.Close() }()
	if now.Sub(r.openedAt) > b.cfg.HandleMaxLifetime {
		return 0, ErrHandleExpired
	}
	n, err := io.Copy(w, r.h)
	if err != nil {
		return n, fmt.Errorf("files: execute: the read failed: %v: %w", err, adapter.ErrDependencyUnavailable)
	}
	return n, nil
}

// EndTask closes every handle of the task (profile HI-2).
func (b *Broker) EndTask(taskID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, r := range b.handles {
		if k.TaskID == taskID {
			_ = r.h.Close()
			delete(b.handles, k)
		}
	}
}
