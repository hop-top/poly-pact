package task

import (
	"context"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// Ref is a native task reference: the task registry's identifier of a native
// task, such as native-task:september-summary-007 (profile section 2). It is
// opaque and compared octet for octet.
type Ref string

// Key is the ledger key (MO-1): the realm together with the native task
// reference. A reference of another realm that is spelled the same is
// another key.
type Key struct {
	Realm adapter.Realm
	Task  Ref
}

// State is the state of a native task (profile section 9.1). Every state but
// StateActive is terminal and immutable; the first terminal state wins
// (MO-49).
type State string

const (
	// StateActive: the registry reports the task active and now is before
	// the deadline.
	StateActive State = "Active"
	// StateCompleted: the registry reports the task done.
	StateCompleted State = "Completed"
	// StateCancelled: the registry cancelled the task.
	StateCancelled State = "Cancelled"
	// StateExpired: the deadline passed (MO-23).
	StateExpired State = "Expired"
)

// OpState is the state of an operation record (profile section 3.2).
// OpSucceeded, OpFailed and OpReleased are terminal for the record.
type OpState string

const (
	// OpReserved: recorded before the request is sent (write-ahead, MO-26).
	OpReserved OpState = "Reserved"
	// OpAccepted: the native API acknowledged without completing (201 or
	// 202, MO-41).
	OpAccepted OpState = "Accepted"
	// OpSucceeded: the operation took effect.
	OpSucceeded OpState = "Succeeded"
	// OpFailed: definitively rejected (MO-37), finished without success
	// (MO-44), or shown not applied by an authoritative status read (MO-38).
	OpFailed OpState = "Failed"
	// OpUnknown: an ambiguous effect (MO-35).
	OpUnknown OpState = "Unknown"
	// OpReleased: provably never sent; the counters are restored (MO-22).
	OpReleased OpState = "Released"
)

// Class is the executor class of a route (profile section 6.1).
type Class string

const (
	// ClassRead: a safe, idempotent method. Each attempt is a new operation
	// (MO-34).
	ClassRead Class = "read"
	// ClassKeyedWrite: a write whose native API accepts a key and suppresses
	// the repeat, with the key behaviour cited by the integration profile
	// (MO-25).
	ClassKeyedWrite Class = "keyed-write"
	// ClassLedgerWrite: a ledger-deduplicated write. The ledger sends at most
	// one request per logical operation (MO-33).
	ClassLedgerWrite Class = "ledger-deduplicated-write"
)

// Limit is one budget dimension of a task. The zero Limit is not set, which
// is a configuration error (MO-15); [Bounded] sets a bound and [Unbounded]
// is the explicit null of an unlimited dimension.
type Limit struct {
	n    int64
	kind limitKind
}

type limitKind uint8

const (
	limitUnset limitKind = iota
	limitBounded
	limitNone
)

// Bounded returns the limit n.
func Bounded(n int64) Limit { return Limit{n: n, kind: limitBounded} }

// Unbounded returns the explicit null of an unlimited dimension (MO-15).
func Unbounded() Limit { return Limit{kind: limitNone} }

// Value returns the limit and true for a bounded dimension, and false for an
// unlimited or unset one.
func (l Limit) Value() (int64, bool) { return l.n, l.kind == limitBounded }

// Limits are the limits of a task (profile section 5.1). They come from the
// registry record and may be lowered, never raised, by the installed mapping
// (MO-18).
type Limits struct {
	MaxOperations Limit
	MaxPages      Limit
	MaxBytes      Limit
	// Deadline is the registry's deadline of the task.
	Deadline time.Time
}

// Record is the registry record of a native task.
type Record struct {
	Ref    Ref
	State  State
	Limits Limits
	// AuthorityExpires is the expiry of the native delegation or authority
	// the task rests on; the zero time means none. The deadline of the task
	// is the earlier of it and Limits.Deadline (MO-23).
	AuthorityExpires time.Time
}

// Registry is the native task registry, the task_attribution_source of the
// deployment (draft Section 17.5). The ledger reads it; it never writes it.
type Registry interface {
	// Resolve reconciles a client task_id (Intent.task_id) for the principal
	// and the agent: it returns every native task reference the value names
	// for them (MO-3). Exactly one reference reconciles the value.
	Resolve(ctx context.Context, realm adapter.Realm, principalID string, agent adapter.AgentID, clientTaskID string) ([]Ref, error)
	// Lookup reads the record of a reference. It returns [ErrNoRecord] when
	// the registry has none and an error that wraps
	// [adapter.ErrDependencyUnavailable] when it cannot answer.
	Lookup(ctx context.Context, realm adapter.Realm, ref Ref) (Record, error)
}

// Route describes the downstream request of a translation row as the
// integration profile states it (profile section 14).
type Route struct {
	// ID names the row; Version is the installed mapping version. A
	// continuation is followed only under the same ones (RB-58).
	ID, Version string
	// Class is the executor class of the row.
	Class Class
	// Page is true when the request returns a page: it counts against
	// max_pages, the first page included (MO-55).
	Page bool
	// Definitive lists the statuses the native API documents as rejected
	// before any effect (MO-37). Every other status that is not a success,
	// and every transport failure after the send, is ambiguous.
	Definitive []int
}

// Request is one admitted operation as the gateway hands it to the ledger.
type Request struct {
	// Principal is the authenticated principal, its realm and workload.
	Principal adapter.Principal
	// AgentID is the enrolled agent of the admission.
	AgentID adapter.AgentID
	// TaskID is the client's Intent.task_id. It is advisory (MO-3).
	TaskID string
	// Operation is the admitted operation context. Its covered
	// idempotency-key header, when present, is the client key (MO-29).
	Operation core.OperationContext
	// Route is the translation row of the operation.
	Route Route
	// Continuation is the gateway token of the page to fetch, empty for a
	// first page or a request that is not a page (RB-57).
	Continuation string
	// BodyLength is the length in octets of the request body the gateway
	// sends: the bytes that Operation.BodyDigest hashes, after HTTP transfer
	// decoding (draft Section 10.2). For a write it counts against max_bytes
	// at the reservation, before the request is sent; a write whose body
	// would pass max_bytes is refused with budget-exhausted (MO-61). It is
	// zero for an empty body.
	BodyLength int64
}

// Binding is the binding of a ledger entry, recorded at its first
// reservation (MO-7).
type Binding struct {
	PrincipalID string
	AgentID     adapter.AgentID
	Workload    adapter.Workload
}

// Budget is the limits and the counters of a task (profile section 5).
type Budget struct {
	// Limits are those of the registry record as last read (MO-18).
	Limits Limits
	// Operations and Pages count reservations; Bytes counts the bytes of
	// response bodies released to the agent (MO-21) and, for a write, the
	// bytes of the request body sent (MO-61).
	Operations, Pages, Bytes int64
}

// Operation is the record of one logical operation of a task (profile
// section 3.2).
type Operation struct {
	// ID identifies the record in its entry.
	ID string
	// OperationID is the operation_id of the operation context that made the
	// record.
	OperationID string
	// Fingerprint is the object_digest of the logical operation (MO-27).
	Fingerprint core.Digest
	// IdempotencyKey is the key sent with every attempt: the client key
	// (MO-29) or the one the ledger drew (MO-30); empty for a read.
	IdempotencyKey string
	State          OpState
	Attempts       int
	// NativeRef is the native reference of the effect, when the native API
	// gave one.
	NativeRef string
	// Handle is the async handle of an accepted operation (MO-41, MO-42).
	Handle string
	// RetryAfter is the wait the native API asked for before the next status
	// read; zero when it gave none (MO-45).
	RetryAfter time.Duration
}

// Entry is the ledger entry of a native task (profile section 3.2).
type Entry struct {
	Key        Key
	State      State
	Binding    Binding
	Budget     Budget
	Operations []Operation
}

// Reservation is the answer to [TaskLedger.Reserve].
type Reservation struct {
	// Key is the ledger key: the native task reference the request
	// reconciled to (MO-3).
	Key Key
	// Operation is the operation record.
	Operation Operation
	// Send is true when the request is to be sent. It is false for a repeat
	// answered from a terminal record (MO-31): nothing is sent.
	Send bool
	// BytesLeft is the remaining max_bytes of the task, or -1 when the
	// dimension is unlimited. The gateway reads the response through a
	// reader that stops at BytesLeft plus one (MO-21).
	BytesLeft int64
}

// Result is how the attempt of a reservation ended, as the gateway saw it.
type Result struct {
	// Sent is false only when the request provably was not sent (MO-22).
	Sent bool
	// Status is the HTTP status of a response that was read; zero when no
	// response establishes the result: a timeout, a connection closed after
	// the request was written, a response that cannot be read (MO-35).
	Status int
	// Handle is the async handle of a 201 or 202: the Azure-AsyncOperation
	// URL when the response carries one, otherwise the Location URL (MO-42).
	Handle string
	// RetryAfter is the response's Retry-After, zero when it had none.
	RetryAfter time.Duration
	// NativeRef is the native reference of the effect, when given.
	NativeRef string
	// Bytes is the length of the response body read for release.
	Bytes int64
	// NextLink is the continuation of a page response, empty when none.
	NextLink string
}

// Settled is the record after an attempt or a status read, with the outcome
// report of the event (profile section 11).
type Settled struct {
	Operation Operation
	// PageToken is the gateway token of the recorded continuation, empty
	// when none was recorded (RB-57, MO-59).
	PageToken string
	// Report is the observation of the event under the draft Section 14.5
	// row of profile section 11; nil when the event has none. Its TaskID is
	// the native task reference (MO-5).
	Report *adapter.Observation
}

// Effect is what a native status read established about an operation.
type Effect string

const (
	// EffectApplied: the operation took effect or finished successfully.
	EffectApplied Effect = "applied"
	// EffectNone: the operation had no effect or finished without success.
	EffectNone Effect = "none"
	// EffectCancelled: the operation finished with the native status
	// cancelled (MO-44).
	EffectCancelled Effect = "cancelled"
	// EffectRunning: the operation is accepted and still running.
	EffectRunning Effect = "running"
	// EffectIndeterminate: the read established nothing.
	EffectIndeterminate Effect = "indeterminate"
)

// Status is the result of one native status read.
type Status struct {
	Effect Effect
	// Authoritative is true when the source is authoritative_current and was
	// read with a status age of zero. Only such a read of no effect makes an
	// Unknown record Failed (MO-38).
	Authoritative bool
	// Handle is the async handle when the read found the operation accepted.
	Handle string
	// RetryAfter is the wait before the next read, zero when none was given.
	RetryAfter time.Duration
}

// StatusSource is the native status source of a route (MO-38, MO-40): a
// read-only native lookup under the executor identity class of the row
// (MO-48). For an accepted operation it reads the handle; for an ambiguous
// one it reads the integration's lookup.
type StatusSource interface {
	ReadStatus(ctx context.Context, k Key, op Operation) (Status, error)
}

// Pager is the hook of a paged row that checks a next link before the ledger
// records it: the link has the origin and path of the row (RB-58). A link it
// refuses is not recorded and yields no page token.
type Pager interface {
	CheckNext(link string) error
}

// TaskLedger is the task ledger.
type TaskLedger interface {
	// Resolve reconciles req.TaskID with the registry (MO-3) and returns the
	// ledger key. It changes nothing and makes no entry (MO-6).
	Resolve(ctx context.Context, req Request) (Key, error)
	// Reserve runs the tests of profile section 3.3, in order: the task state
	// and the registry, the binding, the deadline, the fingerprint, then the
	// budget, and reserves one attempt. A refusal changes no counter (MO-17).
	Reserve(ctx context.Context, req Request) (Reservation, error)
	// Record records how the attempt of a reservation ended. A response that
	// would take the bytes past max_bytes is refused with
	// budget-exhausted and is not released (MO-21).
	Record(ctx context.Context, res Reservation, r Result) (Settled, error)
	// Observe records a native status read of an operation (sections 7, 8).
	Observe(ctx context.Context, k Key, opID string, s Status) (Settled, error)
	// Entry reads the entry of a task. It returns [ErrNoEntry] when the
	// ledger has none.
	Entry(ctx context.Context, k Key) (Entry, error)
}
