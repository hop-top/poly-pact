// Package googledir is the membership and status source of a Google
// Workspace directory: the draft 17.1 function read_native_claim answered
// from the Admin SDK Directory API and the Cloud Identity Groups API, with
// a service account that has domain-wide delegation. It is the fourth user
// of package [source]; the source document is
// spec/v1.0/profiles/sources/googledir.md and its cases are
// spec/v1.0/fixtures/sources/googledir. It uses the standard library only.
//
// # Facts
//
// A [Reader] serves three facts of a user, each at a native path:
//
//	PathAccountState                 "active", or "disabled" for a suspended or archived user
//	MemberPath(group)                members.hasMember: direct, or nested in the same domain
//	TransitiveMemberPath(group)      checkTransitiveMembership: any chain of nested groups
//
// Only the groups named in [Config] are served. A live fact carries the
// time the first request of the read was made. With [Config.Cache] the
// account state is served from the [source.Store] that a [Feed] fills, with
// the request time of the page or user read that produced it, and a fact
// older than [Config.MaxAge] is not served.
//
// # Join
//
// A principal joins a user only through the user's unique ID: the local
// part of the principal under [Config.PrincipalPrefix], in the one spelling
// of identity mapping IM-2. The Directory accepts an address or an alias
// where an ID goes, so the reader refuses a local part with "@" before any
// request, and a reply whose ID is not the one asked for. An address is read
// only to put it in the Cloud Identity query, from the verified user's own
// record at that read.
//
// # Change feed
//
// A [Feed] keeps the cache current in two ways. A push channel of the
// Directory API (users.watch, the update event) names the users that
// changed; [Feed.Handler] verifies each notification and reads the user back.
// A sweep of the user list runs every poll interval whether or not a channel
// is open, because the vendor states no delivery guarantee: the bound of the
// cache is the poll interval, and the channel only shortens the usual time.
// A channel does not renew itself; [Feed.Tick] opens a new one before the
// open one expires, stops the old, and falls back to the sweep alone when no
// channel can be opened. The feed starts no goroutine: the deployment calls
// Tick on its schedule.
//
// # Credentials
//
// A [ServiceAccount] signs the assertion of the service account flow with
// the account's RSA key and exchanges it for an access token, reused until
// shortly before it expires. A [Client] takes one token source per API, each
// holding the read-only scopes of that API only.
package googledir
