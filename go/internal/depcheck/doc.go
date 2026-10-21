// Package depcheck holds the test that keeps module hop.top/pact-go on the
// standard library, except three named adapter packages that may each use
// one named module:
//
//	hop.top/pact-go/adapters/files  golang.org/x/sys
//	hop.top/pact-go/adapters/db     github.com/jackc/pgx/v5
//	hop.top/pact-go/adapters/ldap   github.com/go-ldap/ldap/v3
//
// Every other package of the module, tests included, imports only the
// standard library and the module, and depends on nothing else through
// other packages, adapter packages among them. An allowlisted package
// imports, outside the standard library and the module, only packages of
// its module, and reaches packages of other modules only through those
// imports. Every require line of go.mod names a module that an allowlisted
// package reaches: the named modules and what go mod tidy adds for them.
// Third-party dependencies of the commands, hop.top/kit among them, belong
// to the command module hop.top/pact (cli/ at the repository root),
// which the library never imports.
//
// The test runs go mod edit -json, and go list -deps -test once per
// platform (linux/amd64, darwin/arm64, windows/amd64), because a file
// built for one platform adds imports there only. It runs the go command
// with GOWORK=off, so the workspace of go.work at the repository root,
// which also holds the command module, cannot supply a module the library
// does not require.
package depcheck
