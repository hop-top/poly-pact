package db

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// SecretStore is the secret store that holds the login roles' credentials
// (component C14).
type SecretStore interface {
	// Secret returns the credential that ref names; an error when it holds
	// none.
	Secret(ctx context.Context, ref string) (string, error)
}

// PostgreSQL is the [Dialer] of a PostgreSQL 16 cluster through the pgx
// driver's database/sql connector (github.com/jackc/pgx/v5/stdlib).
type PostgreSQL struct {
	// Config is the connection configuration of the cluster: host, port,
	// database and TLS, as pgx.ParseConfig returns it. Its user and password
	// are replaced by those of the mapped role for every pool; its other
	// fields are kept, except the statement execution settings below.
	Config *pgx.ConnConfig
	// Secrets holds the credential of each mapped role. Required.
	Secrets SecretStore
}

var _ Dialer = PostgreSQL{}

// Connector returns the connector of the role of rec: the cluster's
// configuration with the role as the user and its credential as the
// password (RA-3), so the session user is the role.
//
// Statements run in the extended protocol with no statement or description
// cache (pgx QueryExecModeDescribeExec and capacities 0): DISCARD ALL on
// release deallocates every prepared statement, and a probe showed that the
// default cache of pgx v5.11.0 then fails the next use of a cached statement
// with SQLSTATE 26000 (see the package documentation, CR-5).
func (p PostgreSQL) Connector(ctx context.Context, rec RoleRecord) (driver.Connector, error) {
	if p.Config == nil || p.Secrets == nil {
		return nil, errors.New("db: postgres: no configuration or secret store")
	}
	secret, err := p.Secrets.Secret(ctx, rec.CredentialRef)
	if err != nil || secret == "" {
		return nil, fmt.Errorf("db: postgres: no credential for the role %q", rec.LoginRole)
	}
	cfg := p.Config.Copy()
	cfg.User = rec.LoginRole
	cfg.Password = secret
	cfg.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
	cfg.StatementCacheCapacity = 0
	cfg.DescriptionCacheCapacity = 0
	return stdlib.GetConnector(*cfg), nil
}
