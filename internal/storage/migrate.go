package storage

import (
	"embed"
	"fmt"
	"io"
	"net/url"

	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/postgres"
)

// migrations holds the dbmate migrations, one set per dialect; always a sqlite + postgres pair.
//
//go:embed migrations
var migrations embed.FS

func migrator(kind, dsn string) (*dbmate.DB, error) {
	var u *url.URL
	var err error
	switch kind {
	case "sqlite":
		u, err = url.Parse("sqlite:" + dsn)
	case "postgres":
		u, err = url.Parse(dsn)
	default:
		return nil, fmt.Errorf("storage: unknown VAULT_STORAGE %q", kind)
	}
	if err != nil {
		return nil, fmt.Errorf("storage: bad dsn")
	}
	m := dbmate.New(u)
	m.FS = migrations
	m.MigrationsDir = []string{"migrations/" + kind}
	m.AutoDumpSchema = false
	m.Log = io.Discard
	return m, nil
}

// Migrate applies all pending migrations, creating the database if needed.
func Migrate(kind, dsn string) error {
	m, err := migrator(kind, dsn)
	if err != nil {
		return err
	}
	return m.CreateAndMigrate()
}
