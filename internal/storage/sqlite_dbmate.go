package storage

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	"github.com/amacneil/dbmate/v2/pkg/dbutil"
)

// dbmate's bundled sqlite driver needs cgo; this is the same thing on the
// pure-Go modernc driver. No schema dump (AutoDumpSchema is off).
func init() { dbmate.RegisterDriver(newSQLiteMigrator, "sqlite") }

type sqliteMigrator struct {
	table string
	path  string
}

func newSQLiteMigrator(c dbmate.DriverConfig) dbmate.Driver {
	p := c.DatabaseURL.Opaque
	if p == "" {
		p = c.DatabaseURL.Path
	}
	return &sqliteMigrator{table: c.MigrationsTableName, path: p}
}

func (d *sqliteMigrator) Open() (*sql.DB, error) { return sql.Open("sqlite", d.path) }

func (d *sqliteMigrator) Ping() error {
	db, err := d.Open()
	if err != nil {
		return err
	}
	defer dbutil.MustClose(db)
	return db.Ping()
}

func (d *sqliteMigrator) CreateDatabase() error { return d.Ping() }

func (d *sqliteMigrator) DropDatabase() error {
	if err := os.Remove(d.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (d *sqliteMigrator) DatabaseExists() (bool, error) {
	_, err := os.Stat(d.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (d *sqliteMigrator) DumpSchema(*sql.DB, ...string) ([]byte, error) { return nil, nil }

func (d *sqliteMigrator) MigrationsTableExists(db *sql.DB) (bool, error) {
	var one int
	err := db.QueryRow(`SELECT 1 FROM sqlite_master WHERE type='table' AND name=?`, d.table).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (d *sqliteMigrator) CreateMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %q (version varchar(128) PRIMARY KEY)`, d.table))
	return err
}

func (d *sqliteMigrator) SelectMigrations(db *sql.DB, limit int) (map[string]bool, error) {
	q := fmt.Sprintf(`SELECT version FROM %q ORDER BY version DESC`, d.table) // #nosec G201 -- table name is dbmate config, not user input
	if limit >= 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer dbutil.MustClose(rows)
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func (d *sqliteMigrator) InsertMigration(tx dbutil.Transaction, version string) error {
	_, err := tx.Exec(fmt.Sprintf(`INSERT INTO %q (version) VALUES (?)`, d.table), version)
	return err
}

func (d *sqliteMigrator) DeleteMigration(tx dbutil.Transaction, version string) error {
	_, err := tx.Exec(fmt.Sprintf(`DELETE FROM %q WHERE version = ?`, d.table), version)
	return err
}

func (d *sqliteMigrator) QueryError(query string, err error) error {
	return &dbmate.QueryError{Err: err, Query: query}
}
