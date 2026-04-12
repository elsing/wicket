package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers as "sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps sql.DB and provides all query methods for wicket.
type DB struct {
	sql *sql.DB
}

// Open opens (or creates) the SQLite database at path, applies all pending
// migrations, and returns a ready-to-use DB.
func Open(path string) (*DB, error) {
	// WAL mode allows concurrent readers with one writer.
	// _busy_timeout=15000: wait up to 15s for locks before returning SQLITE_BUSY.
	// _synchronous=NORMAL: safe with WAL, faster than FULL.
	// _txlock=immediate: grab write lock immediately on BEGIN to avoid deadlocks.
	dsn := fmt.Sprintf(
		"file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=15000&_synchronous=NORMAL&_txlock=immediate",
		path,
	)

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// WAL mode supports multiple concurrent readers.
	// Allow up to 4 open connections: typically 1 writer + a few readers.
	// The busy_timeout handles the case where a writer is already active.
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	if err := runMigrations(sqlDB); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &DB{sql: sqlDB}, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error { return d.sql.Close() }

// SQL returns the underlying *sql.DB for complex queries.
func (d *DB) SQL() *sql.DB { return d.sql }

// Ping checks the database is reachable.
func (d *DB) Ping() error { return d.sql.Ping() }

// runMigrations applies .up.sql files from the embedded migrations directory
// that have not yet been applied. Tracks state in a schema_migrations table.
// execMigration runs each statement in a migration individually.
// ALTER TABLE ADD COLUMN statements are skipped if the column already exists,
// which makes migrations safe to apply against DBs that were partially migrated
// or had columns added outside of the migration system.
func execMigration(db *sql.DB, sql string) error {
	// Split on semicolons to get individual statements.
	stmts := splitStatements(sql)
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		// For ALTER TABLE ADD COLUMN, check if the column already exists.
		if isAddColumn(stmt) {
			table, col := parseAddColumn(stmt)
			if table != "" && col != "" {
				exists, err := columnExists(db, table, col)
				if err != nil {
					return err
				}
				if exists {
					continue // already present — skip
				}
			}
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("executing %q: %w", truncate(stmt, 60), err)
		}
	}
	return nil
}

func splitStatements(sql string) []string {
	// Simple split on semicolons. Doesn't handle semicolons inside strings,
	// but our migrations don't have those.
	var stmts []string
	for _, s := range strings.Split(sql, ";") {
		s = strings.TrimSpace(s)
		if s != "" {
			stmts = append(stmts, s)
		}
	}
	return stmts
}

func isAddColumn(stmt string) bool {
	upper := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(upper, "ALTER TABLE") && strings.Contains(upper, "ADD COLUMN")
}

func parseAddColumn(stmt string) (table, column string) {
	// ALTER TABLE <table> ADD COLUMN <col> ...
	// indices: 0=ALTER 1=TABLE 2=<table> 3=ADD 4=COLUMN 5=<col>
	words := strings.Fields(stmt)
	if len(words) >= 6 {
		return words[2], words[5]
	}
	return "", ""
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`SELECT 1 FROM pragma_table_info(?) WHERE name = ?`, table, column)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	return rows.Next(), rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func runMigrations(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT NOT NULL PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading migrations directory: %w", err)
	}

	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	for _, name := range upFiles {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&count); err != nil {
			return fmt.Errorf("checking migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}

		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		if err := execMigration(db, string(content)); err != nil {
			return fmt.Errorf("applying migration %s: %w", name, err)
		}

		if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, name); err != nil {
			return fmt.Errorf("recording migration %s: %w", name, err)
		}
	}

	return nil
}
