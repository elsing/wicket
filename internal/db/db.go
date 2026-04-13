package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a *sql.DB backed by PostgreSQL.
type DB struct {
	sql *sql.DB
}

// Open opens a connection to the PostgreSQL database at dsn, applies all
// pending migrations, and returns a ready-to-use DB.
// dsn format: "postgres://user:pass@host:5432/dbname?sslmode=disable"
func Open(dsn string) (*DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return &DB{sql: db}, nil
}

// Close closes the database connection pool.
func (d *DB) Close() error { return d.sql.Close() }

// SQL returns the underlying *sql.DB.
func (d *DB) SQL() *sql.DB { return d.sql }

// ReadSQL returns the same pool — Postgres handles concurrency natively.
func (d *DB) ReadSQL() *sql.DB { return d.sql }

// Ping checks the database is reachable.
func (d *DB) Ping() error { return d.sql.Ping() }

// runMigrations applies pending .up.sql files from the embedded migrations dir.
// State is tracked in a schema_migrations table.
func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT NOT NULL PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}

	// Sort by filename so migrations run in order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		version := strings.TrimSuffix(name, ".up.sql")

		var applied bool
		err := db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`,
			version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", version, err)
		}
		if applied {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		if err := execMigration(db, string(data)); err != nil {
			return fmt.Errorf("applying migration %s: %w", name, err)
		}

		if _, err := db.Exec(
			`INSERT INTO schema_migrations (version) VALUES ($1)`,
			version,
		); err != nil {
			return fmt.Errorf("recording migration %s: %w", version, err)
		}
	}
	return nil
}

// execMigration runs each statement in a migration individually.
// Ignores empty statements. Skips ADD COLUMN if column already exists.
// Skips RENAME COLUMN if source doesn't exist or target already does.
func execMigration(db *sql.DB, sqlStr string) error {
	stmts := splitStatements(sqlStr)
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		if isAddColumn(stmt) {
			table, col := parseAddColumn(stmt)
			if table != "" && col != "" {
				exists, err := columnExists(db, table, col)
				if err != nil {
					return err
				}
				if exists {
					continue
				}
			}
		}

		if isRenameColumn(stmt) {
			table, oldCol, newCol := parseRenameColumn(stmt)
			if table != "" {
				srcExists, err := columnExists(db, table, oldCol)
				if err != nil {
					return err
				}
				if !srcExists {
					continue
				}
				dstExists, err := columnExists(db, table, newCol)
				if err != nil {
					return err
				}
				if dstExists {
					continue
				}
			}
		}

		if _, err := db.Exec(stmt); err != nil {
			// IF NOT EXISTS statements are idempotent — skip duplicate object errors.
			errMsg := err.Error()
			if strings.Contains(errMsg, "already exists") {
				continue
			}
			return fmt.Errorf("executing statement: %w\nSQL: %s", err, stmt)
		}
	}
	return nil
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_name = $1 AND column_name = $2
		)
	`, strings.ToLower(table), strings.ToLower(column)).Scan(&exists)
	return exists, err
}

func isAddColumn(stmt string) bool {
	upper := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(upper, "ALTER TABLE") && strings.Contains(upper, "ADD COLUMN")
}

func parseAddColumn(stmt string) (table, column string) {
	words := strings.Fields(stmt)
	if len(words) >= 6 {
		return words[2], words[5]
	}
	return "", ""
}

func isRenameColumn(stmt string) bool {
	upper := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(upper, "ALTER TABLE") && strings.Contains(upper, "RENAME COLUMN")
}

func parseRenameColumn(stmt string) (table, oldCol, newCol string) {
	words := strings.Fields(stmt)
	if len(words) >= 8 {
		return words[2], words[5], words[7]
	}
	return "", "", ""
}

// splitStatements splits SQL on semicolons, respecting BEGIN...END blocks.
// Strips inline -- comments before splitting.
func splitStatements(src string) []string {
	cleaned := stripInlineComments(src)
	var stmts []string
	var cur strings.Builder
	depth := 0
	i := 0
	n := len(cleaned)
	for i < n {
		if strings.ToUpper(cleaned[i:min(i+5, n)]) == "BEGIN" &&
			(i == 0 || !isAlpha(cleaned[i-1])) &&
			(i+5 >= n || !isAlpha(cleaned[i+5])) {
			depth++
			cur.WriteString("BEGIN")
			i += 5
			continue
		}
		if strings.ToUpper(cleaned[i:min(i+3, n)]) == "END" &&
			(i == 0 || !isAlpha(cleaned[i-1])) &&
			(i+3 >= n || !isAlpha(cleaned[i+3])) {
			depth--
			cur.WriteString("END")
			i += 3
			if depth == 0 {
				if s := strings.TrimSpace(cur.String()); s != "" {
					stmts = append(stmts, s)
				}
				cur.Reset()
			}
			continue
		}
		if cleaned[i] == ';' && depth == 0 {
			if s := strings.TrimSpace(cur.String()); s != "" {
				stmts = append(stmts, s)
			}
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(cleaned[i])
		i++
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

func stripInlineComments(src string) string {
	var out strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
