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

// DB wraps two sql.DB pools:
//   - writer: single connection, serialises all writes, no SQLITE_BUSY contention
//   - reader: multiple connections, allows concurrent reads without blocking writes
//
// WAL journal mode makes this work: readers never block writers and vice versa.
type DB struct {
	sql    *sql.DB // writer — also used for migrations and the SQL() accessor
	reader *sql.DB // read pool — used for SELECT queries
}

// Open opens (or creates) the SQLite database at path, applies all pending
// migrations, and returns a ready-to-use DB.
func Open(path string) (*DB, error) {
	baseDSN := fmt.Sprintf(
		"file:%s?_foreign_keys=on&_journal_mode=WAL&_synchronous=NORMAL",
		path,
	)

	// Writer pool: single connection serialises all writes.
	// No _txlock=immediate — not needed with one connection.
	// Short busy timeout: with one writer it should almost never trigger.
	writerDSN := baseDSN + "&_busy_timeout=10000"
	writer, err := sql.Open("sqlite", writerDSN)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite writer: %w", err)
	}
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)

	if err := writer.Ping(); err != nil {
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	if err := runMigrations(writer); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	// Reader pool: multiple connections for concurrent SELECTs.
	// WAL mode means readers never see partial writes and never block the writer.
	readerDSN := baseDSN + "&_busy_timeout=5000&mode=ro"
	reader, err := sql.Open("sqlite", readerDSN)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite reader: %w", err)
	}
	reader.SetMaxOpenConns(8)
	reader.SetMaxIdleConns(4)

	if err := reader.Ping(); err != nil {
		return nil, fmt.Errorf("pinging sqlite reader: %w", err)
	}

	return &DB{sql: writer, reader: reader}, nil
}

// Close closes both database connections.
func (d *DB) Close() error {
	_ = d.reader.Close()
	return d.sql.Close()
}

// SQL returns the writer *sql.DB for complex write queries and transactions.
func (d *DB) SQL() *sql.DB { return d.sql }

// ReadSQL returns the reader *sql.DB for complex SELECT queries.
func (d *DB) ReadSQL() *sql.DB { return d.reader }

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
		// For ALTER TABLE ADD COLUMN, skip if column already exists.
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
		// For ALTER TABLE RENAME COLUMN, skip if source doesn't exist or target already does.
		if isRenameColumn(stmt) {
			table, oldCol, newCol := parseRenameColumn(stmt)
			if table != "" && oldCol != "" && newCol != "" {
				srcExists, err := columnExists(db, table, oldCol)
				if err != nil {
					return err
				}
				if !srcExists {
					continue // source column doesn't exist — skip
				}
				dstExists, err := columnExists(db, table, newCol)
				if err != nil {
					return err
				}
				if dstExists {
					continue // target already exists — skip
				}
			}
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("executing %q: %w", truncate(stmt, 60), err)
		}
	}
	return nil
}

func splitStatements(src string) []string {
	// Strip inline -- comments first: they can contain semicolons
	// (e.g. "-- seconds; default 24 hours") that would break naive splitting.
	var sb strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	cleaned := sb.String()

	// Walk character by character, tracking BEGIN...END depth so that
	// trigger bodies (which contain semicolons) are kept intact.
	var stmts []string
	var cur strings.Builder
	depth := 0
	n := len(cleaned)

	for i := 0; i < n; {
		// Detect BEGIN keyword at a word boundary.
		if i+5 <= n && strings.ToUpper(cleaned[i:i+5]) == "BEGIN" &&
			(i == 0 || !isAlpha(cleaned[i-1])) &&
			(i+5 >= n || !isAlpha(cleaned[i+5])) {
			depth++
			cur.WriteString("BEGIN")
			i += 5
			continue
		}
		// Detect END keyword at a word boundary.
		if i+3 <= n && strings.ToUpper(cleaned[i:i+3]) == "END" &&
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
		if cleaned[i] == ';' {
			if depth == 0 {
				if s := strings.TrimSpace(cur.String()); s != "" {
					stmts = append(stmts, s)
				}
				cur.Reset()
			} else {
				cur.WriteByte(';')
			}
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

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
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

func isRenameColumn(stmt string) bool {
	upper := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(upper, "ALTER TABLE") && strings.Contains(upper, "RENAME COLUMN")
}

// parseRenameColumn parses: ALTER TABLE <table> RENAME COLUMN <old> TO <new>
func parseRenameColumn(stmt string) (table, oldCol, newCol string) {
	words := strings.Fields(stmt)
	// 0=ALTER 1=TABLE 2=<table> 3=RENAME 4=COLUMN 5=<old> 6=TO 7=<new>
	if len(words) >= 8 {
		return words[2], words[5], words[7]
	}
	return "", "", ""
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
