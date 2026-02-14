// Package store provides SQLite-backed persistence for sessions and
// decrypted cast data, with FTS5 full-text search over terminal output.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"rb2-tty/internal/models"
)

// Store wraps a SQLite database for session and cast storage.
type Store struct {
	db *sql.DB
}

// SearchResult is a session augmented with a text snippet from FTS.
type SearchResult struct {
	models.Session
	Snippet string `json:"snippet"`
}

// New opens (or creates) the SQLite database at dbPath and runs migrations.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrations

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			s3_path    TEXT PRIMARY KEY,
			host       TEXT NOT NULL,
			session_id TEXT NOT NULL,
			total_size INTEGER NOT NULL,
			blob_count INTEGER NOT NULL,
			start_time INTEGER NOT NULL,
			end_time   INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS casts (
			session_id   TEXT PRIMARY KEY,
			cast_data    BLOB NOT NULL,
			decrypted_at INTEGER NOT NULL
		)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS casts_fts USING fts5(
			session_id UNINDEXED,
			host       UNINDEXED,
			s3_path    UNINDEXED,
			text_content,
			tokenize = 'porter unicode61'
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("migration: %w\nSQL: %s", err, stmt)
		}
	}

	// Add columns (ignore errors if they already exist).
	db.Exec(`ALTER TABLE casts ADD COLUMN users TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE casts ADD COLUMN duration_secs REAL NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE casts ADD COLUMN blob_count_at_index INTEGER NOT NULL DEFAULT 0`)

	return nil
}

// sessions

// UpsertSessions inserts or replaces session metadata.
func (s *Store) UpsertSessions(sessions []models.Session) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO sessions
		(s3_path, host, session_id, total_size, blob_count, start_time, end_time)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, sess := range sessions {
		_, err := stmt.Exec(
			sess.S3Path, sess.Host, sess.SessionID,
			sess.TotalSize, sess.BlobCount,
			sess.StartTime.Unix(), sess.EndTime.Unix(),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListSessions returns all sessions ordered by end_time descending,
// including detected shell users and recording duration from the cast data.
func (s *Store) ListSessions() ([]models.Session, error) {
	rows, err := s.db.Query(`SELECT s.s3_path, s.host, s.session_id,
		s.total_size, s.blob_count, s.start_time, s.end_time,
		COALESCE(c.users, ''),
		COALESCE(c.duration_secs, 0)
		FROM sessions s
		LEFT JOIN casts c ON c.session_id = s.session_id
		ORDER BY s.end_time DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanSessionsWithUsers(rows)
}

// GetSession returns a single session by s3_path.
func (s *Store) GetSession(s3Path string) (*models.Session, error) {
	row := s.db.QueryRow(`SELECT s.s3_path, s.host, s.session_id,
		s.total_size, s.blob_count, s.start_time, s.end_time,
		COALESCE(c.users, ''),
		COALESCE(c.duration_secs, 0)
		FROM sessions s
		LEFT JOIN casts c ON c.session_id = s.session_id
		WHERE s.s3_path = ?`, s3Path)

	var sess models.Session
	var startUnix, endUnix int64
	var usersStr string
	err := row.Scan(&sess.S3Path, &sess.Host, &sess.SessionID,
		&sess.TotalSize, &sess.BlobCount, &startUnix, &endUnix, &usersStr, &sess.DurationSecs)
	if err != nil {
		return nil, err
	}
	sess.StartTime = time.Unix(startUnix, 0)
	sess.EndTime = time.Unix(endUnix, 0)
	if usersStr != "" {
		sess.Users = strings.Split(usersStr, ",")
	}
	sess.Finalize()
	return &sess, nil
}

// casts

// HasCast returns true if the cast data for sessionID is stored.
func (s *Store) HasCast(sessionID string) bool {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM casts WHERE session_id = ?`, sessionID).Scan(&n)
	return err == nil && n > 0
}

// GetCast returns the raw .cast data for a session.
func (s *Store) GetCast(sessionID string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT cast_data FROM casts WHERE session_id = ?`, sessionID).Scan(&data)
	if err != nil {
		return nil, fmt.Errorf("cast not found for %s: %w", sessionID, err)
	}
	return data, nil
}

// StoreCast saves decrypted cast data, detected users, recording duration,
// and indexes the plain text for FTS. blobCountAtIndex is the number of S3
// blobs concatenated into castData, used to detect when new blobs need re-indexing.
func (s *Store) StoreCast(sessionID, host, s3Path string, castData []byte, textContent string, users []string, durationSecs float64, blobCountAtIndex int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	usersStr := strings.Join(users, ",")

	_, err = tx.Exec(`INSERT OR REPLACE INTO casts (session_id, cast_data, decrypted_at, users, duration_secs, blob_count_at_index)
		VALUES (?, ?, ?, ?, ?, ?)`, sessionID, castData, time.Now().Unix(), usersStr, durationSecs, blobCountAtIndex)
	if err != nil {
		return err
	}

	// Remove old FTS entry if exists, then insert new one.
	_, _ = tx.Exec(`DELETE FROM casts_fts WHERE session_id = ?`, sessionID)
	_, err = tx.Exec(`INSERT INTO casts_fts (session_id, host, s3_path, text_content)
		VALUES (?, ?, ?, ?)`, sessionID, host, s3Path, textContent)
	if err != nil {
		return fmt.Errorf("FTS insert: %w", err)
	}

	return tx.Commit()
}

// UnindexedSessionIDs returns session_ids that don't have cast data yet.
func (s *Store) UnindexedSessionIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT session_id FROM sessions
		WHERE session_id NOT IN (SELECT session_id FROM casts)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SessionsNeedingReindex returns session_ids that have a cast but whose S3
// blob_count has increased since we last indexed, so duration/cast_data are stale.
func (s *Store) SessionsNeedingReindex() ([]string, error) {
	rows, err := s.db.Query(`SELECT s.session_id FROM sessions s
		INNER JOIN casts c ON c.session_id = s.session_id
		WHERE s.blob_count > COALESCE(c.blob_count_at_index, 0)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// search

// Search performs an FTS5 query and returns matching sessions with snippets.
func (s *Store) Search(query string) ([]SearchResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}

	// Escape double quotes in user input for FTS5 safety.
	safeQuery := strings.ReplaceAll(query, `"`, `""`)
	// Wrap each word in quotes so FTS treats them as tokens.
	words := strings.Fields(safeQuery)
	for i, w := range words {
		words[i] = `"` + w + `"`
	}
	ftsQuery := strings.Join(words, " ")

	rows, err := s.db.Query(`
		SELECT
			f.session_id,
			f.host,
			f.s3_path,
			snippet(casts_fts, 3, '>>>', '<<<', '...', 48) as snip,
			COALESCE(s.total_size, 0),
			COALESCE(s.blob_count, 0),
			COALESCE(s.start_time, 0),
			COALESCE(s.end_time, 0),
			COALESCE(c.users, ''),
			COALESCE(c.duration_secs, 0)
		FROM casts_fts f
		LEFT JOIN sessions s ON s.s3_path = f.s3_path
		LEFT JOIN casts c ON c.session_id = f.session_id
		WHERE casts_fts MATCH ?
		ORDER BY rank
		LIMIT 50
	`, ftsQuery)
	if err != nil {
		return nil, fmt.Errorf("FTS search: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var startUnix, endUnix int64
		var usersStr string
		err := rows.Scan(
			&r.SessionID, &r.Host, &r.S3Path, &r.Snippet,
			&r.TotalSize, &r.BlobCount, &startUnix, &endUnix,
			&usersStr, &r.DurationSecs,
		)
		if err != nil {
			return nil, err
		}
		r.StartTime = time.Unix(startUnix, 0)
		r.EndTime = time.Unix(endUnix, 0)
		if usersStr != "" {
			r.Users = strings.Split(usersStr, ",")
		}
		r.Finalize()
		results = append(results, r)
	}
	return results, rows.Err()
}

// BackfillUsers re-extracts users from already-stored cast data where
// users is empty. extractFn receives the cast_data bytes and returns users.
func (s *Store) BackfillUsers(extractFn func(castData []byte) []string) error {
	rows, err := s.db.Query(`SELECT session_id, cast_data FROM casts WHERE users = ''`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type pending struct {
		id   string
		data []byte
	}
	var items []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.data); err != nil {
			return err
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range items {
		users := extractFn(p.data)
		usersStr := strings.Join(users, ",")
		if _, err := s.db.Exec(`UPDATE casts SET users = ? WHERE session_id = ?`, usersStr, p.id); err != nil {
			return err
		}
	}
	return nil
}

// BackfillDuration re-extracts duration from stored cast data where
// duration_secs is 0. extractFn receives cast_data bytes and returns seconds.
func (s *Store) BackfillDuration(extractFn func(castData []byte) float64) error {
	rows, err := s.db.Query(`SELECT session_id, cast_data FROM casts WHERE duration_secs = 0`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type pending struct {
		id   string
		data []byte
	}
	var items []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.data); err != nil {
			return err
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, p := range items {
		dur := extractFn(p.data)
		if _, err := s.db.Exec(`UPDATE casts SET duration_secs = ? WHERE session_id = ?`, dur, p.id); err != nil {
			return err
		}
	}
	return nil
}

// helpers

func scanSessionsWithUsers(rows *sql.Rows) ([]models.Session, error) {
	var sessions []models.Session
	for rows.Next() {
		var sess models.Session
		var startUnix, endUnix int64
		var usersStr string
		err := rows.Scan(&sess.S3Path, &sess.Host, &sess.SessionID,
			&sess.TotalSize, &sess.BlobCount, &startUnix, &endUnix, &usersStr,
			&sess.DurationSecs)
		if err != nil {
			return nil, err
		}
		sess.StartTime = time.Unix(startUnix, 0)
		sess.EndTime = time.Unix(endUnix, 0)
		if usersStr != "" {
			sess.Users = strings.Split(usersStr, ",")
		}
		sess.Finalize()
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}
