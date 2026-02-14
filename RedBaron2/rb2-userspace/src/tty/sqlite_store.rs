//! SQLite-backed storage for TTY session recordings
//!
//! Sessions are stored in a `sessions` table and their encrypted+compressed
//! blob chunks in a `blobs` table linked as a chain via `prev_blob_id` + `seq`.

use anyhow::{Context, anyhow};
use log::{debug, warn};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Shared handle to the SQLite store (sqlx pool is Clone + Send + Sync).
#[derive(Clone)]
pub struct TtyDb {
    pool: SqlitePool,
    page_size: i64,
}

/// A row from the blobs table used by the S3 forwarder.
pub struct BlobRow {
    pub blob_id: String,
    pub session_id: String,
    pub data: Vec<u8>,
    pub created_at: i64,
}

impl TtyDb {
    /// Open (or create) the database at `path`.
    ///
    /// If the file is missing, corrupt, or otherwise unreadable the method
    /// removes any partial file and re-creates from scratch with a warning.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating dir {}", parent.display()))?;
        }

        let pool = match try_open(path).await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "TTY SQLite DB at {} failed to open ({e:#}); recreating",
                    path.display()
                );
                let _ = tokio::fs::remove_file(path).await;
                try_open(path).await.with_context(|| {
                    format!("recreating TTY DB at {} also failed", path.display())
                })?
            }
        };

        // page_size
        let page_size: i64 = sqlx::query("PRAGMA page_size;")
            .fetch_one(&pool)
            .await
            .ok()
            .and_then(|row| row.try_get::<i64, _>(0).ok())
            .unwrap_or(4096);

        debug!(
            "TTY SQLite DB opened at {} (page_size={})",
            path.display(),
            page_size
        );

        Ok(Self { pool, page_size })
    }

    // session helpers

    /// Insert a new session row.
    pub async fn insert_session(
        &self,
        session_id: Uuid,
        rows: u16,
        cols: u16,
        header_json: &str,
    ) -> anyhow::Result<()> {
        let now = unix_now();
        let sid = session_id.to_string();

        sqlx::query(
            "INSERT INTO sessions (session_id, created_at, rows, cols, header_json, first_blob_id, last_blob_id)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)"
        )
        .bind(&sid)
        .bind(now)
        .bind(rows as i64)
        .bind(cols as i64)
        .bind(header_json)
        .execute(&self.pool)
        .await
        .with_context(|| format!("insert session {sid}"))?;

        Ok(())
    }

    /// Append a new blob to a session's chain.
    ///
    /// `data` is the already-compressed-then-encrypted payload.
    /// Returns the new `blob_id`.
    pub async fn append_blob(
        &self,
        session_id: &str,
        data: &[u8],
        plain_size: usize,
    ) -> anyhow::Result<String> {
        let blob_id = Uuid::new_v4().to_string();
        let now = unix_now();

        let mut tx = self.pool.begin().await?;

        // last_blob_id
        let last: Option<String> =
            sqlx::query("SELECT last_blob_id FROM sessions WHERE session_id = ?1")
                .bind(session_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| anyhow!("session {session_id} not found"))?
                .try_get::<Option<String>, _>(0)?;

        // next seq
        let seq: i64 = if last.is_some() {
            sqlx::query("SELECT COALESCE(MAX(seq), 0) + 1 FROM blobs WHERE session_id = ?1")
                .bind(session_id)
                .fetch_one(&mut *tx)
                .await?
                .try_get::<i64, _>(0)?
        } else {
            0
        };

        sqlx::query(
            "INSERT INTO blobs (blob_id, session_id, prev_blob_id, seq, data, plain_size, created_at, forwarded)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)"
        )
        .bind(&blob_id)
        .bind(session_id)
        .bind(&last)             // prev_blob_id
        .bind(seq)
        .bind(data)
        .bind(plain_size as i64)
        .bind(now)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("insert blob for session {session_id}"))?;

        // Update chain pointers
        if seq == 0 {
            sqlx::query(
                "UPDATE sessions SET first_blob_id = ?1, last_blob_id = ?1 WHERE session_id = ?2",
            )
            .bind(&blob_id)
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("UPDATE sessions SET last_blob_id = ?1 WHERE session_id = ?2")
                .bind(&blob_id)
                .bind(session_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        debug!(
            "Appended blob {} to session {} (seq={}, {} bytes encrypted, {} bytes plain)",
            blob_id,
            session_id,
            seq,
            data.len(),
            plain_size,
        );

        Ok(blob_id)
    }

    // S3 forwarding helpers

    /// Fetch all blobs that have not been forwarded yet, ordered by session then sequence number.
    pub async fn unforwarded_blobs(&self) -> anyhow::Result<Vec<BlobRow>> {
        let rows = sqlx::query(
            "SELECT blob_id, session_id, data, created_at
             FROM blobs WHERE forwarded = 0
             ORDER BY session_id, seq ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(BlobRow {
                blob_id: r.try_get::<String, _>(0)?,
                session_id: r.try_get::<String, _>(1)?,
                data: r.try_get::<Vec<u8>, _>(2)?,
                created_at: r.try_get::<i64, _>(3)?,
            });
        }
        Ok(out)
    }

    /// Look up the header JSON for a session.
    pub async fn session_header(&self, session_id: &str) -> anyhow::Result<String> {
        let row = sqlx::query("SELECT header_json FROM sessions WHERE session_id = ?1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow!("session {session_id} not found"))?;

        Ok(row.try_get::<String, _>(0)?)
    }

    /// Mark a list of blob IDs as forwarded.
    pub async fn mark_forwarded(&self, blob_ids: &[String]) -> anyhow::Result<()> {
        if blob_ids.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        for id in blob_ids {
            sqlx::query("UPDATE blobs SET forwarded = 1 WHERE blob_id = ?1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    // retention

    /// If the DB file exceeds `max_size_mb` (> 0), delete the oldest **forwarded** blobs in batches until under the limit.
    ///
    /// Never deletes un-forwarded blobs.
    pub async fn recycle_if_over_limit(&self, max_size_mb: u64) -> anyhow::Result<()> {
        if max_size_mb == 0 {
            return Ok(());
        }
        let limit_bytes = (max_size_mb as i64) * 1024 * 1024;

        for _iteration in 0..5 {
            let db_size = self.db_size_bytes().await?;
            if db_size <= limit_bytes {
                return Ok(());
            }

            let deleted = sqlx::query(
                "DELETE FROM blobs WHERE forwarded = 1 AND blob_id IN (
                     SELECT blob_id FROM blobs WHERE forwarded = 1
                     ORDER BY created_at ASC LIMIT 100
                 )",
            )
            .execute(&self.pool)
            .await?
            .rows_affected() as usize;

            if deleted == 0 {
                warn!(
                    "TTY DB is {} MB (limit {} MB) but no forwarded blobs to recycle; \
                     increase sqlite_max_size_mb or check S3 connectivity",
                    db_size / (1024 * 1024),
                    max_size_mb
                );
                return Ok(());
            }

            // Remove orphaned sessions (no blobs left)
            sqlx::query(
                "DELETE FROM sessions WHERE session_id NOT IN (SELECT DISTINCT session_id FROM blobs)"
            )
            .execute(&self.pool)
            .await?;

            // Release freed pages
            // NOTE: incremental_vacuum can be slow; keep same behavior as your rusqlite version.
            let _ = sqlx::query("PRAGMA incremental_vacuum(200);")
                .execute(&self.pool)
                .await;

            debug!(
                "Recycled {deleted} forwarded blobs; DB now ~{} MB",
                self.db_size_bytes().await? / (1024 * 1024)
            );
        }

        Ok(())
    }

    async fn db_size_bytes(&self) -> anyhow::Result<i64> {
        let page_count: i64 = sqlx::query("PRAGMA page_count;")
            .fetch_one(&self.pool)
            .await?
            .try_get::<i64, _>(0)?;
        Ok(page_count * self.page_size)
    }

    // decrypt_cast helpers

    /// List all session IDs in the database.
    pub async fn list_sessions(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let rows =
            sqlx::query("SELECT session_id, created_at FROM sessions ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push((r.try_get::<String, _>(0)?, r.try_get::<i64, _>(1)?));
        }
        Ok(out)
    }

    /// Read all blobs for a session in order (for decryption/export).
    pub async fn blobs_for_session(&self, session_id: &str) -> anyhow::Result<Vec<Vec<u8>>> {
        let rows = sqlx::query("SELECT data FROM blobs WHERE session_id = ?1 ORDER BY seq ASC")
            .bind(session_id)
            .fetch_all(&self.pool)
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(r.try_get::<Vec<u8>, _>(0)?);
        }
        Ok(out)
    }
}

// internal helpers

async fn try_open(path: &Path) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(PathBuf::from(path))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);

    let pool = SqlitePool::connect_with(opts)
        .await
        .with_context(|| format!("opening SQLite at {}", path.display()))?;

    // pragmas (keep parity with your rusqlite settings)
    sqlx::query("PRAGMA auto_vacuum = INCREMENTAL;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA journal_mode = WAL;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA synchronous = NORMAL;")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await?;

    run_migrations(&pool).await?;
    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    // sqlx doesn't have execute_batch; just run each statement.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
             session_id    TEXT PRIMARY KEY,
             created_at    INTEGER NOT NULL,
             rows          INTEGER NOT NULL,
             cols          INTEGER NOT NULL,
             header_json   TEXT NOT NULL,
             first_blob_id TEXT,
             last_blob_id  TEXT
         )",
    )
    .execute(pool)
    .await
    .context("creating sessions table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS blobs (
             blob_id     TEXT PRIMARY KEY,
             session_id  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
             prev_blob_id TEXT,
             seq         INTEGER NOT NULL,
             data        BLOB NOT NULL,
             plain_size  INTEGER NOT NULL,
             created_at  INTEGER NOT NULL,
             forwarded   INTEGER NOT NULL DEFAULT 0
         )",
    )
    .execute(pool)
    .await
    .context("creating blobs table")?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_blobs_session_seq
         ON blobs (session_id, seq)",
    )
    .execute(pool)
    .await
    .context("creating idx_blobs_session_seq")?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_blobs_forwarded
         ON blobs (forwarded) WHERE forwarded = 0",
    )
    .execute(pool)
    .await
    .context("creating idx_blobs_forwarded")?;

    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
