use super::encrypt::{CastWriter, create_encrypted_writer, create_plain_writer, encrypt_buffer};
use super::sqlite_store::TtyDb;

use asciicastlib::{Event, Header, interval_from_ns, output_event_json_line};
use log::warn;
use std::io;
use std::io::Write;
use std::path::Path;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use xz2::write::XzEncoder;

enum WriterMsg {
    Bytes(Vec<u8>),
    Flush(oneshot::Sender<io::Result<()>>),
    Close(oneshot::Sender<io::Result<()>>),
}

struct FileCastSink {
    tx: mpsc::Sender<WriterMsg>,
}

impl FileCastSink {
    fn new(mut writer: CastWriter) -> Self {
        let (tx, mut rx) = mpsc::channel::<WriterMsg>(1024);

        tokio::task::spawn_blocking(move || {
            // Best-effort: keep writing even if a single write fails;
            // flush/close will surface errors.
            let mut last_err: Option<io::Error> = None;

            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    WriterMsg::Bytes(buf) => {
                        if let Err(e) = writer.write_all(&buf) {
                            last_err = Some(e);
                        }
                    }
                    WriterMsg::Flush(resp) => {
                        let r = match last_err.take() {
                            Some(e) => Err(e),
                            None => writer.flush(),
                        };
                        let _ = resp.send(r);
                    }
                    WriterMsg::Close(resp) => {
                        let r = match last_err.take() {
                            Some(e) => Err(e),
                            None => writer.flush(),
                        };
                        let _ = resp.send(r);
                        break;
                    }
                }
            }

            // Channel dropped -> best-effort flush.
            let _ = writer.flush();
        });

        Self { tx }
    }

    async fn write_bytes(&self, data: &[u8]) -> io::Result<()> {
        self.tx
            .send(WriterMsg::Bytes(data.to_vec()))
            .await
            .map_err(|_| io::Error::other("file writer task gone"))
    }

    async fn flush(&self) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(WriterMsg::Flush(tx))
            .await
            .map_err(|_| io::Error::other("file writer task gone"))?;
        rx.await
            .map_err(|_| io::Error::other("file writer task gone"))?
    }

    async fn close(&self) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(WriterMsg::Close(tx))
            .await
            .map_err(|_| io::Error::other("file writer task gone"))?;
        rx.await
            .map_err(|_| io::Error::other("file writer task gone"))?
    }
}

impl Drop for FileCastSink {
    fn drop(&mut self) {
        // Best-effort: ask writer thread to flush+exit.
        // Can't await here; also can't guarantee delivery.
        let (tx, _rx) = oneshot::channel::<io::Result<()>>();
        let _ = self.tx.try_send(WriterMsg::Close(tx));
    }
}

struct SqliteCastSink {
    db: TtyDb,
    session_id: String,
    pubkey: Option<String>,
    buffer: Vec<u8>,
}

impl SqliteCastSink {
    fn new(db: TtyDb, session_id: String, pubkey: Option<String>) -> Self {
        Self {
            db,
            session_id,
            pubkey,
            buffer: Vec::new(),
        }
    }

    async fn write_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let plain_size = self.buffer.len();
        let buf = std::mem::take(&mut self.buffer);
        let pubkey = self.pubkey.clone();

        let payload = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            // xz compress
            let compressed = {
                let mut encoder = XzEncoder::new(Vec::new(), 6);
                encoder.write_all(&buf)?;
                encoder.finish()?
            };
            // optionally encrypt
            if let Some(key) = pubkey {
                encrypt_buffer(&compressed, &key)
            } else {
                Ok(compressed)
            }
        })
        .await
        .map_err(|e| io::Error::other(format!("compress/encrypt join: {e}")))??;

        self.db
            .append_blob(&self.session_id, &payload, plain_size)
            .await
            .map_err(|e| io::Error::other(format!("SQLite append_blob: {e}")))?;

        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.flush().await
    }
}

impl Drop for SqliteCastSink {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            warn!(
                "SqliteCastSink dropped with pending buffered data; ensure close_all().await is called on shutdown"
            );
        }
    }
}

enum WriterBackend {
    File(FileCastSink),
    Sqlite(SqliteCastSink),
}

pub struct CastSession {
    backend: WriterBackend,
    last_ts_ns: u64,
    current_rows: u16,
    current_cols: u16,
    closed: bool,
}

impl CastSession {
    pub async fn new_file(
        dir: &Path,
        session_id: Uuid,
        rows: u16,
        cols: u16,
        ts_ns: u64,
        pubkey: Option<&str>,
    ) -> io::Result<Self> {
        let (filename, writer, file_exists) = if let Some(key) = pubkey {
            let filename = format!("{}.cast.age", session_id);
            let path = dir.join(&filename);
            (filename, create_encrypted_writer(&path, key)?, false)
        } else {
            let filename = format!("{}.cast", session_id);
            let path = dir.join(&filename);
            let (w, exists) = create_plain_writer(&path)?;
            (filename, w, exists)
        };

        let sink = FileCastSink::new(writer);

        let mut session = Self {
            backend: WriterBackend::File(sink),
            last_ts_ns: ts_ns,
            current_rows: rows,
            current_cols: cols,
            closed: false,
        };

        // If file already existed, caller wanted to continue writing without rewriting header.
        if !file_exists {
            Self::write_header(&mut session, &filename, cols, rows).await?;
        }

        Ok(session)
    }

    pub async fn new_sqlite(
        db: TtyDb,
        session_id: Uuid,
        rows: u16,
        cols: u16,
        ts_ns: u64,
        pubkey: Option<&str>,
    ) -> io::Result<Self> {
        let header = Self::build_header(cols, rows);
        let header_json = header
            .to_json_line()
            .map_err(|e| io::Error::other(format!("header JSON: {e}")))?;

        db.insert_session(session_id, rows, cols, &header_json)
            .await
            .map_err(|e| io::Error::other(format!("insert session: {e}")))?;

        let writer = SqliteCastSink::new(db, session_id.to_string(), pubkey.map(str::to_owned));

        let mut session = Self {
            backend: WriterBackend::Sqlite(writer),
            last_ts_ns: ts_ns,
            current_rows: rows,
            current_cols: cols,
            closed: false,
        };

        session.write_bytes(header_json.as_bytes()).await?;
        Ok(session)
    }

    pub async fn write_output(&mut self, ts_ns: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let interval = interval_from_ns(ts_ns, self.last_ts_ns);
        self.last_ts_ns = ts_ns;

        let json = output_event_json_line(interval, data);
        self.write_bytes(json.as_bytes()).await
    }

    pub async fn check_resize(&mut self, ts_ns: u64, rows: u16, cols: u16) -> io::Result<()> {
        if rows != self.current_rows || cols != self.current_cols {
            let interval = interval_from_ns(ts_ns, self.last_ts_ns);
            self.last_ts_ns = ts_ns;

            let event = Event::resize(interval, cols, rows);
            match event.to_json_line() {
                Ok(json) => self.write_bytes(json.as_bytes()).await?,
                Err(e) => warn!("Failed to serialize resize event: {e}"),
            }

            self.current_rows = rows;
            self.current_cols = cols;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        match &mut self.backend {
            WriterBackend::File(w) => w.flush().await,
            WriterBackend::Sqlite(w) => w.flush().await,
        }
    }

    pub async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let r = match &mut self.backend {
            WriterBackend::File(w) => w.close().await,
            WriterBackend::Sqlite(w) => w.close().await,
        };
        if r.is_ok() {
            self.closed = true;
        }
        r
    }

    async fn write_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.backend {
            WriterBackend::File(w) => w.write_bytes(data).await,
            WriterBackend::Sqlite(w) => w.write_bytes(data).await,
        }
    }

    fn build_header(cols: u16, rows: u16) -> Header {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Header::with_timestamp(cols, rows, timestamp)
    }

    async fn write_header(
        session: &mut Self,
        filename: &str,
        cols: u16,
        rows: u16,
    ) -> io::Result<()> {
        let header = Self::build_header(cols, rows);
        match header.to_json_line() {
            Ok(json) => session.write_bytes(json.as_bytes()).await?,
            Err(e) => warn!("Failed to serialize header for {}: {}", filename, e),
        }
        Ok(())
    }
}

impl Drop for CastSession {
    fn drop(&mut self) {
        if !self.closed {
            warn!("CastSession dropped without explicit close().await; pending data may be lost");
        }
    }
}
