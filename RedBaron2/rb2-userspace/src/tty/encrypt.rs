//! Encryption support for TTY session recordings using age with SSH ed25519 keys.
//!
//! Each flush creates a separate encrypted block, base64 encoded, on its own line.
//! This allows for streaming decryption and prevents issues with appending to encrypted streams.

use age::ssh::Recipient as SshRecipient;
use base64::Engine;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Wrapper for the output writer that handles both plain and encrypted modes.
pub enum CastWriter {
    /// Plain text output (no encryption)
    Plain(BufWriter<File>),
    /// Age-encrypted output using SSH ed25519 key.
    /// Buffers data and encrypts on each flush as a separate block.
    Encrypted(Box<EncryptedWriter>),
}

/// Writer that buffers data and encrypts each flush as a separate base64-encoded block.
pub struct EncryptedWriter {
    /// The underlying file
    file: BufWriter<File>,
    /// Buffer for accumulating data before encryption
    buffer: Vec<u8>,
    /// The parsed SSH recipient for encryption
    recipient: SshRecipient,
}

impl EncryptedWriter {
    /// Create a new encrypted writer.
    fn new(file: File, recipient: SshRecipient) -> Self {
        Self {
            file: BufWriter::new(file),
            buffer: Vec::new(),
            recipient,
        }
    }

    /// Encrypt the current buffer and write it as a base64-encoded line.
    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Create a new encryptor for this block
        let r = self.recipient.clone();
        let encryptor = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
            .expect("recipients should not be empty");

        // Encrypt the buffer contents
        let mut encrypted = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| io::Error::other(format!("Encryption error: {}", e)))?;

        writer.write_all(&self.buffer)?;
        writer
            .finish()
            .map_err(|e| io::Error::other(format!("Encryption finish error: {}", e)))?;

        // Base64 encode and write as a line
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        self.file.write_all(encoded.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;

        // Clear the buffer for next batch
        self.buffer.clear();

        Ok(())
    }
}

impl Write for CastWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            CastWriter::Plain(w) => w.write(buf),
            CastWriter::Encrypted(w) => {
                // Buffer the data, don't write yet
                w.buffer.extend_from_slice(buf);
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            CastWriter::Plain(w) => w.flush(),
            CastWriter::Encrypted(w) => w.flush_buffer(),
        }
    }
}

/// Encrypt a buffer of plaintext bytes using the given SSH ed25519 public key.
///
/// Returns the raw age-encrypted ciphertext (not base64-encoded).
pub fn encrypt_buffer(plaintext: &[u8], pubkey: &str) -> io::Result<Vec<u8>> {
    let recipient = parse_ssh_recipient(pubkey)?;

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("recipients should not be empty");

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| io::Error::other(format!("Encryption error: {}", e)))?;

    writer.write_all(plaintext)?;
    writer
        .finish()
        .map_err(|e| io::Error::other(format!("Encryption finish error: {}", e)))?;

    Ok(encrypted)
}

/// Parse an SSH ed25519 public key from the authorized_keys format.
fn parse_ssh_recipient(pubkey: &str) -> io::Result<SshRecipient> {
    pubkey.parse::<SshRecipient>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SSH key: {:?}", e),
        )
    })
}

/// Create an encrypted writer for a file using the provided SSH ed25519 public key.
///
/// Each flush will create a separate encrypted block, base64 encoded, on its own line.
pub fn create_encrypted_writer(path: &Path, pubkey: &str) -> io::Result<CastWriter> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    let recipient = parse_ssh_recipient(pubkey)?;
    Ok(CastWriter::Encrypted(Box::new(EncryptedWriter::new(
        file, recipient,
    ))))
}

/// Create a plain (unencrypted) writer for a file.
///
/// Returns (writer, file_existed) tuple where file_existed indicates if the file
/// already existed before opening (useful for determining if header needs to be written).
pub fn create_plain_writer(path: &Path) -> io::Result<(CastWriter, bool)> {
    let file_exists = path.exists();
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok((CastWriter::Plain(BufWriter::new(file)), file_exists))
}
