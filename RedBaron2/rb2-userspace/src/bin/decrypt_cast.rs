//! Decrypt an age-encrypted .cast file (optionally newline-separated base64 chunks),
//! extract and decrypt sessions stored in an SQLite TTY database, or download
//! and decrypt sessions from an S3/MinIO bucket.

use age::Decryptor;
use age::ssh::Identity as SshIdentity;
use base64::Engine;
use rb2_userspace::config::yaml::ObjectStorageConfig;
use rb2_userspace::tty::object_storage::S3Client;
use rb2_userspace::tty::sqlite_store::TtyDb;
use std::io::{BufRead, BufReader, Read, Write};
use std::iter;
use std::path::Path;
use xz2::read::XzDecoder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut output_path: Option<String> = None;
    let mut from_sqlite: Option<String> = None;
    let mut from_s3 = false;
    let mut s3_endpoint: Option<String> = None;
    let mut s3_bucket: Option<String> = None;
    let mut s3_region: Option<String> = None;
    let mut s3_access_key: Option<String> = None;
    let mut s3_secret_key: Option<String> = None;
    let mut s3_path_style = false;
    let mut list_sessions = false;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                eprintln!(
                    "Usage:\n  \
                     decrypt_cast PRIV_KEY ENCRYPTED_FILE [-o OUTPUT]\n  \
                     decrypt_cast PRIV_KEY --from-sqlite DB_PATH SESSION_ID [-o OUTPUT]\n  \
                     decrypt_cast --from-sqlite DB_PATH --list\n  \
                     decrypt_cast PRIV_KEY --from-s3 --endpoint URL --bucket NAME \\\n    \
                       --region REGION --access-key KEY --secret-key SECRET \\\n    \
                       [--path-style] SESSION_PATH [-o OUTPUT]\n  \
                     decrypt_cast --from-s3 --endpoint URL --bucket NAME \\\n    \
                       --region REGION --access-key KEY --secret-key SECRET \\\n    \
                       [--path-style] --list [PREFIX]\n\n\
                     PRIV_KEY          path to SSH private key\n\
                     ENCRYPTED_FILE    path to .cast.age file to decrypt\n\
                     --from-sqlite     read from SQLite TTY DB instead of a file\n\
                     --from-s3         read from S3/MinIO bucket\n\
                     --endpoint URL    S3 endpoint URL\n\
                     --bucket NAME     S3 bucket name\n\
                     --region REGION   S3 region\n\
                     --access-key KEY  S3 access key\n\
                     --secret-key KEY  S3 secret key\n\
                     --path-style      use path-style URLs (required for MinIO)\n\
                     --list [PREFIX]   list sessions (optionally filtered by prefix)\n\
                     -o OUTPUT         write to OUTPUT"
                );
                return Ok(());
            }
            "-o" | "--output" => {
                i += 1;
                output_path = Some(args.get(i).cloned().ok_or("-o requires an argument")?);
            }
            "--from-sqlite" => {
                i += 1;
                from_sqlite = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--from-sqlite requires a DB path argument")?,
                );
            }
            "--from-s3" => {
                from_s3 = true;
            }
            "--endpoint" => {
                i += 1;
                s3_endpoint = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--endpoint requires a URL argument")?,
                );
            }
            "--bucket" => {
                i += 1;
                s3_bucket = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--bucket requires a name argument")?,
                );
            }
            "--region" => {
                i += 1;
                s3_region = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--region requires a region argument")?,
                );
            }
            "--access-key" => {
                i += 1;
                s3_access_key = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--access-key requires a key argument")?,
                );
            }
            "--secret-key" => {
                i += 1;
                s3_secret_key = Some(
                    args.get(i)
                        .cloned()
                        .ok_or("--secret-key requires a key argument")?,
                );
            }
            "--path-style" => {
                s3_path_style = true;
            }
            "--list" => {
                list_sessions = true;
            }
            _ => {
                positional.push(args[i].clone());
            }
        }
        i += 1;
    }

    // --from-s3 mode
    if from_s3 {
        let s3 = build_s3_client(
            s3_endpoint.as_deref(),
            s3_bucket.as_deref(),
            s3_region.as_deref(),
            s3_access_key.as_deref(),
            s3_secret_key.as_deref(),
            s3_path_style,
        )?;

        if list_sessions {
            // Optional prefix from positional args (e.g. a hostname)
            let prefix = positional.first().map(|s| s.as_str());
            return list_s3_sessions(&s3, prefix);
        }

        // Decrypt a specific session from S3
        let identity_path = positional
            .first()
            .ok_or("PRIV_KEY is required (first positional argument)")?;
        let session_path = positional.get(1).ok_or(
            "SESSION_PATH is required (second positional argument, e.g. hostname/session-uuid)",
        )?;
        let identity = load_ssh_identity(identity_path)?;
        let out = output_path.unwrap_or_else(|| {
            // Derive output name from the session path
            let base = session_path.replace('/', "_");
            format!("{base}.cast")
        });
        return decrypt_from_s3(&s3, session_path, &identity, &out);
    }

    //  --from-sqlite --list mode
    if let Some(ref db_path) = from_sqlite
        && list_sessions
    {
        return list_sqlite_sessions(db_path).await;
    }

    //  --from-sqlite SESSION_ID mode
    if let Some(ref db_path) = from_sqlite {
        let identity_path = positional
            .first()
            .ok_or("PRIV_KEY is required (first positional argument)")?;
        let session_id = positional
            .get(1)
            .ok_or("SESSION_ID is required (second positional argument)")?;
        let identity = load_ssh_identity(identity_path)?;
        let out = output_path.unwrap_or_else(|| format!("{session_id}.cast"));
        return decrypt_from_sqlite(db_path, session_id, &identity, &out).await;
    }

    //  Original file mode
    let identity_path = positional
        .first()
        .ok_or("PRIV_KEY is required (first argument)")?;
    let encrypted_path = positional
        .get(1)
        .ok_or("ENCRYPTED_FILE is required (second argument)")?;

    let identity = load_ssh_identity(identity_path)?;
    let encrypted =
        std::fs::read(encrypted_path).map_err(|e| format!("reading {}: {}", encrypted_path, e))?;

    let decrypted = if is_base64_chunks(&encrypted) {
        decrypt_base64_chunks(&encrypted, &identity)?
    } else {
        decrypt_single(&encrypted, &identity)?
    };

    let out = output_path.unwrap_or_else(|| default_output_path(encrypted_path));
    std::fs::write(&out, &decrypted).map_err(|e| format!("writing {}: {}", out, e))?;
    eprintln!("Wrote decrypted cast to {}", out);

    Ok(())
}

//  SQLite helpers

async fn list_sqlite_sessions(db_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db = TtyDb::open(Path::new(db_path)).await?;
    let sessions = db.list_sessions().await?;

    if sessions.is_empty() {
        eprintln!("No sessions found in {db_path}");
        return Ok(());
    }

    eprintln!("{:<38}  CREATED_AT (unix)", "SESSION_ID");
    for (id, ts) in &sessions {
        eprintln!("{id:<38}  {ts}");
    }
    eprintln!("\n{} session(s)", sessions.len());
    Ok(())
}

async fn decrypt_from_sqlite(
    db_path: &str,
    session_id: &str,
    identity: &SshIdentity,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = TtyDb::open(Path::new(db_path)).await?;

    // Verify session exists by reading header
    let _header = db.session_header(session_id).await?;

    // Get all blobs in order
    let blobs = db.blobs_for_session(session_id).await?;
    if blobs.is_empty() {
        return Err(format!("No blobs found for session {session_id}").into());
    }

    let mut out_file = std::fs::File::create(output)?;

    for (i, encrypted_blob) in blobs.iter().enumerate() {
        // decrypt
        let decrypted = decrypt_one(encrypted_blob, identity)
            .map_err(|e| format!("blob {i}: decrypt failed: {e}"))?;

        // xz decompress
        let mut decoder = XzDecoder::new(decrypted.as_slice());
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| format!("blob {i}: xz decompress failed: {e}"))?;

        out_file.write_all(&decompressed)?;
    }

    eprintln!(
        "Wrote decrypted cast to {} ({} blobs from session {})",
        output,
        blobs.len(),
        session_id
    );
    Ok(())
}

//  S3 helpers

fn build_s3_client(
    endpoint: Option<&str>,
    bucket: Option<&str>,
    region: Option<&str>,
    access_key: Option<&str>,
    secret_key: Option<&str>,
    path_style: bool,
) -> Result<S3Client, Box<dyn std::error::Error>> {
    let cfg = ObjectStorageConfig {
        endpoint: endpoint
            .ok_or("--endpoint is required for --from-s3")?
            .to_string(),
        bucket_tty: bucket
            .ok_or("--bucket is required for --from-s3")?
            .to_string(),
        region: region
            .ok_or("--region is required for --from-s3")?
            .to_string(),
        access_key: access_key
            .ok_or("--access-key is required for --from-s3")?
            .to_string(),
        secret_key: secret_key
            .ok_or("--secret-key is required for --from-s3")?
            .to_string(),
        bucket_samples: None,
        path_style,
    };

    let client = S3Client::new(&cfg)?;
    Ok(client)
}

/// List sessions stored in S3.
///
/// The bucket layout is `{hostname}/{session-uuid}/{session-uuid}-{ts}.cast.age`.
/// This function discovers hostnames and session UUIDs, printing them in a tree.
fn list_s3_sessions(s3: &S3Client, prefix: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let keys: Vec<String> = s3.list_objects(prefix)?;

    if keys.is_empty() {
        let msg = match prefix {
            Some(p) => format!("No objects found with prefix '{p}'"),
            None => "No objects found in bucket".to_string(),
        };
        eprintln!("{msg}");
        return Ok(());
    }

    // Group keys into a hierarchy: hostname -> session-uuid -> [objects]
    // Key format: hostname/session-uuid/filename.cast.age
    use std::collections::BTreeMap;
    let mut tree: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

    for key in &keys {
        let parts: Vec<&str> = key.splitn(3, '/').collect();
        match parts.len() {
            3 => {
                tree.entry(parts[0].to_string())
                    .or_default()
                    .entry(parts[1].to_string())
                    .or_default()
                    .push(parts[2].to_string());
            }
            _ => {
                // Non-standard key, list it under "<other>"
                tree.entry("<other>".to_string())
                    .or_default()
                    .entry(String::new())
                    .or_default()
                    .push(key.clone());
            }
        }
    }

    for (hostname, sessions) in &tree {
        eprintln!("{hostname}/");
        for (session_id, objects) in sessions {
            if session_id.is_empty() {
                for obj in objects {
                    eprintln!("    {obj}");
                }
            } else {
                eprintln!("  {session_id}/  ({} blob(s))", objects.len());
                for obj in objects {
                    eprintln!("    {obj}");
                }
            }
        }
    }

    let session_count: usize = tree.values().map(|s| s.len()).sum();
    eprintln!(
        "\n{} session(s), {} object(s) total",
        session_count,
        keys.len()
    );
    Ok(())
}

/// Download and decrypt a session from S3.
///
/// `session_path` is either:
///   - `hostname/session-uuid`  - downloads all blobs under that prefix
///   - a single object key      - downloads just that one object
///
/// Each S3 object may contain multiple concatenated age-encrypted payloads
/// (the forwarder batches un-forwarded blobs into a single upload).
/// We split on the `age-encryption.org/v1` marker to recover individual
/// age ciphertexts, then decrypt + xz-decompress each one.
fn decrypt_from_s3(
    s3: &S3Client,
    session_path: &str,
    identity: &SshIdentity,
    output: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // List objects under the session path prefix
    let prefix = if session_path.ends_with('/') {
        session_path.to_string()
    } else {
        format!("{session_path}/")
    };

    let mut keys = s3.list_objects(Some(&prefix))?;

    // If no keys found with a trailing slash prefix, try the exact key
    if keys.is_empty() {
        let exact_keys = s3.list_objects(Some(session_path))?;
        if exact_keys.is_empty() {
            return Err(format!("No objects found matching '{session_path}'").into());
        }
        keys = exact_keys;
    }

    // Sort keys to ensure proper ordering (they contain timestamps)
    keys.sort();

    eprintln!(
        "Found {} object(s) for session path '{session_path}'",
        keys.len()
    );

    let mut out_file = std::fs::File::create(output)?;
    let mut total_chunks = 0;

    for key in &keys {
        // Skip non-.cast.age files
        if !key.ends_with(".cast.age") {
            eprintln!("  Skipping non-cast object: {key}");
            continue;
        }

        eprintln!("  Downloading: {key}");
        let raw = s3.get_object(key)?;

        // Split concatenated age payloads.  Each starts with the ASCII
        // marker "age-encryption.org/v1\n".
        let chunks = split_age_payloads(&raw);
        eprintln!(
            "    {} bytes, {} age-encrypted chunk(s)",
            raw.len(),
            chunks.len()
        );

        for (ci, chunk) in chunks.iter().enumerate() {
            // Decrypt
            let decrypted = decrypt_one(chunk, identity)
                .map_err(|e| format!("{key} chunk {ci}: decrypt failed: {e}"))?;

            // xz decompress
            let mut decoder = XzDecoder::new(decrypted.as_slice());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("{key} chunk {ci}: xz decompress failed: {e}"))?;

            out_file.write_all(&decompressed)?;
            total_chunks += 1;
        }
    }

    eprintln!(
        "Wrote decrypted cast to {} ({} chunk(s) from '{}')",
        output, total_chunks, session_path
    );
    Ok(())
}

/// Split a byte buffer that may contain multiple concatenated age-encrypted
/// payloads.  Each payload starts with the ASCII marker `age-encryption.org/v1\n`.
fn split_age_payloads(data: &[u8]) -> Vec<&[u8]> {
    const MARKER: &[u8] = b"age-encryption.org/v1\n";
    let mut chunks = Vec::new();
    let mut start = 0;

    while start < data.len() {
        // Find the next marker after the current position
        let next = data[start + 1..]
            .windows(MARKER.len())
            .position(|w| w == MARKER)
            .map(|p| start + 1 + p);

        match next {
            Some(pos) => {
                chunks.push(&data[start..pos]);
                start = pos;
            }
            None => {
                chunks.push(&data[start..]);
                break;
            }
        }
    }

    chunks
}

// Original file-based helpers

/// Default output path: input with .cast.age replaced by .cast.
fn default_output_path(encrypted_path: &str) -> String {
    if encrypted_path.ends_with(".cast.age") {
        encrypted_path
            .strip_suffix(".cast.age")
            .map(|s| format!("{}.cast", s))
            .unwrap_or_else(|| format!("{}.cast", encrypted_path))
    } else {
        format!("{}.cast", encrypted_path)
    }
}

fn load_ssh_identity(path: &str) -> Result<SshIdentity, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path).map_err(|e| format!("identity file {}: {}", path, e))?;
    let identity = SshIdentity::from_buffer(BufReader::new(file), Some(path.to_string()))
        .map_err(|e| format!("parsing SSH identity: {}", e))?;
    match &identity {
        SshIdentity::Unencrypted(_) => Ok(identity),
        SshIdentity::Encrypted(_) => {
            Err("SSH key is passphrase-protected; use an unencrypted key for this tool".into())
        }
        SshIdentity::Unsupported(k) => Err(format!("unsupported SSH key: {:?}", k).into()),
    }
}

fn is_base64_chunks(data: &[u8]) -> bool {
    let first_line = match data.splitn(2, |&b| b == b'\n').next() {
        Some(line) => line,
        None => return false,
    };
    let trimmed = trim_trailing_cr(first_line);
    if trimmed.is_empty() {
        return false;
    }
    let decoded = base64::engine::general_purpose::STANDARD.decode(trimmed);
    match decoded {
        Ok(chunk) => chunk.starts_with(b"age-encryption.org/v1"),
        Err(_) => false,
    }
}

fn trim_trailing_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn decrypt_base64_chunks(
    data: &[u8],
    identity: &SshIdentity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (i, line) in data.lines().enumerate() {
        let line = line.map_err(|e| format!("reading line {}: {}", i + 1, e))?;
        let line = trim_trailing_cr(line.as_bytes());
        if line.is_empty() {
            continue;
        }
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(line)
            .map_err(|e| format!("base64 decode line {}: {}", i + 1, e))?;
        let decrypted = decrypt_one(&chunk, identity)?;
        out.extend_from_slice(&decrypted);
    }
    Ok(out)
}

fn decrypt_single(
    data: &[u8],
    identity: &SshIdentity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    decrypt_one(data, identity)
}

fn decrypt_one(
    encrypted: &[u8],
    identity: &SshIdentity,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decryptor =
        Decryptor::new_buffered(encrypted).map_err(|e| format!("age decryptor: {}", e))?;

    if decryptor.is_scrypt() {
        return Err("file is passphrase-encrypted, not SSH".into());
    }

    let mut reader = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(|e| format!("decrypt: {}", e))?;

    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}
