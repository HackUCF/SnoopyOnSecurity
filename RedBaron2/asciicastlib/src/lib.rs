//! asciicastlib - Library for handling asciicast v3 format
//! See: https://docs.asciinema.org/manual/asciicast/v3/

use serde::Serialize;
use std::collections::HashMap;

/// Asciicast v3 header containing recording metadata.
#[derive(Debug, Clone, Serialize)]
pub struct Header {
    /// Format version number, always 3.
    pub version: u32,
    pub term: TermInfo,
    /// Unix timestamp of the beginning of the session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    /// Idle limit in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_time_limit: Option<f64>,
    /// Command that was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    /// Categorization tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

impl Header {
    /// Create a new, minimal header
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            version: 3,
            term: TermInfo {
                cols,
                rows,
                term_type: None,
            },
            timestamp: None,
            idle_time_limit: None,
            command: None,
            title: None,
            env: None,
            tags: None,
        }
    }

    /// Create a header with timestamp.
    pub fn with_timestamp(cols: u16, rows: u16, timestamp: i64) -> Self {
        let mut header = Self::new(cols, rows);
        header.timestamp = Some(timestamp);
        header
    }

    /// Serialize header to JSON string (single line, no trailing newline).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize header to JSON string with trailing newline.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = self.to_json()?;
        json.push('\n');
        Ok(json)
    }
}

/// Terminal information for the header.
#[derive(Debug, Clone, Serialize)]
pub struct TermInfo {
    /// Terminal width (number of columns).
    pub cols: u16,
    /// Terminal height (number of rows).
    pub rows: u16,
    /// Terminal type (e.g., "xterm-256color").
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub term_type: Option<String>,
}

/// Event types in the asciicast v3 event stream.
#[derive(Debug, Clone)]
pub enum Event {
    /// Output event - data written to terminal ("o").
    Output {
        /// Time interval from previous event in seconds.
        interval: f64,
        /// Data that was written.
        data: String,
    },
    /// Input event - data read from terminal ("i").
    Input {
        /// Time interval from previous event in seconds.
        interval: f64,
        /// Data that was read.
        data: String,
    },
    /// Marker event ("m").
    Marker {
        /// Time interval from previous event in seconds.
        interval: f64,
        /// Optional label for the marker.
        label: String,
    },
    /// Resize event ("r").
    Resize {
        /// Time interval from previous event in seconds.
        interval: f64,
        /// New terminal width.
        cols: u16,
        /// New terminal height.
        rows: u16,
    },
    /// Exit event ("x").
    Exit {
        /// Time interval from previous event in seconds.
        interval: f64,
        /// Exit status code.
        status: i32,
    },
}

impl Event {
    /// Create an output event.
    pub fn output(interval: f64, data: impl Into<String>) -> Self {
        Self::Output {
            interval,
            data: data.into(),
        }
    }

    /// Create a resize event.
    pub fn resize(interval: f64, cols: u16, rows: u16) -> Self {
        Self::Resize {
            interval,
            cols,
            rows,
        }
    }

    /// Create an exit event.
    pub fn exit(interval: f64, status: i32) -> Self {
        Self::Exit { interval, status }
    }

    /// Get the event code character.
    fn code(&self) -> &'static str {
        match self {
            Self::Output { .. } => "o",
            Self::Input { .. } => "i",
            Self::Marker { .. } => "m",
            Self::Resize { .. } => "r",
            Self::Exit { .. } => "x",
        }
    }

    /// Get the interval from this event.
    fn interval(&self) -> f64 {
        match self {
            Self::Output { interval, .. }
            | Self::Input { interval, .. }
            | Self::Marker { interval, .. }
            | Self::Resize { interval, .. }
            | Self::Exit { interval, .. } => *interval,
        }
    }

    /// Get the data field for this event.
    fn data(&self) -> String {
        match self {
            Self::Output { data, .. } | Self::Input { data, .. } => data.clone(),
            Self::Marker { label, .. } => label.clone(),
            Self::Resize { cols, rows, .. } => format!("{cols}x{rows}"),
            Self::Exit { status, .. } => status.to_string(),
        }
    }

    /// Serialize event to JSON array format: [interval, code, data]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let tuple: (f64, &str, String) = (self.interval(), self.code(), self.data());
        serde_json::to_string(&tuple)
    }

    /// Serialize event to JSON with trailing newline.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut json = self.to_json()?;
        json.push('\n');
        Ok(json)
    }
}

/// Convert bytes to a UTF-8 string, escaping invalid sequences.
///
/// Non-printable characters (except common whitespace) are preserved as-is
/// since serde_json handles the JSON escaping.
pub fn bytes_to_string(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

/// Escape raw TTY output bytes for use as the data field of an asciicast "o" event.
///
/// Preserves every byte: valid UTF-8 is kept (with JSON escaping for `"`, `\`, and
/// control chars 0x00-0x1F and 0x7F encoded as `\uXXXX` per spec). Invalid UTF-8
/// bytes are emitted as `\u00XX` so no data is lost and playback preserves format/spacing.
pub fn escape_output_for_json(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2); // control chars expand to 6
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        match b {
            0x22 => out.push_str("\\\""), // "
            0x5c => out.push_str("\\\\"), // \
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x00..=0x1f | 0x7f => {
                out.push_str(&format!("\\u{:04x}", b as u32));
            }
            _ => {
                // Multi-byte UTF-8 or single-byte ASCII
                let rest = &data[i..];
                match std::str::from_utf8(rest) {
                    Ok(s) => {
                        let ch = s.chars().next().unwrap();
                        if ch as u32 <= 0x1F || ch == '\u{7f}' {
                            out.push_str(&format!("\\u{:04x}", ch as u32));
                        } else {
                            out.push(ch);
                        }
                        i += ch.len_utf8();
                        continue;
                    }
                    Err(e) => {
                        let valid_up_to = e.valid_up_to();
                        if valid_up_to > 0 {
                            let s = std::str::from_utf8(&rest[..valid_up_to]).unwrap();
                            for ch in s.chars() {
                                if ch as u32 <= 0x1F || ch == '\u{7f}' {
                                    out.push_str(&format!("\\u{:04x}", ch as u32));
                                } else {
                                    out.push(ch);
                                }
                            }
                            i += valid_up_to;
                        } else {
                            // Invalid UTF-8 lead byte
                            out.push_str(&format!("\\u{:04x}", b as u32));
                            i += 1;
                        }
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

/// Normalize line endings to CRLF so output matches asciinema recorder format.
/// Replaces any LF not already preceded by CR with CRLF.
pub fn normalize_line_endings(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.iter().filter(|&&b| b == b'\n').count());
    let mut prev = None;
    for &b in data {
        if b == b'\n' && prev != Some(b'\r') {
            out.push(b'\r');
        }
        out.push(b);
        prev = Some(b);
    }
    out
}

/// Format interval as decimal (no scientific notation) for compatibility with asciinema player.
pub fn format_interval(interval: f64) -> String {
    format!("{:.6}", interval)
}

/// Build the full JSON line for an output event from raw bytes: `[interval,"o","escaped_data"]\n`
///
/// Line endings are normalized to CRLF to match asciinema recorder format.
pub fn output_event_json_line(interval: f64, data: &[u8]) -> String {
    let normalized = normalize_line_endings(data);
    let escaped = escape_output_for_json(&normalized);
    format!("[{},\"o\",\"{}\"]\n", format_interval(interval), escaped)
}

/// Calculate interval in seconds from nanosecond timestamps.
pub fn interval_from_ns(current_ns: u64, previous_ns: u64) -> f64 {
    if current_ns >= previous_ns {
        (current_ns - previous_ns) as f64 / 1_000_000_000.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_minimal() {
        let header = Header::new(80, 24);
        let json = header.to_json().unwrap();
        assert!(json.contains("\"version\":3"));
        assert!(json.contains("\"cols\":80"));
        assert!(json.contains("\"rows\":24"));
    }

    #[test]
    fn test_header_with_timestamp() {
        let header = Header::with_timestamp(80, 24, 1234567890);
        let json = header.to_json().unwrap();
        assert!(json.contains("\"timestamp\":1234567890"));
    }

    #[test]
    fn test_output_event() {
        let event = Event::output(1.5, "Hello");
        let json = event.to_json().unwrap();
        assert_eq!(json, "[1.5,\"o\",\"Hello\"]");
    }

    #[test]
    fn test_resize_event() {
        let event = Event::resize(0.5, 100, 50);
        let json = event.to_json().unwrap();
        assert_eq!(json, "[0.5,\"r\",\"100x50\"]");
    }

    #[test]
    fn test_exit_event() {
        let event = Event::exit(0.0, 0);
        let json = event.to_json().unwrap();
        assert_eq!(json, "[0.0,\"x\",\"0\"]");
    }

    #[test]
    fn test_interval_calculation() {
        let interval = interval_from_ns(2_500_000_000, 1_000_000_000);
        assert!((interval - 1.5).abs() < 0.0001);
    }

    #[test]
    fn test_escape_output_preserves_control_chars() {
        // CR and LF must be escaped so playback preserves line structure
        let data = b"hello\r\nworld";
        let escaped = escape_output_for_json(data);
        assert!(escaped.contains("\\r"));
        assert!(escaped.contains("\\n"));
        let line = output_event_json_line(0.0, data);
        assert!(line.starts_with('[') && line.contains("\"o\",\""));
        assert!(line.ends_with("\"]\n"));
        // Parsed data should round-trip
        let parsed: (f64, String, String) = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed.1, "o");
        assert_eq!(parsed.2, "hello\r\nworld");
    }

    #[test]
    fn test_escape_output_preserves_ansi_esc() {
        // ESC (0x1b) must be preserved for ANSI sequences
        let data = b"\x1b[1;31mred\x1b[0m";
        let escaped = escape_output_for_json(data);
        assert!(escaped.contains("\\u001b"));
        assert!(escaped.contains("red"));
    }

    #[test]
    fn test_normalize_line_endings() {
        assert_eq!(normalize_line_endings(b"a\nb"), b"a\r\nb");
        assert_eq!(normalize_line_endings(b"a\r\nb"), b"a\r\nb");
        assert_eq!(normalize_line_endings(b"\n"), b"\r\n");
    }

    #[test]
    fn test_format_interval_no_scientific() {
        assert_eq!(format_interval(0.0), "0.000000");
        assert_eq!(format_interval(0.000029), "0.000029");
        assert!(format_interval(9.09e-6).find('e').is_none());
    }
}
