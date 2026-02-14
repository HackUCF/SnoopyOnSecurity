// Package castutil extracts searchable plain text from asciinema .cast files.
package castutil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

// ansiRe matches ANSI escape sequences (CSI, OSC, simple escapes) and bare \r.
var ansiRe = regexp.MustCompile(
	`\x1b\[[0-9;?]*[a-zA-Z@]` + // CSI sequences
		`|\x1b\][^\x07]*\x07` + // OSC sequences (terminated by BEL)
		`|\x1b[()][AB012]` + // character set selection
		`|\x1b[=>DEHM78]` + // simple escape codes
		`|\r`, // carriage returns
)

// ExtractText parses a .cast file (v2/v3 JSON-lines format) and returns
// the concatenated terminal output with ANSI escape codes stripped,
// suitable for full-text indexing.
func ExtractText(castData []byte) string {
	var b strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(castData))

	// Skip the header line (JSON object).
	if scanner.Scan() {
		// first line is the header, ignore
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Each event line is a JSON array: [timestamp, "o", "data"]
		var event []json.RawMessage
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		if len(event) < 3 {
			continue
		}

		// Check event type is "o" (output).
		var evType string
		if err := json.Unmarshal(event[1], &evType); err != nil || evType != "o" {
			continue
		}

		// Extract the data string.
		var data string
		if err := json.Unmarshal(event[2], &data); err != nil {
			continue
		}

		b.WriteString(data)
	}

	// Strip ANSI escape codes.
	cleaned := ansiRe.ReplaceAllString(b.String(), "")

	// Collapse excessive whitespace / blank lines.
	lines := strings.Split(cleaned, "\n")
	var out []string
	for _, l := range lines {
		trimmed := strings.TrimRight(l, " \t")
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return strings.Join(out, "\n")
}

// ExtractDurationSecs parses a (possibly concatenated multi-blob) .cast file
// and returns the total recording duration in seconds.
//
// Supports both asciinema formats:
//   - v2: event timestamps are absolute (seconds since recording start).
//     Duration = max timestamp per segment.
//   - v3: event timestamps are deltas (seconds since previous event).
//     Duration = sum of all timestamps per segment.
//
// For multi-blob files (concatenated), segments are summed.
func ExtractDurationSecs(castData []byte) float64 {
	var totalDuration float64
	var segmentMax float64
	var segmentSum float64
	version := 2 // default to v2
	inSegment := false

	scanner := bufio.NewScanner(bytes.NewReader(castData))
	// Increase buffer size for very long lines.
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	flushSegment := func() {
		if !inSegment {
			return
		}
		if version >= 3 {
			totalDuration += segmentSum
		} else {
			totalDuration += segmentMax
		}
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Detect header lines (JSON objects starting with '{').
		if line[0] == '{' {
			// Flush the previous segment if any.
			flushSegment()

			// Parse header.
			var header map[string]interface{}
			if err := json.Unmarshal(line, &header); err == nil {
				// Check for explicit "duration" field.
				if d, ok := header["duration"].(float64); ok && d > 0 {
					totalDuration += d
					inSegment = false
					segmentMax = 0
					segmentSum = 0
					continue
				}
				// Detect version.
				if v, ok := header["version"].(float64); ok {
					version = int(v)
				}
			}
			// Start a new segment.
			inSegment = true
			segmentMax = 0
			segmentSum = 0
			continue
		}

		// Event line: JSON array [timestamp, type, data].
		if line[0] != '[' {
			continue
		}
		var event []json.RawMessage
		if err := json.Unmarshal(line, &event); err != nil || len(event) < 2 {
			continue
		}
		var ts float64
		if err := json.Unmarshal(event[0], &ts); err == nil {
			segmentSum += ts
			if ts > segmentMax {
				segmentMax = ts
			}
		}
	}

	// Don't forget the last segment.
	flushSegment()

	return math.Round(totalDuration*10) / 10
}

// promptRe matches common shell prompt patterns and captures the username.
// The username must start with a letter (not -, avoiding false positives from
// process names like "-bash" in ps output), and must be preceded by whitespace
// or line start for the user@host: form.
//
//	[root@ip-172-31-82-132 ~]#          -> root
//	ubuntu@ip-172-31-82-132:~$          -> ubuntu
//	ec2-user@ip-172-31-19-242:~$        -> ec2-user
//	root@host:/var/log#                 -> root
var promptRe = regexp.MustCompile(
	`\[([a-zA-Z][a-zA-Z0-9._-]*)@[a-zA-Z0-9._-]+[^\]]*\][#$%>]\s` +
		`|(?:^|[\s\n])([a-zA-Z][a-zA-Z0-9._-]*)@[a-zA-Z0-9._-]+:[^\s]*[#$%>]\s`,
)

// ExtractUsers scans stripped terminal text for shell prompt patterns and
// returns a deduplicated, sorted list of usernames seen in the session.
func ExtractUsers(text string) []string {
	seen := make(map[string]struct{})
	for _, match := range promptRe.FindAllStringSubmatch(text, -1) {
		// match[1] is from the [user@host]# pattern,
		// match[2] is from the user@host:dir$ pattern.
		user := match[1]
		if user == "" {
			user = match[2]
		}
		if user != "" {
			seen[user] = struct{}{}
		}
	}

	users := make([]string, 0, len(seen))
	for u := range seen {
		users = append(users, u)
	}
	sort.Strings(users)
	return users
}
