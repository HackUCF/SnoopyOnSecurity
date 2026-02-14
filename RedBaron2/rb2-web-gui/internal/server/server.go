package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"rb2-tty/internal/castutil"
	"rb2-tty/internal/decrypt"
	"rb2-tty/internal/s3client"
	"rb2-tty/internal/store"
)

// Config holds everything the server needs.
type Config struct {
	S3      s3client.Config
	KeyPath string
	Port    int
	DBPath  string
}

// Server is the HTTP server for the TTY session viewer.
type Server struct {
	s3       *s3client.Client
	identity age.Identity
	store    *store.Store
	cfg      Config
	decMu    sync.Mutex // serialises decrypt-and-store operations
}

// New creates a Server and resolves the SSH identity.
func New(cfg Config) (*Server, error) {
	s3c, err := s3client.New(cfg.S3)
	if err != nil {
		return nil, err
	}

	id, err := decrypt.LoadSSHIdentity(cfg.KeyPath)
	if err != nil {
		return nil, err
	}

	st, err := store.New(cfg.DBPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		s3:       s3c,
		identity: id,
		store:    st,
		cfg:      cfg,
	}, nil
}

// ListenAndServe starts the HTTP server and background sync.
func (s *Server) ListenAndServe() error {
	// Backfill users for any existing casts that don't have them yet.
	if err := s.store.BackfillUsers(func(castData []byte) []string {
		text := castutil.ExtractText(castData)
		return castutil.ExtractUsers(text)
	}); err != nil {
		log.Printf("backfill users: %v", err)
	}

	// Backfill recording duration for existing casts.
	if err := s.store.BackfillDuration(castutil.ExtractDurationSecs); err != nil {
		log.Printf("backfill duration: %v", err)
	}

	// Initial sync + start background loop.
	go s.syncLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/sessions", s.handleAPISessions)
	mux.HandleFunc("/api/search", s.handleAPISearch)
	mux.HandleFunc("/play/", s.handlePlaySession)
	mux.HandleFunc("/api/cast/", s.handleAPICast)
	mux.HandleFunc("/api/gif/", s.handleAPIGif)

	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)
	log.Printf("Red Baron 2 -- TTY Web Viewer")
	log.Printf("Listening on http://%s", addr)
	log.Printf("Database: %s", s.cfg.DBPath)
	return http.ListenAndServe(addr, mux)
}

// background sync

func (s *Server) syncLoop() {
	s.syncOnce()
	for {
		time.Sleep(30 * time.Second)
		s.syncOnce()
	}
}

func (s *Server) syncOnce() {
	ctx := context.Background()

	// 1. Refresh session list from S3 -> SQLite.
	sessions, err := s.s3.ListSessions(ctx)
	if err != nil {
		log.Printf("sync: listing sessions: %v", err)
		return
	}
	if err := s.store.UpsertSessions(sessions); err != nil {
		log.Printf("sync: upserting sessions: %v", err)
		return
	}

	// 2. Download + decrypt + index any un-indexed sessions.
	unindexed, err := s.store.UnindexedSessionIDs()
	if err != nil {
		log.Printf("sync: finding unindexed: %v", err)
		return
	}

	for _, sessionID := range unindexed {
		// Find the session to get host + s3_path.
		var sess *sessionInfo
		for i := range sessions {
			if sessions[i].SessionID == sessionID {
				sess = &sessionInfo{sessions[i].Host, sessions[i].S3Path}
				break
			}
		}
		if sess == nil {
			continue
		}

		log.Printf("sync: indexing %s (%s)", sessionID[:8], sess.host)
		if err := s.downloadAndIndex(ctx, sessionID, sess.host, sess.s3Path, false); err != nil {
			log.Printf("sync: indexing %s: %v", sessionID[:8], err)
		}
	}

	// 3. Re-index sessions that have new blobs (duration/cast_data stale).
	needingReindex, err := s.store.SessionsNeedingReindex()
	if err != nil {
		log.Printf("sync: finding sessions needing reindex: %v", err)
		return
	}
	for _, sessionID := range needingReindex {
		var sess *sessionInfo
		for i := range sessions {
			if sessions[i].SessionID == sessionID {
				sess = &sessionInfo{sessions[i].Host, sessions[i].S3Path}
				break
			}
		}
		if sess == nil {
			continue
		}
		log.Printf("sync: re-indexing %s (%s) (new blobs)", sessionID[:8], sess.host)
		if err := s.downloadAndIndex(ctx, sessionID, sess.host, sess.s3Path, true); err != nil {
			log.Printf("sync: re-indexing %s: %v", sessionID[:8], err)
		}
	}
}

type sessionInfo struct {
	host   string
	s3Path string
}

func (s *Server) downloadAndIndex(ctx context.Context, sessionID, host, s3Path string, forceReindex bool) error {
	s.decMu.Lock()
	defer s.decMu.Unlock()

	// Skip if we already have a cast, unless we're re-indexing due to new blobs.
	if !forceReindex && s.store.HasCast(sessionID) {
		return nil
	}

	keys, err := s.s3.ListSessionKeys(ctx, s3Path)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no blobs for %s", s3Path)
	}

	var castData []byte
	for _, key := range keys {
		raw, err := s.s3.DownloadObject(ctx, key)
		if err != nil {
			return err
		}
		dec, err := decrypt.DecryptBlob(raw, s.identity)
		if err != nil {
			return fmt.Errorf("decrypting %s: %w", key, err)
		}
		castData = append(castData, dec...)
	}

	textContent := castutil.ExtractText(castData)
	users := castutil.ExtractUsers(textContent)
	durationSecs := castutil.ExtractDurationSecs(castData)
	return s.store.StoreCast(sessionID, host, s3Path, castData, textContent, users, durationSecs, len(keys))
}

// handlers

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListSessions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(sessions) == 0 {
		w.Write([]byte("[]"))
		return
	}
	json.NewEncoder(w).Encode(sessions)
}

func (s *Server) handleAPISearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	results, err := s.store.Search(q)
	if err != nil {
		log.Printf("search error: %v", err)
		// Return empty array on FTS syntax errors rather than 500.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	if results == nil {
		results = []store.SearchResult{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handlePlaySession(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/play/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	host := parts[0]
	sessionID := parts[1]
	s3Path := host + "/" + sessionID

	sess, err := s.store.GetSession(s3Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	page := playerHTML
	page = strings.ReplaceAll(page, "{{TITLE}}", html.EscapeString(host+" / "+sessionID[:8]))
	page = strings.ReplaceAll(page, "{{HOST}}", html.EscapeString(host))
	page = strings.ReplaceAll(page, "{{SESSION_ID}}", html.EscapeString(sessionID))
	page = strings.ReplaceAll(page, "{{SIZE}}", html.EscapeString(sess.SizeHuman))
	page = strings.ReplaceAll(page, "{{BLOBS}}", fmt.Sprintf("%d", sess.BlobCount))
	page = strings.ReplaceAll(page, "{{START}}", html.EscapeString(sess.StartFmt))
	page = strings.ReplaceAll(page, "{{END}}", html.EscapeString(sess.EndFmt))
	page = strings.ReplaceAll(page, "{{S3_PATH}}", s3Path)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) handleAPICast(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/cast/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	host := parts[0]
	sessionID := parts[1]
	s3Path := host + "/" + sessionID

	// Try SQLite cache first.
	if data, err := s.store.GetCast(sessionID); err == nil {
		w.Header().Set("Content-Type", "application/x-asciicast")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(data)
		return
	}

	// Download, decrypt, store, serve.
	if err := s.downloadAndIndex(context.Background(), sessionID, host, s3Path, false); err != nil {
		log.Printf("decrypt error for %s: %v", s3Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := s.store.GetCast(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

func (s *Server) handleAPIGif(w http.ResponseWriter, r *http.Request) {
	// URL: /api/gif/{host}/{session_id}?speed=1&theme=monokai&format=gif|mov
	path := strings.TrimPrefix(r.URL.Path, "/api/gif/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	host := parts[0]
	sessionID := parts[1]
	s3Path := host + "/" + sessionID

	// Optional query params.
	speed := r.URL.Query().Get("speed")
	if speed == "" {
		speed = "1"
	}
	theme := r.URL.Query().Get("theme")
	if theme == "" {
		theme = "monokai"
	}
	format := r.URL.Query().Get("format")
	if format != "mov" {
		format = "gif"
	}

	// Ensure cast data is available.
	if !s.store.HasCast(sessionID) {
		if err := s.downloadAndIndex(context.Background(), sessionID, host, s3Path, false); err != nil {
			log.Printf("export: download error for %s: %v", s3Path, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	castData, err := s.store.GetCast(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write cast to temp file.
	tmpDir, err := os.MkdirTemp("", "rb2tty-export-*")
	if err != nil {
		http.Error(w, "creating temp dir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tmpDir)

	castFile := filepath.Join(tmpDir, "session.cast")
	gifFile := filepath.Join(tmpDir, "session.gif")

	if err := os.WriteFile(castFile, castData, 0o644); err != nil {
		http.Error(w, "writing cast file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 1: Run agg to generate GIF.
	aggArgs := []string{
		"--theme", theme,
		"--speed", speed,
		"--font-size", "14",
		"--font-family", "DejaVu Sans Mono,Noto Sans Mono,Liberation Mono,monospace",
		"--quiet",
		castFile,
		gifFile,
	}

	log.Printf("export: generating %s for %s (speed=%s, theme=%s)", format, sessionID[:8], speed, theme)
	cmd := exec.Command("agg", aggArgs...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("export: agg failed for %s: %v", sessionID[:8], err)
		http.Error(w, "GIF generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if format == "mov" {
		// Step 2: Convert GIF -> MOV with ffmpeg (H.264 via OpenH264).
		movFile := filepath.Join(tmpDir, "session.mov")
		ffArgs := []string{
			"-y",
			"-i", gifFile,
			"-movflags", "faststart",
			"-pix_fmt", "yuv420p",
			"-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2",
			"-c:v", "libopenh264",
			movFile,
		}
		ffCmd := exec.Command("ffmpeg", ffArgs...)
		ffCmd.Stderr = os.Stderr
		if err := ffCmd.Run(); err != nil {
			log.Printf("export: ffmpeg failed for %s: %v", sessionID[:8], err)
			http.Error(w, "MOV conversion failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		movData, err := os.ReadFile(movFile)
		if err != nil {
			http.Error(w, "reading mov: "+err.Error(), http.StatusInternalServerError)
			return
		}

		filename := fmt.Sprintf("%s_%s.mov", host, sessionID[:8])
		w.Header().Set("Content-Type", "video/quicktime")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(movData)))
		w.Write(movData)
		log.Printf("export: served %s (%d bytes)", filename, len(movData))
		return
	}

	// Serve GIF.
	gifData, err := os.ReadFile(gifFile)
	if err != nil {
		http.Error(w, "reading gif: "+err.Error(), http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("%s_%s.gif", host, sessionID[:8])
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(gifData)))
	w.Write(gifData)
	log.Printf("export: served %s (%d bytes)", filename, len(gifData))
}

// HTML templates

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Red Baron 2 &mdash; TTY Sessions</title>
<style>
  :root {
    --bg: #0d0d0d;
    --surface: #181818;
    --surface2: #222;
    --border: #333;
    --text: #e0e0e0;
    --muted: #888;
    --red: #c0392b;
    --red-light: #e74c3c;
    --red-glow: rgba(231,76,60,.15);
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 14px;
    line-height: 1.6;
  }
  header {
    background: linear-gradient(135deg, #1a0000 0%, var(--surface) 100%);
    border-bottom: 2px solid var(--red);
    padding: 20px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  header h1 {
    font-size: 22px;
    font-weight: 700;
    color: var(--red-light);
    letter-spacing: 1px;
  }
  header .sub {
    color: var(--muted);
    font-size: 13px;
  }
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 24px 32px;
  }
  .search-bar {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    align-items: center;
  }
  .search-bar input {
    flex: 1;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 16px;
    color: var(--text);
    font-family: inherit;
    font-size: 14px;
    outline: none;
    transition: border-color .2s;
  }
  .search-bar input:focus {
    border-color: var(--red-light);
  }
  .search-bar input::placeholder {
    color: #555;
  }
  .search-bar .search-hint {
    color: var(--muted);
    font-size: 12px;
    white-space: nowrap;
  }
  .stats {
    color: var(--muted);
    margin-bottom: 16px;
    font-size: 13px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  thead th {
    background: var(--surface2);
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 1px;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  thead th.sortable {
    cursor: pointer;
    user-select: none;
    position: relative;
    padding-right: 22px;
  }
  thead th.sortable:hover { color: var(--text); }
  thead th.sortable::after {
    content: '⇅';
    position: absolute;
    right: 6px;
    opacity: 0.3;
    font-size: 10px;
  }
  thead th.sort-desc::after { content: '▼'; opacity: 0.8; }
  thead th.sort-asc::after  { content: '▲'; opacity: 0.8; }
  tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background .15s;
    cursor: pointer;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover {
    background: var(--red-glow);
  }
  tbody td {
    padding: 10px 16px;
    white-space: nowrap;
  }
  tbody td.session-id {
    font-family: monospace;
    color: var(--red-light);
    font-weight: 600;
  }
  tbody td.host { color: var(--text); }
  tbody td.muted { color: var(--muted); }
  tbody td.users {
    color: #7fdbca;
    font-size: 13px;
  }
  tbody td.users span {
    display: inline-block;
    background: rgba(127,219,202,.12);
    border: 1px solid rgba(127,219,202,.25);
    border-radius: 4px;
    padding: 1px 6px;
    margin: 1px 3px 1px 0;
    font-size: 12px;
  }
  tbody td.snippet {
    color: var(--muted);
    font-size: 12px;
    white-space: normal;
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  tbody td.snippet em {
    color: var(--red-light);
    font-style: normal;
    font-weight: 700;
  }
  a { color: inherit; text-decoration: none; }
  .refresh-note {
    text-align: center;
    color: var(--muted);
    font-size: 12px;
    margin-top: 20px;
  }
</style>
</head>
<body>
<header>
  <h1>RED BARON 2</h1>
  <span class="sub">TTY Session Viewer</span>
</header>
<div class="container">
  <div class="search-bar">
    <input type="text" id="search" placeholder="Search session content (e.g. ssh, root, apt install)..." autocomplete="off">
    <span class="search-hint" id="search-hint">FTS5</span>
  </div>
  <p class="stats" id="stats">Loading&hellip;</p>
  <table>
    <thead id="thead">
      <tr>
        <th>Host</th>
        <th>Session</th>
        <th>Users</th>
        <th>Size</th>
        <th>Blobs</th>
        <th>Start Time</th>
        <th>Duration</th>
      </tr>
    </thead>
    <tbody id="sessions"></tbody>
  </table>
  <p class="refresh-note">Auto-refreshes every 10 seconds &middot; Background indexing active</p>
</div>
<script>
var searchTimer = null;
var isSearching = false;
var cachedSessions = [];
var cachedSearch = [];
var sortField = 'start_unix'; // 'start_unix' or 'duration_secs'
var sortDir = 'desc';         // 'asc' or 'desc'

document.getElementById('search').addEventListener('input', function() {
  clearTimeout(searchTimer);
  var q = this.value.trim();
  if (q === '') {
    isSearching = false;
    setNormalHeaders();
    load();
    return;
  }
  isSearching = true;
  searchTimer = setTimeout(function() { doSearch(q); }, 250);
});

function sortData(data) {
  var sorted = data.slice();
  sorted.sort(function(a, b) {
    var va = a[sortField] || 0;
    var vb = b[sortField] || 0;
    return sortDir === 'desc' ? vb - va : va - vb;
  });
  return sorted;
}

function headerHTML(label, field) {
  var cls = 'sortable';
  if (sortField === field) {
    cls += sortDir === 'desc' ? ' sort-desc' : ' sort-asc';
  }
  return '<th class="' + cls + '" data-sort="' + field + '">' + label + '</th>';
}

function bindSortHeaders() {
  document.querySelectorAll('th.sortable').forEach(function(th) {
    th.addEventListener('click', function() {
      var field = th.getAttribute('data-sort');
      if (sortField === field) {
        sortDir = sortDir === 'desc' ? 'asc' : 'desc';
      } else {
        sortField = field;
        sortDir = 'desc';
      }
      if (isSearching) {
        renderSearch(cachedSearch);
        setSearchHeaders();
      } else {
        renderSessions(cachedSessions);
        setNormalHeaders();
      }
    });
  });
}

function setNormalHeaders() {
  document.getElementById('thead').innerHTML =
    '<tr><th>Host</th><th>Session</th><th>Users</th><th>Size</th><th>Blobs</th>' +
    headerHTML('Start Time', 'start_unix') +
    headerHTML('Duration', 'duration_secs') +
    '</tr>';
  bindSortHeaders();
}

function setSearchHeaders() {
  document.getElementById('thead').innerHTML =
    '<tr><th>Host</th><th>Session</th><th>Users</th><th>Match</th>' +
    headerHTML('Start Time', 'start_unix') +
    headerHTML('Duration', 'duration_secs') +
    '</tr>';
  bindSortHeaders();
}

function renderUsers(users) {
  if (!users || users.length === 0) return '<span style="color:#555">--</span>';
  return users.map(function(u) { return '<span>' + esc(u) + '</span>'; }).join('');
}

function renderSessions(sessions) {
  var sorted = sortData(sessions);
  var tbody = document.getElementById('sessions');
  tbody.innerHTML = '';
  sorted.forEach(function(s) {
    var tr = document.createElement('tr');
    tr.onclick = function() { window.location = '/play/' + s.s3_path; };
    tr.innerHTML =
      '<td class="host">' + esc(s.host) + '</td>' +
      '<td class="session-id">' + esc(s.session_id.substring(0,8)) + '</td>' +
      '<td class="users">' + renderUsers(s.users) + '</td>' +
      '<td class="muted">' + esc(s.size_human) + '</td>' +
      '<td class="muted">' + s.blob_count + '</td>' +
      '<td class="muted">' + esc(s.start_fmt) + '</td>' +
      '<td class="muted">' + esc(s.duration_fmt) + '</td>';
    tbody.appendChild(tr);
  });
  document.getElementById('stats').textContent =
    sessions.length + ' session(s) found';
}

function renderSearch(results) {
  var sorted = sortData(results);
  var tbody = document.getElementById('sessions');
  tbody.innerHTML = '';
  sorted.forEach(function(s) {
    var tr = document.createElement('tr');
    tr.onclick = function() { window.location = '/play/' + s.s3_path; };
    var snip = esc(s.snippet).replace(/&gt;&gt;&gt;/g, '<em>').replace(/&lt;&lt;&lt;/g, '</em>');
    tr.innerHTML =
      '<td class="host">' + esc(s.host) + '</td>' +
      '<td class="session-id">' + esc(s.session_id.substring(0,8)) + '</td>' +
      '<td class="users">' + renderUsers(s.users) + '</td>' +
      '<td class="snippet">' + snip + '</td>' +
      '<td class="muted">' + esc(s.start_fmt) + '</td>' +
      '<td class="muted">' + esc(s.duration_fmt) + '</td>';
    tbody.appendChild(tr);
  });
  document.getElementById('stats').textContent = results.length + ' result(s)';
}

async function doSearch(q) {
  try {
    document.getElementById('search-hint').textContent = 'searching...';
    var r = await fetch('/api/search?q=' + encodeURIComponent(q));
    var results = await r.json();
    if (!results) results = [];
    cachedSearch = results;
    setSearchHeaders();
    renderSearch(results);
    document.getElementById('search-hint').textContent = 'FTS5';
  } catch(e) {
    document.getElementById('stats').textContent = 'Search error: ' + e.message;
    document.getElementById('search-hint').textContent = 'FTS5';
  }
}

async function load() {
  if (isSearching) return;
  try {
    var r = await fetch('/api/sessions');
    var sessions = await r.json();
    if (!sessions) sessions = [];
    cachedSessions = sessions;
    setNormalHeaders();
    renderSessions(sessions);
  } catch(e) {
    document.getElementById('stats').textContent = 'Error: ' + e.message;
  }
}
function esc(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
load();
setInterval(load, 10000);
</script>
</body>
</html>`

const playerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3/dist/bundle/asciinema-player.css">
<style>
  :root {
    --bg: #0d0d0d;
    --surface: #181818;
    --border: #333;
    --text: #e0e0e0;
    --muted: #888;
    --red: #c0392b;
    --red-light: #e74c3c;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 14px;
  }
  header {
    background: linear-gradient(135deg, #1a0000 0%, var(--surface) 100%);
    border-bottom: 2px solid var(--red);
    padding: 16px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  header h1 {
    font-size: 18px;
    color: var(--red-light);
    letter-spacing: 1px;
  }
  header a {
    color: var(--muted);
    text-decoration: none;
    font-size: 13px;
  }
  header a:hover { color: var(--text); }
  header .spacer { margin-left: auto; }
  .info {
    max-width: 1200px;
    margin: 20px auto;
    padding: 0 32px;
    display: flex;
    gap: 32px;
    color: var(--muted);
    font-size: 13px;
    flex-wrap: wrap;
  }
  .info span { white-space: nowrap; }
  .info .label { color: var(--text); font-weight: 600; }
  #player-container {
    max-width: 1200px;
    margin: 20px auto;
    padding: 0 32px;
  }
  #player-container .ap-wrapper {
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  .gif-controls {
    max-width: 1200px;
    margin: 16px auto;
    padding: 0 32px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .gif-controls label {
    color: var(--muted);
    font-size: 13px;
  }
  .gif-controls select {
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 5px 10px;
    font-family: inherit;
    font-size: 13px;
    outline: none;
  }
  .gif-controls select:focus {
    border-color: var(--red-light);
  }
  .gif-btn {
    background: var(--red);
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 8px 20px;
    font-family: inherit;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background .2s;
    letter-spacing: 0.5px;
  }
  .gif-btn:hover { background: var(--red-light); }
  .gif-btn:disabled {
    background: var(--border);
    cursor: not-allowed;
    color: var(--muted);
  }
  .gif-status {
    color: var(--muted);
    font-size: 13px;
  }
</style>
</head>
<body>
<header>
  <h1>RED BARON 2</h1>
  <span class="spacer"></span>
  <a href="/">&larr; Back to sessions</a>
</header>
<div class="info">
  <span><span class="label">Host:</span> {{HOST}}</span>
  <span><span class="label">Session:</span> {{SESSION_ID}}</span>
  <span><span class="label">Size:</span> {{SIZE}}</span>
  <span><span class="label">Blobs:</span> {{BLOBS}}</span>
  <span><span class="label">Start:</span> {{START}}</span>
  <span><span class="label">End:</span> {{END}}</span>
</div>
<div id="player-container">
  <div id="player"></div>
</div>
<div class="gif-controls">
  <label for="export-format">Format:</label>
  <select id="export-format">
    <option value="gif" selected>GIF</option>
    <option value="mov">MOV (H.264)</option>
  </select>
  <label for="gif-speed">Speed:</label>
  <select id="gif-speed">
    <option value="0.5">0.5x</option>
    <option value="1" selected>1x</option>
    <option value="2">2x</option>
    <option value="5">5x</option>
    <option value="10">10x</option>
  </select>
  <label for="gif-theme">Theme:</label>
  <select id="gif-theme">
    <option value="monokai" selected>Monokai</option>
    <option value="dracula">Dracula</option>
    <option value="solarized-dark">Solarized Dark</option>
    <option value="solarized-light">Solarized Light</option>
    <option value="asciinema">Asciinema</option>
  </select>
  <button class="gif-btn" id="gif-btn" onclick="doExport()">Export</button>
  <span class="gif-status" id="gif-status"></span>
</div>
<script src="https://cdn.jsdelivr.net/npm/asciinema-player@3/dist/bundle/asciinema-player.min.js"></script>
<script>
AsciinemaPlayer.create(
  '/api/cast/{{S3_PATH}}',
  document.getElementById('player'),
  {
    theme: 'monokai',
    fit: 'width',
    autoPlay: true,
    speed: 1,
    idleTimeLimit: 3
  }
);

async function doExport() {
  var btn = document.getElementById('gif-btn');
  var status = document.getElementById('gif-status');
  var speed = document.getElementById('gif-speed').value;
  var theme = document.getElementById('gif-theme').value;
  var format = document.getElementById('export-format').value;
  var label = format.toUpperCase();

  btn.disabled = true;
  btn.textContent = 'Generating ' + label + '...';
  status.textContent = 'This may take a moment for long sessions...';

  try {
    var url = '/api/gif/{{S3_PATH}}?speed=' + speed + '&theme=' + theme + '&format=' + format;
    var resp = await fetch(url);
    if (!resp.ok) {
      var errText = await resp.text();
      throw new Error(errText);
    }
    var blob = await resp.blob();
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    var cd = resp.headers.get('Content-Disposition');
    a.download = cd ? cd.split('filename=')[1].replace(/"/g, '') : ('session.' + format);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
    var sizeMB = (blob.size / 1024 / 1024).toFixed(1);
    status.textContent = label + ' downloaded (' + sizeMB + ' MB)';
  } catch(e) {
    status.textContent = 'Error: ' + e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Export';
  }
}
</script>
</body>
</html>`
