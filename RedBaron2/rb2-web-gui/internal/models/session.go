package models

import (
	"fmt"
	"time"
)

// Session represents a single TTY recording session from the S3 bucket.
type Session struct {
	Host      string    `json:"host"`
	SessionID string    `json:"session_id"`
	TotalSize int64     `json:"total_size"`
	SizeHuman string    `json:"size_human"`
	BlobCount int       `json:"blob_count"`
	StartTime time.Time `json:"-"`
	EndTime   time.Time `json:"-"`
	StartFmt     string  `json:"start_fmt"`
	EndFmt       string  `json:"end_fmt"`
	StartUnix    int64   `json:"start_unix"`
	DurationFmt  string  `json:"duration_fmt"`
	DurationSecs float64 `json:"duration_secs"`
	S3Path       string  `json:"s3_path"`
	Users        []string `json:"users"`
}

const timeFmt = "Jan 02 15:04:05"

// Finalize computes the display-friendly fields after all blobs have been
// aggregated.
func (s *Session) Finalize() {
	s.SizeHuman = humanSize(s.TotalSize)
	s.StartFmt = s.StartTime.Local().Format(timeFmt)
	s.EndFmt = s.EndTime.Local().Format(timeFmt)
	s.StartUnix = s.StartTime.Unix()
	// Prefer the true duration from the cast recording over the S3 blob delta.
	if s.DurationSecs > 0 {
		s.DurationFmt = humanDuration(time.Duration(s.DurationSecs * float64(time.Second)))
	} else {
		s.DurationFmt = humanDuration(s.EndTime.Sub(s.StartTime))
	}
	if s.Users == nil {
		s.Users = []string{}
	}
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, sec)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, sec)
	default:
		return fmt.Sprintf("%ds", sec)
	}
}

func humanSize(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
}
