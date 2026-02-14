package s3client

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"rb2-tty/internal/models"
)

// Config holds S3/MinIO connection parameters.
type Config struct {
	Endpoint  string
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	PathStyle bool
}

// Client wraps the MinIO client for TTY session operations.
type Client struct {
	mc     *minio.Client
	bucket string
}

// New creates a new S3 session client.
func New(cfg Config) (*Client, error) {
	// Parse endpoint to extract host and determine TLS.
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint: %w", err)
	}

	host := u.Host
	secure := u.Scheme == "https"

	mc, err := minio.New(host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("creating minio client: %w", err)
	}

	return &Client{mc: mc, bucket: cfg.Bucket}, nil
}

// ListSessions discovers all sessions in the bucket, sorted by most-recent
// end time first.
//
// Bucket layout: {hostname}/{session-uuid}/{session-uuid}-{timestamp}.cast.age
func (c *Client) ListSessions(ctx context.Context) ([]models.Session, error) {
	sessMap := make(map[string]*models.Session)

	for obj := range c.mc.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("listing objects: %w", obj.Err)
		}

		parts := strings.SplitN(obj.Key, "/", 3)
		if len(parts) != 3 || !strings.HasSuffix(parts[2], ".cast.age") {
			continue
		}

		host := parts[0]
		sessionID := parts[1]
		pathKey := host + "/" + sessionID

		// Extract unix timestamp from filename.
		filename := strings.TrimSuffix(parts[2], ".cast.age")
		tsPart := filename[strings.LastIndex(filename, "-")+1:]
		var dt time.Time
		if ts, err := strconv.ParseInt(tsPart, 10, 64); err == nil {
			dt = time.Unix(ts, 0)
		} else {
			dt = obj.LastModified
		}

		sess, ok := sessMap[pathKey]
		if !ok {
			sess = &models.Session{
				Host:      host,
				SessionID: sessionID,
				StartTime: dt,
				EndTime:   dt,
				S3Path:    pathKey,
			}
			sessMap[pathKey] = sess
		}

		sess.TotalSize += obj.Size
		sess.BlobCount++
		if dt.Before(sess.StartTime) {
			sess.StartTime = dt
		}
		if dt.After(sess.EndTime) {
			sess.EndTime = dt
		}
	}

	sessions := make([]models.Session, 0, len(sessMap))
	for _, s := range sessMap {
		s.Finalize()
		sessions = append(sessions, *s)
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].EndTime.After(sessions[j].EndTime)
	})

	return sessions, nil
}

// ListSessionKeys returns all .cast.age object keys under a session prefix,
// sorted lexicographically.
func (c *Client) ListSessionKeys(ctx context.Context, s3Path string) ([]string, error) {
	prefix := s3Path
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var keys []string
	for obj := range c.mc.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("listing session keys: %w", obj.Err)
		}
		if strings.HasSuffix(obj.Key, ".cast.age") {
			keys = append(keys, obj.Key)
		}
	}

	sort.Strings(keys)
	return keys, nil
}

// DownloadObject downloads a single S3 object and returns its raw bytes.
func (c *Client) DownloadObject(ctx context.Context, key string) ([]byte, error) {
	obj, err := c.mc.GetObject(ctx, c.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting object %s: %w", key, err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("reading object %s: %w", key, err)
	}
	return data, nil
}
