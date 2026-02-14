package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"rb2-tty/internal/s3client"
	"rb2-tty/internal/server"
)

func main() {
	endpoint := flag.String("endpoint", "", "S3/MinIO endpoint URL (required)")
	bucket := flag.String("bucket", "", "S3 bucket name (required)")
	region := flag.String("region", "", "S3 region (required)")
	accessKey := flag.String("access-key", "", "S3 access key (required)")
	secretKey := flag.String("secret-key", "", "S3 secret key (required)")
	pathStyle := flag.Bool("path-style", false, "Use path-style S3 URLs (required for MinIO)")
	keyPath := flag.String("key", "", "Path to SSH private key for decryption (required)")
	port := flag.Int("port", 8080, "HTTP server port")
	dbPath := flag.String("db", "rb2tty.db", "Path to SQLite database file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Red Baron 2 -- TTY Session Web Viewer\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags]\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s \\\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    -endpoint http://44.207.7.176:9000 \\\n")
		fmt.Fprintf(os.Stderr, "    -bucket rb2-tty \\\n")
		fmt.Fprintf(os.Stderr, "    -region us-east-1 \\\n")
		fmt.Fprintf(os.Stderr, "    -access-key KEY \\\n")
		fmt.Fprintf(os.Stderr, "    -secret-key SECRET \\\n")
		fmt.Fprintf(os.Stderr, "    -path-style \\\n")
		fmt.Fprintf(os.Stderr, "    -key /path/to/ssh/private/key\n")
	}

	flag.Parse()

	// Validate required flags.
	missing := false
	for _, pair := range []struct {
		val  string
		name string
	}{
		{*endpoint, "-endpoint"},
		{*bucket, "-bucket"},
		{*region, "-region"},
		{*accessKey, "-access-key"},
		{*secretKey, "-secret-key"},
		{*keyPath, "-key"},
	} {
		if pair.val == "" {
			fmt.Fprintf(os.Stderr, "error: %s is required\n", pair.name)
			missing = true
		}
	}
	if missing {
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	_ = *pathStyle // used below in config

	cfg := server.Config{
		S3: s3client.Config{
			Endpoint:  *endpoint,
			Bucket:    *bucket,
			Region:    *region,
			AccessKey: *accessKey,
			SecretKey: *secretKey,
			PathStyle: *pathStyle,
		},
		KeyPath: *keyPath,
		Port:    *port,
		DBPath:  *dbPath,
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
