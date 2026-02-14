package decrypt

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/ulikunitz/xz"
)

var ageMarker = []byte("age-encryption.org/v1\n")

// LoadSSHIdentity reads an SSH private key file and returns an age Identity.
func LoadSSHIdentity(path string) (age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", path, err)
	}

	identity, err := agessh.ParseIdentity(data)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH identity: %w", err)
	}

	return identity, nil
}

// SplitAgePayloads splits a buffer that may contain multiple concatenated
// age-encrypted payloads, each starting with the "age-encryption.org/v1\n"
// marker.
func SplitAgePayloads(data []byte) [][]byte {
	var chunks [][]byte
	start := 0

	for start < len(data) {
		nextPos := bytes.Index(data[start+1:], ageMarker)
		if nextPos == -1 {
			chunks = append(chunks, data[start:])
			break
		}
		nextPos += start + 1
		chunks = append(chunks, data[start:nextPos])
		start = nextPos
	}

	return chunks
}

// DecryptBlob decrypts and xz-decompresses a single S3 object which may
// contain multiple concatenated age payloads.
func DecryptBlob(raw []byte, identity age.Identity) ([]byte, error) {
	chunks := SplitAgePayloads(raw)
	var result []byte

	for i, chunk := range chunks {
		// Age decrypt
		reader, err := age.Decrypt(bytes.NewReader(chunk), identity)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: age decrypt: %w", i, err)
		}
		decrypted, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: reading decrypted data: %w", i, err)
		}

		// XZ decompress
		xzReader, err := xz.NewReader(bytes.NewReader(decrypted))
		if err != nil {
			return nil, fmt.Errorf("chunk %d: xz reader: %w", i, err)
		}
		decompressed, err := io.ReadAll(xzReader)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: xz decompress: %w", i, err)
		}

		result = append(result, decompressed...)
	}

	return result, nil
}
