package resume

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thebluefowl/burrow/internal/enc"
)

const sessionVersion = "burrow.session.v1"

// CompletedPart records a successfully uploaded S3 multipart part.
type CompletedPart struct {
	PartNumber int32  `json:"part_number"`
	ETag       string `json:"etag"`
	Size       int64  `json:"size"`
}

// UploadSession tracks the state of an in-progress resumable upload.
type UploadSession struct {
	Version         string         `json:"version"`
	ObjectID        string         `json:"object_id"`
	SourcePath      string         `json:"source_path"`
	SourceModTime   time.Time      `json:"source_mod_time"`
	SourceSize      int64          `json:"source_size"`
	S3Key           string         `json:"s3_key"`
	UploadID        string         `json:"upload_id"`
	PartSize        int64          `json:"part_size"`
	AEADParams      enc.AEADParams `json:"aead_params"`
	CompressionMode string         `json:"compression_mode"`
	CompletedParts  []CompletedPart `json:"completed_parts"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// CompletedBytes returns the total ciphertext bytes already uploaded.
func (s *UploadSession) CompletedBytes() int64 {
	var total int64
	for _, p := range s.CompletedParts {
		total += p.Size
	}
	return total
}

// AddPart records a completed part.
func (s *UploadSession) AddPart(partNumber int32, etag string, size int64) {
	s.CompletedParts = append(s.CompletedParts, CompletedPart{
		PartNumber: partNumber,
		ETag:       etag,
		Size:       size,
	})
	s.UpdatedAt = time.Now()
}

// DownloadSession tracks the state of an in-progress resumable download.
type DownloadSession struct {
	Version       string    `json:"version"`
	ObjectID      string    `json:"object_id"`
	PartialPath   string    `json:"partial_path"`
	TotalSize     int64     `json:"total_size"`
	BytesReceived int64     `json:"bytes_received"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// sessionsDir returns the path to the sessions directory.
func sessionsDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}
	return filepath.Join(dir, "burrow", "sessions"), nil
}

func ensureSessionsDir() (string, error) {
	dir, err := sessionsDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create sessions directory: %w", err)
	}
	return dir, nil
}

func uploadSessionPath(objectID string) (string, error) {
	dir, err := sessionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "upload-"+objectID+".session.enc"), nil
}

func downloadSessionPath(objectID string) (string, error) {
	dir, err := sessionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "download-"+objectID+".session.enc"), nil
}

// SaveUpload encrypts and saves an upload session to disk.
func SaveUpload(publicKey string, s *UploadSession) error {
	dir, err := ensureSessionsDir()
	if err != nil {
		return err
	}

	s.Version = sessionVersion
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal upload session: %w", err)
	}

	ciphertext, err := enc.EncryptBytes(data, enc.EncryptConfig{
		Recipients: []string{publicKey},
		Armor:      false,
	})
	if err != nil {
		return fmt.Errorf("encrypt upload session: %w", err)
	}

	path := filepath.Join(dir, "upload-"+s.ObjectID+".session.enc")
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write upload session: %w", err)
	}
	return nil
}

// LoadUpload reads and decrypts an upload session by objectID.
func LoadUpload(privateKey string, objectID string) (*UploadSession, error) {
	path, err := uploadSessionPath(objectID)
	if err != nil {
		return nil, err
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read upload session: %w", err)
	}

	data, err := enc.DecryptBytes(ciphertext, enc.DecryptConfig{
		Identities: []string{privateKey},
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt upload session: %w", err)
	}

	var s UploadSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal upload session: %w", err)
	}
	return &s, nil
}

// FindUploadBySource scans all upload sessions for one matching the given source path.
func FindUploadBySource(privateKey string, sourcePath string) (*UploadSession, error) {
	dir, err := sessionsDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sessions directory: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "upload-") || !strings.HasSuffix(name, ".session.enc") {
			continue
		}

		objectID := strings.TrimPrefix(name, "upload-")
		objectID = strings.TrimSuffix(objectID, ".session.enc")

		s, err := LoadUpload(privateKey, objectID)
		if err != nil {
			continue // skip corrupt sessions
		}
		if s != nil && s.SourcePath == sourcePath {
			return s, nil
		}
	}
	return nil, nil
}

// ValidateSource checks that the source file hasn't changed since the session was created.
func ValidateSource(sourcePath string, s *UploadSession) bool {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return false
	}
	return info.ModTime().Equal(s.SourceModTime) && info.Size() == s.SourceSize
}

// SaveDownload encrypts and saves a download session to disk.
func SaveDownload(publicKey string, s *DownloadSession) error {
	dir, err := ensureSessionsDir()
	if err != nil {
		return err
	}

	s.Version = sessionVersion
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal download session: %w", err)
	}

	ciphertext, err := enc.EncryptBytes(data, enc.EncryptConfig{
		Recipients: []string{publicKey},
		Armor:      false,
	})
	if err != nil {
		return fmt.Errorf("encrypt download session: %w", err)
	}

	path := filepath.Join(dir, "download-"+s.ObjectID+".session.enc")
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("write download session: %w", err)
	}
	return nil
}

// LoadDownload reads and decrypts a download session by objectID.
func LoadDownload(privateKey string, objectID string) (*DownloadSession, error) {
	path, err := downloadSessionPath(objectID)
	if err != nil {
		return nil, err
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read download session: %w", err)
	}

	data, err := enc.DecryptBytes(ciphertext, enc.DecryptConfig{
		Identities: []string{privateKey},
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt download session: %w", err)
	}

	var s DownloadSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal download session: %w", err)
	}
	return &s, nil
}

// DeleteUpload removes an upload session file.
func DeleteUpload(objectID string) error {
	path, err := uploadSessionPath(objectID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete upload session: %w", err)
	}
	return nil
}

// DeleteDownload removes a download session file.
func DeleteDownload(objectID string) error {
	path, err := downloadSessionPath(objectID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete download session: %w", err)
	}
	return nil
}
