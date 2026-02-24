package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/envelope"
	"github.com/thebluefowl/burrow/internal/progress"
	"github.com/thebluefowl/burrow/internal/resume"
	"github.com/thebluefowl/burrow/internal/storage"
)

// Downloader handles the complete download workflow
type Downloader struct {
	config   *config.Config
	objectID string
	destPath string

	envelope  *envelope.Envelope
	storage   storage.Storage
	unarchive bool
}

// NewDownloader creates a new Downloader instance
func NewDownloader(cfg *config.Config, objectID string, destPath string, unarchive bool, storageClient storage.Storage) *Downloader {
	return &Downloader{
		config:    cfg,
		objectID:  objectID,
		destPath:  destPath,
		unarchive: unarchive,
		storage:   storageClient,
	}
}

// Execute runs the complete download process
func (d *Downloader) Execute() error {
	if err := d.fetchEnvelope(); err != nil {
		return err
	}

	// Phase 1: Download ciphertext to partial file (resumable)
	partialPath, err := d.downloadCiphertext()
	if err != nil {
		return err
	}

	// Phase 2: Decrypt from local file
	if err := d.decryptFromFile(partialPath); err != nil {
		return err
	}

	// Clean up partial file and session on success
	os.Remove(partialPath)
	_ = resume.DeleteDownload(d.objectID)

	return nil
}

// fetchEnvelope downloads and decrypts the envelope
func (d *Downloader) fetchEnvelope() error {
	ctx := context.Background()
	envelopeKey := "keys/" + d.objectID + ".envelope"

	// Download envelope from storage
	var buf bytes.Buffer
	_, _, err := d.storage.Download(ctx, envelopeKey, &buf)
	if err != nil {
		return fmt.Errorf("download envelope %s: %w", envelopeKey, err)
	}

	// Decrypt and unmarshal envelope using age private key
	decCfg := enc.DecryptConfig{
		Identities: []string{d.config.AgePrivateKey},
	}

	var env envelope.Envelope
	decryptedEnv, err := env.Open(buf.Bytes(), decCfg)
	if err != nil {
		return fmt.Errorf("open envelope: %w", err)
	}

	d.envelope = decryptedEnv
	return nil
}

// downloadCiphertext downloads the encrypted data to a partial file with resume support.
func (d *Downloader) downloadCiphertext() (string, error) {
	ctx := context.Background()
	partialPath := d.destPath + ".partial"
	key := "data/" + d.objectID + ".enc"

	rs, resumable := d.storage.(storage.ResumableStorage)

	// Check for existing download session
	var session *resume.DownloadSession
	if resumable {
		existing, err := resume.LoadDownload(d.config.AgePrivateKey, d.objectID)
		if err == nil && existing != nil {
			// Verify partial file exists and matches session
			info, statErr := os.Stat(partialPath)
			if statErr == nil && info.Size() == existing.BytesReceived {
				session = existing
				color.Yellow("↻ Resuming previous download (%d/%d bytes)\n", session.BytesReceived, session.TotalSize)
			} else {
				// Partial file missing or size mismatch, start fresh
				_ = resume.DeleteDownload(d.objectID)
				os.Remove(partialPath)
			}
		}
	}

	if session != nil && session.BytesReceived >= session.TotalSize {
		// Already fully downloaded
		return partialPath, nil
	}

	if session != nil {
		// Resume: download remaining bytes
		remaining := session.TotalSize - session.BytesReceived

		bar := progress.CreateProgressBar("☁️  DOWNLOAD")
		bar.Add64(session.BytesReceived)

		f, err := os.OpenFile(partialPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return "", fmt.Errorf("open partial file for resume: %w", err)
		}
		defer f.Close()

		progressWriter := io.MultiWriter(f, bar)
		if err := rs.DownloadRange(ctx, key, progressWriter, session.BytesReceived, remaining); err != nil {
			return "", fmt.Errorf("resume download: %w", err)
		}

		session.BytesReceived = session.TotalSize
		_ = resume.SaveDownload(d.config.AgePublicKey, session)
		_ = bar.Finish()
	} else {
		// Fresh download
		bar := progress.CreateProgressBar("☁️  DOWNLOAD")

		f, err := os.OpenFile(partialPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return "", fmt.Errorf("create partial file: %w", err)
		}

		var totalSize int64
		if resumable {
			size, err := rs.HeadObject(ctx, key)
			if err == nil {
				totalSize = size
			}
		}

		progressWriter := io.MultiWriter(f, bar)
		_, _, err = d.storage.Download(ctx, key, progressWriter)
		f.Close()
		if err != nil {
			return "", fmt.Errorf("download ciphertext: %w", err)
		}

		// Get actual downloaded size
		info, _ := os.Stat(partialPath)
		if info != nil {
			totalSize = info.Size()
		}

		// Save session for potential resume
		if resumable {
			session = &resume.DownloadSession{
				ObjectID:      d.objectID,
				PartialPath:   partialPath,
				TotalSize:     totalSize,
				BytesReceived: totalSize,
			}
			_ = resume.SaveDownload(d.config.AgePublicKey, session)
		}
		_ = bar.Finish()
	}

	// Verify ciphertext SHA256
	if err := d.verifyCiphertextSHA(partialPath); err != nil {
		os.Remove(partialPath)
		_ = resume.DeleteDownload(d.objectID)
		return "", err
	}

	return partialPath, nil
}

// verifyCiphertextSHA verifies the SHA256 of the downloaded ciphertext against the envelope.
func (d *Downloader) verifyCiphertextSHA(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open partial file for verification: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("hash ciphertext: %w", err)
	}

	var downloadedSHA [32]byte
	copy(downloadedSHA[:], hasher.Sum(nil))
	if !enc.VerifySHA256(downloadedSHA, d.envelope.CipherSHA) {
		return fmt.Errorf("ciphertext SHA256 verification failed: downloaded data does not match expected checksum")
	}
	return nil
}

// decryptFromFile runs the decryption pipeline reading from a local file.
func (d *Downloader) decryptFromFile(ciphertextPath string) error {
	opts := &DecryptionPipelineOpts{
		ObjectID:       d.objectID,
		Envelope:       d.envelope,
		Config:         d.config,
		DestPath:       d.destPath,
		Unarchive:      d.unarchive,
		CiphertextPath: ciphertextPath,
	}

	return DecryptionPipeline(opts)
}

// DecryptionPipelineOpts contains options for the decryption pipeline
type DecryptionPipelineOpts struct {
	ObjectID       string
	Envelope       *envelope.Envelope
	Config         *config.Config
	Storage        storage.Storage // used only when CiphertextPath is empty
	DestPath       string
	Unarchive      bool
	CiphertextPath string // if set, read ciphertext from this local file instead of storage
}

// DecryptionPipeline executes the complete decryption pipeline
func DecryptionPipeline(opts *DecryptionPipelineOpts) error {
	ctx := context.Background()

	dp := &decryptionPipeline{
		opts: opts,
	}

	return dp.execute(ctx)
}
