package upload

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/segmentio/ksuid"
	"github.com/thebluefowl/burrow/internal/compress"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/envelope"
	"github.com/thebluefowl/burrow/internal/resume"
	"github.com/thebluefowl/burrow/internal/storage"
)

const defaultPartSize = 16 * 1024 * 1024 // 16MB

// Uploader handles the complete upload workflow
type Uploader struct {
	config     *config.Config
	sourcePath string
	objectID   string

	envelope *envelope.Envelope
	storage  storage.Storage
	session  *resume.UploadSession
	resuming bool
}

// NewUploader creates a new Uploader instance
func NewUploader(cfg *config.Config, sourcePath string, storageClient storage.Storage) *Uploader {
	return &Uploader{
		config:     cfg,
		sourcePath: sourcePath,
		storage:    storageClient,
	}
}

// Execute runs the complete upload process
func (u *Uploader) Execute() error {
	if err := u.initialize(); err != nil {
		return err
	}

	encryptionResult, err := u.encryptAndUpload()
	if err != nil {
		return err
	}

	u.fillEnvelope(encryptionResult)

	if err := u.uploadEnvelope(); err != nil {
		return err
	}

	// Clean up session on success
	if u.session != nil {
		_ = resume.DeleteUpload(u.objectID)
	}

	return nil
}

// initialize sets up the uploader state, checking for resumable sessions
func (u *Uploader) initialize() error {
	ctx := context.Background()

	// Check for existing upload session for this source
	rs, resumable := u.storage.(storage.ResumableStorage)
	if resumable {
		existing, err := resume.FindUploadBySource(u.config.AgePrivateKey, u.sourcePath)
		if err == nil && existing != nil && resume.ValidateSource(u.sourcePath, existing) {
			// Verify the multipart upload still exists on S3
			_, err := rs.ListParts(ctx, existing.S3Key, existing.UploadID)
			if err == nil {
				u.session = existing
				u.objectID = existing.ObjectID
				u.envelope = envelope.NewEnvelope(u.objectID, filepath.Base(u.sourcePath))
				u.resuming = true
				completedParts := len(existing.CompletedParts)
				color.Yellow("↻ Resuming previous upload (%d parts already uploaded)\n", completedParts)
				return nil
			}
			// Upload expired or gone, clean up stale session
			_ = resume.DeleteUpload(existing.ObjectID)
		}
	}

	// Fresh upload
	u.objectID = ksuid.New().String()
	u.envelope = envelope.NewEnvelope(u.objectID, filepath.Base(u.sourcePath))

	// Create multipart upload and session if storage supports it
	if resumable {
		key := "data/" + u.objectID + ".enc"
		uploadID, err := rs.CreateMultipartUpload(ctx, key, "application/octet-stream", nil)
		if err != nil {
			return fmt.Errorf("create multipart upload: %w", err)
		}

		info, err := os.Stat(u.sourcePath)
		if err != nil {
			return fmt.Errorf("stat source: %w", err)
		}

		// Generate AEADParams upfront so they're saved to the session
		// before the pipeline starts. This ensures resume can reuse them
		// if the upload is interrupted after some parts are uploaded.
		aeadParams, err := enc.NewAEADParams(u.objectID, enc.AEADDefaultChunkSize)
		if err != nil {
			return fmt.Errorf("generate aead params: %w", err)
		}

		u.session = &resume.UploadSession{
			ObjectID:      u.objectID,
			SourcePath:    u.sourcePath,
			SourceModTime: info.ModTime(),
			SourceSize:    info.Size(),
			S3Key:         key,
			UploadID:      uploadID,
			PartSize:      defaultPartSize,
			AEADParams:    aeadParams,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := resume.SaveUpload(u.config.AgePublicKey, u.session); err != nil {
			return fmt.Errorf("save upload session: %w", err)
		}
	}

	return nil
}

// encryptAndUpload performs the encryption pipeline and uploads to storage
func (u *Uploader) encryptAndUpload() (*EncryptionPipelineResult, error) {
	opts := &EncryptionPipelineOpts{
		ObjectID: u.objectID,
		Config:   u.config,
		B2Client: u.storage,
	}

	if u.session != nil {
		opts.UploadID = u.session.UploadID
		opts.PartSize = u.session.PartSize
		opts.ResumeParams = &u.session.AEADParams

		if u.resuming {
			opts.ResumeCompression = u.session.CompressionMode
			opts.ResumeSkipBytes = u.session.CompletedBytes()
		}

		opts.OnPartUploaded = func(partNumber int32, etag string, size int64) {
			u.session.AddPart(partNumber, etag, size)
			_ = resume.SaveUpload(u.config.AgePublicKey, u.session)
		}
	}

	result, err := EncryptionPipeline(opts, u.sourcePath, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption and upload pipeline failed: %w", err)
	}

	// Save compression mode to session (needed for resume if a future attempt fails)
	if u.session != nil && u.session.CompressionMode == "" {
		if result.CompressInfo != nil {
			u.session.CompressionMode = string(result.CompressInfo.ModeUsed)
		} else {
			u.session.CompressionMode = string(compress.CompressNone)
		}
		_ = resume.SaveUpload(u.config.AgePublicKey, u.session)
	}

	// Complete the multipart upload
	if u.session != nil {
		rs := u.storage.(storage.ResumableStorage)
		parts := make([]storage.CompletedUploadPart, len(u.session.CompletedParts))
		for i, p := range u.session.CompletedParts {
			parts[i] = storage.CompletedUploadPart{
				PartNumber: p.PartNumber,
				ETag:       p.ETag,
				Size:       p.Size,
			}
		}
		if err := rs.CompleteMultipartUpload(context.Background(), u.session.S3Key, u.session.UploadID, parts); err != nil {
			return nil, fmt.Errorf("complete multipart upload: %w", err)
		}
	}

	return result, nil
}

func (u *Uploader) fillEnvelope(result *EncryptionPipelineResult) {
	if result == nil {
		return
	}

	if result.AEADResult != nil {
		u.envelope.Encryption.Params = result.AEADResult.Params
		u.envelope.Encryption.DataKey = result.AEADResult.DataKey
		u.envelope.PlainSHA = result.AEADResult.PlainSHA
	}

	if result.CompressInfo != nil {
		u.envelope.Compression.Mode = string(result.CompressInfo.ModeUsed)
	} else {
		u.envelope.Compression.Mode = string(compress.CompressNone)
	}

	u.envelope.CipherSHA = result.CipherSHA
	u.envelope.CreatedAt = time.Now()
}

// uploadEnvelope seals and uploads the envelope to the /keys directory
func (u *Uploader) uploadEnvelope() error {
	ctx := context.Background()

	// Seal the envelope using age encryption
	recipients := []string{u.config.AgePublicKey}
	sealedEnvelope, err := u.envelope.Seal(recipients, true)
	if err != nil {
		return fmt.Errorf("failed to seal envelope: %w", err)
	}

	// Upload to /keys directory
	key := "keys/" + u.objectID + ".envelope"
	err = u.storage.Upload(ctx, key, bytes.NewReader(sealedEnvelope), "application/octet-stream", nil)
	if err != nil {
		return fmt.Errorf("failed to upload envelope: %w", err)
	}

	return nil
}

// ObjectID returns the generated object ID for this upload
func (u *Uploader) ObjectID() string {
	return u.objectID
}
