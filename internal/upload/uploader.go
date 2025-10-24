package upload

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/segmentio/ksuid"
	"github.com/thebluefowl/burrow/internal/compress"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/envelope"
	"github.com/thebluefowl/burrow/internal/storage/b2"
)

// Uploader handles the complete upload workflow
type Uploader struct {
	config     *config.Config
	sourcePath string
	objectID   string

	envelope *envelope.Envelope
	b2Client *b2.B2Client
}

// NewUploader creates a new Uploader instance
func NewUploader(cfg *config.Config, sourcePath string, b2Client *b2.B2Client) *Uploader {
	return &Uploader{
		config:     cfg,
		sourcePath: sourcePath,
		b2Client:   b2Client,
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

	return nil
}

// initialize sets up the uploader state
func (u *Uploader) initialize() error {
	u.objectID = ksuid.New().String()
	u.envelope = envelope.NewEnvelope(u.objectID, filepath.Base(u.sourcePath))
	return nil
}

// encryptAndUpload performs the encryption pipeline and uploads to B2
func (u *Uploader) encryptAndUpload() (*EncryptionPipelineResult, error) {
	opts := &EncryptionPipelineOpts{
		ObjectID: u.objectID,
		Config:   u.config,
		B2Client: u.b2Client,
	}

	result, err := EncryptionPipeline(opts, u.sourcePath, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption and upload pipeline failed: %w", err)
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
	_, err = u.b2Client.Upload(ctx, key, bytes.NewReader(sealedEnvelope), "application/octet-stream", nil)
	if err != nil {
		return fmt.Errorf("failed to upload envelope: %w", err)
	}

	return nil
}

// ObjectID returns the generated object ID for this upload
func (u *Uploader) ObjectID() string {
	return u.objectID
}
