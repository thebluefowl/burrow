package download

import (
	"bytes"
	"context"
	"fmt"

	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/envelope"
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

	if err := d.downloadAndDecrypt(); err != nil {
		return err
	}

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

// downloadAndDecrypt performs the decryption pipeline and downloads from storage
func (d *Downloader) downloadAndDecrypt() error {
	opts := &DecryptionPipelineOpts{
		ObjectID:  d.objectID,
		Envelope:  d.envelope,
		Config:    d.config,
		Storage:   d.storage,
		DestPath:  d.destPath,
		Unarchive: d.unarchive,
	}

	return DecryptionPipeline(opts)
}

// DecryptionPipelineOpts contains options for the decryption pipeline
type DecryptionPipelineOpts struct {
	ObjectID  string
	Envelope  *envelope.Envelope
	Config    *config.Config
	Storage   storage.Storage
	DestPath  string
	Unarchive bool
}

// DecryptionPipeline executes the complete decryption pipeline
func DecryptionPipeline(opts *DecryptionPipelineOpts) error {
	ctx := context.Background()

	dp := &decryptionPipeline{
		opts: opts,
	}

	return dp.execute(ctx)
}
