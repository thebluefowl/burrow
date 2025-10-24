package download

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/envelope"
	"github.com/thebluefowl/burrow/internal/storage/b2"
)

// Downloader handles the complete download workflow
type Downloader struct {
	config   *config.Config
	objectID string
	destPath string

	envelope  *envelope.Envelope
	b2Client  *b2.B2Client
	unarchive bool
}

// NewDownloader creates a new Downloader instance
func NewDownloader(cfg *config.Config, objectID string, destPath string, unarchive bool, b2Client *b2.B2Client) *Downloader {
	return &Downloader{
		config:    cfg,
		objectID:  objectID,
		destPath:  destPath,
		unarchive: unarchive,
		b2Client:  b2Client,
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

	// Download envelope from B2
	input := &s3.GetObjectInput{
		Bucket: aws.String(d.b2Client.GetBucket()),
		Key:    aws.String(envelopeKey),
	}

	result, err := d.b2Client.GetClient().GetObject(ctx, input)
	if err != nil {
		return fmt.Errorf("get envelope %s: %w", envelopeKey, err)
	}
	defer result.Body.Close()

	// Read envelope bytes
	envBytes, err := io.ReadAll(result.Body)
	if err != nil {
		return fmt.Errorf("read envelope: %w", err)
	}

	// Decrypt and unmarshal envelope using age private key
	decCfg := enc.DecryptConfig{
		Identities: []string{d.config.AgePrivateKey},
	}

	var env envelope.Envelope
	decryptedEnv, err := env.Open(envBytes, decCfg)
	if err != nil {
		return fmt.Errorf("open envelope: %w", err)
	}

	d.envelope = decryptedEnv
	return nil
}

// downloadAndDecrypt performs the decryption pipeline and downloads from B2
func (d *Downloader) downloadAndDecrypt() error {
	opts := &DecryptionPipelineOpts{
		ObjectID:  d.objectID,
		Envelope:  d.envelope,
		Config:    d.config,
		B2Client:  d.b2Client,
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
	B2Client  *b2.B2Client
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
