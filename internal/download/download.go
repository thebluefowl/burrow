package download

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/thebluefowl/burrow/internal/archive"
	"github.com/thebluefowl/burrow/internal/b2"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/envelope"
	"github.com/thebluefowl/burrow/internal/pipeline"
	"github.com/thebluefowl/burrow/internal/progress"
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
func NewDownloader(cfg *config.Config, objectID string, destPath string, unarchive bool) *Downloader {
	return &Downloader{
		config:    cfg,
		objectID:  objectID,
		destPath:  destPath,
		unarchive: unarchive,
	}
}

// Execute runs the complete download process
func (d *Downloader) Execute() error {
	if err := d.initializeB2(); err != nil {
		return err
	}

	if err := d.fetchEnvelope(); err != nil {
		return err
	}

	if err := d.downloadAndDecrypt(); err != nil {
		return err
	}

	return nil
}

// initializeB2 creates the B2 client
func (d *Downloader) initializeB2() error {
	ctx := context.Background()

	b2Config := b2.Config{
		Bucket:      d.config.BucketName,
		Region:      d.config.Region,
		Endpoint:    fmt.Sprintf("https://s3.%s.backblazeb2.com", d.config.Region),
		AccessKey:   d.config.KeyID,
		SecretKey:   d.config.AppKey,
		PartSizeMB:  16,
		Concurrency: 4,
	}

	client, err := b2.NewB2Client(ctx, b2Config)
	if err != nil {
		return fmt.Errorf("failed to create B2 client: %w", err)
	}

	d.b2Client = client
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

// decryptionPipeline manages the decryption pipeline execution
type decryptionPipeline struct {
	opts *DecryptionPipelineOpts
}

// execute runs the complete pipeline
func (dp *decryptionPipeline) execute(ctx context.Context) error {
	if dp.opts.ObjectID == "" {
		return fmt.Errorf("objectID is required")
	}

	if dp.opts.Envelope == nil {
		return fmt.Errorf("envelope is required")
	}

	if dp.opts.Config == nil {
		return fmt.Errorf("config is required")
	}

	if dp.opts.Config.MasterKey == nil {
		return fmt.Errorf("masterKey is required")
	}

	stages := []pipeline.Stage{
		dp.downloadStage,
		dp.decryptStage,
		dp.decompressStage,
	}

	if dp.opts.Unarchive {
		stages = append(stages, dp.unarchiveStage)
	} else {
		stages = append(stages, dp.fileOutputStage)
	}

	if err := pipeline.PipeGraph(ctx, stages...); err != nil {
		return fmt.Errorf("decryption pipeline: %w", err)
	}

	return nil
}

// downloadStage downloads the encrypted data from B2
func (dp *decryptionPipeline) downloadStage(ctx context.Context, r io.Reader, w io.Writer) error {
	if dp.opts.B2Client == nil {
		return fmt.Errorf("B2 client is required for download")
	}

	bar := progress.CreateProgressBar("☁️  DOWNLOAD")
	defer func() { _ = bar.Finish() }()

	key := "data/" + dp.opts.ObjectID + ".enc"

	input := &s3.GetObjectInput{
		Bucket: aws.String(dp.opts.B2Client.GetBucket()),
		Key:    aws.String(key),
	}

	result, err := dp.opts.B2Client.GetClient().GetObject(ctx, input)
	if err != nil {
		return fmt.Errorf("download stage: %w", err)
	}
	defer result.Body.Close()

	progressReader := io.TeeReader(result.Body, bar)
	if _, err := io.Copy(w, progressReader); err != nil {
		return fmt.Errorf("download stage copy: %w", err)
	}

	return nil
}

// decryptStage decrypts the data
func (dp *decryptionPipeline) decryptStage(ctx context.Context, r io.Reader, w io.Writer) error {
	bar := progress.CreateProgressBar("🔓 DECRYPT ")
	defer func() { _ = bar.Finish() }()

	dataKey, err := enc.DeriveDataKey(dp.opts.Config.MasterKey, dp.opts.ObjectID)
	if err != nil {
		return fmt.Errorf("derive data key: %w", err)
	}

	progressReader := io.TeeReader(r, bar)
	aeadResult, err := enc.DecryptAEAD(w, progressReader, dataKey, dp.opts.Envelope.Encryption.Params)
	if err != nil {
		return fmt.Errorf("aead decrypt: %w", err)
	}

	// Verify SHA256
	if !enc.VerifySHA256(aeadResult.PlainSHA, dp.opts.Envelope.PlainSHA) {
		return fmt.Errorf("SHA256 verification failed")
	}

	return nil
}

// decompressStage decompresses the data based on envelope compression mode
func (dp *decryptionPipeline) decompressStage(ctx context.Context, r io.Reader, w io.Writer) error {
	mode := dp.opts.Envelope.Compression.Mode

	switch mode {
	case string(archive.CompressNone), "":
		// No compression, pass through
		bar := progress.CreateProgressBar("➡️  PASSTHRU")
		defer func() { _ = bar.Finish() }()

		progressReader := io.TeeReader(r, bar)
		if _, err := io.Copy(w, progressReader); err != nil {
			return fmt.Errorf("passthrough copy: %w", err)
		}
		return nil

	case string(archive.CompressZstd):
		// Decompress zstd
		bar := progress.CreateProgressBar("🗜️  UNZIP   ")
		defer func() { _ = bar.Finish() }()

		decoder, err := archive.NewZstdDecoder(r)
		if err != nil {
			return fmt.Errorf("create zstd decoder: %w", err)
		}

		progressReader := io.TeeReader(decoder.IOReadCloser(), bar)
		if _, err := io.Copy(w, progressReader); err != nil {
			return fmt.Errorf("decompress stage copy: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported compression mode: %s", mode)
	}
}

func (dp *decryptionPipeline) unarchiveStage(ctx context.Context, r io.Reader, w io.Writer) error {
	bar := progress.CreateProgressBar("�� EXTRACT ")
	defer func() { _ = bar.Finish() }()

	progressReader := io.TeeReader(r, bar)
	if err := archive.ExtractTar(progressReader, dp.opts.DestPath); err != nil {
		return fmt.Errorf("extract tar: %w", err)
	}
	return nil
}

// outputStage writes to file
func (dp *decryptionPipeline) fileOutputStage(ctx context.Context, r io.Reader, _ io.Writer) error {
	// Write to file
	bar := progress.CreateProgressBar("💾 WRITE   ")
	defer func() { _ = bar.Finish() }()
	if dp.opts.DestPath == "" {
		return fmt.Errorf("destPath is required")
	}

	// Determine output path - restore original filename + .tar extension
	var outputPath string
	if stat, err := os.Stat(dp.opts.DestPath); err == nil && stat.IsDir() {
		// DestPath is a directory, construct filename from envelope
		filename := dp.opts.Envelope.OriginalFileName + ".tar"
		outputPath = dp.opts.DestPath + string(os.PathSeparator) + filename
	} else {
		// DestPath is a file path, ensure it has .tar extension
		outputPath = dp.opts.DestPath + ".tar"
	}

	w, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer w.Close()

	progressReader := io.TeeReader(r, bar)
	if _, err := io.Copy(w, progressReader); err != nil {
		return fmt.Errorf("write stage: %w", err)
	}

	return nil
}
