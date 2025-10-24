package upload

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/thebluefowl/burrow/internal/archive"
	"github.com/thebluefowl/burrow/internal/compress"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/pipeline"
	"github.com/thebluefowl/burrow/internal/progress"
)

// Constants for pipeline configuration
const (
	compressionLevel      = 3
	compressionMinSaving  = 0.05
	compressionSampleSize = 1 << 20
)

// EncryptionPipelineOpts contains options for the encryption pipeline
type EncryptionPipelineOpts struct {
	ObjectID string
	Config   *config.Config
	B2Client B2Uploader
}

// B2Uploader interface for uploading to B2
type B2Uploader interface {
	Upload(ctx context.Context, key string, body io.Reader, contentType string, metadata map[string]string) (*manager.UploadOutput, error)
}

// EncryptionPipelineResult contains the results of the encryption pipeline
type EncryptionPipelineResult struct {
	CompressInfo *compress.CompressInfo
	AEADResult   *enc.AEADResult
}

// EncryptionPipeline executes the complete encryption pipeline
func EncryptionPipeline(opts *EncryptionPipelineOpts, src string, dst io.Writer) (*EncryptionPipelineResult, error) {
	ctx := context.Background()

	ep := &encryptionPipeline{
		opts: opts,
		src:  src,
		dst:  dst,
	}

	return ep.execute(ctx)
}

// encryptionPipeline manages the encryption pipeline execution
type encryptionPipeline struct {
	opts *EncryptionPipelineOpts
	src  string
	dst  io.Writer

	compressInfo *compress.CompressInfo
	aeadResult   *enc.AEADResult
}

// execute runs the complete pipeline
func (ep *encryptionPipeline) execute(ctx context.Context) (*EncryptionPipelineResult, error) {
	if ep.opts.ObjectID == "" {
		return nil, fmt.Errorf("objectID is required")
	}

	if ep.opts.Config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if ep.opts.Config.MasterKey == nil {
		return nil, fmt.Errorf("masterKey is required")
	}

	stages := []pipeline.Stage{
		ep.archiveStage,
		ep.compressStage,
		ep.encryptStage,
		ep.uploadStage,
	}

	if err := pipeline.PipeGraph(ctx, stages...); err != nil {
		return nil, fmt.Errorf("encryption pipeline: %w", err)
	}

	return &EncryptionPipelineResult{
		CompressInfo: ep.compressInfo,
		AEADResult:   ep.aeadResult,
	}, nil
}

// tarStage creates a tar archive from the source
func (ep *encryptionPipeline) archiveStage(ctx context.Context, r io.Reader, w io.Writer) error {
	bar := progress.CreateProgressBar("📦 ARCHIVE ")
	defer func() { _ = bar.Finish() }()

	opts := archive.Options{
		IncludeRoot:   true,
		Deterministic: true,
	}

	progressWriter := io.MultiWriter(w, bar)
	if err := archive.StreamTar(ctx, progressWriter, ep.src, opts); err != nil {
		return fmt.Errorf("tar stage: %w", err)
	}

	return nil
}

// compressStage compresses the tar archive
func (ep *encryptionPipeline) compressStage(ctx context.Context, r io.Reader, w io.Writer) error {
	bar := progress.CreateProgressBar("🗜️  COMPRESS")
	defer func() { _ = bar.Finish() }()

	compCfg := compress.CompressorConfig{
		Mode:          compress.CompressionMode("auto"),
		ZstdLevel:     compressionLevel,
		AutoMinSaving: compressionMinSaving,
		SampleBytes:   compressionSampleSize,
	}

	compWriter, compInfo, err := compress.NewCompressorWithInfo(w, compCfg)
	if err != nil {
		return fmt.Errorf("compress stage setup: %w", err)
	}

	ep.compressInfo = compInfo

	progressReader := io.TeeReader(r, bar)
	if _, err := io.Copy(compWriter, progressReader); err != nil {
		compWriter.Close()
		return fmt.Errorf("compress stage copy: %w", err)
	}

	if err := compWriter.Close(); err != nil {
		return fmt.Errorf("compress stage close: %w", err)
	}

	return nil
}

// encryptStage encrypts the compressed data
func (ep *encryptionPipeline) encryptStage(ctx context.Context, r io.Reader, w io.Writer) error {
	bar := progress.CreateProgressBar("🔒 ENCRYPT ")
	defer func() { _ = bar.Finish() }()

	params, err := enc.NewAEADParams(ep.opts.ObjectID, enc.AEADDefaultChunkSize)
	if err != nil {
		return fmt.Errorf("new aead params: %w", err)
	}

	dataKey, err := enc.DeriveDataKey(ep.opts.Config.MasterKey, ep.opts.ObjectID)
	if err != nil {
		return fmt.Errorf("derive data key: %w", err)
	}

	progressReader := io.TeeReader(r, bar)
	aeadResult, err := enc.EncryptAEAD(w, progressReader, dataKey, params)
	if err != nil {
		return fmt.Errorf("aead encrypt: %w", err)
	}

	ep.aeadResult = aeadResult

	return nil
}

// uploadStage uploads the encrypted data to B2
func (ep *encryptionPipeline) uploadStage(ctx context.Context, r io.Reader, w io.Writer) error {
	if ep.opts.B2Client == nil {
		return fmt.Errorf("B2 client is required for upload")
	}

	bar := progress.CreateProgressBar("☁️  UPLOAD  ")
	defer func() { _ = bar.Finish() }()

	key := "data/" + ep.opts.ObjectID + ".enc"
	progressReader := io.TeeReader(r, bar)

	_, err := ep.opts.B2Client.Upload(ctx, key, progressReader, "application/octet-stream", nil)
	if err != nil {
		return fmt.Errorf("upload stage: %w", err)
	}

	return nil
}
