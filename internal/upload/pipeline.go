package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/thebluefowl/burrow/internal/archive"
	"github.com/thebluefowl/burrow/internal/compress"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/pipeline"
	"github.com/thebluefowl/burrow/internal/progress"
	"github.com/thebluefowl/burrow/internal/storage"
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
	B2Client storage.Storage

	// Resume fields — set when resuming a previous upload
	ResumeParams      *enc.AEADParams // reuse NBase from previous attempt
	ResumeCompression string          // force compression mode ("zstd" or "none")
	ResumeSkipBytes   int64           // ciphertext bytes to skip (already uploaded)
	UploadID          string          // S3 multipart upload ID
	PartSize          int64           // bytes per upload part
	OnPartUploaded    func(partNumber int32, etag string, size int64)
}

// EncryptionPipelineResult contains the results of the encryption pipeline
type EncryptionPipelineResult struct {
	CompressInfo *compress.CompressInfo
	AEADResult   *enc.AEADResult
	CipherSHA    [32]byte
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
	cipherSHA    [32]byte
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
		CipherSHA:    ep.cipherSHA,
	}, nil
}

// archiveStage creates a tar archive from the source
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

	mode := compress.CompressAuto
	if ep.opts.ResumeCompression != "" {
		mode = compress.CompressionMode(ep.opts.ResumeCompression)
	}

	compCfg := compress.CompressorConfig{
		Mode:          mode,
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

	var params enc.AEADParams
	if ep.opts.ResumeParams != nil {
		params = *ep.opts.ResumeParams
	} else {
		var err error
		params, err = enc.NewAEADParams(ep.opts.ObjectID, enc.AEADDefaultChunkSize)
		if err != nil {
			return fmt.Errorf("new aead params: %w", err)
		}
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

// uploadStage uploads the encrypted data to storage
func (ep *encryptionPipeline) uploadStage(ctx context.Context, r io.Reader, w io.Writer) error {
	if ep.opts.B2Client == nil {
		return fmt.Errorf("storage client is required for upload")
	}

	// If we have a multipart upload ID, use resumable multipart upload
	if ep.opts.UploadID != "" {
		return ep.multipartUploadStage(ctx, r)
	}

	// Fall back to simple upload (used for non-resumable uploads)
	bar := progress.CreateProgressBar("☁️  UPLOAD  ")
	defer func() { _ = bar.Finish() }()

	key := "data/" + ep.opts.ObjectID + ".enc"

	hasher := sha256.New()
	progressReader := io.TeeReader(r, io.MultiWriter(bar, hasher))

	err := ep.opts.B2Client.Upload(ctx, key, progressReader, "application/octet-stream", nil)
	if err != nil {
		return fmt.Errorf("upload stage: %w", err)
	}

	copy(ep.cipherSHA[:], hasher.Sum(nil))
	return nil
}

// multipartUploadStage uploads using manual multipart upload with resume support.
func (ep *encryptionPipeline) multipartUploadStage(ctx context.Context, r io.Reader) error {
	bar := progress.CreateProgressBar("☁️  UPLOAD  ")
	defer func() { _ = bar.Finish() }()

	rs, ok := ep.opts.B2Client.(storage.ResumableStorage)
	if !ok {
		return fmt.Errorf("storage client does not support resumable uploads")
	}

	key := "data/" + ep.opts.ObjectID + ".enc"
	hasher := sha256.New()
	reader := io.TeeReader(r, hasher)

	partSize := ep.opts.PartSize
	skipBytes := ep.opts.ResumeSkipBytes

	// Skip already-uploaded bytes (hasher still processes them for correct CipherSHA)
	if skipBytes > 0 {
		skipped, err := io.CopyN(io.Discard, reader, skipBytes)
		if err != nil {
			return fmt.Errorf("skip completed bytes: %w", err)
		}
		bar.Add64(skipped)
	}

	// Determine starting part number
	startPart := int32(skipBytes/partSize) + 1

	buf := make([]byte, partSize)
	partNum := startPart

	for {
		n, err := io.ReadFull(reader, buf)
		if n > 0 {
			bar.Add(n)
			partBody := bytes.NewReader(buf[:n])
			etag, uploadErr := rs.UploadPart(ctx, key, ep.opts.UploadID, partNum, partBody, int64(n))
			if uploadErr != nil {
				return fmt.Errorf("upload part %d: %w", partNum, uploadErr)
			}
			if ep.opts.OnPartUploaded != nil {
				ep.opts.OnPartUploaded(partNum, etag, int64(n))
			}
			partNum++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read part data: %w", err)
		}
	}

	copy(ep.cipherSHA[:], hasher.Sum(nil))
	return nil
}
