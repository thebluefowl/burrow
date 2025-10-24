package download

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/thebluefowl/burrow/internal/archive"
	"github.com/thebluefowl/burrow/internal/compress"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/pipeline"
	"github.com/thebluefowl/burrow/internal/progress"
)

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

// downloadStage downloads the encrypted data from storage
func (dp *decryptionPipeline) downloadStage(ctx context.Context, r io.Reader, w io.Writer) error {
	if dp.opts.Storage == nil {
		return fmt.Errorf("storage client is required for download")
	}

	bar := progress.CreateProgressBar("☁️  DOWNLOAD")
	defer func() { _ = bar.Finish() }()

	key := "data/" + dp.opts.ObjectID + ".enc"

	var buf bytes.Buffer
	progressWriter := io.MultiWriter(&buf, bar)

	_, _, err := dp.opts.Storage.Download(ctx, key, progressWriter)
	if err != nil {
		return fmt.Errorf("download stage: %w", err)
	}

	if _, err := io.Copy(w, &buf); err != nil {
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
	case string(compress.CompressNone), "":
		// No compression, pass through
		bar := progress.CreateProgressBar("➡️  PASSTHRU")
		defer func() { _ = bar.Finish() }()

		progressReader := io.TeeReader(r, bar)
		if _, err := io.Copy(w, progressReader); err != nil {
			return fmt.Errorf("passthrough copy: %w", err)
		}
		return nil

	case string(compress.CompressZstd):
		// Decompress zstd
		bar := progress.CreateProgressBar("🗜️  UNZIP   ")
		defer func() { _ = bar.Finish() }()

		decoder, err := compress.NewZstdDecoder(r)
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
