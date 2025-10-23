package archive

import (
	"bytes"
	"fmt"
	"io"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

type CompressionMode string

const (
	CompressNone CompressionMode = "none"
	CompressZstd CompressionMode = "zstd"
	CompressAuto CompressionMode = "auto"
)

// CompressorConfig controls compression behavior.
type CompressorConfig struct {
	Mode          CompressionMode // none | zstd | auto
	ZstdLevel     int             // 1..19 (3 is a great default)
	AutoMinSaving float64         // e.g. 0.05 (5%) threshold to enable in auto
	SampleBytes   int             // bytes to sample in auto (default 4<<20)
}

// CompressInfo reports what happened.
type CompressInfo struct {
	ModeRequested CompressionMode // what you asked for
	ModeUsed      CompressionMode // what actually got used (none or zstd)

	// Estimated savings from the auto sample (only in auto; -1 if not applicable).
	EstimatedSavings float64

	// Final end-to-end savings after Close():
	//   1 - (compressed_bytes_out / uncompressed_bytes_in)
	// For passthrough/none: 0 if any data flowed; -1 if no data.
	FinalSavings float64

	// Raw counters (after Close())
	BytesInUncompressed int64
	BytesOutCompressed  int64

	SampledBytes int // how many bytes were sampled (auto only)
	Decided      bool
}

// NewCompressorWithInfo wraps w with the chosen compression and returns:
// - an io.WriteCloser for the caller to write uncompressed data into,
// - a *CompressInfo that will be filled as the stream progresses/finishes.
func NewCompressorWithInfo(w io.Writer, cfg CompressorConfig) (io.WriteCloser, *CompressInfo, error) {
	if cfg.SampleBytes <= 0 {
		cfg.SampleBytes = 4 << 20 // 4MiB
	}
	if cfg.AutoMinSaving <= 0 {
		cfg.AutoMinSaving = 0.05
	}
	if cfg.ZstdLevel == 0 {
		cfg.ZstdLevel = 3
	}

	info := &CompressInfo{
		ModeRequested:    cfg.Mode,
		ModeUsed:         cfg.Mode, // may change to none in auto
		EstimatedSavings: -1,
		FinalSavings:     -1,
	}

	// Wrap destination so we can count bytes actually emitted (compressed size).
	cw := &countingWriter{dst: w}

	switch cfg.Mode {
	case CompressNone:
		// Unified stream writer with no encoder (passthrough).
		info.Decided = true
		info.ModeUsed = CompressNone
		// Defaults so callers can log immediately; final numbers filled on Close.
		info.EstimatedSavings = 0
		info.FinalSavings = 0
		return &streamCompressor{enc: nil, out: cw, info: info}, info, nil

	case CompressZstd:
		enc, err := newZstdEncoder(cw, cfg.ZstdLevel)
		if err != nil {
			return nil, nil, err
		}
		info.Decided = true
		info.ModeUsed = CompressZstd
		return &streamCompressor{enc: enc, out: cw, info: info}, info, nil

	case CompressAuto:
		ac := &adaptiveCompressor{
			cfg:  cfg,
			out:  cw,
			buf:  &bytes.Buffer{},
			info: info,
		}
		return ac, info, nil

	default:
		return nil, nil, fmt.Errorf("unknown compression mode %q", cfg.Mode)
	}
}

// ---------- internals ----------

type countingWriter struct {
	dst io.Writer
	n   int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.dst.Write(p)
	c.n += int64(n)
	return n, err
}

func newZstdEncoder(w io.Writer, lvl int) (*zstd.Encoder, error) {
	// clamp and map to zstd level
	if lvl < 1 {
		lvl = 1
	}
	if lvl > 19 {
		lvl = 19
	}
	// Enable parallel compression using available CPU cores
	return zstd.NewWriter(w,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(lvl)),
		zstd.WithEncoderConcurrency(runtime.GOMAXPROCS(0)),
	)
}

// ---- unified writer for none|zstd ----

type streamCompressor struct {
	enc  *zstd.Encoder   // nil => passthrough
	out  *countingWriter // counts compressed bytes written
	info *CompressInfo

	inN int64 // uncompressed bytes received
}

func (s *streamCompressor) Write(b []byte) (int, error) {
	s.inN += int64(len(b))
	if s.enc != nil {
		return s.enc.Write(b)
	}
	return s.out.Write(b)
}

func (s *streamCompressor) Close() error {
	var err error
	if s.enc != nil {
		err = s.enc.Close()
	}
	// Fill final counters/savings.
	s.info.BytesInUncompressed = s.inN
	s.info.BytesOutCompressed = s.out.n
	if s.inN > 0 {
		s.info.FinalSavings = 1 - float64(s.out.n)/float64(s.inN)
	} else {
		s.info.FinalSavings = -1
	}
	return err
}

// ---- auto mode ----

type adaptiveCompressor struct {
	cfg  CompressorConfig
	out  *countingWriter
	buf  *bytes.Buffer
	info *CompressInfo

	decided bool
	useZstd bool

	zenc *zstd.Encoder
	inN  int64
}

func (a *adaptiveCompressor) Write(p []byte) (int, error) {
	a.inN += int64(len(p))
	if a.decided {
		if a.useZstd {
			return a.zenc.Write(p)
		}
		return a.out.Write(p)
	}

	// Buffer until we reach SampleBytes, then decide.
	if _, err := a.buf.Write(p); err != nil {
		return 0, err
	}
	if a.buf.Len() >= a.cfg.SampleBytes {
		if err := a.decideAndFlush(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (a *adaptiveCompressor) decideAndFlush() error {
	if a.decided {
		return nil
	}
	a.decided = true

	sample := a.buf.Bytes()
	a.info.SampledBytes = len(sample)

	// Estimate zstd savings on the sample.
	var tmp bytes.Buffer
	enc, err := newZstdEncoder(&tmp, a.cfg.ZstdLevel)
	if err != nil {
		return err
	}
	if _, err := enc.Write(sample); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}

	if len(sample) > 0 {
		a.info.EstimatedSavings = 1 - float64(tmp.Len())/float64(len(sample))
	} else {
		a.info.EstimatedSavings = -1
	}

	a.useZstd = a.info.EstimatedSavings >= a.cfg.AutoMinSaving
	if a.useZstd {
		a.info.ModeUsed = CompressZstd
		a.zenc, err = newZstdEncoder(a.out, a.cfg.ZstdLevel)
		if err != nil {
			return err
		}
		// Feed the buffered sample through the real encoder.
		if _, err := a.zenc.Write(sample); err != nil {
			return err
		}
	} else {
		a.info.ModeUsed = CompressNone
		// Passthrough: write buffered bytes as-is.
		if _, err := a.out.Write(sample); err != nil {
			return err
		}
	}
	// release buffer memory
	a.buf = &bytes.Buffer{}
	a.info.Decided = true
	return nil
}

func (a *adaptiveCompressor) Close() error {
	// If caller closed before reaching SampleBytes, still decide.
	if !a.decided {
		if err := a.decideAndFlush(); err != nil {
			return err
		}
	}

	var err error
	if a.useZstd && a.zenc != nil {
		err = a.zenc.Close()
	}

	// Fill final counters/savings.
	a.info.BytesInUncompressed = a.inN
	a.info.BytesOutCompressed = a.out.n
	if a.inN > 0 {
		a.info.FinalSavings = 1 - float64(a.out.n)/float64(a.inN)
	} else {
		a.info.FinalSavings = -1
	}
	return err
}

// --------- optional: decoder helper (for restore) ---------

func NewZstdDecoder(r io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(r)
}
