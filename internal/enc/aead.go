package enc

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const aeadVersionTag = "burrow.v1"

const (
	AEADDefaultChunkSize = 4 << 20
	aeadMaxChunkSize     = 64 << 20
	aeadTagSize          = 16
)

type AEADParams struct {
	ObjectID  string
	ChunkSize int
	NBase     [24]byte
}

type AEADResult struct {
	Params     AEADParams
	DataKey    []byte
	PlainSHA   [32]byte
	TotalPlain int64
}

func NewAEADParams(objectID string, chunkSize int) (AEADParams, error) {
	if objectID == "" {
		return AEADParams{}, errors.New("aead: objectID required")
	}
	if chunkSize <= 0 {
		chunkSize = AEADDefaultChunkSize
	}
	if chunkSize < 32<<10 || chunkSize > aeadMaxChunkSize {
		return AEADParams{}, fmt.Errorf("aead: invalid chunkSize %d", chunkSize)
	}
	var n [24]byte
	if _, err := rand.Read(n[:]); err != nil {
		return AEADParams{}, fmt.Errorf("aead: nonce gen: %w", err)
	}
	return AEADParams{ObjectID: objectID, ChunkSize: chunkSize, NBase: n}, nil
}

func DeriveDataKey(masterKey []byte, objectID string) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("aead: masterKey empty")
	}
	r := hkdf.New(sha256.New, masterKey, []byte(objectID), []byte("burrow/data"))
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, fmt.Errorf("aead: hkdf: %w", err)
	}
	return k, nil
}

// EncryptAEAD encrypts the data from src to dst using ChaCha20-Poly1305 with the provided dataKey and AEADParams.
// WARNING: AEADParams must be freshly initialized via NewAEADParams for each encryption session, even for the same object (same KSUID).
// Reusing AEADParams with the same NBase and dataKey across multiple encryption sessions for the same object will cause nonce reuse,
// compromising confidentiality and authenticity. Each object must have a unique KSUID, and AEADParams must not be persisted for reuse.
func EncryptAEAD(dst io.Writer, src io.Reader, dataKey []byte, p AEADParams) (aeadResult *AEADResult, err error) {
	plainSHA := [32]byte{}
	totalPlain := int64(0)
	if len(dataKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("aead: dataKey must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(src)
	bw := bufio.NewWriter(dst)
	defer func() {
		if err == nil {
			err = bw.Flush()
		}
	}()

	if p.ChunkSize <= 0 {
		p.ChunkSize = AEADDefaultChunkSize
	}
	buf := make([]byte, p.ChunkSize)
	h := sha256.New()
	var idx uint64

	for {
		n, rerr := io.ReadFull(br, buf)
		switch {
		case rerr == io.EOF:
			copy(plainSHA[:], h.Sum(nil))
			return &AEADResult{Params: p, DataKey: dataKey, PlainSHA: plainSHA, TotalPlain: totalPlain}, nil
		case rerr == io.ErrUnexpectedEOF:
		case rerr != nil:
			return nil, fmt.Errorf("aead read: %w", rerr)
		}
		if n == 0 {
			return nil, errors.New("aead: zero-length chunk")
		}

		aad := buildAAD(p.ObjectID, idx, uint64(n))

		var nonce [24]byte
		copy(nonce[:16], p.NBase[:16])
		binary.LittleEndian.PutUint64(nonce[16:], idx)

		ct := aead.Seal(nil, nonce[:], buf[:n], aad)

		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(ct)))
		if _, err := bw.Write(hdr[:]); err != nil {
			return nil, err
		}
		if _, err := bw.Write(ct); err != nil {
			return nil, err
		}

		h.Write(buf[:n])
		totalPlain += int64(n)
		idx++
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	copy(plainSHA[:], h.Sum(nil))
	return &AEADResult{Params: p, DataKey: dataKey, PlainSHA: plainSHA, TotalPlain: totalPlain}, nil
}

func DecryptAEAD(dst io.Writer, src io.Reader, dataKey []byte, p AEADParams) (aeadResult *AEADResult, err error) {
	plainSHA := [32]byte{}
	totalPlain := int64(0)

	if len(dataKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("aead: dataKey must be 32 bytes")
	}
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(src)
	bw := bufio.NewWriter(dst)
	defer func() {
		if err == nil {
			err = bw.Flush()
		}
	}()

	h := sha256.New()
	var idx uint64

	for {
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("aead read hdr: %w", err)
		}
		ctLen := binary.LittleEndian.Uint32(hdr[:])
		if ctLen < aeadTagSize {
			return nil, fmt.Errorf("aead ct too short")
		}

		ct := make([]byte, int(ctLen))
		if _, err := io.ReadFull(br, ct); err != nil {
			return nil, err
		}

		aad := buildAAD(p.ObjectID, idx, uint64(ctLen-aeadTagSize))
		var nonce [24]byte
		copy(nonce[:16], p.NBase[:16])
		binary.LittleEndian.PutUint64(nonce[16:], idx)

		pt, err := aead.Open(nil, nonce[:], ct, aad)
		if err != nil {
			return nil, fmt.Errorf("aead chunk %d: %w", idx, err)
		}

		if _, err := bw.Write(pt); err != nil {
			return nil, err
		}
		h.Write(pt)
		totalPlain += int64(len(pt))
		idx++
	}
	copy(plainSHA[:], h.Sum(nil))
	return &AEADResult{Params: p, DataKey: dataKey, PlainSHA: plainSHA, TotalPlain: totalPlain}, nil
}

func VerifySHA256(a, b [32]byte) bool { return hmac.Equal(a[:], b[:]) }

func buildAAD(objectID string, idx, ptLen uint64) []byte {
	var b bytes.Buffer
	b.WriteString(aeadVersionTag)
	b.WriteString(objectID)
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], idx)
	b.Write(tmp[:])
	binary.LittleEndian.PutUint64(tmp[:], ptLen)
	b.Write(tmp[:])
	return b.Bytes()
}
