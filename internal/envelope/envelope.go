package envelope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/thebluefowl/burrow/internal/enc"
)

const (
	Version1 = "burrow.1.1"
)

type Encryption struct {
	Params  enc.AEADParams
	DataKey []byte
}

type Compression struct {
	Mode string
}

type Envelope struct {
	Version          string            `json:"version"`
	ObjectID         string            `json:"object_id"`
	Encryption       Encryption        `json:"encryption"`
	Compression      Compression       `json:"compression"`
	PlainSHA         [32]byte          `json:"plain_sha"`
	OriginalFileName string            `json:"original_file_name"`
	Metadata         map[string]string `json:"metadata"`
	CreatedAt        time.Time
}

func NewEnvelope(objectID string, original string) *Envelope {
	return &Envelope{
		Version:          Version1,
		ObjectID:         objectID,
		OriginalFileName: original,
	}
}

func (e *Envelope) Seal(recipients []string, armor bool) ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_, err = enc.Encrypt(&buf, bytes.NewReader(raw), enc.EncryptConfig{Recipients: recipients, Armor: armor})
	if err != nil {
		return nil, fmt.Errorf("age seal: %w", err)
	}
	return buf.Bytes(), nil
}

func (e *Envelope) Open(cipher []byte, dec enc.DecryptConfig) (*Envelope, error) {
	r, err := enc.NewDecryptReader(bytes.NewReader(cipher), dec)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	return &env, nil
}
