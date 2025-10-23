package enc

const (
	HashAlgoSHA256 = "sha256"
)

type Sidecar struct {
	Version int
}

// // EnvelopeV1 is what we age-encrypt as the "sidecar".
// type EnvelopeV1 struct {
// 	Version  int            `json:"version"`
// 	Params   AEADParams     `json:"params"`
// 	KMaster  []byte         `json:"k_master"`  // 32 rand bytes
// 	HashAlgo string         `json:"hash_algo"` // "sha256"
// 	HashSum  []byte         `json:"hash_sum"`  // 32 bytes (plaintext digest)
// 	Optional map[string]any `json:"optional,omitempty"`
// }

// func NewEnvelope(objectID string, chunkSize int) (*EnvelopeV1, error) {
// 	p, err := NewAEADParams(objectID, chunkSize)
// 	if err != nil {
// 		return nil, err
// 	}
// 	k := make([]byte, 32)
// 	if _, err := rand.Read(k); err != nil {
// 		return nil, fmt.Errorf("k_master: %w", err)
// 	}
// 	return &EnvelopeV1{Version: 1, Params: p, KMaster: k, HashAlgo: HashAlgoSHA256}, nil
// }

// func (e *EnvelopeV1) Seal(recipients []string, armor bool) ([]byte, error) {
// 	if len(recipients) == 0 {
// 		return nil, errors.New("sidecar: no recipients")
// 	}
// 	raw, err := json.Marshal(e)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var buf bytes.Buffer
// 	_, err = Encrypt(&buf, bytes.NewReader(raw), EncryptConfig{Recipients: recipients, Armor: armor})
// 	if err != nil {
// 		return nil, fmt.Errorf("age seal: %w", err)
// 	}
// 	return buf.Bytes(), nil
// }

// func OpenEnvelope(cipher []byte, dec DecryptConfig) (*EnvelopeV1, error) {
// 	r, err := NewDecryptReader(bytes.NewReader(cipher), dec)
// 	if err != nil {
// 		return nil, err
// 	}
// 	b, err := io.ReadAll(r)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var env EnvelopeV1
// 	if err := json.Unmarshal(b, &env); err != nil {
// 		return nil, err
// 	}
// 	if env.Version != 1 {
// 		return nil, fmt.Errorf("unsupported envelope version %d", env.Version)
// 	}
// 	return &env, nil
// }

// func (e *EnvelopeV1) SetPlainSHA(h [32]byte) { e.HashSum = append(e.HashSum[:0], h[:]...) }

// func (e *EnvelopeV1) DeriveDataKey() ([]byte, error) {
// 	return DeriveDataKey(e.KMaster, e.Params.ObjectID)
// }

// func VerifyPlainSHA(env *EnvelopeV1, got [32]byte) bool {
// 	return env.HashAlgo == "sha256" && len(env.HashSum) == sha256.Size &&
// 		bytes.Equal(env.HashSum, got[:])
// }
