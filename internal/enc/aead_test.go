package enc

import (
	"bytes"
	"crypto/rand"
	"errors"

	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestNewAEADParams(t *testing.T) {
	tests := []struct {
		name      string
		objectID  string
		chunkSize int
		wantErr   bool
	}{
		{"valid default chunk", "obj123", 0, false},
		{"valid custom chunk", "obj456", 1 << 20, false},
		{"valid min chunk", "obj789", 32 << 10, false},
		{"valid max chunk", "objmax", aeadMaxChunkSize, false},
		{"empty objectID", "", 0, true},
		{"chunk too small", "obj", 1024, true},
		{"chunk too large", "obj", aeadMaxChunkSize + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewAEADParams(tt.objectID, tt.chunkSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAEADParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if p.ObjectID != tt.objectID {
					t.Errorf("ObjectID = %v, want %v", p.ObjectID, tt.objectID)
				}
				expectedChunk := tt.chunkSize
				if tt.chunkSize <= 0 {
					expectedChunk = AEADDefaultChunkSize
				}
				if p.ChunkSize != expectedChunk {
					t.Errorf("ChunkSize = %v, want %v", p.ChunkSize, expectedChunk)
				}
				// Check nonce is not zero
				var zero [24]byte
				if p.NBase == zero {
					t.Error("NBase should not be zero")
				}
			}
		})
	}
}

func TestDeriveDataKey(t *testing.T) {
	tests := []struct {
		name      string
		masterKey []byte
		objectID  string
		wantErr   bool
	}{
		{"valid", make([]byte, 32), "obj123", false},
		{"empty masterKey", []byte{}, "obj123", true},
		{"nil masterKey", nil, "obj123", true},
		{"different objectID", make([]byte, 32), "different", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.masterKey) > 0 {
				rand.Read(tt.masterKey)
			}
			key, err := DeriveDataKey(tt.masterKey, tt.objectID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveDataKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(key) != chacha20poly1305.KeySize {
					t.Errorf("key length = %d, want %d", len(key), chacha20poly1305.KeySize)
				}
			}
		})
	}
}

func TestDeriveDataKeyDeterministic(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	objectID := "test-obj"

	key1, err := DeriveDataKey(masterKey, objectID)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveDataKey(masterKey, objectID)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveDataKey should be deterministic for same inputs")
	}
}

func TestDeriveDataKeyDifferentObjects(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	key1, _ := DeriveDataKey(masterKey, "obj1")
	key2, _ := DeriveDataKey(masterKey, "obj2")

	if bytes.Equal(key1, key2) {
		t.Error("Different objectIDs should produce different keys")
	}
}

func TestEncryptDecryptAEAD(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		chunkSize int
	}{
		{"small", "hello world", 32 << 10},
		{"exact chunk", strings.Repeat("a", 32<<10), 32 << 10},
		{"multi chunk", strings.Repeat("test", 10000), 32 << 10},
		{"large", strings.Repeat("x", 100000), 64 << 10},
		{"empty", "", 32 << 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masterKey := make([]byte, 32)
			rand.Read(masterKey)
			objectID := "test-obj-" + tt.name

			dataKey, err := DeriveDataKey(masterKey, objectID)
			if err != nil {
				t.Fatal(err)
			}

			params, err := NewAEADParams(objectID, tt.chunkSize)
			if err != nil {
				t.Fatal(err)
			}

			// Encrypt
			var encrypted bytes.Buffer
			plainReader := strings.NewReader(tt.plaintext)
			encResult, err := EncryptAEAD(&encrypted, plainReader, dataKey, params)
			if err != nil {
				t.Fatalf("EncryptAEAD() error = %v", err)
			}

			if encResult.TotalPlain != int64(len(tt.plaintext)) {
				t.Errorf("TotalPlain = %d, want %d", encResult.TotalPlain, len(tt.plaintext))
			}

			// Decrypt
			var decrypted bytes.Buffer
			decResult, err := DecryptAEAD(&decrypted, &encrypted, dataKey, params)
			if err != nil {
				t.Fatalf("DecryptAEAD() error = %v", err)
			}

			if decResult.TotalPlain != int64(len(tt.plaintext)) {
				t.Errorf("Decrypt TotalPlain = %d, want %d", decResult.TotalPlain, len(tt.plaintext))
			}

			if decrypted.String() != tt.plaintext {
				t.Errorf("Decrypted text mismatch, got %q, want %q", decrypted.String(), tt.plaintext)
			}

			// Verify SHA256
			if !VerifySHA256(encResult.PlainSHA, decResult.PlainSHA) {
				t.Error("PlainSHA mismatch between encrypt and decrypt")
			}
		})
	}
}

func TestEncryptAEADInvalidKey(t *testing.T) {
	params, _ := NewAEADParams("obj", 32<<10)
	src := strings.NewReader("test")
	var dst bytes.Buffer

	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"too short", 16, true},
		{"too long", 64, true},
		{"valid", 32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			_, err := EncryptAEAD(&dst, src, key, params)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAEAD() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptAEADInvalidKey(t *testing.T) {
	params, _ := NewAEADParams("obj", 32<<10)
	src := bytes.NewReader([]byte{0, 0, 0, 0})
	var dst bytes.Buffer

	key := make([]byte, 16) // too short
	_, err := DecryptAEAD(&dst, src, key, params)
	if err == nil {
		t.Error("DecryptAEAD() should error with invalid key length")
	}
}

func TestDecryptAEADTamperedCiphertext(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	objectID := "test-obj"
	dataKey, _ := DeriveDataKey(masterKey, objectID)
	params, _ := NewAEADParams(objectID, 32<<10)

	// Encrypt
	var encrypted bytes.Buffer
	plainReader := strings.NewReader("hello world")
	_, err := EncryptAEAD(&encrypted, plainReader, dataKey, params)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext
	cipherBytes := encrypted.Bytes()
	if len(cipherBytes) > 10 {
		cipherBytes[10] ^= 0xFF
	}

	// Try to decrypt tampered data
	var decrypted bytes.Buffer
	tamperedReader := bytes.NewReader(cipherBytes)
	_, err = DecryptAEAD(&decrypted, tamperedReader, dataKey, params)
	if err == nil {
		t.Error("DecryptAEAD() should fail with tampered ciphertext")
	}
}

func TestDecryptAEADWrongKey(t *testing.T) {
	objectID := "test-obj"
	params, _ := NewAEADParams(objectID, 32<<10)

	// Encrypt with one key
	key1 := make([]byte, 32)
	rand.Read(key1)
	var encrypted bytes.Buffer
	plainReader := strings.NewReader("secret data")
	_, err := EncryptAEAD(&encrypted, plainReader, key1, params)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with different key
	key2 := make([]byte, 32)
	rand.Read(key2)
	var decrypted bytes.Buffer
	_, err = DecryptAEAD(&decrypted, &encrypted, key2, params)
	if err == nil {
		t.Error("DecryptAEAD() should fail with wrong key")
	}
}

func TestDecryptAEADCorruptHeader(t *testing.T) {
	params, _ := NewAEADParams("obj", 32<<10)
	dataKey := make([]byte, 32)
	rand.Read(dataKey)

	tests := []struct {
		name string
		data []byte
	}{
		{"too short header", []byte{0, 0, 0}},
		{"ct too short", []byte{15, 0, 0, 0}}, // ctLen < aeadTagSize
		{"incomplete ct", []byte{32, 0, 0, 0, 1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst bytes.Buffer
			src := bytes.NewReader(tt.data)
			_, err := DecryptAEAD(&dst, src, dataKey, params)
			if err == nil {
				t.Error("DecryptAEAD() should fail with corrupt data")
			}
		})
	}
}

func TestVerifySHA256(t *testing.T) {
	var a, b [32]byte
	rand.Read(a[:])
	copy(b[:], a[:])

	if !VerifySHA256(a, b) {
		t.Error("VerifySHA256() should return true for equal hashes")
	}

	b[0] ^= 0xFF
	if VerifySHA256(a, b) {
		t.Error("VerifySHA256() should return false for different hashes")
	}
}

func TestBuildAAD(t *testing.T) {
	aad1 := buildAAD("obj1", 0, 100)
	aad2 := buildAAD("obj1", 0, 100)

	if !bytes.Equal(aad1, aad2) {
		t.Error("buildAAD should be deterministic")
	}

	aad3 := buildAAD("obj1", 1, 100)
	if bytes.Equal(aad1, aad3) {
		t.Error("buildAAD should differ for different idx")
	}

	aad4 := buildAAD("obj2", 0, 100)
	if bytes.Equal(aad1, aad4) {
		t.Error("buildAAD should differ for different objectID")
	}

	aad5 := buildAAD("obj1", 0, 200)
	if bytes.Equal(aad1, aad5) {
		t.Error("buildAAD should differ for different ptLen")
	}
}

func TestEncryptAEADZeroChunkSize(t *testing.T) {
	dataKey := make([]byte, 32)
	rand.Read(dataKey)
	params := AEADParams{
		ObjectID:  "obj",
		ChunkSize: 0, // zero chunk size should default
	}
	rand.Read(params.NBase[:])

	var encrypted bytes.Buffer
	plainReader := strings.NewReader("test data")
	result, err := EncryptAEAD(&encrypted, plainReader, dataKey, params)
	if err != nil {
		t.Fatal(err)
	}

	// Should have used default chunk size
	if result.Params.ChunkSize != AEADDefaultChunkSize {
		t.Errorf("Expected default chunk size, got %d", result.Params.ChunkSize)
	}
}

type errorReader struct{}

func (e errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestEncryptAEADReadError(t *testing.T) {
	dataKey := make([]byte, 32)
	rand.Read(dataKey)
	params, _ := NewAEADParams("obj", 32<<10)

	var dst bytes.Buffer
	_, err := EncryptAEAD(&dst, errorReader{}, dataKey, params)
	if err == nil {
		t.Error("EncryptAEAD() should fail with read error")
	}
}

type errorWriter struct{}

func (e errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

func TestEncryptAEADWriteError(t *testing.T) {
	dataKey := make([]byte, 32)
	rand.Read(dataKey)
	params, _ := NewAEADParams("obj", 32<<10)

	src := strings.NewReader("test data")
	_, err := EncryptAEAD(errorWriter{}, src, dataKey, params)
	if err == nil {
		t.Error("EncryptAEAD() should fail with write error")
	}
}

func TestDecryptAEADWriteError(t *testing.T) {
	dataKey := make([]byte, 32)
	rand.Read(dataKey)
	params, _ := NewAEADParams("obj", 32<<10)

	// Create valid encrypted data
	var encrypted bytes.Buffer
	plainReader := strings.NewReader("test")
	_, err := EncryptAEAD(&encrypted, plainReader, dataKey, params)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt to error writer
	_, err = DecryptAEAD(errorWriter{}, &encrypted, dataKey, params)
	if err == nil {
		t.Error("DecryptAEAD() should fail with write error")
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large data test in short mode")
	}

	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	objectID := "large-obj"
	dataKey, _ := DeriveDataKey(masterKey, objectID)
	params, _ := NewAEADParams(objectID, 1<<20)

	// Generate 10MB of random data
	plaintext := make([]byte, 10<<20)
	rand.Read(plaintext)

	var encrypted bytes.Buffer
	encResult, err := EncryptAEAD(&encrypted, bytes.NewReader(plaintext), dataKey, params)
	if err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	decResult, err := DecryptAEAD(&decrypted, &encrypted, dataKey, params)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Error("Large data decryption mismatch")
	}

	if !VerifySHA256(encResult.PlainSHA, decResult.PlainSHA) {
		t.Error("Large data SHA mismatch")
	}
}

func BenchmarkEncryptAEAD(b *testing.B) {
	dataKey := make([]byte, 32)
	rand.Read(dataKey)
	params, _ := NewAEADParams("bench-obj", 1<<20)
	data := make([]byte, 1<<20) // 1MB
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dst bytes.Buffer
		_, _ = EncryptAEAD(&dst, bytes.NewReader(data), dataKey, params)
	}
}

func BenchmarkDecryptAEAD(b *testing.B) {
	dataKey := make([]byte, 32)
	rand.Read(dataKey)
	params, _ := NewAEADParams("bench-obj", 1<<20)
	data := make([]byte, 1<<20) // 1MB
	rand.Read(data)

	var encrypted bytes.Buffer
	_, _ = EncryptAEAD(&encrypted, bytes.NewReader(data), dataKey, params)
	encData := encrypted.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dst bytes.Buffer
		_, _ = DecryptAEAD(&dst, bytes.NewReader(encData), dataKey, params)
	}
}
