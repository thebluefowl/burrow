// internal/enc/age.go
package enc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// GenerateKey generates a new age X25519 key pair
func GenerateKey() (publicKey, privateKey string, err error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate age key: %w", err)
	}

	return identity.Recipient().String(), identity.String(), nil
}

// EncryptConfig selects passphrase- or key-based encryption.
// Exactly one of Passphrase or Recipients must be provided.
type EncryptConfig struct {
	Passphrase string   // password for scrypt recipient
	Recipients []string // age public keys: "age1..." (X25519)
	Armor      bool     // optional ASCII armor (default: false)
}

// DecryptConfig selects passphrase- or key-based decryption.
// Exactly one of Passphrase or Identities must be provided.
type DecryptConfig struct {
	Passphrase string   // password for scrypt identity
	Identities []string // age secret keys: "AGE-SECRET-KEY-1..."
}

// NewEncryptWriter returns a WriteCloser that encrypts plaintext written to it
// and emits age ciphertext to dst. Call Close() when done to finalize.
func NewEncryptWriter(dst io.Writer, cfg EncryptConfig) (io.WriteCloser, error) {
	if err := validateEncryptConfig(cfg); err != nil {
		return nil, err
	}

	// Optionally wrap with ASCII armor
	var out io.Writer = dst
	var armorWriter io.Closer
	if cfg.Armor {
		aw := armor.NewWriter(dst)
		out = aw
		armorWriter = aw
	}

	// Build age recipients
	var wr io.WriteCloser

	switch {
	case cfg.Passphrase != "":
		recipient, err := age.NewScryptRecipient(cfg.Passphrase)
		if err != nil {
			if armorWriter != nil {
				_ = armorWriter.Close()
			}
			return nil, fmt.Errorf("age scrypt: %w", err)
		}
		wr, err = age.Encrypt(out, recipient)
		if err != nil {
			if armorWriter != nil {
				_ = armorWriter.Close()
			}
			return nil, fmt.Errorf("age encrypt: %w", err)
		}
	default:
		rcpts, err := parseRecipients(cfg.Recipients)
		if err != nil {
			if armorWriter != nil {
				_ = armorWriter.Close()
			}
			return nil, err
		}
		wr, err = age.Encrypt(out, rcpts...)
		if err != nil {
			if armorWriter != nil {
				_ = armorWriter.Close()
			}
			return nil, fmt.Errorf("age encrypt: %w", err)
		}
	}

	// Build closers list: close age writer first, THEN armor wrapper
	// This ensures age.Encrypt finalizes (writes auth tag) before armor closes
	closers := []io.Closer{wr}
	if armorWriter != nil {
		closers = append(closers, armorWriter)
	}

	return &multiCloseWriter{Writer: wr, finals: closers}, nil
}

// Encrypt copies all plaintext from r, encrypts it, and writes to dst.
// It closes the internal age writer but does NOT close r or dst.
func EncryptAge(dst io.Writer, r io.Reader, cfg EncryptConfig) (int64, error) {
	w, err := NewEncryptWriter(dst, cfg)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(w, r)
	closeErr := w.Close()
	if copyErr != nil {
		return n, copyErr
	}
	return n, closeErr
}

// NewDecryptReader returns a Reader that yields plaintext from an age ciphertext stream.
// The returned reader must be fully read; no Close() needed (but you can wrap with io.NopCloser if convenient).
// Automatically detects and handles ASCII armor if present.
func NewDecryptReader(src io.Reader, cfg DecryptConfig) (io.Reader, error) {
	if err := validateDecryptConfig(cfg); err != nil {
		return nil, err
	}

	// Detect if input is ASCII armored by peeking at the first line
	// We need a bufio.Reader or similar to peek without consuming
	const armorPrefix = "-----BEGIN AGE ENCRYPTED FILE-----"

	// Read a small buffer to check for armor header
	peekBuf := make([]byte, len(armorPrefix))
	n, err := io.ReadFull(src, peekBuf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("failed to peek at input: %w", err)
	}

	// Reconstruct the source with the peeked data prepended
	src = io.MultiReader(bytes.NewReader(peekBuf[:n]), src)

	// If it starts with armor prefix, unwrap it
	if n >= len(armorPrefix) && string(peekBuf[:len(armorPrefix)]) == armorPrefix {
		src = armor.NewReader(src)
	}

	switch {
	case cfg.Passphrase != "":
		identity, err := age.NewScryptIdentity(cfg.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("age scrypt: %w", err)
		}
		return age.Decrypt(src, identity)
	default:
		ids, err := parseIdentities(cfg.Identities)
		if err != nil {
			return nil, err
		}
		return age.Decrypt(src, ids...)
	}
}

// Decrypt reads age ciphertext from src, decrypts it, and writes plaintext to dst.
func DecryptAge(dst io.Writer, src io.Reader, cfg DecryptConfig) (int64, error) {
	r, err := NewDecryptReader(src, cfg)
	if err != nil {
		return 0, err
	}
	return io.Copy(dst, r)
}

// -------- File helpers (convenience) --------

// EncryptFile reads inPath and writes an encrypted file to outPath.
// It creates/overwrites outPath. Caller owns removing partial files on error.
func EncryptFile(cfg EncryptConfig, inPath, outPath string) (int64, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = out.Close()
	}()

	n, err := EncryptAge(out, in, cfg)
	if err != nil {
		return n, err
	}
	return n, out.Close()
}

// DecryptFile reads an age file at inPath and writes plaintext to outPath.
func DecryptFile(cfg DecryptConfig, inPath, outPath string) (int64, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = out.Close()
	}()

	n, err := DecryptAge(out, in, cfg)
	if err != nil {
		return n, err
	}
	return n, out.Close()
}

// -------- internals --------

func validateEncryptConfig(cfg EncryptConfig) error {
	pass := cfg.Passphrase != ""
	keys := len(cfg.Recipients) > 0
	if pass == keys { // both true or both false
		return errors.New("encryption config: exactly one of Passphrase or Recipients must be set")
	}
	return nil
}

func validateDecryptConfig(cfg DecryptConfig) error {
	pass := cfg.Passphrase != ""
	keys := len(cfg.Identities) > 0
	if pass == keys {
		return errors.New("decryption config: exactly one of Passphrase or Identities must be set")
	}
	return nil
}

func parseRecipients(keys []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		rcpt, err := age.ParseX25519Recipient(k)
		if err != nil {
			return nil, fmt.Errorf("parse recipient %q: %w", k, err)
		}
		out = append(out, rcpt)
	}
	if len(out) == 0 {
		return nil, errors.New("no valid recipients provided")
	}
	return out, nil
}

func parseIdentities(keys []string) ([]age.Identity, error) {
	var out []age.Identity
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		// Support passing the secret key directly ("AGE-SECRET-KEY-1...")
		if strings.HasPrefix(k, "AGE-SECRET-KEY-") {
			id, err := age.ParseX25519Identity(k)
			if err != nil {
				return nil, fmt.Errorf("parse identity: %w", err)
			}
			out = append(out, id)
			continue
		}
		// Or treat as a file path containing the secret key.
		data, err := os.ReadFile(k)
		if err != nil {
			return nil, fmt.Errorf("read identity file %q: %w", k, err)
		}
		lines := strings.Split(string(data), "\n")
		var parsed bool
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "AGE-SECRET-KEY-") {
				id, err := age.ParseX25519Identity(ln)
				if err != nil {
					return nil, fmt.Errorf("parse identity from %q: %w", k, err)
				}
				out = append(out, id)
				parsed = true
			}
		}
		if !parsed {
			return nil, fmt.Errorf("no AGE-SECRET-KEY found in %q", k)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no valid identities provided")
	}
	return out, nil
}

type multiCloseWriter struct {
	io.Writer
	finals []io.Closer
}

func (m *multiCloseWriter) Close() error {
	var firstErr error
	// Close in order: age writer first, then armor wrapper
	for i := 0; i < len(m.finals); i++ {
		if err := m.finals[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
