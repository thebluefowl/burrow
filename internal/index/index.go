package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thebluefowl/burrow/internal/enc"
)

var ErrIndexNotFound = errors.New("index not found")

type Entry struct {
	ObjectID    string    `json:"object_id"`
	FileName    string    `json:"file_name"`
	CreatedAt   time.Time `json:"created_at"`
	Size        int64     `json:"size,omitempty"`
}

type Index struct {
	Entries []Entry `json:"entries"`
}

func indexFilePath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "index.enc"), nil
}

func configDirPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}
	return filepath.Join(dir, "burrow"), nil
}

// Load reads and decrypts the index file
func Load(password string) (*Index, error) {
	path, err := indexFilePath()
	if err != nil {
		return nil, err
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Index{Entries: []Entry{}}, nil // Return empty index if file doesn't exist
		}
		return nil, fmt.Errorf("failed to read index file: %w", err)
	}

	plain, err := enc.DecryptBytes(ciphertext, enc.DecryptConfig{
		Passphrase: password,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt index (wrong password?): %w", err)
	}

	var idx Index
	if err := json.Unmarshal(plain, &idx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	return &idx, nil
}

// Save encrypts and writes the index file
func Save(idx *Index, password string) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	path, err := indexFilePath()
	if err != nil {
		return err
	}

	plain, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	ciphertext, err := enc.EncryptBytes(plain, enc.EncryptConfig{
		Passphrase: password,
		Armor:      false,
	})
	if err != nil {
		return fmt.Errorf("failed to encrypt index: %w", err)
	}

	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("failed to write index file: %w", err)
	}

	return nil
}

// AddEntry adds a new entry to the index
func AddEntry(password string, entry Entry) error {
	idx, err := Load(password)
	if err != nil {
		return err
	}

	// Check if entry already exists and update it, otherwise append
	found := false
	for i, e := range idx.Entries {
		if e.ObjectID == entry.ObjectID {
			idx.Entries[i] = entry
			found = true
			break
		}
	}
	if !found {
		idx.Entries = append(idx.Entries, entry)
	}

	return Save(idx, password)
}

// RemoveEntry removes an entry from the index
func RemoveEntry(password string, objectID string) error {
	idx, err := Load(password)
	if err != nil {
		return err
	}

	var newEntries []Entry
	for _, e := range idx.Entries {
		if e.ObjectID != objectID {
			newEntries = append(newEntries, e)
		}
	}
	idx.Entries = newEntries

	return Save(idx, password)
}
