package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	// Replace this import path with your module path, e.g. "github.com/yourorg/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/enc"
)

var ErrConfigNotFound = errors.New("config not found")

type Config struct {
	KeyID         string `json:"key_id"`
	AppKey        string `json:"app_key"`
	BucketName    string `json:"bucket_name"`
	Region        string `json:"region"`
	MasterKey     []byte `json:"master_key"`
	AgePublicKey  string `json:"age_public_key"`
	AgePrivateKey string `json:"age_private_key"`
}

func configDirPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}
	return filepath.Join(dir, "burrow"), nil
}

func configFilePath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.enc"), nil
}

// Save marshals and encrypts the config using age passphrase mode.
func Save(cfg Config, password string) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	path, err := configFilePath()
	if err != nil {
		return err
	}

	plain, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	ciphertext, err := enc.EncryptBytes(plain, enc.EncryptConfig{
		Passphrase: password, // simple string password is fine (age handles salt/KDF)
		Armor:      false,    // set true if you prefer ASCII armor
	})
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}

	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

// Load reads, decrypts, and unmarshals the config using age passphrase mode.
func Load(password string) (*Config, error) {
	path, err := configFilePath()
	if err != nil {
		return nil, err
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	plain, err := enc.DecryptBytes(ciphertext, enc.DecryptConfig{
		Passphrase: password,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt config (wrong password?): %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &cfg, nil
}

func Exists() bool {
	path, err := configFilePath()
	if err != nil {
		return false
	}
	_, statErr := os.Stat(path)
	return !os.IsNotExist(statErr)
}
