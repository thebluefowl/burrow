package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
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

// deriveKey creates an encryption key from the user's password
func deriveKey(password string) []byte {
	salt := []byte("burrow-config-salt-v1-2025")
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// Save encrypts and saves the config using the provided password
func Save(config Config, password string) error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	burrowConfigDir := filepath.Join(configDir, "burrow")
	if err := os.MkdirAll(burrowConfigDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configFile := filepath.Join(burrowConfigDir, "config.enc")

	// Marshal config to JSON
	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Derive encryption key from password
	key := deriveKey(password)

	// Encrypt the data
	encryptedData, err := encrypt(jsonData, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}

	// Write encrypted data
	if err := os.WriteFile(configFile, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Load decrypts and loads the config using the provided password
func Load(password string) (*Config, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %w", err)
	}

	configFile := filepath.Join(configDir, "burrow", "config.enc")

	// Read encrypted data
	encryptedData, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Derive decryption key from password
	key := deriveKey(password)

	// Decrypt the data
	jsonData, err := decrypt(encryptedData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt config (wrong password?): %w", err)
	}

	// Unmarshal JSON
	var config Config
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

func Exists() bool {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return false
	}
	path := filepath.Join(configDir, "burrow", "config.enc")
	_, err = os.Stat(path)
	return !os.IsNotExist(err)
}

// encrypt encrypts data using AES-GCM
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
