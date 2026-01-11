package main

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/enc"
	"github.com/thebluefowl/burrow/internal/envelope"
	"github.com/thebluefowl/burrow/internal/index"
)

var indexCmd = &cobra.Command{
	Use:   "index",
	Short: "Rebuild the index from envelope files",
	Long:  `Rebuilds the local index file by scanning all envelope files in storage. This is useful if the index gets out of sync or is deleted.`,
	RunE:  runIndex,
}

func runIndex(cmd *cobra.Command, args []string) error {
	cfg, err := loadOrSetupConfig()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	password, err := askMasterPassword()
	if err != nil {
		return fmt.Errorf("failed to get master password: %w", err)
	}

	ctx := context.Background()
	b2Client, err := initB2Client(ctx, cfg)
	if err != nil {
		return err
	}

	color.New(color.BgWhite).Println(" Rebuilding Index ")
	fmt.Println()
	color.Yellow("Scanning envelope files in storage...")
	fmt.Println()

	// List all envelope files in the keys/ directory
	objects, err := b2Client.List(ctx, "keys/")
	if err != nil {
		return fmt.Errorf("failed to list objects: %w", err)
	}

	// Filter to only .envelope files and extract object IDs
	var entries []index.Entry
	successCount := 0
	errorCount := 0

	for _, obj := range objects {
		if !strings.HasSuffix(obj.Key, ".envelope") {
			continue
		}

		// Extract object ID from key (keys/{objectID}.envelope)
		baseName := filepath.Base(obj.Key)
		objectID := strings.TrimSuffix(baseName, ".envelope")

		// Download and decrypt envelope to get file name
		var buf bytes.Buffer
		_, _, err := b2Client.Download(ctx, obj.Key, &buf)
		if err != nil {
			errorCount++
			continue
		}

		decCfg := enc.DecryptConfig{
			Identities: []string{cfg.AgePrivateKey},
		}

		var env envelope.Envelope
		decryptedEnv, err := env.Open(buf.Bytes(), decCfg)
		if err != nil {
			errorCount++
			continue
		}

		entries = append(entries, index.Entry{
			ObjectID:  objectID,
			FileName:  decryptedEnv.OriginalFileName,
			CreatedAt: decryptedEnv.CreatedAt,
			Size:      obj.Size,
		})
		successCount++
	}

	if len(entries) == 0 {
		color.Yellow("No envelope files found. Upload a file first using 'burrow upload'.")
		return nil
	}

	// Create new index with all entries
	newIndex := &index.Index{
		Entries: entries,
	}

	// Save the rebuilt index
	if err := index.Save(newIndex, password); err != nil {
		return fmt.Errorf("failed to save index: %w", err)
	}

	color.Green("✓ Index rebuilt successfully!")
	fmt.Printf("  Found %d file(s)\n", successCount)
	if errorCount > 0 {
		color.Yellow("  Warning: %d envelope(s) could not be decrypted (may be from different key or corrupted)\n", errorCount)
	}

	return nil
}
