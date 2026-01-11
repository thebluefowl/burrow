package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/index"
	"github.com/thebluefowl/burrow/internal/upload"
)

var uploadCmd = &cobra.Command{
	Use:   "upload <file-or-directory>",
	Short: "Encrypt and upload a file or directory to Backblaze B2",
	Long:  `Encrypts the specified file or directory (as a tar archive) and uploads it to Backblaze B2.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runUpload,
}

// runUpload is the main entry point for the upload command
func runUpload(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	sourcePath := args[0]

	cfg, password, err := loadOrSetupConfigWithPassword()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	b2Client, err := initB2Client(ctx, cfg)
	if err != nil {
		return err
	}

	uploader := upload.NewUploader(cfg, sourcePath, b2Client)
	if err := uploader.Execute(); err != nil {
		return err
	}

	objectID := uploader.ObjectID()
	
	// Add entry to local index
	entry := index.Entry{
		ObjectID:  objectID,
		FileName:  filepath.Base(sourcePath),
		CreatedAt: time.Now(),
	}
	if err := index.AddEntry(password, entry); err != nil {
		// Log warning but don't fail the upload
		color.Yellow("⚠ Warning: Failed to update local index: %v\n", err)
	}

	printUploadSuccess(objectID)
	return nil
}

// printUploadSuccess displays a success message
func printUploadSuccess(objectID string) {
	color.Green("✓ Successfully uploaded to B2: %s\n", objectID+".enc")
}

// loadOrSetupConfig loads existing config or runs setup
func loadOrSetupConfig() (*config.Config, error) {
	cfg, _, err := loadOrSetupConfigWithPassword()
	return cfg, err
}

// loadOrSetupConfigWithPassword loads existing config or runs setup, returning both config and password
func loadOrSetupConfigWithPassword() (*config.Config, string, error) {
	if !config.Exists() {
		return setupWithPassword()
	}

	password, err := askMasterPassword()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get master password: %w", err)
	}

	cfg, err := config.Load(password)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load config: %w", err)
	}

	return cfg, password, nil
}

