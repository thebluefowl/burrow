package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/config"
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
	sourcePath := args[0]

	cfg, err := loadOrSetupConfig()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	uploader := upload.NewUploader(cfg, sourcePath)
	if err := uploader.Execute(); err != nil {
		return err
	}

	printUploadSuccess(uploader.ObjectID())
	return nil
}

// printUploadSuccess displays a success message
func printUploadSuccess(objectID string) {
	color.Green("✓ Successfully uploaded to B2: %s\n", objectID+".enc")
}

// loadOrSetupConfig loads existing config or runs setup
func loadOrSetupConfig() (*config.Config, error) {
	if !config.Exists() {
		return setup()
	}

	password, err := askMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to get master password: %w", err)
	}

	cfg, err := config.Load(password)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return cfg, nil
}
