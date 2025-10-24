package main

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/thebluefowl/burrow/internal/download"
)

var (
	unarchiveFlag bool
)

var downloadCmd = &cobra.Command{
	Use:   "download <object-id> <destination>",
	Short: "Download and decrypt a file or directory from Backblaze B2",
	Long:  `Downloads the specified object from Backblaze B2, decrypts it, and optionally extracts it.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runDownload,
}

func init() {
	downloadCmd.Flags().BoolVarP(&unarchiveFlag, "extract", "x", false, "Extract tar archive to destination directory")
}

// runDownload is the main entry point for the download command
func runDownload(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	objectID := args[0]
	destPath := args[1]

	cfg, err := loadOrSetupConfig()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	b2Client, err := initB2Client(ctx, cfg)
	if err != nil {
		return err
	}

	downloader := download.NewDownloader(cfg, objectID, destPath, unarchiveFlag, b2Client)
	if err := downloader.Execute(); err != nil {
		return err
	}

	printDownloadSuccess(objectID, destPath)
	return nil
}

// printDownloadSuccess displays a success message
func printDownloadSuccess(objectID, destPath string) {
	if unarchiveFlag {
		color.Green("✓ Successfully downloaded and extracted %s to %s\n", objectID, destPath)
	} else {
		color.Green("✓ Successfully downloaded %s to %s\n", objectID, destPath)
	}
}
