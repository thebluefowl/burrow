package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/config"
	"github.com/thebluefowl/burrow/internal/storage/b2"
)

var rootCmd = &cobra.Command{
	Use:   "burrow",
	Short: "Backblaze B2 backup tool with encryption",
	Long:  `A CLI tool for securely backing up files to Backblaze B2 with encryption`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(uploadCmd)
	rootCmd.AddCommand(downloadCmd)
}

// initB2Client creates a B2 client from config
func initB2Client(ctx context.Context, cfg *config.Config) (*b2.B2Client, error) {
	const (
		b2PartSizeMB  = 16
		b2Concurrency = 4
	)

	opts := &b2.Opts{
		Bucket:      cfg.BucketName,
		Region:      cfg.Region,
		Endpoint:    fmt.Sprintf("https://s3.%s.backblazeb2.com", cfg.Region),
		AccessKey:   cfg.KeyID,
		SecretKey:   cfg.AppKey,
		PartSizeMB:  b2PartSizeMB,
		Concurrency: b2Concurrency,
	}

	client, err := b2.New(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create B2 client: %w", err)
	}

	return client, nil
}
