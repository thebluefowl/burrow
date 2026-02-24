package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/config"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export encrypted configuration as base64",
	Long:  `Export the encrypted configuration file as a base64-encoded string for backup purposes.`,
	RunE:  runExport,
}

func runExport(cmd *cobra.Command, args []string) error {
	path, err := config.ConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to resolve config path: %w", err)
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no configuration found. Please run setup first")
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))
	return nil
}
