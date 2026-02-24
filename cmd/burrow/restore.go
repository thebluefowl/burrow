package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/config"
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore configuration from a base64-encoded export",
	Long:  `Restore the encrypted configuration file from a base64-encoded string produced by 'burrow config export'.`,
	RunE:  runRestore,
}

func runRestore(cmd *cobra.Command, args []string) error {
	var input string
	if err := survey.AskOne(&survey.Password{
		Message: "Paste exported config:",
	}, &input); err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return fmt.Errorf("invalid base64 input: %w", err)
	}

	if config.Exists() {
		var confirm bool
		if err := survey.AskOne(&survey.Confirm{
			Message: "Existing configuration found. Overwrite?",
			Default: false,
		}, &confirm); err != nil {
			return fmt.Errorf("failed to get confirmation: %w", err)
		}
		if !confirm {
			fmt.Println("Restore cancelled.")
			return nil
		}
	}

	path, err := config.ConfigFilePath()
	if err != nil {
		return fmt.Errorf("failed to resolve config path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	color.Green("✓ Configuration restored successfully!")
	return nil
}
