package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/thebluefowl/burrow/internal/config"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update existing configuration",
	Long:  `Update your Backblaze B2 configuration settings. You can update Key ID, Application Key, Bucket Name, and Region.`,
	RunE:  runUpdate,
}

func runUpdate(cmd *cobra.Command, args []string) error {
	if !config.Exists() {
		return fmt.Errorf("no configuration found. Please run setup first")
	}

	password, err := askMasterPassword()
	if err != nil {
		return fmt.Errorf("failed to get master password: %w", err)
	}

	cfg, err := config.Load(password)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	color.New(color.BgWhite).Println("Update Configuration")
	fmt.Println()
	color.Yellow("Leave fields empty to keep current values.")
	fmt.Println()

	updatedCfg, err := updateConfig(cfg)
	if err != nil {
		return err
	}

	if err := config.Save(*updatedCfg, password); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	color.Green("✓ Configuration updated successfully!")
	return nil
}

func updateConfig(currentCfg *config.Config) (*config.Config, error) {
	questions := []*survey.Question{
		{
			Name: "keyid",
			Prompt: &survey.Input{
				Message: fmt.Sprintf("Backblaze Key ID (current: %s):", maskString(currentCfg.KeyID)),
				Default: currentCfg.KeyID,
			},
		},
		{
			Name: "appkey",
			Prompt: &survey.Password{
				Message: "Backblaze Application Key (leave empty to keep current):",
			},
		},
		{
			Name: "bucketname",
			Prompt: &survey.Input{
				Message: fmt.Sprintf("Backblaze Bucket Name (current: %s):", currentCfg.BucketName),
				Default: currentCfg.BucketName,
			},
		},
		{
			Name: "region",
			Prompt: &survey.Input{
				Message: fmt.Sprintf("Backblaze Region (current: %s):", currentCfg.Region),
				Default: currentCfg.Region,
				Help:    "e.g., us-west-002, us-east-005, eu-central-003",
			},
		},
	}

	var answers struct {
		KeyID      string
		AppKey     string
		BucketName string
		Region     string
	}

	if err := survey.Ask(questions, &answers); err != nil {
		return nil, err
	}

	updatedCfg := *currentCfg

	// Update fields only if new values are provided
	if answers.KeyID != "" {
		updatedCfg.KeyID = answers.KeyID
	}
	if answers.AppKey != "" {
		updatedCfg.AppKey = answers.AppKey
	}
	if answers.BucketName != "" {
		updatedCfg.BucketName = answers.BucketName
	}
	if answers.Region != "" {
		updatedCfg.Region = answers.Region
	}

	return &updatedCfg, nil
}

// maskString masks sensitive strings, showing only first 4 and last 4 characters
func maskString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
